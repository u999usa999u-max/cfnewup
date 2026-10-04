// =========================================================================
// Cloudflare VLESS 极简纯净版 Worker
// 特性：
// 1. 零外部依赖、零第三方接口、零冷启动开销，彻底杜绝 1101 错误
// 2. 纯原生 cloudflare:sockets 直连，支持标准 VLESS over WebSocket
// 3. 支持 early data (?ed=2048 / Sec-WebSocket-Protocol)
// 4. 支持 UDP DNS (53 端口通过 1.1.1.1 DoH 解析)
// 5. 非 WebSocket 访问返回轻量极速状态面板，支持 /sub 查看订阅
// =========================================================================

import { connect } from 'cloudflare:sockets';

// 支持的 UUID 列表（内置你的 Clash 现有配置 UUID，直接免配置生效）
const DEFAULT_UUIDS = [
  '351c9981-04b6-4103-aa4b-864aa9c91469',
  '8e2b7c4d-91a5-4f3e-8c76-2d1f0b9e5a3c'
];

// 可选反向代理 IP（当直连目标网站被阻断时兜底，默认直连留空即可）
const PROXY_IP = '';

export default {
  /**
   * @param {Request} request
   * @param {Record<string, string>} env
   * @param {ExecutionContext} ctx
   */
  async fetch(request, env, ctx) {
    try {
      const upgradeHeader = request.headers.get('Upgrade');
      const allowedUUIDs = [
        ...(env && env.UUID ? [env.UUID.trim().toLowerCase()] : []),
        ...DEFAULT_UUIDS.map(u => u.toLowerCase())
      ];

      // 1. 普通 HTTP 请求：返回轻量状态面板或订阅
      if (!upgradeHeader || upgradeHeader.toLowerCase() !== 'websocket') {
        const url = new URL(request.url);
        return handleHttpRequest(request, url, allowedUUIDs[0]);
      }

      // 2. WebSocket 请求：处理 VLESS 代理
      return await handleVlessOverWS(request, allowedUUIDs);
    } catch (err) {
      return new Response(`Worker Internal Error: ${err.message}`, { status: 500 });
    }
  }
};

/**
 * 处理 VLESS over WebSocket
 */
async function handleVlessOverWS(request, allowedUUIDs) {
  const webSocketPair = new WebSocketPair();
  const [client, server] = Object.values(webSocketPair);

  server.accept();

  const earlyDataHeader = request.headers.get('sec-websocket-protocol') || '';
  const readableWebSocketStream = makeReadableWebSocketStream(server, earlyDataHeader);

  let remoteSocketWrapper = { value: null };
  let udpStreamWrite = null;
  let isDns = false;

  readableWebSocketStream.pipeTo(new WritableStream({
    async write(chunk, controller) {
      if (isDns && udpStreamWrite) {
        return udpStreamWrite(chunk);
      }
      if (remoteSocketWrapper.value) {
        const writer = remoteSocketWrapper.value.writable.getWriter();
        await writer.write(chunk);
        writer.releaseLock();
        return;
      }

      // 解析首包 VLESS 头部
      const {
        hasError,
        message,
        portRemote,
        addressRemote,
        rawDataIndex,
        vlessVersion,
        isUDP
      } = parseVlessHeader(chunk, allowedUUIDs);

      if (hasError) {
        controller.error(new Error(message));
        return;
      }

      // UDP 处理 (仅针对 DNS 53 端口走 DoH，其他非 53 UDP 友好拒绝不崩溃)
      if (isUDP) {
        if (portRemote === 53) {
          isDns = true;
          udpStreamWrite = makeDnsHandler(server, vlessVersion);
          const rawClientData = chunk.slice(rawDataIndex);
          if (rawClientData.byteLength > 0) {
            udpStreamWrite(rawClientData);
          }
          return;
        } else {
          controller.error(new Error(`UDP port ${portRemote} is not supported on Cloudflare Sockets`));
          return;
        }
      }

      // TCP 连接到目标地址
      handleTcpOutbound(
        remoteSocketWrapper,
        addressRemote,
        portRemote,
        chunk.slice(rawDataIndex),
        server,
        vlessVersion
      );
    },
    close() {
      safeCloseWebSocket(server);
      if (remoteSocketWrapper.value) {
        try { remoteSocketWrapper.value.close(); } catch (_) {}
      }
    },
    abort() {
      safeCloseWebSocket(server);
      if (remoteSocketWrapper.value) {
        try { remoteSocketWrapper.value.close(); } catch (_) {}
      }
    }
  })).catch(() => {
    safeCloseWebSocket(server);
  });

  return new Response(null, {
    status: 101,
    webSocket: client,
    headers: earlyDataHeader ? { 'Sec-WebSocket-Protocol': earlyDataHeader } : undefined
  });
}

/**
 * 建立 TCP 出站连接并双向流转数据
 */
async function handleTcpOutbound(
  remoteSocketWrapper,
  addressRemote,
  portRemote,
  rawClientData,
  webSocketServer,
  vlessVersion
) {
  async function connectAndWrite(address, port) {
    const tcpSocket = connect({
      hostname: address,
      port: port
    });
    remoteSocketWrapper.value = tcpSocket;

    const writer = tcpSocket.writable.getWriter();
    if (rawClientData && rawClientData.byteLength > 0) {
      await writer.write(rawClientData);
    }
    writer.releaseLock();
    return tcpSocket;
  }

  async function retry() {
    if (PROXY_IP) {
      try {
        const tcpSocket = await connectAndWrite(PROXY_IP, portRemote);
        pipeRemoteToClient(tcpSocket);
      } catch (_) {
        safeCloseWebSocket(webSocketServer);
      }
    } else {
      safeCloseWebSocket(webSocketServer);
    }
  }

  try {
    const tcpSocket = await connectAndWrite(addressRemote, portRemote);
    pipeRemoteToClient(tcpSocket);
  } catch (err) {
    await retry();
  }

  function pipeRemoteToClient(tcpSocket) {
    let vlessResponseHeader = new Uint8Array([vlessVersion[0], 0]);
    tcpSocket.readable.pipeTo(new WritableStream({
      async write(chunk, controller) {
        if (webSocketServer.readyState !== 1) { // 1 = OPEN
          controller.error('webSocket is closed');
          return;
        }
        if (vlessResponseHeader) {
          const combined = new Uint8Array(vlessResponseHeader.byteLength + chunk.byteLength);
          combined.set(vlessResponseHeader, 0);
          combined.set(new Uint8Array(chunk), vlessResponseHeader.byteLength);
          webSocketServer.send(combined.buffer);
          vlessResponseHeader = null;
        } else {
          webSocketServer.send(chunk);
        }
      },
      close() {
        safeCloseWebSocket(webSocketServer);
      },
      abort() {
        safeCloseWebSocket(webSocketServer);
      }
    })).catch(() => {
      safeCloseWebSocket(webSocketServer);
    });
  }
}

/**
 * 处理 DNS 53 端口 (DoH)
 */
function makeDnsHandler(webSocketServer, vlessVersion) {
  let vlessResponseHeader = new Uint8Array([vlessVersion[0], 0]);
  return async (chunk) => {
    let offset = 0;
    while (offset + 2 <= chunk.byteLength) {
      const view = new DataView(chunk instanceof ArrayBuffer ? chunk : chunk.buffer, chunk.byteOffset + offset);
      const dnsLen = view.getUint16(0);
      offset += 2;
      if (offset + dnsLen > chunk.byteLength) break;
      const dnsQuery = chunk.slice(offset, offset + dnsLen);
      offset += dnsLen;

      try {
        const resp = await fetch('https://1.1.1.1/dns-query', {
          method: 'POST',
          headers: { 'content-type': 'application/dns-message' },
          body: dnsQuery
        });
        if (resp.ok) {
          const dnsResp = await resp.arrayBuffer();
          const dnsRespLen = dnsResp.byteLength;
          const lenPrefix = new Uint8Array([(dnsRespLen >> 8) & 0xff, dnsRespLen & 0xff]);

          if (vlessResponseHeader) {
            const combined = new Uint8Array(vlessResponseHeader.byteLength + 2 + dnsRespLen);
            combined.set(vlessResponseHeader, 0);
            combined.set(lenPrefix, vlessResponseHeader.byteLength);
            combined.set(new Uint8Array(dnsResp), vlessResponseHeader.byteLength + 2);
            webSocketServer.send(combined.buffer);
            vlessResponseHeader = null;
          } else {
            const combined = new Uint8Array(2 + dnsRespLen);
            combined.set(lenPrefix, 0);
            combined.set(new Uint8Array(dnsResp), 2);
            webSocketServer.send(combined.buffer);
          }
        }
      } catch (_) {}
    }
  };
}

/**
 * 解析 VLESS 头部
 */
function parseVlessHeader(buffer, allowedUUIDs) {
  if (buffer.byteLength < 24) {
    return { hasError: true, message: 'Invalid data: header too short' };
  }
  const view = new DataView(buffer instanceof ArrayBuffer ? buffer : buffer.buffer, buffer.byteOffset || 0);
  const version = new Uint8Array(buffer.slice(0, 1));
  const uuidBytes = new Uint8Array(buffer.slice(1, 17));
  const clientUUID = stringifyUUID(uuidBytes);

  const isValidUser = allowedUUIDs.some(id => id.toLowerCase() === clientUUID.toLowerCase());
  if (!isValidUser) {
    return { hasError: true, message: `Invalid UUID: ${clientUUID}` };
  }

  const addonLength = view.getUint8(17);
  let offset = 18 + addonLength;

  if (offset >= buffer.byteLength) {
    return { hasError: true, message: 'Invalid data: truncated after addons' };
  }

  const command = view.getUint8(offset); // 1 = TCP, 2 = UDP
  offset += 1;

  if (command !== 1 && command !== 2) {
    return { hasError: true, message: `Unsupported command: ${command}` };
  }

  const portRemote = view.getUint16(offset);
  offset += 2;

  const addressType = view.getUint8(offset);
  offset += 1;

  let addressRemote = '';
  if (addressType === 1) { // IPv4
    if (offset + 4 > buffer.byteLength) return { hasError: true, message: 'Truncated IPv4' };
    const u8 = new Uint8Array(buffer.slice(offset, offset + 4));
    addressRemote = `${u8[0]}.${u8[1]}.${u8[2]}.${u8[3]}`;
    offset += 4;
  } else if (addressType === 2) { // Domain
    if (offset + 1 > buffer.byteLength) return { hasError: true, message: 'Truncated domain length' };
    const domainLength = view.getUint8(offset);
    offset += 1;
    if (offset + domainLength > buffer.byteLength) return { hasError: true, message: 'Truncated domain string' };
    const domainBytes = new Uint8Array(buffer.slice(offset, offset + domainLength));
    addressRemote = new TextDecoder().decode(domainBytes);
    offset += domainLength;
  } else if (addressType === 3) { // IPv6
    if (offset + 16 > buffer.byteLength) return { hasError: true, message: 'Truncated IPv6' };
    const ipv6Parts = [];
    for (let i = 0; i < 8; i++) {
      ipv6Parts.push(view.getUint16(offset + i * 2).toString(16));
    }
    addressRemote = ipv6Parts.join(':');
    offset += 16;
  } else {
    return { hasError: true, message: `Unsupported addressType: ${addressType}` };
  }

  return {
    hasError: false,
    addressRemote,
    portRemote,
    rawDataIndex: offset,
    vlessVersion: version,
    isUDP: command === 2
  };
}

/**
 * UUID 转换
 */
const byteToHex = [];
for (let i = 0; i < 256; ++i) {
  byteToHex.push((i + 0x100).toString(16).slice(1));
}

function stringifyUUID(buf) {
  return (
    byteToHex[buf[0]] + byteToHex[buf[1]] + byteToHex[buf[2]] + byteToHex[buf[3]] + '-' +
    byteToHex[buf[4]] + byteToHex[buf[5]] + '-' +
    byteToHex[buf[6]] + byteToHex[buf[7]] + '-' +
    byteToHex[buf[8]] + byteToHex[buf[9]] + '-' +
    byteToHex[buf[10]] + byteToHex[buf[11]] + byteToHex[buf[12]] +
    byteToHex[buf[13]] + byteToHex[buf[14]] + byteToHex[buf[15]]
  ).toLowerCase();
}

/**
 * 创建 WebSocket 可读流（支持 EarlyData 提取）
 */
function makeReadableWebSocketStream(webSocketServer, earlyDataHeader) {
  let readableStreamCancel = false;
  return new ReadableStream({
    start(controller) {
      webSocketServer.addEventListener('message', (event) => {
        if (readableStreamCancel) return;
        controller.enqueue(event.data);
      });

      webSocketServer.addEventListener('error', (err) => {
        readableStreamCancel = true;
        controller.error(err);
      });

      webSocketServer.addEventListener('close', () => {
        if (readableStreamCancel) return;
        controller.close();
      });

      // 处理 earlyData (Base64url 格式)
      if (earlyDataHeader) {
        try {
          const rawBase64 = earlyDataHeader.replace(/-/g, '+').replace(/_/g, '/');
          const binary = atob(rawBase64);
          const buf = new Uint8Array(binary.length);
          for (let i = 0; i < binary.length; i++) {
            buf[i] = binary.charCodeAt(i);
          }
          controller.enqueue(buf.buffer);
        } catch (_) {}
      }
    },
    cancel() {
      readableStreamCancel = true;
      safeCloseWebSocket(webSocketServer);
    }
  });
}

function safeCloseWebSocket(ws) {
  try {
    if (ws.readyState === 1 || ws.readyState === 0) {
      ws.close();
    }
  } catch (_) {}
}

/**
 * 处理 HTTP 请求（非 WebSocket）
 */
function handleHttpRequest(request, url, primaryUUID) {
  const host = request.headers.get('Host') || url.hostname;

  if (url.pathname === '/sub' || url.pathname.includes(primaryUUID)) {
    const vlessLink = `vless://${primaryUUID}@${host}:443?encryption=none&security=tls&sni=${host}&type=ws&host=${host}&path=%2F%3Fed%3D2048#CF-Pure-VLESS`;
    return new Response(btoa(vlessLink), {
      status: 200,
      headers: {
        'content-type': 'text/plain; charset=utf-8',
        'cache-control': 'no-store'
      }
    });
  }

  const html = `<!DOCTYPE html>
<html lang="zh-CN">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Cloudflare VLESS Node</title>
  <style>
    :root { --bg: #0d1117; --card: #161b22; --border: #30363d; --text: #c9d1d9; --accent: #238636; --cyan: #58a6ff; }
    body { background: var(--bg); color: var(--text); font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Helvetica, Arial, sans-serif; display: flex; justify-content: center; align-items: center; min-height: 100vh; margin: 0; padding: 20px; box-sizing: border-box; }
    .card { background: var(--card); border: 1px solid var(--border); border-radius: 12px; padding: 28px; max-width: 580px; width: 100%; box-shadow: 0 8px 24px rgba(0,0,0,0.4); }
    h1 { font-size: 20px; margin: 0 0 16px 0; color: #fff; display: flex; align-items: center; gap: 10px; }
    .badge { background: rgba(35, 134, 54, 0.2); color: #3fb950; border: 1px solid rgba(63, 185, 80, 0.4); font-size: 13px; font-weight: 500; padding: 3px 10px; border-radius: 20px; }
    p { font-size: 14px; line-height: 1.6; margin: 8px 0; color: #8b949e; }
    .box { background: #0b0e14; border: 1px solid var(--border); border-radius: 8px; padding: 12px; font-family: ui-monospace, SFMono-Regular, monospace; font-size: 13px; color: #58a6ff; word-break: break-all; margin: 12px 0; user-select: all; }
    .label { font-size: 12px; color: #8b949e; text-transform: uppercase; letter-spacing: 0.5px; }
    .tip { font-size: 13px; color: #8b949e; border-left: 3px solid #58a6ff; padding-left: 10px; margin-top: 18px; }
  </style>
</head>
<body>
  <div class="card">
    <h1><span>⚡</span> CF 纯净版 VLESS 节点 <span class="badge">Running 正常</span></h1>
    <p>此 Worker 采用零外部依赖极简内核，WebSocket 双向流传输，免疫 1101 错误。</p>
    <div class="label">Host / SNI 域名:</div>
    <div class="box">${host}</div>
    <div class="label">当前主 UUID:</div>
    <div class="box">${primaryUUID}</div>
    <div class="label">WS 路径:</div>
    <div class="box">/?ed=2048</div>
    <div class="tip">Clash Verge 配置直接生效，无需改动已有节点列表。</div>
  </div>
</body>
</html>`;

  return new Response(html, {
    status: 200,
    headers: {
      'content-type': 'text/html; charset=utf-8',
      'cache-control': 'no-store'
    }
  });
}
