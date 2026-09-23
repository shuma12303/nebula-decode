// 验证脚本：mock 掉 cloudflare:sockets 后，在 Node 中直接测试 _worker.js 的纯逻辑
import { readFileSync } from 'node:fs';

let src = readFileSync(new URL('../public/_worker.js', import.meta.url), 'utf8');
src = src.replace(/import\s*{\s*connect\s*}\s*from\s*['"]cloudflare:sockets['"];?/, "const connect = () => { throw new Error('mock: no network in tests'); };");
src = src.replace('export default', 'const _default =');
src += '\nexport { sha224Hex, uuidStringify, isValidUUID, bytesToB64, parseClientPacket, buildNodes, buildClashYaml, buildSingBox, normalizeBase, qrGfMul, qrDataCodewords, qrFormatBits, qrVersionBits, qrEncode, qrSvg, BUILTIN_OPTIMAL, _default };';
const mod = await import('data:text/javascript;base64,' + Buffer.from(src, 'utf8').toString('base64'));

let pass = 0, fail = 0;
const eq = (name, got, want) => {
  const ok = got === want;
  ok ? pass++ : fail++;
  console.log(`${ok ? 'PASS' : 'FAIL'}  ${name}${ok ? '' : `\n      got:  ${got}\n      want: ${want}`}`);
};

// ---- SHA-224 标准测试向量 (FIPS 180-4) ----
eq('sha224("abc")', mod.sha224Hex('abc'), '23097d223405d8228642a477bda255b32aadbce4bda0b3f7e36c9da7');
eq('sha224("")', mod.sha224Hex(''), 'd14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f');
eq('sha224("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq")',
  mod.sha224Hex('abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq'),
  '75388b16512776cc5dba5da1fd890150b0c6455cb4f58b1952522525');
// 长文本（多块填充 + 长度字段）——直接与 node:crypto 对比
import crypto from 'node:crypto';
eq('sha224(100万字符a)',
  mod.sha224Hex('a'.repeat(1000000)),
  crypto.createHash('sha224').update('a'.repeat(1000000)).digest('hex'));
eq('sha224(中文文本)',
  mod.sha224Hex('云支付终端测试_PASSWORD-2026!'),
  crypto.createHash('sha224').update('云支付终端测试_PASSWORD-2026!').digest('hex'));

// ---- UUID 工具 ----
eq('uuidStringify', mod.uuidStringify(new Uint8Array([
  0x24, 0xb3, 0xc8, 0xb0, 0x0b, 0x1e, 0x4f, 0x5e, 0x9c, 0x2a, 0x7f, 0x6d, 0x5a, 0x4b, 0x3c, 0x2d,
])), '24b3c8b0-0b1e-4f5e-9c2a-7f6d5a4b3c2d');
eq('isValidUUID ok', mod.isValidUUID('24b3c8b0-0b1e-4f5e-9c2a-7f6d5a4b3c2d'), true);
eq('isValidUUID bad', mod.isValidUUID('not-a-uuid'), false);

// ---- VLESS 首包解析（域名 + IPv4 + IPv6）----
const uuid = '24b3c8b0-0b1e-4f5e-9c2a-7f6d5a4b3c2d';
const cfg = { uuid, enableVless: true, enableTrojan: false, trojanPassword: '' };

function vlessPacket(host, port, addrType) {
  const bytes = [0, ...Array.from({ length: 16 }, (_, i) => parseInt(uuid.replace(/-/g, '').slice(i * 2, i * 2 + 2), 16)), 0, 1];
  bytes.push((port >> 8) & 0xff, port & 0xff, addrType);
  if (addrType === 2) {
    const d = Array.from(host, (c) => c.charCodeAt(0));
    bytes.push(d.length, ...d);
  } else if (addrType === 1) {
    bytes.push(...host.split('.').map(Number));
  } else {
    for (const part of host.split(':')) bytes.push(parseInt(part, 16) >> 8, parseInt(part, 16) & 0xff);
  }
  bytes.push(0x16, 0x03, 0x01); // 模拟 TLS ClientHello 负载
  return new Uint8Array(bytes);
}

const p1 = await mod.parseClientPacket(vlessPacket('www.example.com', 443, 2), cfg);
eq('vless domain', `${p1.proto}|${p1.address}|${p1.port}|${p1.command}`, 'vless|www.example.com|443|1');
eq('vless responseHeader', Array.from(p1.responseHeader).join(','), '0,0');
eq('vless payload', Array.from(p1.payload.slice(0, 3)).join(','), '22,3,1');

const p2 = await mod.parseClientPacket(vlessPacket('1.2.3.4', 8080, 1), cfg);
eq('vless ipv4', `${p2.address}:${p2.port}`, '1.2.3.4:8080');

const p3 = await mod.parseClientPacket(vlessPacket('2606:4700:4700:0:0:0:0:1111', 443, 3), cfg);
eq('vless ipv6', p3.address, '2606:4700:4700:0:0:0:0:1111');

// ---- Trojan 首包解析 ----
// 格式: hex(sha224(password)) 56B + CRLF + CMD + ATYP + LEN + 域名 + 端口2B + CRLF + 负载
const pw = 'test-pass';
const t = [...Array.from(mod.sha224Hex(pw)).map((c) => c.charCodeAt(0))];
t.push(13, 10);                                  // CRLF
t.push(1);                                       // CMD = CONNECT
t.push(2);                                       // ATYP = 域名
t.push('example.org'.length);
for (const c of 'example.org') t.push(c.charCodeAt(0));
t.push(0x01, 0xbb);                              // 端口 443
t.push(13, 10);                                  // CRLF
t.push(1, 2, 3);                                 // 负载
const trojanBytes = new Uint8Array(t);
const p4 = await mod.parseClientPacket(trojanBytes, { ...cfg, enableTrojan: true, trojanPassword: pw });
eq('trojan parse', `${p4.proto}|${p4.address}|${p4.port}|${p4.command}`, 'trojan|example.org|443|1');
eq('trojan payload', Array.from(p4.payload).join(','), '1,2,3');
eq('trojan responseHeader empty', p4.responseHeader.length, 0);

// ---- 错误路径 ----
try {
  await mod.parseClientPacket(vlessPacket('www.example.com', 443, 2), { ...cfg, uuid: '11111111-1111-1111-1111-111111111111' });
  eq('vless wrong uuid rejected', 'no-error', 'error');
} catch (e) { eq('vless wrong uuid rejected', /UUID/.test(e.message), true); }

try {
  await mod.parseClientPacket(trojanBytes, { ...cfg, enableTrojan: true, trojanPassword: 'wrong' });
  eq('trojan wrong password rejected', 'no-error', 'error');
} catch (e) { eq('trojan wrong password rejected', /Trojan/.test(e.message), true); }

// ---- 节点 / 订阅生成 ----
const url = new URL('https://demo.example.workers.dev');
const POOL = mod.BUILTIN_OPTIMAL;
eq('内置优选池条目数 20~30', POOL.length >= 20 && POOL.length <= 30, true);
eq('内置优选池覆盖 HK/SG/JP/US/EU',
  ['HK', 'SG', 'JP', 'US', 'EU'].every((r) => POOL.some((p) => p.region === r)), true);
eq('内置优选池全部为 IP', POOL.every((p) => /^(\d{1,3}\.){3}\d{1,3}$/.test(p.host)), true);
eq('内置优选池无重复 host', new Set(POOL.map((p) => p.host)).size, POOL.length);

const subCfg = { uuid, path: '', enableVless: true, enableTrojan: true, trojanPassword: pw, preferredDomains: ['cf.090227.xyz'] };
const nodes = mod.buildNodes(url, subCfg, ['104.16.1.1']);
// hosts = Worker 域名 + 用户优选域名 + 内置优选池 + 用户优选 IP，每个 host 生成 vless + trojan 两个节点
const expectedHosts = 1 + 1 + POOL.length + 1;
eq('node count (hosts x vless+trojan, 含内置池)', nodes.length, expectedHosts * 2);
eq('内置池节点全部出现', POOL.every((p) => nodes.some((n) => n.server === p.host)), true);
eq('内置池节点带地区前缀命名', nodes.find((n) => n.server === POOL[0].host).name, POOL[0].region + '-IP-' + POOL[0].host);
eq('默认节点(Worker 域名)不带地区前缀', nodes[0].name, 'demo.example.workers.dev');
eq('ip node sni uses worker domain', nodes.find((n) => n.server === '104.16.1.1').sni, 'demo.example.workers.dev');
// 关闭内置池 → 只保留 Worker 域名 + 用户优选域名 + 用户 IP
const noPool = mod.buildNodes(url, { ...subCfg, useBuiltinPool: false }, ['104.16.1.1']);
eq('关闭内置池后仅用户来源节点', noPool.length, 3 * 2);
// 用户手填 IP 与内置池重复时去重
const dedup = mod.buildNodes(url, { ...subCfg, preferredDomains: [] }, [POOL[0].host]);
eq('用户 IP 与内置池重复时去重', dedup.length, (1 + POOL.length) * 2);
eq('vless link format', nodes[0].link,
  `vless://${uuid}@demo.example.workers.dev:443?encryption=none&security=tls&sni=demo.example.workers.dev&fp=chrome&type=ws&host=demo.example.workers.dev&path=%2F${uuid}%3Fed%3D2048#demo.example.workers.dev`);
const yaml = mod.buildClashYaml(nodes);
eq('clash yaml has proxies', /proxies:\n {2}- name:/.test(yaml), true);
eq('clash yaml vless ws-opts', /type: vless[\s\S]*?network: ws/.test(yaml), true);

// ---- base64 编解码（分块大文本）----
const big = new TextEncoder().encode('vless://x\n'.repeat(5000));
eq('bytesToB64 roundtrip', Buffer.from(mod.bytesToB64(big), 'base64').toString(), Buffer.from(big).toString());

// ---- 配置路径归一化 ----
eq('normalizeBase multi-level', mod.normalizeBase('my/nodes/'), '/my/nodes');
eq('normalizeBase empty', mod.normalizeBase(''), '');

// ---- QR 编码器：GF(2^8) 与容量表 ----
eq('qrGfMul(2,128)=0x1D（本原多项式 0x11D 归约）', mod.qrGfMul(2, 128), 0x1D);
eq('qrGfMul 交换律', mod.qrGfMul(0x53, 0xCA), mod.qrGfMul(0xCA, 0x53));
eq('qrGfMul 与 0 结合', mod.qrGfMul(0x9A, 0), 0);
let gfInvertible = true;
for (let a = 1; a < 256 && gfInvertible; a++) {
  let found = false;
  for (let b = 1; b < 256; b++) { if (mod.qrGfMul(a, b) === 1) { found = true; break; } }
  if (!found) gfInvertible = false;
}
eq('GF(256) 非零元均有乘法逆元', gfInvertible, true);

// 数据码字容量（ISO/IEC 18004 表 7，用于校验 ECC/block 表未被笔误破坏）
eq('数据码字数 v1-L', mod.qrDataCodewords(1, 0), 19);
eq('数据码字数 v1-M', mod.qrDataCodewords(1, 1), 16);
eq('数据码字数 v1-Q', mod.qrDataCodewords(1, 2), 13);
eq('数据码字数 v1-H', mod.qrDataCodewords(1, 3), 9);
eq('数据码字数 v40-L', mod.qrDataCodewords(40, 0), 2956);
eq('数据码字数 v40-H', mod.qrDataCodewords(40, 3), 1276);

// 格式信息 BCH(15,5)（ISO/IEC 18004 表 12，mask=0 的四个已知常量）
eq('格式信息 L/mask0', mod.qrFormatBits('L', 0), 0x77C4);
eq('格式信息 M/mask0', mod.qrFormatBits('M', 0), 0x5412);
eq('格式信息 Q/mask0', mod.qrFormatBits('Q', 0), 0x355F);
eq('格式信息 H/mask0', mod.qrFormatBits('H', 0), 0x1689);

// 版本信息 BCH(18,6)（ISO/IEC 18004 附录 D）
eq('版本信息 v7', mod.qrVersionBits(7), 0x07C94);
eq('版本信息 v40', mod.qrVersionBits(40), 0x28C69);

// 端到端：文本 -> 矩阵 -> SVG
const qrM = mod.qrEncode('HELLO NEBULA', 'M');
eq('QR v1 矩阵大小 21x21', qrM.length, 21 * 21);
eq('QR 矩阵仅含 0/1', qrM.every((v) => v === 0 || v === 1), true);
eq('QR v1 左上定位图形左上角为黑', qrM[0], 1);
eq('QR v1 定位图形内圈 (1,1) 为白', qrM[1 * 21 + 1], 0);
const qrBig = mod.qrEncode('x'.repeat(200), 'M');
eq('QR v10 矩阵大小 57x57', qrBig.length, 57 * 57);

const qrSvgStr = mod.qrSvg(qrM);
eq('SVG 根元素', qrSvgStr.startsWith('<svg'), true);
eq('SVG 含合并 path', qrSvgStr.includes('<path d="M'), true);
eq('SVG 完整闭合', qrSvgStr.endsWith('</svg>'), true);
eq('SVG 带 viewBox', qrSvgStr.includes('viewBox="0 0 '), true);
eq('SVG 未含非法字符 <', qrSvgStr.slice(qrSvgStr.indexOf('<path')).includes('<<'), false);

// ---- 路由冒烟测试（mock KV + 标准 Request/Response，不依赖 Cloudflare 运行时）----
const memKV = {
  store: new Map(),
  get: async (k) => memKV.store.get(k) ?? null,
  put: async (k, v) => { memKV.store.set(k, v); },
};
const worker = mod._default;
const env = { KV: memKV };
const U0 = '24b3c8b0-0b1e-4f5e-9c2a-7f6d5a4b3c2d';
const origin = 'https://demo.example.workers.dev';
const req = (method, path, body, headers) =>
  new Request(origin + path, { method, body, headers: body ? { 'content-type': 'application/json', ...headers } : headers });

let r = await worker.fetch(req('GET', '/' + U0), env);
eq('面板可访问', r.status, 200);
eq('面板响应头品牌标识', (r.headers.get('x-powered-by') || '').includes('shumajiedu'), true);
const panelHtml = await r.text();
eq('面板标题', panelHtml.includes('NEBULA-DECODE'), true);
eq('面板品牌水印(数码解码)', panelHtml.includes('数码解码 出品'), true);
eq('面板页脚含GitHub链接', panelHtml.includes('github.com/smzxtv/nebula-decode'), true);

r = await worker.fetch(req('GET', '/' + U0 + '/api/config'), env);
eq('GET config 默认 UUID', (await r.json()).uuid, U0);

r = await worker.fetch(req('POST', '/' + U0 + '/api/config', JSON.stringify({
  uuid: U0, path: 'my/nodes', proxyIP: '1.1.1.1', trojanPassword: 'pw123',
  enableVless: true, enableTrojan: true, preferredDomains: ['cf.090227.xyz'],
})), env);
eq('POST config 保存', (await r.json()).ok, true);
eq('默认开启内置优选池', (await (await worker.fetch(req('GET', '/my/nodes/api/config'), env)).json()).useBuiltinPool, true);

r = await worker.fetch(req('GET', '/my/nodes/api/config'), env);
const cfg1 = await r.json();
eq('自定义路径生效', cfg1.path, '/my/nodes');
eq('ProxyIP 已存', cfg1.proxyIP, '1.1.1.1');
eq('旧 UUID 路径已失效→返回伪装页', (await worker.fetch(req('GET', '/' + U0), env)).status, 200);

r = await worker.fetch(req('POST', '/my/nodes/api/ips', JSON.stringify({ text: '104.16.1.1\nbad_input\n104.16.2.2' })), env);
eq('批量添加 IP 过滤非法项', (await r.json()).ips.join(','), '104.16.1.1,104.16.2.2');

r = await worker.fetch(req('GET', '/my/nodes/sub'), env);
eq('订阅响应头品牌标识', (r.headers.get('x-powered-by') || '').includes('shumajiedu'), true);
const subText = Buffer.from(await r.text(), 'base64').toString();
eq('订阅含 vless 节点', subText.includes('vless://'), true);
eq('订阅含 trojan 节点', subText.includes('trojan://'), true);
// base64 订阅正文不能掺广告词(会破坏客户端解析)
eq('订阅正文无广告词(纯节点)', !subText.includes('数码解码'), true);
// hosts = Worker 域名 + 优选域名 + 内置优选池(默认开启) + 2 个用户 IP，每个 host 两个协议
eq('订阅节点数（含内置优选池）', subText.split('\n').filter(Boolean).length, (1 + 1 + POOL.length + 2) * 2);
eq('订阅含内置池地区节点', subText.includes(POOL[0].region + '-IP-' + POOL[0].host), true);

r = await worker.fetch(req('GET', '/my/nodes/sub?target=clash'), env);
const yamlText = await r.text();
eq('clash 订阅', yamlText.includes('type: trojan'), true);
eq('clash 订阅品牌水印', yamlText.includes('数码解码'), true);

r = await worker.fetch(new Request(origin + '/my/nodes/sub', { headers: { 'user-agent': 'clash-verge/1.0' } }), env);
eq('UA 自动返回 clash', (await r.text()).includes('proxies:'), true);

// ---- Sing-box 订阅 ----
r = await worker.fetch(req('GET', '/my/nodes/sub?target=singbox'), env);
eq('sing-box content-type', r.headers.get('content-type'), 'application/json; charset=utf-8');
eq('sing-box 下载文件名', (r.headers.get('content-disposition') || '').includes('nebula-decode.json'), true);
const sbText = await r.text();
const sb = JSON.parse(sbText); // 必须是合法 JSON，否则这里直接抛错
eq('sing-box outbounds 为数组', Array.isArray(sb.outbounds), true);
eq('sing-box 含 selector', sb.outbounds.some((o) => o.type === 'selector' && o.tag === 'NEBULA-DECODE'), true);
eq('sing-box 含 urltest', sb.outbounds.some((o) => o.type === 'urltest' && o.tag === 'auto'), true);
eq('sing-box 含 vless 出站', sb.outbounds.some((o) => o.type === 'vless'), true);
eq('sing-box 含 trojan 出站', sb.outbounds.some((o) => o.type === 'trojan'), true);
eq('sing-box 含 direct 出站', sb.outbounds.some((o) => o.type === 'direct' && o.tag === 'direct'), true);
eq('sing-box route.final 指向 selector', sb.route.final, 'NEBULA-DECODE');
const sbProxy = sb.outbounds.filter((o) => o.type === 'vless' || o.type === 'trojan');
eq('sing-box 每个代理出站都带 tls.server_name（SNI 修正保留）', sbProxy.every((o) => o.tls && o.tls.server_name), true);
eq('sing-box 每个代理出站都带 utls chrome', sbProxy.every((o) => o.tls && o.tls.utls && o.tls.utls.fingerprint === 'chrome'), true);
eq('sing-box ws 传输 headers.Host 对齐', sbProxy.every((o) => o.transport && o.transport.type === 'ws' && o.transport.headers && o.transport.headers.Host), true);
eq('sing-box 无 dns 段（客户端版本兼容）', sb.dns === undefined, true);

r = await worker.fetch(new Request(origin + '/my/nodes/sub', { headers: { 'user-agent': 'sing-box/1.10.0' } }), env);
eq('UA 自动返回 sing-box', (r.headers.get('content-type') || '').includes('application/json'), true);

// ---- /qr 二维码路由 ----
r = await worker.fetch(req('GET', '/my/nodes/qr?t=singbox'), env);
eq('/qr 状态 200', r.status, 200);
eq('/qr content-type svg', (r.headers.get('content-type') || '').includes('image/svg+xml'), true);
const qrBody = await r.text();
eq('/qr 返回完整 SVG', qrBody.startsWith('<svg') && qrBody.endsWith('</svg>'), true);
eq('/qr SVG 含绘制路径', qrBody.includes('<path d="M'), true);

r = await worker.fetch(req('GET', '/my/nodes/qr?t=clash'), env);
eq('/qr?t=clash 可访问', r.status, 200);
r = await worker.fetch(req('GET', '/my/nodes/qr'), env);
eq('/qr 无参数默认 base64 可访问', r.status, 200);

r = await worker.fetch(req('POST', '/my/nodes/api/config', JSON.stringify({ uuid: 'bad', enableVless: true })), env);
eq('非法 UUID 被拒绝', (await r.json()).ok, false);

eq('随机路径返回伪装页(200)', (await worker.fetch(req('GET', '/nothing/here'), env)).status, 200);

// ---- 伪装页（防主动扫描）----
r = await worker.fetch(req('GET', '/'), env);
eq('根路径伪装页状态 200', r.status, 200);
const camoHtml = await r.text();
eq('伪装页是结构完整的 HTML', camoHtml.includes('<!DOCTYPE html>') && camoHtml.includes('</html>'), true);
eq('伪装页含博客标题/导航/文章', camoHtml.includes('class="nav"') && camoHtml.includes('class="post"') && camoHtml.includes('<footer>'), true);
eq('伪装页不含任何项目标识', /NEBULA|nebula|数码解码|shumajiedu|cf_terminal/i.test(camoHtml), false);
eq('伪装页无品牌响应头', r.headers.get('x-powered-by'), null);

// 同一域名必须返回同一身份，否则会被扫描器识破
const camoHtml2 = await (await worker.fetch(req('GET', '/some/random/path'), env)).text();
eq('伪装页同域名内容稳定', camoHtml2, camoHtml);

r = await worker.fetch(req('HEAD', '/'), env);
eq('HEAD 伪装页无正文', (await r.text()).length, 0);

// ---- /api/* 密钥鉴权 ----
r = await worker.fetch(req('POST', '/my/nodes/api/config', JSON.stringify({
  uuid: U0, path: 'my/nodes', proxyIP: '1.1.1.1', trojanPassword: 'pw123',
  enableVless: true, enableTrojan: true, preferredDomains: ['cf.090227.xyz'], apiToken: 'secret-token-123',
})), env);
eq('保存 API 密钥', (await r.json()).ok, true);

eq('无密钥访问 API 被拒(401)', (await worker.fetch(req('GET', '/my/nodes/api/config'), env)).status, 401);
eq('错误密钥被拒(401)', (await worker.fetch(req('GET', '/my/nodes/api/config', null, { 'x-api-token': 'wrong' }), env)).status, 401);

r = await worker.fetch(req('GET', '/my/nodes/api/config', null, { 'x-api-token': 'secret-token-123' }), env);
eq('带 X-API-Token 通过', r.status, 200);
eq('密钥值回读一致', (await r.json()).apiToken, 'secret-token-123');

r = await worker.fetch(req('GET', '/my/nodes/api/ips', null, { authorization: 'Bearer secret-token-123' }), env);
eq('Authorization Bearer 亦可', r.status, 200);

r = await worker.fetch(req('POST', '/my/nodes/api/ips', JSON.stringify({ text: '104.16.9.9' }), { origin: 'https://evil.example' }), env);
eq('跨站写操作被拒(403)', r.status, 403);

r = await worker.fetch(req('POST', '/my/nodes/api/ips', JSON.stringify({ text: '104.16.9.9' }), { origin: origin, 'x-api-token': 'secret-token-123' }), env);
eq('同源写操作放行', (await r.json()).ok, true);

// 面板页面必须把密钥注入进去（否则面板自己调不动 API）
const panelWithToken = await (await worker.fetch(req('GET', '/my/nodes'), env)).text();
eq('面板已注入 API_TOKEN', panelWithToken.includes('"secret-token-123"'), true);

// 清空密钥 → 恢复「仅路径鉴权」模式
r = await worker.fetch(req('POST', '/my/nodes/api/config', JSON.stringify({
  uuid: U0, path: 'my/nodes', proxyIP: '1.1.1.1', trojanPassword: 'pw123',
  enableVless: true, enableTrojan: true, preferredDomains: ['cf.090227.xyz'], apiToken: '',
}), { 'x-api-token': 'secret-token-123' }), env);
eq('清空 API 密钥', (await r.json()).ok, true);
eq('清空后 API 恢复开放', (await worker.fetch(req('GET', '/my/nodes/api/config'), env)).status, 200);

console.log(`\n结果: ${pass} 通过, ${fail} 失败`);
process.exit(fail ? 1 : 0);