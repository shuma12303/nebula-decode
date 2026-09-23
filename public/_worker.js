// ============================================================
//  NEBULA-DECODE —— Cloudflare Pages/Workers 单文件终端
//  · VLESS-WS / Trojan-WS 双协议（同一入口自动识别）
//  · Web 图形化管理面板（挂载在 /{UUID 或自定义路径}）
//  · 配置存 KV，改完立即生效，无需重新部署
//  · 订阅生成 + UA 自动识别（base64 / Clash / Sing-box）
//  · 订阅二维码（内置零依赖 QR 编码器，手机扫码导入）
//  · 优选 IP / 域名管理 + REST API
//  · ProxyIP 回落（直连无响应自动走 ProxyIP）
//  · 伪装页（未带正确入口路径 → 返回静态博客首页，防主动扫描）
//  · API 鉴权（可选 Header 密钥 + 同源校验）
//  作者: 数码解码  ·  https://github.com/smzxtv/nebula-decode
// ============================================================
import { connect } from 'cloudflare:sockets';

const CFG_KEY = 'cf_terminal_cfg';
const IPS_KEY = 'cf_terminal_ips';
const WS_OPEN = 1;

const DEFAULT_UUID = '24b3c8b0-0b1e-4f5e-9c2a-7f6d5a4b3c2d';

// 内置公共优选域名（可在面板中修改，修改后存 KV）
const BUILTIN_PREFERRED = [
  'cf.090227.xyz',
  'bestcf.top',
  'cloudflare.182682.xyz',
  'cf.zhetengsha.eu.org',
];

// 内置 Cloudflare 优选 IP 池（按地区分组；生成订阅时自动与用户配置的域名合并，批量产出节点）
//
// 说明与免责：
//  · 下列地址取自 Cloudflare 官方公开的 Anycast 网段（104.16.0.0/13、172.64.0.0/13、
//    162.159.0.0/16、188.114.96.0/20、190.93.240.0/20、197.234.240.0/22、198.41.128.0/17、
//    103.21.244.0/22、103.22.200.0/22、103.31.4.0/22、108.162.192.0/18、131.0.72.0/22、
//    141.101.64.0/18、173.245.48.0/20）中各取一个代表地址。
//  · region 仅用于「节点命名 / 分组」（HK / SG / JP / US / EU），并不代表该 IP 的物理落地
//    机房 —— Cloudflare Anycast 按客户端位置就近调度，真实出口由网络路径决定。
//  · 这些地址只作为连接地址 (server)；SNI / Host 仍强制为本 Worker 域名，见 buildNodes。
const BUILTIN_OPTIMAL = [
  { region: 'HK', host: '104.28.0.1' },
  { region: 'HK', host: '172.64.145.1' },
  { region: 'HK', host: '103.21.244.1' },
  { region: 'HK', host: '173.245.48.1' },
  { region: 'SG', host: '104.26.0.1' },
  { region: 'SG', host: '104.27.0.1' },
  { region: 'SG', host: '162.159.46.1' },
  { region: 'SG', host: '198.41.128.1' },
  { region: 'JP', host: '104.24.0.1' },
  { region: 'JP', host: '104.25.0.1' },
  { region: 'JP', host: '162.159.36.1' },
  { region: 'JP', host: '197.234.240.1' },
  { region: 'US', host: '104.16.0.1' },
  { region: 'US', host: '104.17.0.1' },
  { region: 'US', host: '104.18.0.1' },
  { region: 'US', host: '104.19.0.1' },
  { region: 'US', host: '172.64.0.1' },
  { region: 'US', host: '172.67.0.1' },
  { region: 'US', host: '162.159.0.1' },
  { region: 'EU', host: '104.21.0.1' },
  { region: 'EU', host: '104.22.0.1' },
  { region: 'EU', host: '172.64.80.1' },
  { region: 'EU', host: '188.114.96.1' },
  { region: 'EU', host: '190.93.240.1' },
  { region: 'GLOBAL', host: '103.22.200.1' },
  { region: 'GLOBAL', host: '103.31.4.1' },
  { region: 'GLOBAL', host: '108.162.192.1' },
  { region: 'GLOBAL', host: '131.0.72.1' },
];

// ============================ 基础工具 ============================

function uuidStringify(bytes) {
  const hex = Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20, 32)}`;
}

function isValidUUID(s) {
  return /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(s || '');
}

function bytesToB64(bytes) {
  let s = '';
  const chunk = 0x8000;
  for (let i = 0; i < bytes.length; i += chunk) {
    s += String.fromCharCode.apply(null, bytes.subarray(i, i + chunk));
  }
  return btoa(s);
}

function isIPv4(s) {
  return /^(\d{1,3}\.){3}\d{1,3}$/.test(s);
}
function isIPv6(s) {
  return s.includes(':') && /^[0-9a-f:.]+$/i.test(s);
}
function isIP(s) {
  return isIPv4(s) || isIPv6(s);
}

// SHA-224 纯 JS 实现（Workers 的 crypto.subtle 不支持 SHA-224，Trojan 协议必需）
// 常数表已用高精度计算并校验锚点值（K[0]=0x428a2f98, K[63]=0xc67178f2）
const K = [
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
  0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
  0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
  0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
  0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
  0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

function rotr(x, n) {
  return ((x >>> n) | (x << (32 - n))) >>> 0;
}

function sha224Hex(text) {
  const msg = new TextEncoder().encode(text);
  const bitLen = msg.length * 8;
  const paddedLen = (((msg.length + 8) >> 6) << 6) + 64;
  const data = new Uint8Array(paddedLen);
  data.set(msg);
  data[msg.length] = 0x80;
  const dv = new DataView(data.buffer);
  dv.setUint32(paddedLen - 8, Math.floor(bitLen / 4294967296));
  dv.setUint32(paddedLen - 4, bitLen >>> 0);

  let h0 = 0xc1059ed8, h1 = 0x367cd507, h2 = 0x3070dd17, h3 = 0xf70e5939,
      h4 = 0xffc00b31, h5 = 0x68581511, h6 = 0x64f98fa7, h7 = 0xbefa4fa4;
  const w = new Array(64);

  for (let off = 0; off < paddedLen; off += 64) {
    for (let i = 0; i < 16; i++) w[i] = dv.getUint32(off + i * 4);
    for (let i = 16; i < 64; i++) {
      const s0 = rotr(w[i - 15], 7) ^ rotr(w[i - 15], 18) ^ (w[i - 15] >>> 3);
      const s1 = rotr(w[i - 2], 17) ^ rotr(w[i - 2], 19) ^ (w[i - 2] >>> 10);
      w[i] = (w[i - 16] + s0 + w[i - 7] + s1) | 0;
    }
    let a = h0, b = h1, c = h2, d = h3, e = h4, f = h5, g = h6, h = h7;
    for (let i = 0; i < 64; i++) {
      const S1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
      const ch = (e & f) ^ (~e & g);
      const t1 = (h + S1 + ch + K[i] + w[i]) | 0;
      const S0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
      const maj = (a & b) ^ (a & c) ^ (b & c);
      const t2 = (S0 + maj) | 0;
      h = g; g = f; f = e; e = (d + t1) | 0;
      d = c; c = b; b = a; a = (t1 + t2) | 0;
    }
    h0 = (h0 + a) | 0; h1 = (h1 + b) | 0; h2 = (h2 + c) | 0; h3 = (h3 + d) | 0;
    h4 = (h4 + e) | 0; h5 = (h5 + f) | 0; h6 = (h6 + g) | 0; h7 = (h7 + h) | 0;
  }
  return [h0, h1, h2, h3, h4, h5, h6]
    .map((v) => (v >>> 0).toString(16).padStart(8, '0'))
    .join('');
}

// ============================ 配置（KV > 环境变量 > 默认值） ============================

function normalizeBase(p) {
  p = (p || '').trim().replace(/^\/+|\/+$/g, '');
  return p ? '/' + p : '';
}

async function loadConfig(env) {
  let kv = {};
  try {
    const raw = env.KV ? await env.KV.get(CFG_KEY) : null;
    if (raw) kv = JSON.parse(raw) || {};
  } catch (e) { /* KV 数据损坏时按默认处理 */ }

  return {
    uuid: String(kv.uuid || env.UUID || DEFAULT_UUID).trim().toLowerCase(),
    path: normalizeBase(kv.path || env.CUSTOM_PATH || ''),
    proxyIP: String(kv.proxyIP || env.PROXYIP || '').trim(),
    trojanPassword: String(kv.trojanPassword || env.TROJAN_PASSWORD || '').trim(),
    apiToken: String(kv.apiToken || env.API_TOKEN || '').trim(),
    enableVless: kv.enableVless !== undefined ? !!kv.enableVless : true,
    enableTrojan: kv.enableTrojan !== undefined ? !!kv.enableTrojan : false,
    preferredDomains: Array.isArray(kv.preferredDomains) && kv.preferredDomains.length
      ? kv.preferredDomains.map((s) => String(s).trim()).filter(Boolean)
      : [...BUILTIN_PREFERRED],
    // 是否把内置 Cloudflare 优选 IP 池并入订阅节点；默认开启（旧配置无此字段也自动开启）
    useBuiltinPool: kv.useBuiltinPool !== undefined ? !!kv.useBuiltinPool : true,
  };
}

// 管理面板 / 隧道 / 订阅 的统一入口路径：自定义路径优先，否则用 UUID
function accessBase(cfg) {
  return cfg.path || '/' + cfg.uuid;
}

function matchBase(pathname, base) {
  return pathname === base || pathname === base + '/';
}

async function getPreferredIPs(env) {
  try {
    const raw = env.KV ? await env.KV.get(IPS_KEY) : null;
    if (raw) {
      const arr = JSON.parse(raw);
      if (Array.isArray(arr)) return arr;
    }
  } catch (e) { /* ignore */ }
  return [];
}

async function savePreferredIPs(env, ips) {
  if (!env.KV) throw new Error('未绑定 KV 存储');
  await env.KV.put(IPS_KEY, JSON.stringify(ips));
}

function jsonResp(obj, status = 200) {
  return new Response(JSON.stringify(obj, null, 2), {
    status,
    headers: { 'content-type': 'application/json; charset=utf-8' },
  });
}

// 常数时间字符串比较：长度不同时也走完整循环，避免通过响应时间逐字节猜测密钥
function timingSafeEqual(a, b) {
  const x = String(a == null ? '' : a);
  const y = String(b == null ? '' : b);
  let diff = x.length ^ y.length;
  const n = Math.max(x.length, y.length);
  for (let i = 0; i < n; i++) {
    diff |= (x.charCodeAt(i) || 0) ^ (y.charCodeAt(i) || 0);
  }
  return diff === 0;
}

// /api/* 防护：返回 Response 表示拒绝，返回 null 表示放行
//  ① 路径层：/api/* 只能挂在 UUID / 自定义路径之下（主路由已保证，猜不到路径就够不到）
//  ② Header 层：设置了 cfg.apiToken 后，所有 /api/* 必须携带 X-API-Token 或 Authorization: Bearer
//  ③ 同源层：写操作若带 Origin 且与 Host 不一致则拒绝，防止面板被第三方站点跨站调用（CSRF）
function checkApiAuth(request, cfg) {
  const method = (request.method || 'GET').toUpperCase();
  if (method !== 'GET' && method !== 'HEAD') {
    const origin = request.headers.get('origin');
    if (origin) {
      let oh = '';
      try { oh = new URL(origin).host; } catch (e) { oh = ''; }
      // Host 头缺失时（部分运行时/测试环境）回退用请求 URL 的 host 推导
      let host = request.headers.get('host') || '';
      if (!host) {
        try { host = new URL(request.url).host; } catch (e) { host = ''; }
      }
      if (oh && host && oh !== host) {
        return jsonResp({ ok: false, error: '跨站请求被拒绝' }, 403);
      }
    }
  }

  if (!cfg.apiToken) return null;   // 未设置密钥 → 仅依赖入口路径保密（向后兼容旧部署）

  const given = request.headers.get('x-api-token')
    || (request.headers.get('authorization') || '').replace(/^Bearer\s+/i, '');
  if (!timingSafeEqual(given, cfg.apiToken)) {
    return jsonResp({ ok: false, error: '鉴权失败：缺少或错误的 API 密钥（X-API-Token）' }, 401);
  }
  return null;
}

// ============================ 主路由 ============================

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    try {
      const cfg = await loadConfig(env);
      const base = accessBase(cfg);
      const pathname = url.pathname;
      const isWS = (request.headers.get('upgrade') || '').toLowerCase() === 'websocket';

      // WebSocket 代理隧道入口（VLESS / Trojan 共用，自动识别）
      if (isWS) {
        if (matchBase(pathname, base)) {
          return handleWSTunnel(request, cfg);
        }
        return camouflage(url, request);
      }

      // 面板 / 订阅 / API 均挂在 base 路径下
      const rest = pathname === base ? '' : pathname.startsWith(base + '/') ? pathname.slice(base.length) : null;
      if (rest === null) return camouflage(url, request);

      if (rest === '' || rest === '/') return renderPanel(url, request, cfg, env);
      if (rest === '/sub') return handleSub(request, url, env, cfg);
      if (rest === '/qr') return handleQr(url, cfg);

      // /api/* 双保险：① 必须位于 UUID / 自定义路径之下 ② 可选 Header 密钥 + 同源校验
      if (rest === '/api/config' || rest === '/api/ips') {
        const denied = checkApiAuth(request, cfg);
        if (denied) return denied;
        return rest === '/api/config' ? apiConfig(request, env, cfg) : apiIPs(request, env);
      }
      return camouflage(url, request);
    } catch (err) {
      return new Response('NEBULA-DECODE Error: ' + (err && err.message), {
        status: 500,
        headers: { 'content-type': 'text/plain; charset=utf-8' },
      });
    }
  },
};

// ============================ 伪装页（防主动扫描） ============================
//
// 未携带正确入口路径的访问（根路径、扫描器探测的 /admin、/.env 等）不再返回 404，
// 而是返回一个结构完整的静态博客首页（状态码 200），使站点在主动扫描下表现为普通个人博客。
// 站点身份由域名做稳定散列选取：同一域名每次返回同一个博客，
// 不会因为内容随机变化而被扫描器识别为「动态生成的假页面」。
// 注意：本页面不得出现任何项目名 / 品牌词 / 特征性注释，否则等于主动告诉扫描器这是隧道站点。

const CAMO_IDENTITIES = [
  { name: '拾光集', tagline: '把日子过成可以回看的片段', author: '阿柚', bio: '写字的人，偶尔拍照片。在这里放一些不想丢掉的东西。' },
  { name: '晚风手记', tagline: '记录一些没什么用、但很想留下的东西', author: '南舟', bio: '白天上班，晚上写点别的。更新随缘，留言必回。' },
  { name: '像素与茶', tagline: '写代码，也写字；煮咖啡，也煮茶', author: '老白', bio: '前端工程师。业余爱好是折腾各种工具，以及把工具折腾坏。' },
  { name: '半山腰', tagline: '爬到一半也挺好的，风景已经够看了', author: '林一', bio: '不赶路的人。喜欢慢慢走，慢慢写，偶尔发呆。' },
  { name: '周三笔记', tagline: '每周三更新一点点', author: '小满', bio: '读书、做饭、散步，然后把它们写下来。' },
  { name: '旧木桌', tagline: '桌上摊着没写完的信', author: '陈默', bio: '写信的人。写给别人，也写给自己。' },
];

const CAMO_POSTS = [
  ['在雨里走完一条老街', '城市散步', '雨从傍晚开始下，路灯亮起来的时候，整条街的招牌都泡在水里。我撑着伞慢慢走，看每一家店门口的水渍倒映出不同的颜色。'],
  ['关于早起这件事', '生活习惯', '试过很多次早起，也失败了很多次。后来才明白，问题不在于几点起，而在于起来之后想做什么。'],
  ['把书架整理了一遍', '读书', '整理书架的时候才发现，有些书买回来就没翻过。它们安静地站在那里，像一个没被拆开的礼物。'],
  ['第一次自己做面包', '厨房', '面粉、水、酵母和盐，四样东西。听起来简单，但第一次做出来的东西硬得能砸核桃。'],
  ['城市里的树', '城市观察', '每天上下班都会路过同一排梧桐。直到有一天它们被修剪得光秃秃，我才意识到自己一直在看它们。'],
  ['写给三年前的自己', '随笔', '你现在很着急，觉得一切都来不及。其实不用急，很多事情要再过两年才会显出意义。'],
  ['一台旧相机的复活', '数码', '在二手市场淘到一台十几年前的相机，电池鼓包，快门卡顿。拆开清理之后，它居然还能拍。'],
  ['夜里的便利店', '城市观察', '凌晨一点的便利店有一种特殊的安静，货架上的灯很亮，店员在补货，微波炉在转。'],
  ['学一门新语言的第一个月', '学习', '最初的新鲜感过去之后，剩下的就是每天重复。重复本身没什么意思，但重复能带来变化。'],
  ['阳台上的三盆植物', '生活', '一盆活了，一盆半死不活，一盆彻底没了。我至今没搞明白它们的区别到底在哪。'],
  ['换了一条通勤路线', '城市散步', '多走十分钟，但会经过一个小公园。这十分钟成了一天里我最不着急的时间。'],
];

const CAMO_TAGS = ['随笔', '城市散步', '读书', '厨房', '数码', '生活', '摄影', '学习', '城市观察', '生活习惯'];

const CAMO_CSS = `
:root{--ink:#22252b;--muted:#71767f;--line:#e5e7eb;--bg:#fbfbf9;--card:#fff;--accent:#2f6f4e}
*{box-sizing:border-box;margin:0;padding:0}
body{background:var(--bg);color:var(--ink);font:16px/1.75 -apple-system,BlinkMacSystemFont,"Segoe UI","Noto Sans SC","PingFang SC","Microsoft YaHei",sans-serif;-webkit-font-smoothing:antialiased}
a{color:inherit;text-decoration:none}
.nav{border-bottom:1px solid var(--line);background:rgba(255,255,255,.86);position:sticky;top:0;z-index:9}
.nav-inner{max-width:960px;margin:0 auto;padding:14px 22px;display:flex;align-items:center;justify-content:space-between;gap:16px}
.logo{font-family:Georgia,"Songti SC",serif;font-size:20px;letter-spacing:1px;color:var(--accent)}
.nav nav{display:flex;gap:20px;font-size:14px;color:var(--muted)}
.nav nav a:hover{color:var(--accent)}
.hero{max-width:960px;margin:0 auto;padding:56px 22px 34px;border-bottom:1px solid var(--line)}
.hero h1{font-family:Georgia,"Songti SC",serif;font-size:38px;font-weight:600;letter-spacing:1px}
.hero p{margin-top:12px;color:var(--muted);font-size:15px;max-width:34em}
.layout{max-width:960px;margin:0 auto;padding:36px 22px 60px;display:grid;grid-template-columns:minmax(0,1fr) 260px;gap:44px}
.post{padding-bottom:26px;margin-bottom:26px;border-bottom:1px dashed var(--line)}
.post:last-child{border-bottom:0}
.post h2{font-family:Georgia,"Songti SC",serif;font-size:22px;font-weight:600;margin-bottom:8px}
.post h2 a:hover{color:var(--accent)}
.meta{font-size:13px;color:var(--muted);margin-bottom:10px}
.meta .cat{display:inline-block;border:1px solid var(--line);border-radius:999px;padding:1px 10px;margin-right:8px;background:var(--card)}
.excerpt{color:#3d4149;font-size:15px}
.more{display:inline-block;margin-top:10px;font-size:14px;color:var(--accent)}
.widget{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:18px;margin-bottom:20px}
.widget h3{font-size:14px;letter-spacing:1px;color:var(--muted);font-weight:600;margin-bottom:10px}
.widget p{font-size:14px;color:#3d4149}
.tags{display:flex;flex-wrap:wrap;gap:8px}
.tags span{font-size:12px;color:var(--muted);border:1px solid var(--line);border-radius:999px;padding:2px 10px;background:var(--bg)}
footer{border-top:1px solid var(--line);padding:26px 22px;text-align:center;font-size:13px;color:var(--muted)}
@media(max-width:760px){.layout{grid-template-columns:1fr;gap:28px}.hero h1{font-size:30px}.nav nav{gap:14px}}
`;

// 由域名派生稳定种子（FNV-1a），保证同域名每次渲染出同一个博客身份
function hostSeed(host) {
  let h = 2166136261;
  for (let i = 0; i < host.length; i++) {
    h ^= host.charCodeAt(i);
    h = Math.imul(h, 16777619);
  }
  return h >>> 0;
}

function camouflage(url, request) {
  const host = (url && url.hostname) || 'localhost';
  const seed = hostSeed(host);
  const id = CAMO_IDENTITIES[seed % CAMO_IDENTITIES.length];

  // 文章挑选：步长 7 与 11 条文章互质，保证 5 篇互不重复
  const posts = [];
  for (let i = 0; i < 5; i++) {
    const p = CAMO_POSTS[(seed + i * 7) % CAMO_POSTS.length];
    const t = new Date(Date.UTC(2026, 7, 20) - (((seed >>> 3) % 120) + i * 19 + 1) * 86400000);
    posts.push({
      title: p[0],
      cat: p[1],
      excerpt: p[2],
      date: t.getUTCFullYear() + '-' + String(t.getUTCMonth() + 1).padStart(2, '0') + '-' + String(t.getUTCDate()).padStart(2, '0'),
    });
  }

  const tags = [];
  for (let i = 0; i < 8; i++) tags.push(CAMO_TAGS[(seed + i * 3) % CAMO_TAGS.length]);

  const postHtml = posts.map((p) =>
    '<article class="post">' +
      '<h2><a href="/post/' + encodeURIComponent(p.title) + '">' + p.title + '</a></h2>' +
      '<div class="meta"><span class="cat">' + p.cat + '</span>' + p.date + '</div>' +
      '<p class="excerpt">' + p.excerpt + '</p>' +
      '<a class="more" href="/post/' + encodeURIComponent(p.title) + '">阅读全文 →</a>' +
    '</article>'
  ).join('\n');

  const html = '<!DOCTYPE html>\n<html lang="zh-CN">\n<head>\n' +
    '<meta charset="utf-8">\n' +
    '<meta name="viewport" content="width=device-width,initial-scale=1">\n' +
    '<title>' + id.name + ' · 首页</title>\n' +
    '<meta name="description" content="' + id.tagline + '">\n' +
    '<link rel="icon" href="data:image/svg+xml,%3Csvg xmlns=%22http://www.w3.org/2000/svg%22 viewBox=%220 0 32 32%22%3E%3Crect width=%2232%22 height=%2232%22 rx=%227%22 fill=%22%232f6f4e%22/%3E%3C/svg%3E">\n' +
    '<style>' + CAMO_CSS + '</style>\n' +
    '</head>\n<body>\n' +
    '<header class="nav"><div class="nav-inner"><a class="logo" href="/">' + id.name + '</a>' +
    '<nav><a href="/">首页</a><a href="/archive">归档</a><a href="/tags">标签</a><a href="/about">关于</a></nav>' +
    '</div></header>\n' +
    '<section class="hero"><h1>' + id.name + '</h1><p>' + id.tagline + '</p></section>\n' +
    '<main class="layout">\n<div class="posts">\n' + postHtml + '\n</div>\n' +
    '<aside>' +
    '<div class="widget"><h3>关于我</h3><p>' + id.bio + '</p></div>' +
    '<div class="widget"><h3>标签</h3><div class="tags">' + tags.map((t) => '<span>' + t + '</span>').join('') + '</div></div>' +
    '<div class="widget"><h3>说两句</h3><p>慢慢写，慢慢看。谢谢你来过。</p></div>' +
    '</aside>\n</main>\n' +
    '<footer>© ' + new Date().getUTCFullYear() + ' ' + id.author + ' · 本博客内容版权所有</footer>\n' +
    '</body>\n</html>';

  return new Response(request && request.method === 'HEAD' ? null : html, {
    status: 200,
    headers: {
      'content-type': 'text/html; charset=utf-8',
      'cache-control': 'public, max-age=600',
    },
  });
}

// ============================ WebSocket 隧道 ============================

function safeCloseWS(ws) {
  try {
    if (ws.readyState === WS_OPEN) ws.close(1000);
  } catch (e) { /* ignore */ }
}

// 读取 WS 0-RTT 早期数据（path 带 ?ed=2048 时，客户端把首包放在 Sec-WebSocket-Protocol 头里）
function getEarlyData(request) {
  const header = request.headers.get('sec-websocket-protocol') || '';
  if (!header) return null;
  try {
    const b64 = header.replace(/-/g, '+').replace(/_/g, '/');
    const bin = atob(b64 + '='.repeat((4 - (b64.length % 4)) % 4));
    const bytes = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
    return bytes;
  } catch (e) {
    return null;
  }
}

async function handleWSTunnel(request, cfg) {
  const pair = new WebSocketPair();
  const client = pair[0];
  const server = pair[1];
  server.accept();

  const log = (...args) => console.log('[NEBULA-DECODE]', ...args);

  let firstPacketDone = false;
  let upstreamWriter = null;      // 远端 TCP / DNS socket 的 writer
  let pendingHeader = null;       // 协议响应头（VLESS 需要且只发一次；Trojan 为空）
  const pendingWrites = [];       // 连接建立期间到达的后续数据

  const sendToClient = (data) => {
    if (server.readyState !== WS_OPEN) return;
    if (pendingHeader && pendingHeader.length) {
      const merged = new Uint8Array(pendingHeader.length + data.byteLength);
      merged.set(pendingHeader);
      merged.set(data instanceof Uint8Array ? data : new Uint8Array(data), pendingHeader.length);
      pendingHeader = null;
      server.send(merged);
    } else {
      server.send(data);
    }
  };

  const setUpstream = (socket) => {
    upstreamWriter = socket.writable.getWriter();
    while (pendingWrites.length) {
      upstreamWriter.write(pendingWrites.shift()).catch(() => {});
    }
    return socket;
  };

  // 远端 → 客户端；返回是否收到过数据（用于 ProxyIP 回落判断）
  const pipeRemoteToWS = (socket) => {
    let hasIncomingData = false;
    return socket.readable.pipeTo(new WritableStream({
      write(data) {
        hasIncomingData = true;
        sendToClient(data);
      },
    })).then(
      () => hasIncomingData,
      (err) => {
        log('upstream read error:', err && err.message);
        return hasIncomingData;
      }
    );
  };

  const processFirst = async (buffer) => {
    const parsed = await parseClientPacket(buffer, cfg);
    pendingHeader = parsed.responseHeader;
    log(`proto=${parsed.proto} ${parsed.address}:${parsed.port}`);

    if (parsed.command === 2) {
      // UDP：仅支持 DNS(53)，通过 TCP DNS 转发（2 字节长度前缀帧格式一致）
      if (parsed.port !== 53) throw new Error('UDP 仅支持 53 端口(DNS)');
      const dnsSocket = connect({ hostname: '8.8.8.8', port: 53 });
      setUpstream(dnsSocket);
      await upstreamWriter.write(parsed.payload);
      pipeRemoteToWS(dnsSocket).finally(() => safeCloseWS(server));
      return;
    }

    await forwardTCP(parsed, setUpstream, pipeRemoteToWS, cfg, log, () => safeCloseWS(server));
  };

  server.addEventListener('message', (event) => {
    (async () => {
      try {
        // 统一把 event.data 转成 Uint8Array, 兼容 Blob(异步) / ArrayBuffer / Uint8Array / string / DataView
        let buf = event.data;
        if (buf instanceof Blob) buf = await buf.arrayBuffer();
        else if (typeof buf === 'string') buf = new TextEncoder().encode(buf);
        if (buf instanceof ArrayBuffer) buf = new Uint8Array(buf);
        else if (ArrayBuffer.isView(buf)) buf = new Uint8Array(buf.buffer, buf.byteOffset, buf.byteLength);
        if (!(buf instanceof Uint8Array)) buf = new Uint8Array(0);

        if (!firstPacketDone) {
          firstPacketDone = true;
          processFirst(buf).catch((err) => {
            log('handshake error:', err && err.message);
            // 诊断探针: 输出真实错误 + 线上收到的数据类型/长度/前16字节
            try {
              server.send('NEBULA-DEBUG: ' + (err && err.message)
                + ' | type=' + (event.data && event.data.constructor ? event.data.constructor.name : typeof event.data)
                + ' len=' + (buf ? buf.length : 0)
                + ' first8=' + Array.from(buf.slice(0, 8)).join(','));
            } catch (e) {}
            safeCloseWS(server);
          });
          return;
        }
        if (upstreamWriter) {
          upstreamWriter.write(buf).catch(() => {});
        } else {
          pendingWrites.push(buf);
        }
      } catch (e) { /* ignore */ }
    })();
  });

  server.addEventListener('close', () => {
    try { if (upstreamWriter) upstreamWriter.releaseLock(); } catch (e) {}
    upstreamWriter = null;
  });

  // 首包可能在 WS 升级时已经带来（ed=2048 早期数据）
  const early = getEarlyData(request);
  if (early && early.byteLength > 0) {
    firstPacketDone = true;
    processFirst(early).catch((err) => {
      log('handshake(early-data) error:', err && err.message);
      try { server.send('NEBULA-DEBUG-EARLY: ' + (err && err.message)); } catch (e) {}
      safeCloseWS(server);
    });
  }

  return new Response(null, { status: 101, webSocket: client });
}

async function forwardTCP(parsed, setUpstream, pipeRemoteToWS, cfg, log, onDead) {
  const connectAndWrite = async (address, port) => {
    const socket = connect({ hostname: address, port });
    const writer = socket.writable.getWriter();
    await writer.write(parsed.payload);
    writer.releaseLock();
    return socket;
  };

  // 第一跳：直连目标地址。注意 connect() 对被禁止的地址（Cloudflare 自家 IP 段、
  // 本机 / 内网 IP 等）会**立即抛错**而不是挂起，因此必须 try/catch，
  // 否则异常会直接炸掉整个握手，下面的 ProxyIP 回落永远没有机会执行。
  let socket = null;
  try {
    socket = await connectAndWrite(parsed.address, parsed.port);
  } catch (err) {
    log(`直连 ${parsed.address}:${parsed.port} 被拒: ${err && err.message}`);
    if (socket) { try { socket.close(); } catch (e) {} socket = null; }
  }

  if (socket) {
    setUpstream(socket);
    const hasData = pipeRemoteToWS(socket);

    // 直连拿到数据前给一个宽限期；超时且配置了 ProxyIP 则回落重连
    let got = false;
    if (cfg.proxyIP) {
      got = await Promise.race([
        hasData,
        new Promise((r) => setTimeout(() => r(false), 4000)),
      ]);
      if (!got) {
        log(`直连 ${parsed.address}:${parsed.port} 无响应，回落 ProxyIP ${cfg.proxyIP}`);
        try { socket.close(); } catch (e) {}
        socket = await connectAndWrite(cfg.proxyIP, parsed.port);
        setUpstream(socket);
        pipeRemoteToWS(socket).finally(onDead);
        return;
      }
    } else {
      got = await hasData;
    }
    if (!got) onDead();
    return;
  }

  // 直连被立即拒绝（典型：目标是 Cloudflare 自家站点）。此时必须走 ProxyIP 回落，
  // 否则该站点永远打不开。ProxyIP 必须是「非 Cloudflare IP 的、按 SNI 中继裸 TCP」
  // 的服务器，Worker 会把客户端发来的原始 TLS 握手（含目标 SNI）转发给它。
  if (!cfg.proxyIP) {
    throw new Error(`无法直连 ${parsed.address}:${parsed.port}，且未配置 ProxyIP 回落`);
  }
  log(`直连 ${parsed.address}:${parsed.port} 失败，回落 ProxyIP ${cfg.proxyIP}`);
  socket = await connectAndWrite(cfg.proxyIP, parsed.port);
  setUpstream(socket);
  pipeRemoteToWS(socket).finally(onDead);
}


// ============================ 协议解析（VLESS / Trojan 自动识别） ============================

// 根据首包特征自动识别协议：
//  · Trojan: 前 56 字节为 hex(sha224(密码))，后跟 \r\n CMD ATYP ...
//  · VLESS:  [版本0][UUID长度16][UUID 16B][指令长度][指令][端口2B][地址类型][地址]负载
async function parseClientPacket(buffer, cfg) {
  // 兼容 Cloudflare WS message 事件的各种数据类型: string(文本帧) / ArrayBuffer / Uint8Array / DataView
  let bytes;
  if (typeof buffer === 'string') {
    bytes = new TextEncoder().encode(buffer);
  } else if (buffer instanceof Uint8Array) {
    bytes = buffer;
  } else if (buffer instanceof ArrayBuffer) {
    bytes = new Uint8Array(buffer);
  } else if (ArrayBuffer.isView(buffer)) {
    bytes = new Uint8Array(buffer.buffer, buffer.byteOffset, buffer.byteLength);
  } else {
    bytes = new Uint8Array(0);
  }
  const dv = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);

  // ---------- Trojan ----------
  if (cfg.enableTrojan && cfg.trojanPassword && bytes.length >= 62) {
    let isHex = true;
    for (let i = 0; i < 56; i++) {
      const c = bytes[i];
      if (!((c >= 48 && c <= 57) || (c >= 97 && c <= 102))) { isHex = false; break; }
    }
    if (isHex && bytes[56] === 13 && bytes[57] === 10) {
      const expect = sha224Hex(cfg.trojanPassword);
      const got = Array.from(bytes.slice(0, 56), (b) => String.fromCharCode(b)).join('');
      if (got !== expect) throw new Error('Trojan 密码认证失败');
      return parseTrojan(bytes, dv);
    }
  }

  // ---------- VLESS ----------
  if (!cfg.enableVless) throw new Error('VLESS 已禁用');
  if (bytes.length < 24) throw new Error('VLESS 首包过短');
  if (bytes[0] !== 0) throw new Error('不支持的 VLESS 版本');

  const userId = uuidStringify(bytes.slice(1, 17));
  if (userId !== cfg.uuid) throw new Error('VLESS UUID 认证失败');

  const optLen = bytes[17];
  const command = bytes[18 + optLen];           // 0x01 TCP / 0x02 UDP / 0x03 MUX
  if (command === 3) throw new Error('暂不支持 MUX');
  const port = dv.getUint16(19 + optLen);
  const addrType = bytes[21 + optLen];

  const addr = parseAddress(bytes, dv, addrType, 22 + optLen);
  return {
    proto: 'vless',
    command,
    address: addr.host,
    port,
    payload: bytes.slice(addr.offset),
    responseHeader: new Uint8Array([bytes[0], 0]),
  };
}

function parseTrojan(bytes, dv) {
  const cmd = bytes[58];                        // 0x01 CONNECT / 0x03 UDP_ASSOCIATE
  const addrType = bytes[59];
  const addr = parseAddress(bytes, dv, addrType, 60);
  let off = addr.offset;
  const port = dv.getUint16(off);
  off += 2;
  if (bytes[off] === 13 && bytes[off + 1] === 10) off += 2;
  return {
    proto: 'trojan',
    command: cmd === 3 ? 2 : 1,
    address: addr.host,
    port,
    payload: bytes.slice(off),
    responseHeader: new Uint8Array(0),          // Trojan 服务端不发响应头
  };
}

function parseAddress(bytes, dv, addrType, start) {
  if (addrType === 1) {                         // IPv4
    return { host: Array.from(bytes.slice(start, start + 4)).join('.'), offset: start + 4 };
  }
  if (addrType === 2) {                         // 域名
    const len = bytes[start];
    const host = new TextDecoder().decode(bytes.slice(start + 1, start + 1 + len));
    return { host, offset: start + 1 + len };
  }
  if (addrType === 3) {                         // IPv6
    const parts = [];
    for (let i = 0; i < 8; i++) parts.push(dv.getUint16(start + i * 2).toString(16));
    return { host: parts.join(':'), offset: start + 16 };
  }
  throw new Error('不支持的地址类型: ' + addrType);
}

// ============================ 节点 / 订阅生成 ============================

// 汇总节点列表：本 Worker 域名 + 用户优选域名 + 内置优选池 + 用户优选 IP
// 面板里手填的域名往往只有几个，节点过于单薄；因此把内置 BUILTIN_OPTIMAL 一并并入，
// 去重后批量生成，节点命名带地区前缀（如 HK-104.28.0.1）便于在客户端里挑选。
function buildNodes(url, cfg, ips) {
  const wsPath = accessBase(cfg) + '?ed=2048';
  const labels = new Map();          // host -> 地区标签（仅用于命名）
  const hosts = [];
  const push = (h, label) => {
    h = String(h || '').trim();
    if (!h) return;
    if (labels.has(h)) {             // 已存在：仅在原来没有标签时补上
      if (!labels.get(h) && label) labels.set(h, label);
      return;
    }
    labels.set(h, label || '');
    hosts.push(h);
  };
  push(url.hostname, 'SELF');
  cfg.preferredDomains.forEach((d) => push(d));
  if (cfg.useBuiltinPool !== false) {  // 默认开启；显式关掉则只用用户自己填的
    for (const item of BUILTIN_OPTIMAL) push(item.host, item.region);
  }
  ips.forEach((ip) => push(ip));

  const nodes = [];
  hosts.forEach((host) => {
    const ipNode = isIP(host);
    // 关键: SNI/Host 头必须始终用 Worker 自己的域名, Cloudflare 才会把请求路由到本 Worker;
    // 优选域名/IP 只作为连接地址 (server), 决定客户端到 CF 边缘的链路质量
    const sni = url.hostname;
    const base = ipNode ? (isIPv4(host) ? 'IP-' + host : 'IPv6-' + host) : host;
    const label = labels.get(host);
    const name = (label && label !== 'SELF') ? label + '-' + base : base;
    if (cfg.enableVless) {
      nodes.push({
        proto: 'vless', name, server: host, port: 443,
        uuid: cfg.uuid, sni, host: sni, path: wsPath,
        link: `vless://${cfg.uuid}@${host}:443?encryption=none&security=tls&sni=${sni}&fp=chrome&type=ws&host=${sni}&path=${encodeURIComponent(wsPath)}#${encodeURIComponent(name)}`,
      });
    }
    if (cfg.enableTrojan && cfg.trojanPassword) {
      nodes.push({
        proto: 'trojan', name: name + '-trojan', server: host, port: 443,
        password: cfg.trojanPassword, sni, host: sni, path: wsPath,
        link: `trojan://${encodeURIComponent(cfg.trojanPassword)}@${host}:443?security=tls&sni=${sni}&fp=chrome&type=ws&host=${sni}&path=${encodeURIComponent(wsPath)}#${encodeURIComponent(name + '-trojan')}`,
      });
    }
  });
  return nodes;
}

function yamlQuote(s) {
  return '"' + String(s).replace(/\\/g, '\\\\').replace(/"/g, '\\"') + '"';
}

function buildClashYaml(nodes) {
  const lines = [];
  lines.push('# ═══════ 数码解码 · NEBULA-DECODE Clash 订阅 ═══════');
  lines.push('port: 7890');
  lines.push('socks-port: 7891');
  lines.push('allow-lan: false');
  lines.push('mode: rule');
  lines.push('log-level: info');
  lines.push('proxies:');
  for (const n of nodes) {
    lines.push(`  - name: ${yamlQuote(n.name)}`);
    lines.push(`    type: ${n.proto}`);
    lines.push(`    server: ${n.server}`);
    lines.push('    port: 443');
    lines.push('    udp: true');
    if (n.proto === 'vless') {
      lines.push(`    uuid: ${n.uuid}`);
      lines.push('    flow: ""');
    } else {
      lines.push(`    password: ${yamlQuote(n.password)}`);
    }
    lines.push('    tls: true');
    lines.push(`    servername: ${yamlQuote(n.sni)}`);
    lines.push('    skip-cert-verify: false');
    lines.push('    network: ws');
    lines.push('    ws-opts:');
    lines.push(`      path: ${yamlQuote(n.path)}`);
    lines.push('      headers:');
    lines.push(`        Host: ${yamlQuote(n.host)}`);
  }
  const names = nodes.map((n) => yamlQuote(n.name));
  lines.push('proxy-groups:');
  lines.push('  - name: "NEBULA-DECODE"');
  lines.push('    type: select');
  lines.push(names.length ? `    proxies: [${names.join(', ')}, DIRECT]` : '    proxies: [DIRECT]');
  lines.push('rules:');
  lines.push('  - MATCH,NEBULA-DECODE');
  return lines.join('\n') + '\n';
}

// Sing-box 配置（JSON，v1.8+ 客户端可直接导入 / 作为远程订阅）
// 说明：刻意省略 dns 段，改用系统默认 DNS —— sing-box 1.11/1.12 大改过 dns 字段语法，
// 写死任一种都会让另一批客户端导入失败；留给客户端自己的 dns 配置更稳。
function buildSingBox(nodes) {
  const outbounds = nodes.map((n) => {
    const tls = {
      enabled: true,
      server_name: n.sni,
      insecure: false,
      utls: { enabled: true, fingerprint: 'chrome' },
    };
    const transport = { type: 'ws', path: n.path, headers: { Host: n.host } };
    return n.proto === 'vless'
      ? {
        type: 'vless', tag: n.name, server: n.server, server_port: 443,
        uuid: n.uuid, flow: '', packet_encoding: 'xudp', tls, transport,
      }
      : {
        type: 'trojan', tag: n.name, server: n.server, server_port: 443,
        password: n.password, packet_encoding: 'xudp', tls, transport,
      };
  });

  const tags = outbounds.map((o) => o.tag);
  const chain = tags.length ? tags : ['direct'];
  const config = {
    log: { level: 'info', timestamp: true },
    inbounds: [
      { type: 'mixed', tag: 'mixed-in', listen: '127.0.0.1', listen_port: 2080, sniff: true },
    ],
    outbounds: [
      { type: 'selector', tag: 'NEBULA-DECODE', outbounds: ['auto', ...chain], default: 'auto' },
      {
        type: 'urltest', tag: 'auto', outbounds: chain,
        url: 'https://www.gstatic.com/generate_204', interval: '3m', tolerance: 50,
      },
      ...outbounds,
      { type: 'direct', tag: 'direct' },
    ],
    route: {
      rules: [{ ip_is_private: true, outbound: 'direct' }],
      final: 'NEBULA-DECODE',
      auto_detect_interface: true,
    },
  };
  return JSON.stringify(config, null, 2) + '\n';
}

async function handleSub(request, url, env, cfg) {
  const ips = await getPreferredIPs(env);
  const nodes = buildNodes(url, cfg, ips);
  const ua = (request.headers.get('user-agent') || '').toLowerCase();
  const target = (url.searchParams.get('target') || '').toLowerCase()
    || (ua.includes('clash') || ua.includes('stash') || ua.includes('mihomo') ? 'clash'
      : (ua.includes('sing-box') || ua.includes('singbox') ? 'singbox' : 'base64'));

  const headers = { 'content-type': 'text/plain; charset=utf-8', 'x-powered-by': 'shumajiedu | NEBULA-DECODE' };
  if (target === 'clash') {
    headers['content-type'] = 'text/yaml; charset=utf-8';
    headers['content-disposition'] = 'attachment; filename="nebula-decode.yaml"';
    return new Response(buildClashYaml(nodes), { headers });
  }
  if (target === 'singbox' || target === 'sing-box') {
    headers['content-type'] = 'application/json; charset=utf-8';
    headers['content-disposition'] = 'attachment; filename="nebula-decode.json"';
    return new Response(buildSingBox(nodes), { headers });
  }
  const text = nodes.map((n) => n.link).join('\n');
  return new Response(bytesToB64(new TextEncoder().encode(text)), { headers });
}

// ============================ QR 编码器（零依赖） ============================
//
// 完整实现 ISO/IEC 18004：字节模式、版本 1-40、ECC L/M/Q/H、Reed-Solomon 纠错、
// 8 种掩码自动优选（含 4 项罚分规则）、格式信息 BCH(15,5) 与版本信息 BCH(18,6)。
// 之所以内置而不引 CDN：整站是单文件 Worker，外部脚本会带来额外请求、破坏离线可用性，
// 并可能与 CSP / 隐私策略冲突。输出为按行游程合并的紧凑 SVG，体积小、无需外部字体。

const QR_ECL = { L: 0, M: 1, Q: 2, H: 3 };
const QR_ECL_FMT = { L: 1, M: 0, Q: 3, H: 2 };

// 每块纠错码字数（[ecl][version]，下标 0 为占位）
const QR_ECC_PER_BLOCK = [
  [-1, 7, 10, 15, 20, 26, 18, 20, 24, 30, 18, 20, 24, 26, 30, 22, 24, 28, 30, 28, 28, 28, 28, 30, 30, 26, 28, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30],
  [-1, 10, 16, 26, 18, 24, 16, 18, 22, 22, 26, 30, 22, 22, 24, 24, 28, 28, 26, 26, 26, 26, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28],
  [-1, 13, 22, 18, 26, 18, 24, 18, 22, 20, 24, 28, 26, 24, 20, 30, 24, 28, 28, 26, 30, 28, 30, 30, 30, 30, 28, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30],
  [-1, 17, 28, 22, 16, 22, 28, 26, 26, 24, 28, 24, 28, 22, 24, 24, 30, 28, 28, 26, 28, 30, 24, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30],
];

// 纠错块数量（[ecl][version]，下标 0 为占位）
const QR_EC_BLOCKS = [
  [-1, 1, 1, 1, 1, 1, 2, 2, 2, 2, 4, 4, 4, 4, 4, 6, 6, 6, 6, 7, 8, 8, 9, 9, 10, 12, 12, 12, 13, 14, 15, 16, 17, 18, 19, 19, 20, 21, 22, 24, 25],
  [-1, 1, 1, 1, 2, 2, 4, 4, 4, 5, 5, 5, 8, 9, 9, 10, 10, 11, 13, 14, 16, 17, 17, 18, 20, 21, 23, 25, 26, 28, 29, 31, 33, 35, 37, 38, 40, 43, 45, 47, 49],
  [-1, 1, 1, 2, 2, 4, 4, 6, 6, 8, 8, 8, 10, 12, 16, 12, 17, 16, 18, 21, 20, 23, 23, 25, 27, 29, 34, 34, 35, 38, 40, 43, 45, 48, 51, 53, 56, 59, 62, 65, 68],
  [-1, 1, 1, 2, 4, 4, 4, 5, 6, 8, 8, 11, 11, 16, 16, 18, 16, 19, 21, 25, 25, 25, 34, 30, 32, 35, 37, 40, 42, 45, 48, 51, 54, 57, 60, 63, 66, 70, 74, 77, 81],
];

// GF(2^8) 乘法，本原多项式 0x11D
function qrGfMul(x, y) {
  let z = 0;
  for (let i = 7; i >= 0; i--) {
    z = (z << 1) ^ ((z >>> 7) * 0x11D);
    z ^= ((y >>> i) & 1) * x;
  }
  return z & 0xFF;
}

// 指定版本的数据模块总数（ISO/IEC 18004 公式，免去硬编码 40 行表）
function qrRawModules(ver) {
  let r = (16 * ver + 128) * ver + 64;
  if (ver >= 2) {
    const n = Math.floor(ver / 7) + 2;
    r -= (25 * n - 10) * n - 55;
    if (ver >= 7) r -= 36;
  }
  return r;
}

function qrDataCodewords(ver, ecl) {
  return Math.floor(qrRawModules(ver) / 8) - QR_ECC_PER_BLOCK[ecl][ver] * QR_EC_BLOCKS[ecl][ver];
}

// 选能容纳 len 字节的最小版本
function qrPickVersion(len, ecl) {
  for (let v = 1; v <= 40; v++) {
    const need = 4 + (v <= 9 ? 8 : 16) + len * 8;
    if (need <= qrDataCodewords(v, ecl) * 8) return v;
  }
  return -1;
}

// Reed-Solomon 生成多项式（次数 deg）
function qrRsDivisor(deg) {
  const result = new Uint8Array(deg);
  result[deg - 1] = 1;
  let root = 1;
  for (let i = 0; i < deg; i++) {
    for (let j = 0; j < deg; j++) {
      result[j] = qrGfMul(result[j], root);
      if (j + 1 < deg) result[j] ^= result[j + 1];
    }
    root = qrGfMul(root, 0x02);
  }
  return result;
}

function qrRsRemainder(data, divisor) {
  const result = new Uint8Array(divisor.length);
  for (const b of data) {
    const factor = b ^ result[0];
    result.copyWithin(0, 1);
    result[result.length - 1] = 0;
    for (let i = 0; i < divisor.length; i++) result[i] ^= qrGfMul(divisor[i], factor);
  }
  return result;
}

// 分块做 RS 纠错，再按 ISO/IEC 18004 规则交错输出最终码字流
function qrAddEcc(data, ver, ecl) {
  const numBlocks = QR_EC_BLOCKS[ecl][ver];
  const eccLen = QR_ECC_PER_BLOCK[ecl][ver];
  const rawCodewords = Math.floor(qrRawModules(ver) / 8);
  const numShort = numBlocks - (rawCodewords % numBlocks);
  const shortLen = Math.floor(rawCodewords / numBlocks);
  const divisor = qrRsDivisor(eccLen);
  const blocks = [];
  for (let i = 0, k = 0; i < numBlocks; i++) {
    const datLen = shortLen - eccLen + (i < numShort ? 0 : 1);
    const dat = data.slice(k, k + datLen);
    k += datLen;
    const ecc = Array.from(qrRsRemainder(dat, divisor));
    if (i < numShort) dat.push(0); // 短块占位，保证交错列对齐
    blocks.push(dat.concat(ecc));
  }
  const out = [];
  for (let i = 0; i < blocks[0].length; i++) {
    for (let j = 0; j < blocks.length; j++) {
      if (i !== shortLen - eccLen || j >= numShort) out.push(blocks[j][i]);
    }
  }
  return out;
}

// 字节模式位流 + 填充（终止符 / 字节对齐 / 0xEC-0x11 交替填充）
function qrBitstream(bytes, ver, ecl) {
  const bits = [];
  const push = (val, len) => {
    for (let i = len - 1; i >= 0; i--) bits.push((val >>> i) & 1);
  };
  push(4, 4); // 字节模式
  push(bytes.length, ver <= 9 ? 8 : 16);
  for (const b of bytes) push(b, 8);
  const capacity = qrDataCodewords(ver, ecl) * 8;
  push(0, Math.min(4, capacity - bits.length));
  push(0, (8 - (bits.length % 8)) % 8);
  for (let pad = 0xEC; bits.length < capacity; pad ^= 0xEC ^ 0x11) push(pad, 8);
  const out = [];
  for (let i = 0; i < bits.length; i += 8) {
    let b = 0;
    for (let j = 0; j < 8; j++) b = (b << 1) | bits[i + j];
    out.push(b);
  }
  return out;
}

// 文本 -> QR 矩阵（自动选版本、纠错、掩码）
function qrEncode(text, eclName) {
  const name = QR_ECL[eclName] != null ? eclName : 'M';
  const ecl = QR_ECL[name];
  const bytes = Array.from(new TextEncoder().encode(text));
  const ver = qrPickVersion(bytes.length, ecl);
  if (ver < 0) throw new Error('内容过长，超出 QR 版本 40 容量');
  const codewords = qrAddEcc(qrBitstream(bytes, ver, ecl), ver, ecl);
  return qrBuildMatrix(ver, codewords, name);
}

// 格式信息 BCH(15,5)，最后异或 0x5412 掩码
function qrFormatBits(eclName, mask) {
  const data = (QR_ECL_FMT[eclName] << 3) | mask;
  let rem = data;
  for (let i = 0; i < 10; i++) rem = (rem << 1) ^ ((rem >>> 9) * 0x537);
  return ((data << 10) | rem) ^ 0x5412;
}

// 版本信息 BCH(18,6)，仅版本 >= 7 需要
function qrVersionBits(ver) {
  let rem = ver;
  for (let i = 0; i < 12; i++) rem = (rem << 1) ^ ((rem >>> 11) * 0x1F25);
  return (ver << 12) | rem;
}

// 对齐图形中心坐标（ISO/IEC 18004 附录 E 步长规则）
function qrAlignPositions(ver, size) {
  if (ver === 1) return [];
  const num = Math.floor(ver / 7) + 2;
  const step = ver === 32 ? 26 : Math.ceil((ver * 4 + 4) / (num * 2 - 2)) * 2;
  const result = [6];
  for (let pos = size - 7; result.length < num; pos -= step) result.splice(1, 0, pos);
  return result;
}

// 在矩阵上放置一个模块，并标记为功能图形（不参与掩码与数据填充）
function qrSetFn(mod, isFn, size, x, y, dark) {
  mod[y * size + x] = dark ? 1 : 0;
  isFn[y * size + x] = 1;
}

// 定位图形 + 分隔符：以 (cx,cy) 为中心，dist 为切比雪夫距离
// dist 0/1 → 实心；2 → 白环；3 → 实心；4 → 分隔符（白）
function qrPlaceFinder(mod, isFn, size, cx, cy) {
  for (let dy = -4; dy <= 4; dy++) {
    for (let dx = -4; dx <= 4; dx++) {
      const x = cx + dx, y = cy + dy;
      if (x < 0 || x >= size || y < 0 || y >= size) continue;
      const dist = Math.max(Math.abs(dx), Math.abs(dy));
      qrSetFn(mod, isFn, size, x, y, dist !== 2 && dist !== 4);
    }
  }
}

// 定时图形：第 6 行 / 第 6 列交替黑白，供解码器定位模块栅格
function qrPlaceTiming(mod, isFn, size) {
  for (let i = 0; i < size; i++) {
    qrSetFn(mod, isFn, size, 6, i, i % 2 === 0);
    qrSetFn(mod, isFn, size, i, 6, i % 2 === 0);
  }
}

// 校正图形 5x5（中心实心，外圈白环，最外圈实心）
function qrPlaceAlignment(mod, isFn, size, cx, cy) {
  for (let dy = -2; dy <= 2; dy++) {
    for (let dx = -2; dx <= 2; dx++) {
      qrSetFn(mod, isFn, size, cx + dx, cy + dy, Math.max(Math.abs(dx), Math.abs(dy)) !== 1);
    }
  }
}

// 格式信息：共 15 bit，在左上角与右上/左下两份镜像放置，另含固定暗模块
function qrPlaceFormat(mod, isFn, size, mask, eclName) {
  const bits = qrFormatBits(eclName, mask);
  for (let i = 0; i <= 5; i++) qrSetFn(mod, isFn, size, 8, i, ((bits >>> i) & 1) !== 0);
  qrSetFn(mod, isFn, size, 8, 7, ((bits >>> 6) & 1) !== 0);
  qrSetFn(mod, isFn, size, 8, 8, ((bits >>> 7) & 1) !== 0);
  qrSetFn(mod, isFn, size, 7, 8, ((bits >>> 8) & 1) !== 0);
  for (let i = 9; i < 15; i++) qrSetFn(mod, isFn, size, 14 - i, 8, ((bits >>> i) & 1) !== 0);
  for (let i = 0; i < 8; i++) qrSetFn(mod, isFn, size, size - 1 - i, 8, ((bits >>> i) & 1) !== 0);
  for (let i = 8; i < 15; i++) qrSetFn(mod, isFn, size, 8, size - 15 + i, ((bits >>> i) & 1) !== 0);
  qrSetFn(mod, isFn, size, 8, size - 8, true);
}

// 版本信息：18 bit，仅版本 >= 7 需要，同样两份镜像放置
function qrPlaceVersion(mod, isFn, size, ver) {
  if (ver < 7) return;
  const bits = qrVersionBits(ver);
  for (let i = 0; i < 18; i++) {
    const bit = ((bits >>> i) & 1) !== 0;
    const a = size - 11 + (i % 3);
    const b = Math.floor(i / 3);
    qrSetFn(mod, isFn, size, a, b, bit);
    qrSetFn(mod, isFn, size, b, a, bit);
  }
}

// 数据区按 ISO/IEC 18004 的之字形（两列一组、上下交替）填充
function qrPlaceData(mod, isFn, size, codewords) {
  let i = 0;
  const total = codewords.length * 8;
  for (let right = size - 1; right >= 1; right -= 2) {
    if (right === 6) right = 5; // 跳过竖直定时列
    for (let vert = 0; vert < size; vert++) {
      for (let j = 0; j < 2; j++) {
        const x = right - j;
        const upward = ((right + 1) & 2) === 0;
        const y = upward ? size - 1 - vert : vert;
        if (!isFn[y * size + x] && i < total) {
          mod[y * size + x] = (codewords[i >>> 3] >>> (7 - (i & 7))) & 1;
          i++;
        }
      }
    }
  }
}

// 8 种掩码函数（ISO/IEC 18004 表 10）
function qrMaskBit(mask, x, y) {
  switch (mask) {
    case 0: return (x + y) % 2 === 0;
    case 1: return y % 2 === 0;
    case 2: return x % 3 === 0;
    case 3: return (x + y) % 3 === 0;
    case 4: return (Math.floor(x / 3) + Math.floor(y / 2)) % 2 === 0;
    case 5: return ((x * y) % 2) + ((x * y) % 3) === 0;
    case 6: return (((x * y) % 2) + ((x * y) % 3)) % 2 === 0;
    default: return (((x + y) % 2) + ((x * y) % 3)) % 2 === 0;
  }
}

// 对数据区异或掩码；同一函数再次调用即可撤销（XOR 自反）
function qrApplyMask(mod, isFn, size, mask) {
  for (let y = 0; y < size; y++) {
    for (let x = 0; x < size; x++) {
      if (!isFn[y * size + x] && qrMaskBit(mask, x, y)) mod[y * size + x] ^= 1;
    }
  }
}

// 四类罚分（ISO/IEC 18004 表 11），用于在 8 种掩码中挑最优
function qrPenalty(mod, size) {
  let result = 0;
  const at = (x, y) => mod[y * size + x];

  // 规则 1：行 / 列上同色连续模块 >= 5（3 + 超出部分）
  for (let y = 0; y < size; y++) {
    let run = 1;
    for (let x = 1; x < size; x++) {
      if (at(x, y) === at(x - 1, y)) { run++; if (run === 5) result += 3; else if (run > 5) result++; }
      else run = 1;
    }
  }
  for (let x = 0; x < size; x++) {
    let run = 1;
    for (let y = 1; y < size; y++) {
      if (at(x, y) === at(x, y - 1)) { run++; if (run === 5) result += 3; else if (run > 5) result++; }
      else run = 1;
    }
  }

  // 规则 2：2x2 同色块，每处 +3
  for (let y = 0; y < size - 1; y++) {
    for (let x = 0; x < size - 1; x++) {
      const c = at(x, y);
      if (c === at(x + 1, y) && c === at(x, y + 1) && c === at(x + 1, y + 1)) result += 3;
    }
  }

  // 规则 3：类定位图形的 1:1:3:1:1 序列（含一侧 4 个浅色模块），每处 +40
  const P1 = [1, 0, 1, 1, 1, 0, 1, 0, 0, 0, 0];
  const P2 = [0, 0, 0, 0, 1, 0, 1, 1, 1, 0, 1];
  const hit = (get, i) => {
    let a = true, b = true;
    for (let k = 0; k < 11 && (a || b); k++) {
      const v = get(i + k);
      if (v !== P1[k]) a = false;
      if (v !== P2[k]) b = false;
    }
    return a || b;
  };
  for (let y = 0; y < size; y++) {
    const get = (i) => at(i, y);
    for (let x = 0; x + 11 <= size; x++) if (hit(get, x)) result += 40;
  }
  for (let x = 0; x < size; x++) {
    const get = (i) => at(x, i);
    for (let y = 0; y + 11 <= size; y++) if (hit(get, y)) result += 40;
  }

  // 规则 4：深色模块占比每偏离 50% 达 5%，罚 10 分
  let dark = 0;
  for (let i = 0; i < mod.length; i++) dark += mod[i];
  result += Math.floor(Math.abs(dark * 100 / (size * size) - 50) / 5) * 10;
  return result;
}

// 组装最终矩阵：功能图形 → 数据 → 8 种掩码择优
function qrBuildMatrix(ver, codewords, eclName) {
  const size = ver * 4 + 17;
  const mod = new Uint8Array(size * size);
  const isFn = new Uint8Array(size * size);

  qrPlaceFinder(mod, isFn, size, 3, 3);
  qrPlaceFinder(mod, isFn, size, size - 4, 3);
  qrPlaceFinder(mod, isFn, size, 3, size - 4);
  qrPlaceTiming(mod, isFn, size);

  const aligns = qrAlignPositions(ver, size);
  for (let i = 0; i < aligns.length; i++) {
    for (let j = 0; j < aligns.length; j++) {
      if ((i === 0 && j === 0) || (i === 0 && j === aligns.length - 1) || (i === aligns.length - 1 && j === 0)) continue;
      qrPlaceAlignment(mod, isFn, size, aligns[i], aligns[j]);
    }
  }

  qrPlaceFormat(mod, isFn, size, 0, eclName); // 先占位，确保数据区跳过这些模块
  qrPlaceVersion(mod, isFn, size, ver);
  qrPlaceData(mod, isFn, size, codewords);

  let bestMask = 0, bestScore = Infinity;
  for (let mask = 0; mask < 8; mask++) {
    qrApplyMask(mod, isFn, size, mask);
    qrPlaceFormat(mod, isFn, size, mask, eclName);
    const score = qrPenalty(mod, size);
    if (score < bestScore) { bestScore = score; bestMask = mask; }
    qrApplyMask(mod, isFn, size, mask); // XOR 自反，撤销本轮的掩码
  }
  qrApplyMask(mod, isFn, size, bestMask);
  qrPlaceFormat(mod, isFn, size, bestMask, eclName);
  return mod;
}

// 矩阵 → SVG：按行把连续的深色模块合并成一条 path，节点数极少、无需外部字体
function qrSvg(mod, scale = 4, border = 4) {
  const size = Math.round(Math.sqrt(mod.length));
  const dim = (size + border * 2) * scale;
  let path = '';
  for (let y = 0; y < size; y++) {
    let x = 0;
    while (x < size) {
      if (!mod[y * size + x]) { x++; continue; }
      let run = 1;
      while (x + run < size && mod[y * size + x + run]) run++;
      path += 'M' + (x + border) * scale + ' ' + (y + border) * scale +
        'h' + run * scale + 'v' + scale + 'h-' + run * scale + 'z';
      x += run;
    }
  }
  return '<svg xmlns="http://www.w3.org/2000/svg" width="' + dim + '" height="' + dim +
    '" viewBox="0 0 ' + dim + ' ' + dim + '" shape-rendering="crispEdges">' +
    '<rect width="' + dim + '" height="' + dim + '" fill="#ffffff"/>' +
    '<path d="' + path + '" fill="#000000"/></svg>';
}

// /qr?t=base64|clash|singbox —— 把对应订阅地址渲染成二维码（SVG）
function handleQr(url, cfg) {
  const t = (url.searchParams.get('t') || 'base64').toLowerCase();
  const target = (t === 'clash' || t === 'stash' || t === 'mihomo') ? 'clash'
    : (t === 'singbox' || t === 'sing-box') ? 'singbox' : 'base64';
  const subURL = url.origin + accessBase(cfg) + '/sub' + (target === 'base64' ? '' : '?target=' + target);

  let svg;
  try {
    svg = qrSvg(qrEncode(subURL, 'M'));
  } catch (err) {
    return new Response('QR 生成失败: ' + (err && err.message), {
      status: 500,
      headers: { 'content-type': 'text/plain; charset=utf-8' },
    });
  }
  return new Response(svg, {
    headers: {
      'content-type': 'image/svg+xml; charset=utf-8',
      'cache-control': 'public, max-age=3600',
      'x-powered-by': 'shumajiedu | NEBULA-DECODE',
    },
  });
}

// ============================ REST API ============================

async function apiConfig(request, env, cfg) {
  if (request.method === 'GET') return jsonResp(cfg);

  if (request.method === 'POST') {
    if (!env.KV) return jsonResp({ ok: false, error: '未绑定 KV 存储，无法保存配置' }, 500);
    let body;
    try { body = await request.json(); } catch (e) { return jsonResp({ ok: false, error: '请求体不是合法 JSON' }, 400); }

    const uuid = String(body.uuid || '').trim().toLowerCase();
    if (!isValidUUID(uuid)) return jsonResp({ ok: false, error: 'UUID 格式不合法' }, 400);

    const path = normalizeBase(body.path || '');
    if (path && (path === '/sub' || path.startsWith('/api'))) {
      return jsonResp({ ok: false, error: '自定义路径与保留路径冲突' }, 400);
    }

    const next = {
      uuid,
      path,
      proxyIP: String(body.proxyIP || '').trim(),
      trojanPassword: String(body.trojanPassword || '').trim(),
      apiToken: String(body.apiToken || '').trim(),
      enableVless: !!body.enableVless,
      enableTrojan: !!body.enableTrojan,
      preferredDomains: Array.isArray(body.preferredDomains)
        ? body.preferredDomains.map((s) => String(s).trim()).filter(Boolean)
        : [...BUILTIN_PREFERRED],
      useBuiltinPool: body.useBuiltinPool !== false,
    };
    if (!next.enableVless && !(next.enableTrojan && next.trojanPassword)) {
      return jsonResp({ ok: false, error: '至少启用一个协议（Trojan 需设置密码）' }, 400);
    }
    await env.KV.put(CFG_KEY, JSON.stringify(next));
    return jsonResp({ ok: true });
  }
  return jsonResp({ ok: false, error: 'Method Not Allowed' }, 405);
}

async function apiIPs(request, env) {
  if (request.method === 'GET') {
    return jsonResp({ ips: await getPreferredIPs(env) });
  }
  if (request.method === 'POST') {
    if (!env.KV) return jsonResp({ ok: false, error: '未绑定 KV 存储' }, 500);
    let body;
    try { body = await request.json(); } catch (e) { return jsonResp({ ok: false, error: '请求体不是合法 JSON' }, 400); }
    const incoming = Array.isArray(body.ips) ? body.ips : String(body.text || '').split(/\r?\n/);
    const valid = incoming
      .map((s) => String(s).trim())
      .filter((s) => isIP(s) || /^[a-z0-9.-]+\.[a-z]{2,}$/i.test(s));
    if (!valid.length) return jsonResp({ ok: false, error: '没有合法的 IP / 域名' }, 400);
    const current = await getPreferredIPs(env);
    const merged = [...new Set([...current, ...valid])];
    await savePreferredIPs(env, merged);
    return jsonResp({ ok: true, ips: merged });
  }
  if (request.method === 'DELETE') {
    if (!env.KV) return jsonResp({ ok: false, error: '未绑定 KV 存储' }, 500);
    const ip = new URL(request.url).searchParams.get('ip');
    if (ip) {
      const rest = (await getPreferredIPs(env)).filter((s) => s !== ip);
      await savePreferredIPs(env, rest);
      return jsonResp({ ok: true, ips: rest });
    }
    await savePreferredIPs(env, []);
    return jsonResp({ ok: true, ips: [] });
  }
  return jsonResp({ ok: false, error: 'Method Not Allowed' }, 405);
}

// ============================ Web 管理面板 ============================

async function renderPanel(url, request, cfg, env) {
  const ips = await getPreferredIPs(env);
  const colo = (request.cf && request.cf.colo) || 'N/A';
  const base = accessBase(cfg);
  const subURL = url.origin + base + '/sub';
  const clashURL = url.origin + base + '/sub?target=clash';
  const singboxURL = url.origin + base + '/sub?target=singbox';
  const protoBadges =
    (cfg.enableVless ? '<span class="pill"><span class="dot"></span>VLESS-WS</span>' : '<span class="pill"><span class="dot off"></span>VLESS 关</span>') +
    (cfg.enableTrojan && cfg.trojanPassword ? '<span class="pill"><span class="dot"></span>TROJAN-WS</span>' : '<span class="pill"><span class="dot off"></span>TROJAN 关</span>') +
    (cfg.path ? '<span class="pill">自定义路径</span>' : '');

  const logoSvg = '<svg width="26" height="26" viewBox="0 0 24 24" fill="none">' +
'<circle cx="12" cy="12" r="3.1" fill="#5eead4"/>' +
'<ellipse cx="12" cy="12" rx="10" ry="4.3" stroke="#818cf8" stroke-width="1.2" opacity=".9"/>' +
'<ellipse cx="12" cy="12" rx="10" ry="4.3" stroke="#5eead4" stroke-width="1.2" opacity=".55" transform="rotate(62 12 12)"/>' +
'<ellipse cx="12" cy="12" rx="10" ry="4.3" stroke="#5eead4" stroke-width="1.2" opacity=".3" transform="rotate(118 12 12)"/>' +
'</svg>';

  const html = '<!DOCTYPE html>' +
'<html lang="zh-CN"><head><meta charset="utf-8">' +
'<meta name="viewport" content="width=device-width,initial-scale=1">' +
'<title>NEBULA-DECODE 终端</title><style>' +
'*{box-sizing:border-box;margin:0;padding:0}' +
':root{--fg:#e6edf3;--mut:#94a3b8;--dim:#64748b;--ac:#5eead4;--line:rgba(148,163,184,.14);--sur:rgba(148,163,184,.05)}' +
'body{background:#05080f;color:var(--fg);font:14px/1.65 "Segoe UI",system-ui,-apple-system,"PingFang SC","Microsoft YaHei",sans-serif;min-height:100vh;background-image:radial-gradient(1100px 520px at 12% -8%,rgba(45,212,191,.12),transparent 60%),radial-gradient(900px 480px at 88% 112%,rgba(129,140,248,.11),transparent 60%);background-attachment:fixed}' +
'::selection{background:rgba(94,234,212,.25)}' +
'::-webkit-scrollbar{width:10px;height:10px}::-webkit-scrollbar-thumb{background:rgba(148,163,184,.22);border-radius:6px}::-webkit-scrollbar-track{background:transparent}' +
'.wrap{max-width:940px;margin:0 auto;padding:36px 22px 40px}' +
'.hero{display:flex;align-items:center;gap:16px;flex-wrap:wrap}' +
'.mark{width:46px;height:46px;flex:none;border-radius:14px;display:grid;place-items:center;background:linear-gradient(135deg,rgba(94,234,212,.14),rgba(129,140,248,.14));border:1px solid rgba(94,234,212,.3);box-shadow:0 0 26px rgba(45,212,191,.16)}' +
'h1{font-size:23px;font-weight:700;letter-spacing:3px;background:linear-gradient(92deg,#eafffb 0%,#5eead4 48%,#818cf8 100%);-webkit-background-clip:text;background-clip:text;color:transparent}' +
'h1 .v{font-size:12px;font-weight:500;letter-spacing:1px;color:var(--dim);-webkit-text-fill-color:var(--dim);margin-left:8px;vertical-align:4px}' +
'.brand{color:#fbbf77;border:1px solid rgba(251,191,119,.32);background:rgba(251,191,119,.06);border-radius:999px;padding:4px 13px;font-size:12px;letter-spacing:1px}' +
'.tg{display:inline-flex;align-items:center;gap:7px;color:#5eead4;border:1px solid rgba(94,234,212,.34);background:rgba(94,234,212,.07);border-radius:999px;padding:4px 13px;font-size:12px;letter-spacing:1px;text-decoration:none;transition:background .18s,border-color .18s,box-shadow .18s}' +
'.tg:hover{background:rgba(94,234,212,.15);border-color:rgba(94,234,212,.55);box-shadow:0 0 18px rgba(45,212,191,.22)}' +
'.status{display:flex;gap:8px;flex-wrap:wrap;margin:16px 0 26px}' +
'.pill{display:inline-flex;align-items:center;gap:8px;border:1px solid var(--line);background:var(--sur);border-radius:999px;padding:4px 13px;font-size:12px;color:var(--mut)}' +
'.pill b{color:var(--fg);font-weight:600;font-family:ui-monospace,Consolas,monospace}' +
'.dot{width:7px;height:7px;border-radius:50%;background:#5eead4;box-shadow:0 0 8px rgba(94,234,212,.9);flex:none}' +
'.dot.off{background:#f87171;box-shadow:0 0 8px rgba(248,113,113,.8)}' +
'.card{background:var(--sur);border:1px solid var(--line);border-radius:16px;padding:22px 24px;margin-bottom:18px;backdrop-filter:blur(14px);-webkit-backdrop-filter:blur(14px);box-shadow:0 20px 44px -26px rgba(0,0,0,.7);animation:rise .45s ease both}' +
'@keyframes rise{from{opacity:0;transform:translateY(12px)}to{opacity:1;transform:none}}' +
'.card h2{display:flex;align-items:center;gap:10px;font-size:14px;font-weight:600;letter-spacing:2px;margin-bottom:6px;padding-bottom:12px;border-bottom:1px solid var(--line)}' +
'.card h2 .no{color:var(--ac);font:600 11px/1 ui-monospace,Consolas,monospace;border:1px solid rgba(94,234,212,.3);border-radius:6px;padding:4px 7px;background:rgba(94,234,212,.06)}' +
'.card h2 em{margin-left:auto;font-style:normal;font-size:11px;font-weight:400;color:var(--dim);letter-spacing:0}' +
'label{display:block;color:var(--mut);font-size:12px;margin:14px 0 6px}' +
'input[type=text],textarea{width:100%;background:rgba(2,6,14,.6);border:1px solid var(--line);border-radius:10px;color:var(--fg);padding:10px 12px;font:13px/1.5 ui-monospace,Consolas,Menlo,monospace;transition:border-color .18s,box-shadow .18s}' +
'input:focus,textarea:focus{outline:none;border-color:rgba(94,234,212,.5);box-shadow:0 0 0 3px rgba(45,212,191,.1)}' +
'textarea{resize:vertical;min-height:84px}' +
'button{appearance:none;-webkit-appearance:none;border:1px solid transparent;border-radius:10px;padding:9px 18px;font-family:inherit;font-size:13px;font-weight:600;cursor:pointer;color:#052e28;background:linear-gradient(135deg,#5eead4,#38bdf8);box-shadow:0 8px 20px -10px rgba(45,212,191,.6);transition:filter .15s,transform .15s,background .15s}' +
'button:hover{filter:brightness(1.1);transform:translateY(-1px)}' +
'button.ghost{background:rgba(148,163,184,.08);border-color:var(--line);color:var(--fg);box-shadow:none}' +
'button.ghost:hover{background:rgba(148,163,184,.16)}' +
'button.danger{background:rgba(248,113,113,.1);border-color:rgba(248,113,113,.35);color:#fca5a5;box-shadow:none}' +
'button.danger:hover{background:rgba(248,113,113,.2)}' +
'button.mini{padding:6px 13px;font-size:12px;border-radius:8px}' +
'.btnrow{display:flex;gap:10px;flex-wrap:wrap;align-items:center;margin-top:12px}' +
'code,a.code{display:block;white-space:pre-wrap;background:rgba(2,6,14,.6);border:1px solid var(--line);border-left:2px solid rgba(94,234,212,.45);border-radius:10px;padding:10px 12px;color:#9fe8c8;font:12px/1.7 ui-monospace,Consolas,monospace;word-break:break-all;margin:6px 0;text-decoration:none;transition:border-color .18s,background .18s}' +
'a.code:hover{border-color:rgba(94,234,212,.4);background:rgba(4,10,18,.85)}' +
'.chk{display:inline-flex;align-items:center;gap:9px;margin:10px 24px 0 0;color:var(--fg);font-size:13px;cursor:pointer;user-select:none}' +
'.chk input{appearance:none;-webkit-appearance:none;width:38px;height:21px;border-radius:999px;background:rgba(148,163,184,.16);border:1px solid var(--line);position:relative;cursor:pointer;transition:background .2s,border-color .2s;flex:none;margin:0;vertical-align:middle}' +
'.chk input:before{content:"";position:absolute;top:2px;left:2px;width:15px;height:15px;border-radius:50%;background:#9aa8b8;transition:left .2s,background .2s}' +
'.chk input:checked{background:rgba(45,212,191,.32);border-color:rgba(94,234,212,.5)}' +
'.chk input:checked:before{left:19px;background:#5eead4;box-shadow:0 0 8px rgba(94,234,212,.8)}' +
'.row{display:flex;gap:14px;flex-wrap:wrap}.row>div{flex:1;min-width:240px}' +
'.msg{margin-top:10px;font-size:12px;color:var(--ac);min-height:18px}' +
'.hint{color:var(--dim);font-size:12px;margin-top:12px;line-height:1.8}' +
'.footer{color:var(--dim);font-size:12px;text-align:center;margin:28px 0 6px}' +
'.footer a{color:var(--ac);text-decoration:none}' +
'.footer a:hover{text-decoration:underline}' +
'.qrbar{margin:2px 0 12px}' +
'.modal{display:none;position:fixed;inset:0;background:rgba(3,6,12,.72);backdrop-filter:blur(6px);-webkit-backdrop-filter:blur(6px);z-index:99;padding:16px}' +
'.modal.on{display:flex;align-items:center;justify-content:center}' +
'.modal-box{position:relative;width:100%;max-width:400px;height:min(580px,90vh);background:#0a101c;border:1px solid rgba(94,234,212,.22);border-radius:18px;overflow:hidden;box-shadow:0 30px 80px -20px rgba(0,0,0,.85)}' +
'.modal-box iframe{width:100%;height:100%;border:0;display:block;background:#fff}' +
'.modal-x{position:absolute;top:8px;right:8px;z-index:2;margin:0;padding:4px 12px;border-radius:8px;background:rgba(10,16,28,.88);color:var(--fg);font-size:12px}' +
'@media(max-width:640px){.wrap{padding:24px 14px 32px}.card{padding:18px 16px;border-radius:14px}.row>div{min-width:100%}}' +
'</style></head><body><div class="wrap">' +
'<div class="hero"><div class="mark">' + logoSvg + '</div>' +
'<h1>NEBULA-DECODE<span class="v">v2.1</span></h1>' +
'<span class="brand">数码解码 出品</span>' +
'<a class="tg" href="https://t.me/+tVg48WK48tlkNGVl" target="_blank" rel="noopener noreferrer" title="加入 Telegram 群组">✈️ 加入群组</a></div>' +
'<div class="status"><span class="pill"><span class="dot"></span>节点机房 <b>' + colo + '</b></span>' +
'<span class="pill">入口路径 <b>' + base + '</b></span>' + protoBadges + '</div>';

  const body = html +
'<div class="card" style="animation-delay:.04s"><h2><span class="no">01</span>节点配置<em>保存后立即生效，无需重新部署</em></h2>' +
'<div class="row"><div><label>UUID（VLESS 凭据，也是面板入口路径）</label><input type="text" id="uuid"></div>' +
'<div><label>自定义路径（可多级，如 my/nodes；留空用 UUID）</label><input type="text" id="path"></div></div>' +
'<div class="btnrow"><button class="ghost mini" onclick="genUuid()">🎲 随机生成 UUID</button></div>' +
'<div class="row"><div><label>ProxyIP（直连 Cloudflare 自家站点被拒时回落；须为非 CF 段的 SNI 中继，如 ProxyIP.US.CMLiussss.net）</label><input type="text" id="proxyIP"></div>' +
'<div><label>Trojan 密码（启用 Trojan 时必填）</label><input type="text" id="trojanPassword"></div></div>' +
'<div><label>API 密钥（可选；设置后所有 /api/* 请求必须携带 X-API-Token 头）</label><input type="text" id="apiToken"></div>' +
'<div class="btnrow"><button class="ghost mini" onclick="genToken()">🎲 随机生成密钥</button></div>' +
'<label>协议开关</label>' +
'<div class="btnrow" style="margin-top:4px"><label class="chk"><input type="checkbox" id="enableVless">VLESS-WS-TLS</label>' +
'<label class="chk"><input type="checkbox" id="enableTrojan">Trojan-WS-TLS</label></div>' +
'<div class="btnrow"><button onclick="saveCfg()">保存配置 · 立即生效</button></div><div class="msg" id="msg1"></div>' +
'<div class="hint">提示：修改 UUID / 自定义路径保存后，面板地址会变为新入口路径。</div></div>' +

'<div class="card" style="animation-delay:.08s"><h2><span class="no">02</span>优选 IP / 域名<em>合并生成订阅节点</em></h2>' +
'<label>每行一个 IP 或域名（与下方优选域名、内置优选池合并生成订阅节点）</label>' +
'<textarea id="ips"></textarea>' +
'<div class="btnrow"><button class="mini" onclick="addIps()">添加</button><button class="danger mini" onclick="clearIps()">清空</button><span class="msg" id="msg2" style="margin:0"></span></div>' +
'<label>优选域名列表（逗号分隔，内置公共优选域名可自行替换）</label>' +
'<input type="text" id="preferredDomains">' +
'<label class="chk" style="margin-top:14px"><input type="checkbox" id="useBuiltinPool">自动并入内置 Cloudflare 优选 IP 池（28 个，含 HK / SG / JP / US / EU 分组）</label></div>' +

'<div class="card" style="animation-delay:.12s"><h2><span class="no">03</span>订阅与导入<em>桌面一键导入，手机扫码即用</em></h2>' +
'<label>通用订阅（v2rayN / v2rayNG / Shadowrocket / Nekoray 等，base64）</label>' +
'<a class="code" id="subA" href="' + subURL + '">' + subURL + '</a>' +
'<div class="btnrow"><button class="ghost mini" onclick="copyTo(\'' + subURL + '\',this)">复制通用订阅</button>' +
'<button class="ghost mini" onclick="showQr(\'base64\')">📱 显示二维码</button></div>' +
'<label>Clash / Stash / Mihomo 订阅（YAML）</label>' +
'<a class="code" id="clashA" href="' + clashURL + '">' + clashURL + '</a>' +
'<div class="btnrow"><button class="ghost mini" onclick="copyTo(\'' + clashURL + '\',this)">复制 Clash 订阅</button>' +
'<button class="ghost mini" onclick="showQr(\'clash\')">📱 显示二维码</button></div>' +
'<label>Sing-box 订阅（JSON，v1.8+ 客户端可直接导入）</label>' +
'<a class="code" id="singboxA" href="' + singboxURL + '">' + singboxURL + '</a>' +
'<div class="btnrow"><button class="ghost mini" onclick="copyTo(\'' + singboxURL + '\',this)">复制 Sing-box 订阅</button>' +
'<button class="ghost mini" onclick="showQr(\'singbox\')">📱 显示二维码</button></div>' +
'<label>一键导入</label>' +
'<div class="btnrow">' +
'<button class="ghost mini" onclick="location.href=\'v2rayng://install-sub?url=\' + encodeURIComponent(\'' + subURL + '\')">v2rayNG</button>' +
'<button class="ghost mini" onclick="location.href=\'shadowrocket://add/sub://\' + encodeURIComponent(\'' + subURL + '\')">Shadowrocket</button>' +
'<button class="ghost mini" onclick="location.href=\'clash://install-config?url=\' + encodeURIComponent(\'' + clashURL + '\')">Clash</button>' +
'<button class="ghost mini" onclick="location.href=\'sing-box://import-remote-profile?url=\' + encodeURIComponent(\'' + singboxURL + '\')">Sing-box</button></div>' +
'<div class="hint">客户端也可直接把订阅地址填入「订阅分组」，更新即用；UA 为 Clash / Sing-box 系时自动返回对应格式。手机端可点「显示二维码」扫码导入。</div></div>' +

'<div class="card" style="animation-delay:.16s"><h2><span class="no">04</span>API 管理<em>所有端点均挂载在入口路径之下</em></h2>' +
'<code>GET    ' + base + '/api/ips          查询优选 IP</code>' +
'<code>POST   ' + base + '/api/ips          {"text":"1.2.3.4\\n5.6.7.8"} 批量添加</code>' +
'<code>DELETE ' + base + '/api/ips?ip=1.2.3.4  删除单个；不带 ip 清空</code>' +
'<code>GET/POST ' + base + '/api/config     读取 / 保存全部配置</code></div>' +

'</div>' +
'<div id="qrModal" class="modal"><div class="modal-box"><button class="modal-x" onclick="hideQr()">✕</button><iframe id="qrFrame" title="订阅二维码"></iframe></div></div>' +
'<div class="footer">✦ 由 <b style="color:#fbbf77">数码解码</b> 出品 · <a href="https://github.com/smzxtv/nebula-decode" target="_blank">GitHub 开源项目</a> ✦</div>' +
'<script>var BASE=' + JSON.stringify(base + '/') + ';var API_TOKEN=' + JSON.stringify(cfg.apiToken || '') + ';</script>' + PANEL_TAIL;
  return new Response(body, { headers: { 'content-type': 'text/html; charset=utf-8', 'x-powered-by': 'shumajiedu | NEBULA-DECODE' } });
}

const PANEL_TAIL = '<script>' +
'function $(id){return document.getElementById(id)}' +
'function show(id,t){$(id).textContent=t;setTimeout(function(){$(id).textContent=""},4000)}' +
'function apiHeaders(extra){var h=extra||{};if(API_TOKEN){h["X-API-Token"]=API_TOKEN}return h}' +
'async function loadCfg(){' +
'  var r=await fetch(BASE+"api/config",{headers:apiHeaders()}),c=await r.json();' +
'  $("uuid").value=c.uuid;$("path").value=(c.path||"").replace(/^\\//,"");$("proxyIP").value=c.proxyIP||"";' +
'  $("trojanPassword").value=c.trojanPassword||"";$("apiToken").value=c.apiToken||"";$("enableVless").checked=!!c.enableVless;' +
'  $("enableTrojan").checked=!!c.enableTrojan;$("useBuiltinPool").checked=c.useBuiltinPool!==false;$("preferredDomains").value=(c.preferredDomains||[]).join(",");' +
'  var r2=await fetch(BASE+"api/ips",{headers:apiHeaders()}),c2=await r2.json();$("ips").value=(c2.ips||[]).join("\\n");' +
'}' +
'async function saveCfg(){' +
'  var body={uuid:$("uuid").value.trim(),path:$("path").value.trim(),proxyIP:$("proxyIP").value.trim(),' +
'    trojanPassword:$("trojanPassword").value.trim(),apiToken:$("apiToken").value.trim(),enableVless:$("enableVless").checked,' +
'    enableTrojan:$("enableTrojan").checked,useBuiltinPool:$("useBuiltinPool").checked,preferredDomains:$("preferredDomains").value.split(",").map(function(s){return s.trim()}).filter(Boolean)};' +
'  var r=await fetch(BASE+"api/config",{method:"POST",headers:apiHeaders({"content-type":"application/json"}),body:JSON.stringify(body)});' +
'  var c=await r.json();if(!c.ok){show("msg1","保存失败: "+(c.error||"未知错误"));return}' +
'  show("msg1","已保存，即将跳转到新入口...");' +
'  var base=body.path?"/"+body.path.replace(/^\\/+|\\/+$/g,""):"/"+body.uuid;' +
'  setTimeout(function(){location.href=base+"/"},800);' +
'}' +
'async function addIps(){' +
'  var r=await fetch(BASE+"api/ips",{method:"POST",headers:apiHeaders({"content-type":"application/json"}),body:JSON.stringify({text:$("ips").value})});' +
'  var c=await r.json();if(c.ok){$("ips").value=c.ips.join("\\n");show("msg2","已添加 "+c.ips.length+" 条")}else show("msg2","失败: "+c.error);' +
'}' +
'async function clearIps(){' +
'  var r=await fetch(BASE+"api/ips",{method:"DELETE",headers:apiHeaders()});var c=await r.json();if(c.ok){$("ips").value="";show("msg2","已清空")}' +
'}' +
'function copyTo(t,btn){navigator.clipboard.writeText(t).then(function(){btn.textContent="已复制";setTimeout(function(){btn.textContent=btn.textContent.replace("已复制","复制")},1500)})}' +
'function genUuid(){if(window.crypto&&crypto.randomUUID){$("uuid").value=crypto.randomUUID()}else{var s="0123456789abcdef",u="";for(var j=0;j<36;j++){u+=(j===8||j===12||j===16||j===20)?"-":(j===14)?"4":s.charAt(Math.floor(Math.random()*16))}$("uuid").value=u}}' +
'function genToken(){var a=new Uint8Array(16);if(window.crypto&&crypto.getRandomValues){crypto.getRandomValues(a)}else{for(var i=0;i<a.length;i++){a[i]=Math.floor(Math.random()*256)}}var s="";for(var j=0;j<a.length;j++){s+=("0"+a[j].toString(16)).slice(-2)}$("apiToken").value=s}' +
'function showQr(t){$("qrFrame").src=BASE+"qr?t="+t;document.getElementById("qrModal").classList.add("on")}' +
'function hideQr(){document.getElementById("qrModal").classList.remove("on");$("qrFrame").src="about:blank"}' +
'document.addEventListener("keydown",function(e){if(e.key==="Escape")hideQr()});' +
'loadCfg();' +
'<\/script></body></html>';




