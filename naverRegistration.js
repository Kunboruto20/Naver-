#!/usr/bin/env node
/* =====================================================================
 * naverRegistration.js — End-to-end Naver mobile account registration
 * Pure Node.js (no Puppeteer / no headless browser).
 *
 * Flow:
 *   1.  Prompt the operator for id, password, email, name, birthday, gender.
 *   2.  Lease a Polish phone number from HeroSMS (service "nv", country 15).
 *   3.  GET /user2/V2Join.nhn?m=agree    -> session cookies
 *   4.  GET /user2/join/agree            -> hidden token_sjoin
 *   5.  GET /user2/join/begin            -> RSA pubkey + sessionKey + keyName
 *                                          + bvsd siteKey + ncaptcha siteKey
 *   6.  GET  /user2/joinAjax?m=checkId   -> ensure id is free
 *   7.  POST /user2/joinAjax?m=checkPswd -> ensure password is acceptable
 *   8.  POST /user2/joinAjax?m=sendAuthno (with nid_kb2 from bvsd) -> SMS
 *   9.  Poll HeroSMS for the 4-digit code (regex \b\d{4}\b)
 *  10.  GET  /user2/joinAjax?m=checkAuthno -> validates code
 *  11.  POST /user2/join/end (with nid_kb2, nid_kb3, encPswd, all fields)
 *  12.  Mark HeroSMS activation as completed (status=6).
 *
 * The bvsd / ncaptcha / RSA SDKs are executed inside a real DOM sandbox
 * (jsdom) loaded with the SAME scripts the mobile webview pulls down,
 * so every cryptographic payload (nid_kb2, nid_kb3, encPswd) is byte-
 * identical to what the official Naver app produces.
 * ===================================================================== */

"use strict";

const path = require("path");
const fs = require("fs");
const readline = require("node:readline/promises");
const { stdin: input, stdout: output } = require("node:process");
const { webcrypto } = require("node:crypto");
const crypto = require("node:crypto");

// Resolve runtime deps from the bundled naver-tools/ folder
const TOOLS = path.join(__dirname, "naver-tools", "node_modules");
const { JSDOM } = require(path.join(TOOLS, "jsdom"));
const { CookieJar } = require(path.join(TOOLS, "tough-cookie"));
const { ProxyAgent, EnvHttpProxyAgent, setGlobalDispatcher, Agent: UndiciAgent } = require(path.join(TOOLS, "undici"));

// --------------------------------------------------------------------------
//  CONSTANTS
// --------------------------------------------------------------------------

const SDK_DIR = path.join(__dirname, "sdks");
const BVSD_JS = fs.readFileSync(path.join(SDK_DIR, "bvsd.1.3.9.js"), "utf8");
const RSA_JS = fs.readFileSync(path.join(SDK_DIR, "rsaAll.js"), "utf8");
const NCAPTCHA_API_JS = fs.readFileSync(path.join(SDK_DIR, "ncaptcha-api.js"), "utf8");
const NCAPTCHA_REAL_JS = fs.readFileSync(path.join(SDK_DIR, "real_sdk.js"), "utf8");

// --------------------------------------------------------------------------
//  AUTO-MODE FILE POOLS (proxy.txt / username.txt next to this script)
//  When present, the tool runs hands-free: no Enter prompts, random pick.
// --------------------------------------------------------------------------
const PROXY_FILE    = path.join(__dirname, "proxy.txt");
const USERNAME_FILE = path.join(__dirname, "username.txt");
const ACCOUNTS_FILE = path.join(__dirname, "accounts.json");

function _loadLines(file) {
  try {
    if (!fs.existsSync(file)) return [];
    return fs.readFileSync(file, "utf8")
      .split(/\r?\n/)
      .map(s => s.trim())
      .filter(s => s && !s.startsWith("#"));
  } catch { return []; }
}

const PROXY_POOL    = _loadLines(PROXY_FILE);
const USERNAME_POOL = _loadLines(USERNAME_FILE);
// In-memory shuffled queue of remaining usernames for auto-retry on conflict
const USERNAME_QUEUE = USERNAME_POOL.slice().sort(() => Math.random() - 0.5);
const HAS_PROXY_FILE    = PROXY_POOL.length > 0;
const HAS_USERNAME_FILE = USERNAME_POOL.length > 0;
// Auto-mode: any file present skips ALL prompts (proxy, username, sms, etc.)
const AUTO_MODE = HAS_PROXY_FILE || HAS_USERNAME_FILE;

function pickRandomProxyFromPool() {
  if (!PROXY_POOL.length) return null;
  return PROXY_POOL[Math.floor(Math.random() * PROXY_POOL.length)];
}
function pickNextUsernameFromPool() {
  if (!USERNAME_QUEUE.length) return null;
  return USERNAME_QUEUE.shift();
}
function appendAccountRecord(record) {
  try {
    let arr = [];
    if (fs.existsSync(ACCOUNTS_FILE)) {
      try {
        const raw = fs.readFileSync(ACCOUNTS_FILE, "utf8").trim();
        if (raw) {
          const parsed = JSON.parse(raw);
          if (Array.isArray(parsed)) arr = parsed;
        }
      } catch { arr = []; }
    }
    arr.push(record);
    fs.writeFileSync(ACCOUNTS_FILE, JSON.stringify(arr, null, 2), "utf8");
    return true;
  } catch (e) {
    return false;
  }
}

// --------------------------------------------------------------------------
//  DEVICE POOL — randomised per session to avoid Naver flagging "same device"
//  Each entry is a real Android phone with verified build fingerprint.
//  Combined with random Chrome version + locale + timezone, every run looks
//  like a brand-new device to Naver's anti-abuse system.
// --------------------------------------------------------------------------
const DEVICE_POOL = [
  { model:"SM-A536B",  brand:"samsung", android:"13", androidVer:"13.0.0", build:"TP1A.220624.014",  w:360, dh:800, bh:776, sw:1080, sh:2400, pr:3, mem:4, cores:8, platform:"Linux armv8l" },
  { model:"SM-A235F",  brand:"samsung", android:"12", androidVer:"12.0.0", build:"SP1A.210812.016",  w:360, dh:800, bh:774, sw:1080, sh:2408, pr:3, mem:4, cores:8, platform:"Linux armv8l" },
  { model:"SM-A135F",  brand:"samsung", android:"12", androidVer:"12.0.0", build:"SP1A.210812.016",  w:360, dh:780, bh:756, sw:720,  sh:1600, pr:2, mem:2, cores:8, platform:"Linux armv7l" },
  { model:"SM-A528B",  brand:"samsung", android:"13", androidVer:"13.0.0", build:"TP1A.220624.014",  w:360, dh:800, bh:778, sw:1080, sh:2400, pr:3, mem:4, cores:8, platform:"Linux armv8l" },
  { model:"SM-G991B",  brand:"samsung", android:"13", androidVer:"13.0.0", build:"TP1A.220624.014",  w:360, dh:800, bh:772, sw:1080, sh:2400, pr:3, mem:8, cores:8, platform:"Linux armv8l" },
  { model:"2201116TG", brand:"Xiaomi",  android:"12", androidVer:"12.0.0", build:"SP1A.210812.016",  w:393, dh:873, bh:849, sw:1080, sh:2400, pr:2.75, mem:4, cores:8, platform:"Linux armv8l" },
  { model:"2201116PG", brand:"Xiaomi",  android:"12", androidVer:"12.0.0", build:"SP1A.210812.016",  w:393, dh:873, bh:847, sw:1080, sh:2400, pr:2.75, mem:4, cores:8, platform:"Linux armv8l" },
  { model:"M2101K7BG", brand:"Xiaomi",  android:"11", androidVer:"11.0.0", build:"RKQ1.201004.002",  w:393, dh:873, bh:851, sw:1080, sh:2400, pr:2.75, mem:4, cores:8, platform:"Linux armv8l" },
  { model:"220333QBI", brand:"Xiaomi",  android:"11", androidVer:"11.0.0", build:"RP1A.200720.011",  w:360, dh:800, bh:776, sw:720,  sh:1600, pr:2, mem:2, cores:8, platform:"Linux armv7l" },
  { model:"RMX3261",   brand:"realme",  android:"11", androidVer:"11.0.0", build:"RP1A.200720.011",  w:360, dh:800, bh:754, sw:720,  sh:1600, pr:2, mem:2, cores:8, platform:"Linux armv7l" },
  { model:"M2006C3MNG",brand:"Xiaomi",  android:"11", androidVer:"11.0.0", build:"RP1A.200720.011",  w:360, dh:724, bh:684, sw:720,  sh:1449, pr:2, mem:2, cores:4, platform:"Linux armv7l" },
];

const CHROME_VERSIONS = [
  { major:"124", full:"124.0.6367.82"  },
  { major:"125", full:"125.0.6422.165" },
  { major:"126", full:"126.0.6478.122" },
  { major:"128", full:"128.0.6613.137" },
  { major:"130", full:"130.0.6723.102" },
  { major:"132", full:"132.0.6834.163" },
  { major:"134", full:"134.0.6998.135" },
  { major:"146", full:"146.0.7680.119" },
];

const LANG_POOL = [
  { code:"ko-KR", accept:"ko-KR,ko;q=0.9,en-US;q=0.8,en;q=0.7", langs:["ko-KR","ko","en-US","en"] },
  { code:"en-US", accept:"en-US,en;q=0.9",                       langs:["en-US","en"] },
  { code:"zh-CN", accept:"zh-CN,zh;q=0.9,en-US;q=0.8,en;q=0.7", langs:["zh-CN","zh","en-US","en"] },
  { code:"ro-RO", accept:"ro-RO,ro;q=0.9,en-US;q=0.8,en;q=0.7", langs:["ro-RO","ro","en-US","en"] },
  { code:"ja-JP", accept:"ja-JP,ja;q=0.9,en-US;q=0.8,en;q=0.7", langs:["ja-JP","ja","en-US","en"] },
];

const TZ_POOL = [
  "Asia/Seoul", "America/New_York", "Europe/Bucharest",
  "Asia/Tokyo", "America/Los_Angeles", "Europe/London",
  "Asia/Shanghai", "America/Chicago",
];

function _pick(arr) { return arr[Math.floor(Math.random() * arr.length)]; }

// Pick ONE profile per process (= per registration session).
// Everything below — UA, sec-ch-ua-*, jsdom navigator/screen, nlog env —
// is derived from this object so the entire session presents a consistent,
// believable device fingerprint that changes from run to run.
const SESSION_DEV  = _pick(DEVICE_POOL);
const SESSION_CHR  = _pick(CHROME_VERSIONS);
const SESSION_LANG = _pick(LANG_POOL);
const SESSION_TZ   = _pick(TZ_POOL);

const NAVER_UA =
  `Mozilla/5.0 (Linux; Android ${SESSION_DEV.android}; ${SESSION_DEV.model} Build/${SESSION_DEV.build}; wv) ` +
  `AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/${SESSION_CHR.full} ` +
  `Mobile Safari/537.36 Android/${SESSION_DEV.android} Model/${SESSION_DEV.model} ` +
  `com.nhn.android.search/9.0.6(90006,uid:${10300 + Math.floor(Math.random() * 100)}) LoginMod/6.6.0`;

const SEC_CH_UA = `"Chromium";v="${SESSION_CHR.major}", "Not-A.Brand";v="24", "Android WebView";v="${SESSION_CHR.major}"`;
const SEC_CH_UA_FULL = `"Chromium";v="${SESSION_CHR.full}", "Not-A.Brand";v="24.0.0.0", "Android WebView";v="${SESSION_CHR.full}"`;

// ---------------------------------------------------------------------------
//  Plain Chrome Mobile profile — used for the App Password flow only.
//
//  Reverse-engineered from the working HAR (ProxyPin4-25 23:17:22), which
//  was captured from a regular Chrome browser on Android (NOT the Naver
//  app webview). The 2StepVerif management endpoint returns a Base64
//  redirect / placeholder page (~500 chars instead of ~23000) when the
//  session is identified as "Android WebView" / com.nhn.android.search,
//  causing createApplicationPassword to reply {"resultCode":-1}.
//
//  Switching to a plain Chrome mobile UA + brand list mirrors what the
//  HAR shows the browser sending and unblocks the page.
// ---------------------------------------------------------------------------
const CHROME_PLAIN_UA =
  `Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) ` +
  `Chrome/${SESSION_CHR.major}.0.0.0 Mobile Safari/537.36`;
const SEC_CH_UA_PLAIN = `"Google Chrome";v="${SESSION_CHR.major}", "Not.A/Brand";v="8", "Chromium";v="${SESSION_CHR.major}"`;
const SEC_CH_UA_PLAIN_FULL =
  `"Google Chrome";v="${SESSION_CHR.full}", "Not.A/Brand";v="8.0.0.0", "Chromium";v="${SESSION_CHR.full}"`;

const NAVER_HOST = "https://nid.naver.com";
const HEROSMS_HOST = "https://hero-sms.com/stubs/handler_api.php";
let HEROSMS_KEY = process.env.HEROSMS_API_KEY || "dbcd85f6e0b4446eA5AAe8b7A4c8A186";
const HEROSMS_SERVICE = "nv"; // Naver

// HeroSMS country code → ITU dialing code mapping
const HEROSMS_COUNTRY_MAP = {
  "187": "1",  // USA (physical) ← default, confirmed working with Naver
  "15":  "48", // Poland
  "32":  "40", // Romania
  "1":   "380",// Ukraine
};
const HEROSMS_COUNTRY = process.env.NV_HEROSMS_COUNTRY || "187"; // default USA
const HEROSMS_NATION_NO = HEROSMS_COUNTRY_MAP[HEROSMS_COUNTRY] || "1";

const POLAND_NATION_NO = "48"; // kept for compat

// --------------------------------------------------------------------------
//  Residential proxy support
//  Set PROXY_URL env var or enter it interactively when prompted.
//  Supported input formats (all are auto-normalized to http://user:pass@host:port):
//    http://user:pass@host:port         ← already correct, passed through
//    https://user:pass@host:port        ← already correct, passed through
//    socks5://user:pass@host:port       ← already correct, passed through
//    host:port:user:pass                ← common provider format
//    user:pass:host:port                ← alternative provider format
//    user:pass@host:port                ← missing protocol, http:// added
//    host:port                          ← no auth, http:// added
// --------------------------------------------------------------------------

/**
 * Normalize any proxy string to the canonical form  protocol://user:pass@host:port
 * so that ProxyAgent / undici can parse it without errors.
 *
 * Handles the following input shapes (all case-insensitive for the protocol):
 *
 *   Already-valid URLs  → returned as-is
 *     http://user:pass@host:port
 *     https://user:pass@host:port
 *     socks5://user:pass@host:port
 *     socks4://user:pass@host:port
 *
 *   Missing protocol, has @  → http:// prepended
 *     user:pass@host:port
 *
 *   No protocol, no @, 4+ colon-separated segments  → host:port:user:pass assumed first,
 *   then user:pass:host:port if last segment is the port number.
 *     host:port:user:pass
 *     user:pass:host:port
 *
 *   No protocol, no @, 2 segments  → http://host:port  (no-auth proxy)
 *     host:port
 */
function normalizeProxyUrl(raw) {
  if (!raw) return raw;

  // ── 0. Pre-clean ─────────────────────────────────────────────────────────
  raw = String(raw).trim()
    .replace(/^['"]+|['"]+$/g, '')   // strip wrapping quotes
    .replace(/\s+/g, '');             // remove any whitespace inside

  if (!raw) return raw;

  // ── 1. Detect & extract protocol if present ──────────────────────────────
  //  Accepted protocols (case-insensitive): http, https, socks4, socks5,
  //  socks5h. Anything else falls back to http.
  let protocol = 'http';
  let body = raw;
  const protoMatch = raw.match(/^([a-zA-Z][a-zA-Z0-9+\-.]*):\/\/(.*)$/);
  if (protoMatch) {
    const p = protoMatch[1].toLowerCase();
    if (/^(https?|socks(4|5h?))$/.test(p)) protocol = p;
    body = protoMatch[2];
  }

  if (!body) return `${protocol}://`;

  // ── 2. Strip optional trailing slash / path / query ───────────────────────
  //  We only care about the auth + host:port part.
  let trailingPath = '';
  const slashIdx = body.indexOf('/');
  if (slashIdx > 0) {
    trailingPath = body.slice(slashIdx);
    body = body.slice(0, slashIdx);
  }

  // ── 3. body has '@' → standard user:pass@host:port form ───────────────────
  //  Use lastIndexOf so a stray '@' inside the password does not confuse us.
  if (body.includes('@')) {
    const atIdx = body.lastIndexOf('@');
    const credPart = body.slice(0, atIdx);
    const hostPart = body.slice(atIdx + 1);
    let userPass;
    const colonIdx = credPart.indexOf(':');
    if (colonIdx >= 0) {
      const user = credPart.slice(0, colonIdx);
      const pass = credPart.slice(colonIdx + 1);
      userPass = `${encodeURIComponent(user)}:${encodeURIComponent(pass)}`;
    } else {
      userPass = encodeURIComponent(credPart);
    }
    return `${protocol}://${userPass}@${hostPart}${trailingPath}`;
  }

  // ── 4. Colon-only format ─────────────────────────────────────────────────
  //  Common provider exports (SmartProxy, BrightData, IPRoyal, Evomi, etc.)
  //    host:port:user:pass     ← port is parts[1]  (digits)
  //    user:pass:host:port     ← port is the LAST part (digits)
  //  Password may itself contain ':' — re-join safely.
  const parts = body.split(':');

  if (parts.length >= 4) {
    // host:port:user:pass
    if (/^\d{1,5}$/.test(parts[1])) {
      const host = parts[0];
      const port = parts[1];
      const user = parts[2];
      const pass = parts.slice(3).join(':');
      return `${protocol}://${encodeURIComponent(user)}:${encodeURIComponent(pass)}@${host}:${port}${trailingPath}`;
    }
    // user:pass:host:port
    if (/^\d{1,5}$/.test(parts[parts.length - 1])) {
      const port = parts[parts.length - 1];
      const host = parts[parts.length - 2];
      const user = parts[0];
      const pass = parts.slice(1, parts.length - 2).join(':');
      return `${protocol}://${encodeURIComponent(user)}:${encodeURIComponent(pass)}@${host}:${port}${trailingPath}`;
    }
  }

  // ── 5. host:port (no auth) ───────────────────────────────────────────────
  if (parts.length === 2 && /^\d{1,5}$/.test(parts[1])) {
    return `${protocol}://${parts[0]}:${parts[1]}${trailingPath}`;
  }

  // ── 6. Fallback — pass through with chosen protocol ──────────────────────
  return `${protocol}://${body}${trailingPath}`;
}

let PROXY_URL = normalizeProxyUrl((process.env.PROXY_URL || "").trim());

function buildProxyDispatcher(proxyUrl) {
  if (!proxyUrl) return undefined;
  try {
    return new ProxyAgent(proxyUrl);
  } catch (e) {
    throw new Error(`Invalid proxy URL "${proxyUrl}": ${e.message}`);
  }
}

// Lazily built once after askInputs() resolves the proxy URL.
let _proxyDispatcher = undefined;

// Wrap global fetch so every call automatically uses the proxy dispatcher.
function proxiedFetch(url, init = {}) {
  if (_proxyDispatcher) {
    return fetch(url, { dispatcher: _proxyDispatcher, ...init });
  }
  return fetch(url, init);
}

// --------------------------------------------------------------------------
//  ABSOLUTE LEAK GUARD — installs proxy at every possible network layer:
//    1. undici / global fetch  ............ via setGlobalDispatcher
//    2. Native http.request / https.request via monkey-patch -> tunneled
//       through the same HTTP CONNECT proxy as undici
//    3. Refuses any direct request that would leak the server's real IP
//
//  Result: when the user enters a residential proxy at startup, EVERY
//  outbound TCP connection from this process — including any cert-pinned
//  SDK call buried inside jsdom or third-party deps — exits through the
//  proxy's residential IP. Running on a VPS becomes indistinguishable
//  from running on the operator's home connection.
// --------------------------------------------------------------------------
const _nativeHttp  = require("http");
const _nativeHttps = require("https");
const _nativeHttpRequest  = _nativeHttp.request.bind(_nativeHttp);
const _nativeHttpsRequest = _nativeHttps.request.bind(_nativeHttps);
const _nativeHttpGet      = _nativeHttp.get.bind(_nativeHttp);
const _nativeHttpsGet     = _nativeHttps.get.bind(_nativeHttps);

let _proxyHostInfo = null; // { protocol, host, port, auth }
function _parseProxyForNative(proxyUrl) {
  try {
    const u = new URL(proxyUrl);
    return {
      protocol: u.protocol.replace(":", ""),
      host: u.hostname,
      port: u.port || (u.protocol === "https:" ? "443" : "80"),
      auth: (u.username || u.password)
        ? Buffer.from(`${decodeURIComponent(u.username)}:${decodeURIComponent(u.password)}`).toString("base64")
        : null,
    };
  } catch { return null; }
}

// Tunnel an HTTPS request through an HTTP CONNECT proxy (used for the
// rare cases when some dep uses native https.request instead of undici).
function _tunnelHttpsThroughProxy(targetOpts, callback) {
  const net = require("net");
  const tls = require("tls");
  const targetHost = targetOpts.hostname || targetOpts.host;
  const targetPort = targetOpts.port || 443;
  const sock = net.connect(parseInt(_proxyHostInfo.port, 10), _proxyHostInfo.host);
  let connectReq = `CONNECT ${targetHost}:${targetPort} HTTP/1.1\r\nHost: ${targetHost}:${targetPort}\r\n`;
  if (_proxyHostInfo.auth) connectReq += `Proxy-Authorization: Basic ${_proxyHostInfo.auth}\r\n`;
  connectReq += "\r\n";
  let buf = "";
  const onData = (chunk) => {
    buf += chunk.toString("binary");
    const idx = buf.indexOf("\r\n\r\n");
    if (idx === -1) return;
    sock.removeListener("data", onData);
    const head = buf.slice(0, idx);
    if (!/^HTTP\/1\.[01]\s+200/.test(head)) {
      sock.destroy();
      return callback(new Error(`Proxy CONNECT failed: ${head.split("\r\n")[0]}`));
    }
    const tlsSock = tls.connect({
      socket: sock,
      servername: targetHost,
      ALPNProtocols: ["http/1.1"],
    }, () => callback(null, tlsSock));
    tlsSock.on("error", (e) => callback(e));
  };
  sock.on("data", onData);
  sock.on("error", (e) => callback(e));
  sock.write(connectReq);
}

function installNativeHttpProxyHooks() {
  if (!_proxyHostInfo) return;
  // Intercept native https.request — route through proxy via CONNECT tunnel.
  // We rebuild the request as a stream over the tunneled socket so that any
  // legacy code using https.request keeps working transparently.
  const wrapHttps = (orig) => function (urlOrOpts, optsOrCb, cb) {
    let opts, callback;
    if (typeof urlOrOpts === "string" || urlOrOpts instanceof URL) {
      const u = new URL(urlOrOpts);
      opts = { hostname: u.hostname, port: u.port || 443, path: u.pathname + u.search,
               method: "GET", headers: {} };
      if (typeof optsOrCb === "function") { callback = optsOrCb; }
      else { Object.assign(opts, optsOrCb || {}); callback = cb; }
    } else {
      opts = { ...(urlOrOpts || {}) };
      callback = optsOrCb;
    }
    // Already targeting proxy host? pass through to original.
    if (opts.hostname === _proxyHostInfo.host && String(opts.port) === String(_proxyHostInfo.port)) {
      return orig(urlOrOpts, optsOrCb, cb);
    }
    // Build a fake ClientRequest using the EventEmitter API surface that
    // callers depend on (write, end, on('response'), on('error'), setTimeout).
    const { EventEmitter } = require("events");
    const fakeReq = new EventEmitter();
    fakeReq.setTimeout = (ms, onTimeout) => {
      fakeReq._timeoutMs = ms;
      if (onTimeout) fakeReq.once("timeout", onTimeout);
      return fakeReq;
    };
    let pendingChunks = [];
    let ended = false;
    fakeReq.write = (chunk) => { pendingChunks.push(Buffer.from(chunk)); return true; };
    fakeReq.end = (chunk) => {
      if (chunk) pendingChunks.push(Buffer.from(chunk));
      ended = true;
      _tunnelHttpsThroughProxy(opts, (err, tlsSock) => {
        if (err) { fakeReq.emit("error", err); return; }
        if (fakeReq._timeoutMs) {
          tlsSock.setTimeout(fakeReq._timeoutMs, () => fakeReq.emit("timeout"));
        }
        const headers = opts.headers || {};
        const body = Buffer.concat(pendingChunks);
        let reqLine = `${opts.method || "GET"} ${opts.path || "/"} HTTP/1.1\r\n`;
        reqLine += `Host: ${opts.hostname}\r\n`;
        for (const k of Object.keys(headers)) {
          if (k.toLowerCase() === "host") continue;
          reqLine += `${k}: ${headers[k]}\r\n`;
        }
        if (body.length && !Object.keys(headers).some(k => k.toLowerCase() === "content-length")) {
          reqLine += `Content-Length: ${body.length}\r\n`;
        }
        reqLine += "Connection: close\r\n\r\n";
        tlsSock.write(reqLine);
        if (body.length) tlsSock.write(body);
        // Parse the response into a fake IncomingMessage
        const { Readable } = require("stream");
        let respBuf = Buffer.alloc(0);
        let headersParsed = false;
        let resp;
        tlsSock.on("data", (chunk) => {
          if (!headersParsed) {
            respBuf = Buffer.concat([respBuf, chunk]);
            const idx = respBuf.indexOf("\r\n\r\n");
            if (idx === -1) return;
            const head = respBuf.slice(0, idx).toString("binary");
            const rest = respBuf.slice(idx + 4);
            const lines = head.split("\r\n");
            const statusMatch = lines[0].match(/HTTP\/\d\.\d\s+(\d+)\s*(.*)/);
            const status = statusMatch ? parseInt(statusMatch[1], 10) : 0;
            const statusText = statusMatch ? statusMatch[2] : "";
            const respHeaders = {};
            for (let i = 1; i < lines.length; i++) {
              const hi = lines[i].indexOf(":");
              if (hi > 0) {
                const hk = lines[i].slice(0, hi).trim().toLowerCase();
                const hv = lines[i].slice(hi + 1).trim();
                respHeaders[hk] = respHeaders[hk] ? respHeaders[hk] + ", " + hv : hv;
              }
            }
            resp = new Readable({ read() {} });
            resp.statusCode = status;
            resp.statusMessage = statusText;
            resp.headers = respHeaders;
            resp.rawHeaders = lines.slice(1);
            headersParsed = true;
            if (callback) callback(resp);
            fakeReq.emit("response", resp);
            if (rest.length) resp.push(rest);
          } else {
            resp.push(chunk);
          }
        });
        tlsSock.on("end", () => { if (resp) resp.push(null); });
        tlsSock.on("error", (e) => fakeReq.emit("error", e));
      });
      return fakeReq;
    };
    fakeReq.destroy = (e) => { if (e) fakeReq.emit("error", e); };
    fakeReq.abort   = () => fakeReq.destroy(new Error("aborted"));
    return fakeReq;
  };

  _nativeHttps.request = wrapHttps(_nativeHttpsRequest);
  _nativeHttps.get = function (...args) {
    const r = _nativeHttps.request(...args);
    r.end();
    return r;
  };
  // For plain http.request — same idea but no TLS wrap. Most Naver SDKs
  // are HTTPS only so this is mostly defensive.
  _nativeHttp.request = function (urlOrOpts, optsOrCb, cb) {
    // If the destination is http://, just route via undici fetch as a fallback.
    // We keep the original for backward compat with any CONNECT-based caller.
    return _nativeHttpRequest(urlOrOpts, optsOrCb, cb);
  };
  _nativeHttp.get = _nativeHttpGet;
}

// Optional: live verification that the proxy is actually carrying traffic.
// Returns the public IP observed through the proxy (or throws on leak).
async function verifyProxyOrAbort() {
  if (!_proxyDispatcher) return null;
  // 1) Direct (no proxy) IP — what the server's real IP is.
  //    IMPORTANT: passing `dispatcher: undefined` to fetch falls back to the
  //    GLOBAL dispatcher (which we just set to the proxy), so it would NOT
  //    actually bypass the proxy. We must build a fresh non-proxy Agent and
  //    pass it explicitly to truly hit the destination directly.
  let directIp = "unknown";
  try {
    const directAgent = new UndiciAgent();
    const r = await fetch("https://api.ipify.org?format=json", { dispatcher: directAgent });
    directIp = (await r.json()).ip;
    try { await directAgent.close(); } catch {}
  } catch (e) {
    // If the direct probe fails (firewall, no direct internet, etc.) we just
    // skip the leak comparison rather than abort — proxy is the safe default.
    warn(`Could not measure server's real IP (${e.message}); skipping leak check.`);
  }
  // 2) Through proxy — what Naver will see.
  let proxyIp;
  try {
    const r = await proxiedFetch("https://api.ipify.org?format=json", {
      headers: { "user-agent": "naver-cli/1.0" },
    });
    proxyIp = (await r.json()).ip;
  } catch (e) {
    err(`PROXY VERIFICATION FAILED: ${e.message}`);
    err(`Refusing to start — proxy is unreachable, traffic would leak on real IP.`);
    process.exit(1);
  }
  if (!proxyIp) {
    err(`PROXY VERIFICATION FAILED: empty response from ipify.`);
    process.exit(1);
  }
  if (directIp !== "unknown" && proxyIp === directIp) {
    err(`LEAK DETECTED: proxy IP (${proxyIp}) equals the server's real IP (${directIp}).`);
    err(`This usually means the proxy URL is wrong or the provider is broken.`);
    process.exit(1);
  }
  ok(`Proxy verified — server real IP: ${directIp}`);
  ok(`Proxy verified — outbound IP Naver will see: ${proxyIp}`);
  // 3) Verify native https.request also goes through proxy (ncpt path).
  try {
    const nativeIp = await new Promise((resolve, reject) => {
      const req = _nativeHttps.request({
        hostname: "api.ipify.org", port: 443, path: "/?format=json", method: "GET",
        headers: { "user-agent": "naver-cli/1.0", "accept": "application/json" },
      }, (r) => {
        const chunks = [];
        r.on("data", (c) => chunks.push(c));
        r.on("end", () => {
          try { resolve(JSON.parse(Buffer.concat(chunks).toString("utf8")).ip); }
          catch (e) { reject(e); }
        });
      });
      req.on("error", reject);
      req.setTimeout(15000, () => req.destroy(new Error("native https probe timeout")));
      req.end();
    });
    if (directIp !== "unknown" && nativeIp === directIp) {
      err(`LEAK DETECTED on native https path: ${nativeIp} = real IP.`);
      err(`This means ncpt.naver.com calls would reveal the server. Aborting.`);
      process.exit(1);
    }
    ok(`Native https.request also goes through proxy — IP: ${nativeIp}`);
  } catch (e) {
    warn(`Native https proxy probe inconclusive: ${e.message} — continuing.`);
  }
  return proxyIp;
}

// --------------------------------------------------------------------------
//  Tiny ANSI logger
// --------------------------------------------------------------------------
const C = {
  reset: "\x1b[0m",
  dim: "\x1b[2m",
  red: "\x1b[31m",
  grn: "\x1b[32m",
  ylw: "\x1b[33m",
  blu: "\x1b[34m",
  cyn: "\x1b[36m",
  bold: "\x1b[1m",
};
function log(tag, msg, color = C.cyn) {
  const ts = new Date().toISOString().slice(11, 19);
  console.log(`${C.dim}[${ts}]${C.reset} ${color}${tag.padEnd(7)}${C.reset} ${msg}`);
}
const info = (m) => log("INFO", m, C.cyn);
const ok = (m) => log("OK", m, C.grn);
const warn = (m) => log("WARN", m, C.ylw);
const err = (m) => log("ERROR", m, C.red);
const step = (n, m) => log(`STEP ${n}`, m, C.bold + C.blu);

// --------------------------------------------------------------------------
//  Sleep + jittered human-ish delays
// --------------------------------------------------------------------------
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
function humanPause(min = 800, max = 2200) {
  return sleep(Math.floor(min + Math.random() * (max - min)));
}

// --------------------------------------------------------------------------
//  CLI prompts (English) — interactive terminal UI
// --------------------------------------------------------------------------
let _rl = null;
function getRl() {
  if (!_rl) {
    _rl = readline.createInterface({ input, output, terminal: process.stdin.isTTY });
  }
  return _rl;
}
function ask(prompt, def) {
  const rl = getRl();
  return new Promise((resolve) => {
    const hint = def !== undefined ? ` [${def}]` : "";
    process.stdout.write(`  ${prompt}${hint}: `);
    rl.once("line", (line) => {
      const v = (line || "").trim();
      resolve(v || def || "");
    });
  });
}
function askSecret(prompt) {
  return ask(prompt);
}
function closeRl() { if (_rl) { _rl.close(); _rl = null; } }

function printBanner() {
  console.log("");
  console.log("  ╔══════════════════════════════════════════════════════╗");
  console.log("  ║        Naver Account Auto-Registration Tool         ║");
  console.log("  ║       github.com/naver-tools v2.4 (zero-leak)       ║");
  console.log("  ║       Press Enter on any field to auto-generate     ║");
  console.log("  ╚══════════════════════════════════════════════════════╝");
  console.log("");
}

// ── Random value generators (used when user presses Enter) ─────────────────
const _RAND_FIRST = ["Alex","John","Michael","David","Daniel","Chris","Kevin","Brian","Mark","Steven",
  "Andrew","Ryan","Eric","Justin","Tyler","Jason","Aaron","Adam","Nathan","Sean",
  "Emily","Sarah","Jessica","Ashley","Amanda","Jennifer","Megan","Hannah","Lauren","Rachel",
  "Olivia","Sophia","Emma","Mia","Chloe","Lily","Grace","Anna","Maria","Julia"];
const _RAND_LAST = ["Kim","Lee","Park","Choi","Jung","Cho","Yoon","Han","Smith","Johnson",
  "Brown","Davis","Miller","Wilson","Moore","Taylor","Anderson","Thomas","Martin","White"];

function _randInt(min, max) { return Math.floor(Math.random() * (max - min + 1)) + min; }
function _randPick(arr) { return arr[_randInt(0, arr.length - 1)]; }

function genUsername() {
  const letters = "abcdefghijklmnopqrstuvwxyz";
  const digits  = "0123456789";
  let s = letters[_randInt(0, 25)];
  const len = _randInt(8, 12);
  for (let i = 1; i < len - 3; i++) s += letters[_randInt(0, 25)];
  for (let i = 0; i < 3; i++) s += digits[_randInt(0, 9)];
  return s;
}
function genPassword() {
  const lo = "abcdefghijklmnopqrstuvwxyz";
  const up = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
  const di = "0123456789";
  const sy = "!@#$%";
  const all = lo + up + di;
  let s = up[_randInt(0, 25)] + lo[_randInt(0, 25)] + di[_randInt(0, 9)] + sy[_randInt(0, 4)];
  const len = _randInt(10, 12);
  for (let i = s.length; i < len; i++) s += all[_randInt(0, all.length - 1)];
  return s.split("").sort(() => Math.random() - 0.5).join("");
}
function genName() {
  return `${_randPick(_RAND_FIRST)} ${_randPick(_RAND_LAST)}`;
}
function genBirthday() {
  const yr = _randInt(1985, 2003);
  const mo = _randInt(1, 12);
  const maxDay = (mo === 2) ? 28 : ([4,6,9,11].includes(mo) ? 30 : 31);
  const dy = _randInt(1, maxDay);
  return `${yr}${String(mo).padStart(2,"0")}${String(dy).padStart(2,"0")}`;
}
function genGender() { return Math.random() < 0.5 ? "M" : "F"; }

async function inputId() {
  while (true) {
    const v = await ask("Username (press Enter for random, or 6-20 chars starting with a letter)");
    if (!v) {
      const g = genUsername();
      console.log(`  ${C.cyn}↻ Auto-generated username: ${g}${C.reset}`);
      return g;
    }
    if (/^[a-zA-Z][a-zA-Z0-9_]{5,19}$/.test(v)) return v.toLowerCase();
    console.log(`  ${C.ylw}✗ Invalid. Must start with a letter, 6-20 chars, letters/digits/underscore only.${C.reset}`);
  }
}
async function inputPassword() {
  while (true) {
    const v = await ask("Password (press Enter for random, or 8+ chars with letters + numbers)");
    if (!v) {
      const g = genPassword();
      console.log(`  ${C.cyn}↻ Auto-generated password: ${g}${C.reset}`);
      return g;
    }
    if (v.length >= 8 && /[a-zA-Z]/.test(v) && /[0-9]/.test(v)) return v;
    console.log(`  ${C.ylw}✗ Too weak. Min 8 chars, must include letters and numbers.${C.reset}`);
  }
}
async function inputName() {
  while (true) {
    const v = await ask("Full name (press Enter for random, or 2-30 chars e.g. Alex Kim)");
    if (!v) {
      const g = genName();
      console.log(`  ${C.cyn}↻ Auto-generated name: ${g}${C.reset}`);
      return g;
    }
    if (v.length >= 2 && v.length <= 30) return v;
    console.log(`  ${C.ylw}✗ Name must be 2-30 characters.${C.reset}`);
  }
}
async function inputBirthday() {
  while (true) {
    const v = await ask("Birthday (press Enter for random, or YYYYMMDD e.g. 19950315)");
    if (!v) {
      const g = genBirthday();
      console.log(`  ${C.cyn}↻ Auto-generated birthday: ${g}${C.reset}`);
      return g;
    }
    if (/^\d{8}$/.test(v)) {
      const yr = parseInt(v.slice(0, 4));
      const mo = parseInt(v.slice(4, 6));
      const dy = parseInt(v.slice(6, 8));
      if (yr >= 1940 && yr <= 2007 && mo >= 1 && mo <= 12 && dy >= 1 && dy <= 31) return v;
    }
    console.log(`  ${C.ylw}✗ Invalid date. Use YYYYMMDD, year must be 1940-2007.${C.reset}`);
  }
}
async function inputGender() {
  while (true) {
    const raw = await ask("Gender (press Enter for random, or M/F)");
    if (!raw) {
      const g = genGender();
      console.log(`  ${C.cyn}↻ Auto-generated gender: ${g}${C.reset}`);
      return g;
    }
    const v = raw.toUpperCase();
    if (v === "M" || v === "F") return v;
    console.log(`  ${C.ylw}✗ Enter M or F (or press Enter for random).${C.reset}`);
  }
}
async function inputEmail() {
  const v = await ask("Recovery email (press Enter to auto-generate)");
  if (!v) return null;
  if (/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(v)) return v;
  console.log(`  ${C.ylw}⚠ Invalid email format — auto-generating.${C.reset}`);
  return null;
}

async function askInputs() {
  printBanner();

  // ── Residential proxy — FIRST, before any network call ──────────────────
  // Priority: env PROXY_URL → proxy.txt (random pick) → interactive ask
  if (!PROXY_URL && HAS_PROXY_FILE) {
    const rawProxy = pickRandomProxyFromPool();
    const normalized = normalizeProxyUrl(rawProxy);
    PROXY_URL = normalized;
    console.log(`  ${C.grn}✓ Loaded ${PROXY_POOL.length} proxies from proxy.txt — picked one at random:${C.reset}`);
    console.log(`    ${C.cyn}${normalized.replace(/\/\/([^:@]+):([^@]+)@/, "//$1:***@")}${C.reset}`);
    console.log("");
  } else if (!PROXY_URL) {
    console.log(`  ${C.bold}Residential proxy (recommended for non-residential IPs):${C.reset}`);
    console.log(`  Naver blocks registration from cloud/datacenter IPs.`);
    console.log(`  Accepted formats (auto-detected):`);
    console.log(`    http://user:pass@host:port`);
    console.log(`    socks5://user:pass@host:port`);
    console.log(`    host:port:user:pass`);
    console.log(`    user:pass:host:port`);
    console.log(`    user:pass@host:port`);
    console.log(`  (Press Enter to skip only if you are on a home/residential IP)`);
    console.log(`  (Tip: drop a proxy.txt file next to this script to skip this prompt)`);
    console.log("");
    const rawProxy = (await ask("Enter your residential proxy URL")).trim();
    if (rawProxy) {
      const normalized = normalizeProxyUrl(rawProxy);
      PROXY_URL = normalized;
      if (normalized !== rawProxy) {
        console.log(`  ${C.ylw}↳ Detected format — normalized to:${C.reset}`);
        console.log(`    ${C.grn}${normalized.replace(/\/\/([^:@]+):([^@]+)@/, "//$1:***@")}${C.reset}`);
      }
      console.log(`  ${C.grn}✓ Proxy set successfully.${C.reset}`);
    } else {
      console.log(`  ${C.ylw}⚠ No proxy — make sure you are on a residential IP.${C.reset}`);
    }
    console.log("");
  } else {
    info(`Using proxy from PROXY_URL env: ${PROXY_URL}`);
  }

  // Build the dispatcher immediately so ALL subsequent requests use the proxy
  if (PROXY_URL && !_proxyDispatcher) {
    _proxyDispatcher = buildProxyDispatcher(PROXY_URL);
    // Force EVERY undici / global fetch() in this process through the proxy,
    // including calls made by jsdom, tough-cookie or any third-party dep.
    setGlobalDispatcher(_proxyDispatcher);
    // Patch native http/https.request so even the few legacy code paths that
    // bypass undici (e.g. ncpt direct calls) are tunneled through the proxy.
    _proxyHostInfo = _parseProxyForNative(PROXY_URL);
    if (_proxyHostInfo) {
      installNativeHttpProxyHooks();
      ok(`Native http/https patched — tunneled via ${_proxyHostInfo.host}:${_proxyHostInfo.port}`);
    } else {
      warn(`Could not parse proxy URL for native hook (only fetch will be proxied).`);
    }
    ok(`Proxy dispatcher ready (global + native hooks installed)`);
    // Live verification: confirm the proxy actually carries traffic and that
    // both fetch() AND native https.request go through it. Aborts on leak.
    await verifyProxyOrAbort();
  }

  // ── Non-interactive override via env vars (for scripted/CI use) ─────────
  const env = process.env;
  const allFromEnv = env.NV_ID && env.NV_PW && env.NV_EMAIL && env.NV_NAME && env.NV_BIRTHDAY;
  let id, pw, email, name, birthday, gender;

  if (allFromEnv) {
    info("Reading credentials from environment variables (NV_*)");
    id       = env.NV_ID;
    pw       = env.NV_PW;
    email    = env.NV_EMAIL;
    name     = env.NV_NAME;
    birthday = env.NV_BIRTHDAY;
    gender   = (env.NV_GENDER || "M").toUpperCase();
    if (gender !== "M" && gender !== "F") gender = "M";
  } else if (AUTO_MODE) {
    // ── Fully-automatic mode (proxy.txt or username.txt present) ───────────
    // No prompts at all — everything is generated/picked silently.
    console.log("  ┌─────────────────────────────────────────────────────┐");
    console.log("  │   Auto mode — generating account details silently   │");
    console.log("  └─────────────────────────────────────────────────────┘");
    if (HAS_USERNAME_FILE) {
      id = pickNextUsernameFromPool();
      console.log(`  ${C.cyn}↻ Username from username.txt (${USERNAME_POOL.length} available): ${id}${C.reset}`);
    } else {
      id = genUsername();
      console.log(`  ${C.cyn}↻ Auto-generated username: ${id}${C.reset}`);
    }
    pw       = genPassword();      console.log(`  ${C.cyn}↻ Auto-generated password: ${pw}${C.reset}`);
    name     = genName();          console.log(`  ${C.cyn}↻ Auto-generated name:     ${name}${C.reset}`);
    birthday = genBirthday();      console.log(`  ${C.cyn}↻ Auto-generated birthday: ${birthday}${C.reset}`);
    gender   = genGender();        console.log(`  ${C.cyn}↻ Auto-generated gender:   ${gender}${C.reset}`);
    email    = null;               // will be filled by the auto-email block below
    console.log("");
  } else {
    // ── Interactive mode ────────────────────────────────────────────────────
    console.log("  ┌─────────────────────────────────────────────────────┐");
    console.log("  │            Fill in your account details             │");
    console.log("  └─────────────────────────────────────────────────────┘");
    console.log("");
    id       = await inputId();
    pw       = genPassword();      console.log(`  ${C.cyn}↻ Auto-generated password: ${pw}${C.reset}`);
    name     = genName();          console.log(`  ${C.cyn}↻ Auto-generated name:     ${name}${C.reset}`);
    birthday = genBirthday();      console.log(`  ${C.cyn}↻ Auto-generated birthday: ${birthday}${C.reset}`);
    gender   = genGender();        console.log(`  ${C.cyn}↻ Auto-generated gender:   ${gender}${C.reset}`);
    email    = null;
    console.log("");
  }

  // Auto-generate email if blank
  if (!email) {
    email = `${id}${Math.floor(Math.random() * 9000 + 1000)}@gmail.com`;
    info(`Auto-generated email: ${email}`);
  }

  if (!id || !pw || !name || !/^\d{8}$/.test(birthday)) {
    err("Missing or invalid input. Please re-run.");
    process.exit(1);
  }

  // ── SMS source selection ─────────────────────────────────────────────────
  let smsSource, phone, nation, heroKey;

  if (env.NV_PHONE_NO) {
    smsSource = "manual";
    nation = (env.NV_NATION_NO || "40").replace(/\D/g, "");
    phone  = env.NV_PHONE_NO.replace(/\D/g, "").replace(/^0+/, "");
    if (nation && phone.startsWith(nation)) phone = phone.slice(nation.length);
    info(`Using NV_PHONE_NO from env: +${nation} ${phone}`);
  } else if (env.NV_SMS_SOURCE === "hero") {
    smsSource = "hero";
    info("SMS source: HeroSMS (from NV_SMS_SOURCE=hero)");
  } else if (AUTO_MODE) {
    // Auto-mode: always use HeroSMS, no prompt.
    smsSource = "hero";
    console.log(`  ${C.grn}✓ Auto mode — SMS source: HeroSMS (built-in key, number picked automatically).${C.reset}`);
    console.log("");
  } else {
    // Interactive choice
    console.log(`  ${C.bold}How do you want to receive the SMS verification code?${C.reset}`);
    console.log("");
    console.log(`    1) ${C.bold}HeroSMS${C.reset} — service automatically rents a virtual number`);
    console.log(`       (built-in API key, picks numbers automatically)`);
    console.log(`    2) ${C.bold}Your own phone${C.reset} — you enter the code you receive`);
    console.log("");
    const choice = (await ask("Choose 1 or 2", "1")).trim();
    if (choice === "1") {
      smsSource = "hero";
      console.log(`  ${C.grn}✓ Using built-in HeroSMS key — number will be picked automatically.${C.reset}`);
      console.log("");
    } else {
      smsSource = "manual";
      console.log("");
      const raw = await ask("Your phone number with country code (e.g. +407xxxxx or 40xxxx)");
      const digits = raw.replace(/\D/g, "");
      // Auto-detect country code (1-3 digit prefix)
      const CC = { "1":1, "7":1, "20":2, "27":2, "30":2, "31":2, "32":2, "33":2, "34":2,
        "36":2, "39":2, "40":2, "41":2, "43":2, "44":2, "45":2, "46":2, "47":2, "48":2,
        "49":2, "51":2, "52":2, "55":2, "60":2, "61":2, "62":2, "63":2, "64":2, "65":2,
        "66":2, "81":2, "82":2, "84":2, "86":2, "90":2, "91":2, "92":2, "93":2, "94":2,
        "95":2, "98":2, "380":3 };
      let detected = false;
      for (const len of [3, 2, 1]) {
        const pfx = digits.slice(0, len);
        if (CC[pfx] !== undefined) {
          nation = pfx;
          phone  = digits.slice(len);
          detected = true;
          break;
        }
      }
      if (!detected) {
        nation = await ask("Country dialing code (digits only, e.g. 40 for Romania)", "40");
        phone  = digits.slice(nation.length) || digits;
      }
      if (!phone) { err("Phone number is required."); process.exit(1); }
      console.log(`  ${C.grn}✓ Phone: +${nation} ${phone}${C.reset}`);
      console.log("");
    }
  }

  // Print summary before starting
  const proxyDisplay = PROXY_URL
    ? PROXY_URL.replace(/\/\/([^:@]+):([^@]+)@/, "//$1:***@")
    : "none (direct connection)";
  console.log("  ┌─────────────────────────────────────────────────────┐");
  console.log(`  │  Username  : ${(id + "@naver.com").padEnd(39)}│`);
  console.log(`  │  Password  : ${"*".repeat(Math.min(pw.length, 12)).padEnd(39)}│`);
  console.log(`  │  Name      : ${name.padEnd(39)}│`);
  console.log(`  │  Birthday  : ${birthday.padEnd(39)}│`);
  console.log(`  │  Gender    : ${gender.padEnd(39)}│`);
  console.log(`  │  Email     : ${email.padEnd(39)}│`);
  if (smsSource === "manual") {
    console.log(`  │  Phone     : ${("+"+nation+" "+phone).padEnd(39)}│`);
  } else {
    console.log(`  │  Phone     : ${"HeroSMS auto-lease".padEnd(39)}│`);
  }
  console.log(`  │  Proxy     : ${proxyDisplay.slice(0, 39).padEnd(39)}│`);
  console.log("  └─────────────────────────────────────────────────────┘");
  console.log("");

  return { id, pw, email, name, birthday, gender, smsSource, phone, nation, heroKey };
}

// --------------------------------------------------------------------------
//  HeroSMS client (sms-activate compatible)
// --------------------------------------------------------------------------
async function heroCall(action, extra = {}) {
  const params = new URLSearchParams({ api_key: HEROSMS_KEY, action, ...extra });
  const url = `${HEROSMS_HOST}?${params}`;
  const resp = await proxiedFetch(url, { headers: { "User-Agent": "naver-cli/1.0" } });
  const text = (await resp.text()).trim();
  return text;
}

async function heroBalance() {
  const r = await heroCall("getBalance");
  if (!r.startsWith("ACCESS_BALANCE:")) throw new Error(`Hero balance failed: ${r}`);
  return parseFloat(r.split(":")[1]);
}

async function heroGetNumber() {
  // Try a few times — number availability fluctuates
  for (let i = 0; i < 3; i++) {
    const r = await heroCall("getNumber", {
      service: HEROSMS_SERVICE,
      country: HEROSMS_COUNTRY,
    });
    if (r.startsWith("ACCESS_NUMBER:")) {
      const [, sid, phone] = r.split(":");
      return { id: sid, phone };
    }
    if (r === "NO_NUMBERS" || r === "NO_BALANCE") {
      warn(`HeroSMS: ${r} (retry ${i + 1}/3 in 5s)`);
      await sleep(5000);
      continue;
    }
    throw new Error(`HeroSMS getNumber error: ${r}`);
  }
  throw new Error("HeroSMS: no numbers available after 3 retries");
}

async function heroSetStatus(activationId, status) {
  // 1=sent SMS, 3=request another SMS, 6=complete, 8=cancel
  const r = await heroCall("setStatus", { id: activationId, status });
  return r;
}

async function heroPollCode(activationId, timeoutMs = 600000) {
  const start = Date.now();
  let attempts = 0;
  while (Date.now() - start < timeoutMs) {
    attempts++;
    const r = await heroCall("getStatus", { id: activationId });
    if (r.startsWith("STATUS_OK:")) {
      const raw = r.slice("STATUS_OK:".length);
      const m = raw.match(/\b(\d{4})\b/);
      if (!m) throw new Error(`Cannot extract 4-digit code from "${raw}"`);
      return m[1];
    }
    if (r === "STATUS_WAIT_CODE") {
      if (attempts % 3 === 0) info(`SMS still pending… (${Math.floor((Date.now() - start) / 1000)}s)`);
      await sleep(5000);
      continue;
    }
    if (r === "STATUS_CANCEL") throw new Error("HeroSMS reports activation cancelled");
    throw new Error(`HeroSMS unexpected status: ${r}`);
  }
  throw new Error("HeroSMS: SMS code timeout");
}

// --------------------------------------------------------------------------
//  HTTP layer with cookie jar (tough-cookie)
// --------------------------------------------------------------------------
const jar = new CookieJar();

async function naverFetch(url, opts = {}) {
  const finalUrl = url.startsWith("http") ? url : NAVER_HOST + url;
  const cookieHeader = await jar.getCookieString(finalUrl);
  const isPost = (opts.method || "GET").toUpperCase() === "POST";
  const isAjax = url.includes("/joinAjax") || opts.ajax === true;
  // ----- Headers identical to those captured from the real Naver Android
  // WebView (HAR ProxyPin4-3). Without them, Naver's anti-bot returns NNNNS
  // but silently DROPS the SMS dispatch. The critical ones are:
  //   x-requested-with: XMLHttpRequest           (marks request as in-app AJAX)
  //   sec-ch-ua-* + sec-fetch-*                  (Chromium 146 client hints)
  //   accept-language: ro-RO,...                 (matches Romanian device locale)
  //   priority + dpr/viewport-width/device-memory (mobile hints)
  const headers = {
    "User-Agent": NAVER_UA,
    Accept: "*/*",
    "Accept-Language": SESSION_LANG.accept,
    "Accept-Encoding": "gzip, deflate, br, zstd",
    Referer: opts.referer || `${NAVER_HOST}/user2/V2Join.nhn?m=agree&lang=en_US`,
    "sec-ch-ua": SEC_CH_UA,
    "sec-ch-ua-mobile": "?1",
    "sec-ch-ua-platform": '"Android"',
    "sec-ch-ua-platform-version": `"${SESSION_DEV.androidVer}"`,
    "sec-ch-ua-model": `"${SESSION_DEV.model}"`,
    "sec-ch-ua-arch": '""',
    "sec-ch-ua-full-version": `"${SESSION_CHR.full}"`,
    "sec-ch-ua-full-version-list": SEC_CH_UA_FULL,
    "viewport-width": String(SESSION_DEV.w),
    "device-memory": String(SESSION_DEV.mem),
    dpr: String(SESSION_DEV.pr),
    downlink: "10",
    ect: "4g",
    rtt: "0",
    priority: "u=1, i",
    ...(isAjax || isPost ? { "x-requested-with": "XMLHttpRequest" } : {}),
    ...(isAjax || isPost
      ? { "sec-fetch-site": "same-origin", "sec-fetch-mode": "cors", "sec-fetch-dest": "empty" }
      : {}),
    // Naver checks Origin on POSTs from the WebView. Without it, the server
    // accepts the request but silently drops downstream actions (e.g. SMS).
    ...(isPost ? { Origin: NAVER_HOST } : {}),
    ...(cookieHeader ? { Cookie: cookieHeader } : {}),
    ...(opts.headers || {}),
  };
  const init = { method: opts.method || "GET", headers, redirect: "manual" };
  if (opts.body !== undefined) {
    init.body = opts.body;
    if (!headers["Content-Type"]) {
      headers["Content-Type"] = "application/x-www-form-urlencoded; charset=UTF-8";
    }
  }
  // Allow callers (e.g. activateImap) to override the global proxy dispatcher
  // with a direct (no-proxy) Agent. proxiedFetch's spread order means this
  // takes precedence over _proxyDispatcher when both are set.
  if (opts.dispatcher) init.dispatcher = opts.dispatcher;
  const resp = await proxiedFetch(finalUrl, init);

  // Persist cookies (handles multiple Set-Cookie correctly)
  const setCookieList = resp.headers.getSetCookie
    ? resp.headers.getSetCookie()
    : (resp.headers.raw && resp.headers.raw()["set-cookie"]) || [];
  for (const sc of setCookieList) {
    try {
      await jar.setCookie(sc, finalUrl);
    } catch {
      /* ignore malformed cookie */
    }
  }

  // Follow one level of redirects manually so cookies survive each hop
  if ([301, 302, 303, 307, 308].includes(resp.status)) {
    const loc = resp.headers.get("location");
    if (loc) {
      const nextUrl = loc.startsWith("http") ? loc : new URL(loc, finalUrl).href;
      return naverFetch(nextUrl, { ...opts, method: "GET", body: undefined });
    }
  }
  const text = await resp.text();
  return { status: resp.status, headers: resp.headers, text, url: finalUrl };
}

// --------------------------------------------------------------------------
//  jsdom sandbox — runs the real bvsd/ncaptcha/RSA SDKs
// --------------------------------------------------------------------------
function createSandbox(beginUrl) {
  const html = `<!DOCTYPE html><html><body>
    <form id="join_form" method="POST" action="/user2/join/end">
      <input type="hidden" id="token_sjoin" name="token_sjoin" value="" />
      <input type="hidden" id="nid_kb2" name="nid_kb2" value="" />
      <input type="hidden" id="nid_kb3" name="nid_kb3" value="" />
      <input type="hidden" id="encPswd" name="encPswd" value="" />
      <input type="hidden" id="encKey" name="encKey" value="" />
      <input type="text"   id="id" name="id" />
      <input type="password" id="pswd1" name="pswd1" />
      <input type="text"   id="phoneNo" name="phoneNo" />
      <input type="email"  id="email" name="email" />
      <input type="text"   id="name" name="name" />
      <input type="text"   id="birthdayInput" />
    </form>
  </body></html>`;

  const dom = new JSDOM(html, {
    url: beginUrl,
    referrer: `${NAVER_HOST}/user2/join/agree?lang=en_US`,
    runScripts: "outside-only",
    pretendToBeVisual: true,
  });
  const w = dom.window;

  // Inject Node's WebCrypto so ncaptcha real_sdk's crypto.subtle.importKey works
  Object.defineProperty(w, "crypto", { value: webcrypto, configurable: true, writable: true });

  Object.defineProperty(w.navigator, "userAgent", { value: NAVER_UA, configurable: true });
  Object.defineProperty(w.navigator, "language",  { value: SESSION_LANG.code, configurable: true });
  Object.defineProperty(w.navigator, "languages", { value: SESSION_LANG.langs, configurable: true });
  Object.defineProperty(w.navigator, "platform",  { value: SESSION_DEV.platform, configurable: true });
  Object.defineProperty(w.navigator, "hardwareConcurrency", { value: SESSION_DEV.cores, configurable: true });
  Object.defineProperty(w.navigator, "deviceMemory", { value: SESSION_DEV.mem, configurable: true });
  Object.defineProperty(w.navigator, "maxTouchPoints", { value: 5, configurable: true });

  // Screen dimensions matching the randomly-picked SESSION_DEV.
  // bvsd samples these to build the browser fingerprint (BFP).
  // JSDOM leaves them as 0 which bvsd detects as headless → smaller encData.
  try {
    Object.defineProperty(w, "innerWidth",  { value: SESSION_DEV.w,  configurable: true });
    Object.defineProperty(w, "innerHeight", { value: SESSION_DEV.dh, configurable: true });
    Object.defineProperty(w, "outerWidth",  { value: SESSION_DEV.w,  configurable: true });
    Object.defineProperty(w, "outerHeight", { value: SESSION_DEV.dh, configurable: true });
    Object.defineProperty(w, "devicePixelRatio", { value: SESSION_DEV.pr, configurable: true });
    if (w.screen) {
      Object.defineProperty(w.screen, "width",       { value: SESSION_DEV.sw, configurable: true });
      Object.defineProperty(w.screen, "height",      { value: SESSION_DEV.sh, configurable: true });
      Object.defineProperty(w.screen, "availWidth",  { value: SESSION_DEV.sw, configurable: true });
      Object.defineProperty(w.screen, "availHeight", { value: SESSION_DEV.sh, configurable: true });
      Object.defineProperty(w.screen, "colorDepth",  { value: 24, configurable: true });
      Object.defineProperty(w.screen, "pixelDepth",  { value: 24, configurable: true });
    }
  } catch { /* jsdom may restrict some assignments */ }

  // ---- Stub browser APIs that bvsd samples for fingerprinting -------------
  // AudioContext fingerprint (bvsd hashes oscillator output)
  w.AudioContext = w.AudioContext || class AudioContext {
    createOscillator() { return { type: "sine", frequency: { value: 0, setValueAtTime() {} }, connect() {}, start() {}, disconnect() {} }; }
    createDynamicsCompressor() { return { connect() {}, threshold: { value: -24 }, knee: { value: 30 }, ratio: { value: 12 }, attack: { value: 0.003 }, release: { value: 0.25 } }; }
    createGain() { return { gain: { value: 1 }, connect() {}, disconnect() {} }; }
    get destination() { return { connect() {}, disconnect() {} }; }
    get sampleRate() { return 44100; }
    get state() { return "suspended"; }
    resume() { return Promise.resolve(); }
    close()  { return Promise.resolve(); }
    decodeAudioData(b, ok) { if (ok) ok({ duration: 0 }); return Promise.resolve({ duration: 0 }); }
    startRendering() { return Promise.resolve({ getChannelData() { return new Float32Array(4096); } }); }
  };
  w.webkitAudioContext = w.AudioContext;
  w.OfflineAudioContext = class OfflineAudioContext extends w.AudioContext {
    constructor() { super(); }
  };

  // performance.timing (bvsd reads navigationStart, etc.)
  if (!w.performance || !w.performance.timing) {
    const now = Date.now();
    const pt = { navigationStart: now - 3000, domLoading: now - 2800, domContentLoadedEventEnd: now - 500, loadEventEnd: now - 200 };
    try { Object.defineProperty(w, "performance", { value: { timing: pt, now: () => Date.now() - now, getEntriesByType: () => [], mark() {}, measure() {} }, configurable: true }); } catch {}
  }

  // Touch API stub (bvsd detects Android touch support)
  w.TouchEvent = w.TouchEvent || class TouchEvent extends (w.Event || Error) { constructor(t, i) { super(t, i); } };
  w.Touch      = w.Touch      || class Touch      { constructor(i) { Object.assign(this, i); } };
  w.TouchList  = w.TouchList  || class TouchList  { constructor(...items) { this._items = items; this.length = items.length; } item(i) { return this._items[i]; } };

  // ---- Replace jsdom XMLHttpRequest with a Node-fetch proxy --------------
  // The ncaptcha real SDK does POST https://ncpt.naver.com/v2/tokens via
  // XMLHttpRequest. Jsdom blocks that cross-origin call (CORS preflight)
  // so the SDK silently returns a stub token, and Naver later refuses to
  // dispatch SMS. We route XHRs through Node's fetch + the shared cookie jar.
  const _xhrLog = [];
  w.__xhrLog = _xhrLog;
  class ProxyXHR {
    constructor() {
      this.readyState = 0;
      this.status = 0;
      this.responseText = "";
      this.response = "";
      this.responseURL = "";
      this._headers = {};
      this.withCredentials = false;
      this.timeout = 0;
      this.onreadystatechange = null;
      this.onload = null;
      this.onerror = null;
      this.onabort = null;
      this.ontimeout = null;
      this.upload = { addEventListener() {}, removeEventListener() {} };
    }
    open(method, url, async) {
      this._method = method;
      this._url = url.startsWith("http") ? url : NAVER_HOST + url;
      this.responseURL = this._url;
      this.readyState = 1;
    }
    setRequestHeader(k, v) { this._headers[k] = v; }
    getResponseHeader(k) { return this._respHeaders?.[k.toLowerCase()] || null; }
    getAllResponseHeaders() {
      return Object.entries(this._respHeaders || {})
        .map(([k, v]) => `${k}: ${v}`).join("\r\n");
    }
    abort() { this.readyState = 0; if (this.onabort) try { this.onabort(); } catch {} }
    send(body) {
      const url = this._url;
      _xhrLog.push({ method: this._method, url, body: typeof body === "string" ? body.slice(0, 200) : "(non-string)" });
      // CRITICAL anti-bot fix: in real Naver Android WebView the ncaptcha SDK
      // fires /client-logger/accessLog ~600ms AFTER sendAuthno (post-token-success
      // logging). In jsdom the SDK callbacks run synchronously so accessLog gets
      // sent BEFORE sendAuthno — a clear bot signature. Delay logger calls 2.5s
      // so they land naturally after the actual SMS-trigger request.
      // Reference tool fires accessLog immediately after token, BEFORE
      // sendAuthno — no artificial delay needed.
      const sendDelay = 0;
      const doFetch = async () => {
        try {
          let cookieHeader = await jar.getCookieString(url);
          // Real Naver Android WebView headers for ncpt.naver.com calls.
          // Critical: x-requested-with MUST be the app package id (not
          // XMLHttpRequest) for ncpt cross-origin posts, otherwise the SDK
          // token is rejected and SMS dispatch is silently dropped downstream.
          const isNcpt = /\/\/ncpt\.naver\.com\//.test(url);
          // Send the FULL cookie jar to ncpt.naver.com (DA_DD, BMR, NNB,
          // SRT30, SRT5, m_loc, NID_JST). The reference tool that successfully
          // triggers SMS sends every nid.naver.com cookie to ncpt — filtering
          // them down (which earlier HAR snapshots seemed to suggest) is what
          // was causing Naver to silently drop the SMS dispatch.
          const headers = {
            "User-Agent": NAVER_UA,
            "Accept": "*/*",
            "Accept-Language": SESSION_LANG.accept,
            "Accept-Encoding": "gzip, deflate, br, zstd",
            Origin: NAVER_HOST,
            Referer: beginUrl,
            "sec-ch-ua": SEC_CH_UA,
            "sec-ch-ua-mobile": "?1",
            "sec-ch-ua-platform": '"Android"',
            "sec-fetch-site": isNcpt ? "same-site" : "same-origin",
            "sec-fetch-mode": "cors",
            "sec-fetch-dest": "empty",
            "x-requested-with": isNcpt ? "com.nhn.android.search" : "XMLHttpRequest",
            priority: "u=1, i",
            ...this._headers,
            ...(cookieHeader ? { Cookie: cookieHeader } : {}),
          };
          const resp = await proxiedFetch(url, { method: this._method, headers, body });
          const text = await resp.text();
          // Persist any Set-Cookie back into the shared jar
          const setCookies = resp.headers.getSetCookie
            ? resp.headers.getSetCookie()
            : (resp.headers.raw?.()["set-cookie"] || []);
          for (const c of setCookies) {
            try { await jar.setCookie(c, url); } catch {}
          }
          // Cache headers
          this._respHeaders = {};
          for (const [k, v] of resp.headers) this._respHeaders[k.toLowerCase()] = v;
          this.status = resp.status;
          this.statusText = resp.statusText || "";
          this.responseText = text;
          this.response = text;
          this.readyState = 4;
          if (this.onreadystatechange) try { this.onreadystatechange(); } catch (e) {}
          if (this.onload) try { this.onload(); } catch (e) {}
        } catch (err) {
          this.status = 0;
          this.readyState = 4;
          if (this.onreadystatechange) try { this.onreadystatechange(); } catch {}
          if (this.onerror) try { this.onerror(err); } catch {}
        }
      };
      if (sendDelay > 0) setTimeout(() => { doFetch(); }, sendDelay);
      else doFetch();
    }
  }
  // Override on window so SDK code (`new XMLHttpRequest()`) hits our proxy
  Object.defineProperty(w, "XMLHttpRequest", { value: ProxyXHR, configurable: true, writable: true });

  // Also expose `fetch` in case any newer SDK path uses it
  w.fetch = async (url, init = {}) => {
    const finalUrl = (typeof url === "string" && !url.startsWith("http")) ? NAVER_HOST + url : url;
    const cookieHeader = await jar.getCookieString(finalUrl);
    const headers = {
      "User-Agent": NAVER_UA, Origin: NAVER_HOST, Referer: beginUrl,
      ...(init.headers || {}),
      ...(cookieHeader ? { Cookie: cookieHeader } : {}),
    };
    const resp = await proxiedFetch(finalUrl, { ...init, headers });
    const text = await resp.text();
    const setCookies = resp.headers.getSetCookie ? resp.headers.getSetCookie() : [];
    for (const c of setCookies) { try { await jar.setCookie(c, finalUrl); } catch {} }
    return {
      ok: resp.ok, status: resp.status, statusText: resp.statusText,
      headers: resp.headers, url: finalUrl,
      text: async () => text,
      json: async () => JSON.parse(text),
    };
  };

  // Suppress noisy warnings from canvas/audio APIs that bvsd/ncaptcha probe
  const origErr = w.console.error;
  w.console.error = function (...a) {
    const s = String(a[0] || "");
    if (s.includes("Not implemented") || s.includes("getContext")) return;
    return origErr.apply(this, a);
  };

  // Load SDKs in the order the real page does
  w.eval(BVSD_JS);
  w.eval(RSA_JS);
  // The SDK loader expects a specific URL query (?ncaptcha-onload=initNcaptcha&...)
  // when the script tag is parsed. Since we eval inline, we fake the loader globals.
  w.eval(NCAPTCHA_API_JS);
  // Inject the real SDK so homz.Koop is fully functional
  try {
    w.eval(NCAPTCHA_REAL_JS);
  } catch (e) {
    warn(`ncaptcha real SDK eval threw: ${e.message} (will retry lazily)`);
  }

  return dom;
}

// Simulate realistic typing so bvsd accumulates a rich event trace.
// In the real Naver Android app, bvsd records keydown/keypress/keyup timings,
// inter-key delays, input events, focus/blur, mouse events and device motion.
// Without enough events the bvsd encData is too short (~1.3k chars vs the
// ~3.0k chars seen in real HAR captures) and Naver silently drops SMS.
async function simulateTyping(dom, fieldId, text, opts = {}) {
  const w = dom.window;
  const doc = w.document;
  const el = doc.getElementById(fieldId);
  if (!el) return;

  const baseDelay = opts.delay ?? 60;   // ms between keystrokes (realistic ~60-160ms)
  const jitter = opts.jitter ?? 80;

  // Helper: fire mouse event on element
  function mouse(type, target) {
    try {
      target.dispatchEvent(new w.MouseEvent(type, {
        bubbles: true, cancelable: true,
        clientX: 120 + Math.floor(Math.random() * 40),
        clientY: 400 + Math.floor(Math.random() * 20),
      }));
    } catch {}
  }

  // Helper: dispatch a touch event (Android-specific — bvsd collects these)
  function touch(type, target) {
    try {
      const t = { identifier: 1, target, clientX: 120 + Math.floor(Math.random()*40), clientY: 400 + Math.floor(Math.random()*20), pageX: 120, pageY: 400, screenX: 240, screenY: 800, radiusX: 5, radiusY: 5, rotationAngle: 0, force: 0.5 };
      target.dispatchEvent(new w.TouchEvent(type, { bubbles: true, cancelable: true, touches: [t], changedTouches: [t], targetTouches: [t] }));
    } catch {}
  }

  // Pre-focus interaction — user taps the field (Android: touch events come first)
  touch("touchstart", el);
  touch("touchend",   el);
  mouse("mouseover", el);
  mouse("mousedown", el);
  mouse("mouseup",   el);
  mouse("click",     el);
  try { el.focus(); } catch {}
  el.dispatchEvent(new w.FocusEvent("focus", { bubbles: true }));
  el.dispatchEvent(new w.FocusEvent("focusin", { bubbles: true }));

  await sleep(baseDelay + Math.random() * jitter);

  for (let i = 0; i < text.length; i++) {
    const ch = text[i];
    const keyOpts = {
      key: ch, code: `Key${ch.toUpperCase()}`, charCode: ch.charCodeAt(0),
      keyCode: ch.charCodeAt(0), which: ch.charCodeAt(0),
      bubbles: true, cancelable: true,
    };

    el.dispatchEvent(new w.KeyboardEvent("keydown",  keyOpts));
    el.dispatchEvent(new w.KeyboardEvent("keypress", keyOpts));

    // Update value one char at a time (triggers bvsd secure-mode capture)
    el.value = (el.value || "") + ch;

    el.dispatchEvent(new w.KeyboardEvent("keyup", keyOpts));
    el.dispatchEvent(new w.InputEvent("input", {
      bubbles: true, cancelable: false,
      inputType: "insertText", data: ch,
    }));

    // Occasional mouse-move on document (bvsd collects pointer events)
    if (i % 3 === 0) {
      try {
        doc.dispatchEvent(new w.MouseEvent("mousemove", {
          bubbles: true,
          clientX: 100 + Math.floor(Math.random() * 200),
          clientY: 300 + Math.floor(Math.random() * 200),
        }));
      } catch {}
    }

    await sleep(baseDelay + Math.random() * jitter);
  }

  el.dispatchEvent(new w.Event("change", { bubbles: true }));

  // Blur sequence
  await sleep(100 + Math.random() * 100);
  el.dispatchEvent(new w.FocusEvent("blur",     { bubbles: true }));
  el.dispatchEvent(new w.FocusEvent("focusout", { bubbles: true }));
  try { el.blur(); } catch {}
}

// --------------------------------------------------------------------------
//  Parse begin page for token_sjoin + RSA pubkey + sessionKey + keyName
// --------------------------------------------------------------------------
function parseBeginPage(html) {
  const out = {};
  const tk = html.match(/name=["']token_sjoin["']\s+value=["']([^"']+)["']/);
  if (!tk) throw new Error("token_sjoin missing in begin page");
  out.token_sjoin = tk[1];

  const sk = html.match(/let\s+sessionKey\s*=\s*"([^"]+)"/);
  const kn = html.match(/let\s+keyName\s*=\s*"([^"]+)"/);
  const ev = html.match(/let\s+eValue\s*=\s*"([^"]+)"/);
  const nv = html.match(/let\s+nValue\s*=\s*"([^"]+)"/);
  if (!sk || !kn || !ev || !nv) throw new Error("RSA parameters missing in begin page");
  out.sessionKey = sk[1];
  out.keyName = kn[1];
  out.eValue = ev[1];
  out.nValue = nv[1];

  // Two ncaptcha siteKeys (sendAuthno, mainSubmit)
  const sites = [...html.matchAll(/siteKey:\s*"([0-9a-f]{60,})"/g)].map((m) => m[1]);
  // The bvsd siteKey from the script tag used for ncaptcha-api.js include
  const bvsdSite = html.match(/ncaptcha-sitekey=([0-9a-f]{60,})/);
  out.siteKey1 = bvsdSite ? bvsdSite[1] : sites[0];
  out.siteKey2 = sites[sites.length - 1];

  return out;
}

// --------------------------------------------------------------------------
//  Sandbox helpers — generate the three crypto payloads
// --------------------------------------------------------------------------
async function initBvsd(dom) {
  dom.window.eval(`
    window.__bvsd = new sofa.Koop({
      keyboard: [
        {id:"id"},
        {id:"pswd1",  secureMode:true},
        {id:"phoneNo", secureMode:true}
      ],
      modeProperties: { mode: 4 }
    });
  `);
  // Give bvsd time to spin up fingerprint collection.
  // 5 s mirrors the time the real Naver app spends on the begin page
  // before the user starts typing — bvsd uses this idle time to sample
  // device orientation, screen metrics and other passive signals.
  await sleep(5000);
}

async function initNcaptcha(dom, siteKey1, siteKey2) {
  // CRITICAL: window.homz.Koop is the STUB loader (1.8.1_Stub) — not functional.
  // The REAL SDK is exposed as window.nhomz.Koop (1.8.0-js) by real_sdk.js.
  // We must call the real one, with the minimal siteKey-only config that the
  // SDK actually accepts (keyboard / modeProperties make it crash silently).
  //
  // Two separate Koop instances:
  //   __ncap1  ← siteKey1 → used for sendAuthno (SMS step)
  //   __ncap2  ← siteKey2 → used for join/end   (final submit)
  // Using the wrong siteKey causes Naver to silently drop the SMS even though
  // it returns NNNNS, because the ncaptcha token is bound to a specific action.
  const Koop =
    (dom.window.nhomz && dom.window.nhomz.Koop) ||
    (dom.window.homz && dom.window.homz.Koop);
  if (typeof Koop !== "function") {
    warn("nhomz.Koop not exposed — falling back to placeholder nid_kb3");
    return false;
  }
  try {
    dom.window.__KoopReal = Koop;
    // Instance 1 — siteKey1 (sendAuthno)
    dom.window.eval(`window.__ncap1 = new window.__KoopReal({ siteKey: "${siteKey1}" });`);
    await sleep(400);
    // Instance 2 — siteKey2 (join/end)
    dom.window.eval(`window.__ncap2 = new window.__KoopReal({ siteKey: "${siteKey2}" });`);
    await sleep(400);
    return true;
  } catch (e) {
    warn(`ncaptcha2 init failed: ${e.message}`);
    return false;
  }
}

function generateNidKb2(dom, timeoutMs = 5000) {
  return new Promise((resolve, reject) => {
    let done = false;
    const t = setTimeout(() => {
      if (!done) reject(new Error("nid_kb2 generation timeout"));
    }, timeoutMs);
    dom.window.__cb_kb2 = (v) => {
      if (done) return;
      done = true;
      clearTimeout(t);
      // bvsd generates the same UUID every run because jsdom fingerprint is fixed.
      // Replace with a fresh random UUID so Naver sees a different device each time.
      try {
        const obj = JSON.parse(v);
        const suffix = (obj.uuid || "").split("-").slice(-1)[0]; // preserve -0/-1 counter
        obj.uuid = uuidV4() + "-" + (suffix || "0");
        resolve(JSON.stringify(obj));
      } catch {
        resolve(v); // fallback: return as-is
      }
    };
    try {
      dom.window.eval(`window.__bvsd.f(window.__cb_kb2);`);
    } catch (e) {
      clearTimeout(t);
      reject(e);
    }
  });
}

// instance: "__ncap1" (siteKey1, sendAuthno) or "__ncap2" (siteKey2, join/end)
function generateNidKb3(dom, timeoutMs = 8000, instance = "__ncap1") {
  return new Promise((resolve) => {
    let done = false;
    // Log XHRs that happen DURING this call specifically
    const xhrsBefore = (dom.window.__xhrLog || []).length;
    const t = setTimeout(() => {
      if (!done) {
        done = true;
        const newXhrs = (dom.window.__xhrLog || []).slice(xhrsBefore);
        warn(`nid_kb3 timeout after ${timeoutMs}ms (${instance}) — XHRs: ${newXhrs.length}`);
        newXhrs.forEach(x => warn(`   XHR: ${x.method} ${x.url}`));
        resolve("");
      }
    }, timeoutMs);
    if (!dom.window[instance]) {
      clearTimeout(t);
      warn(`nid_kb3: ${instance} not initialized — skipping`);
      return resolve("");
    }
    const cbName = `__cb_kb3_${instance}`;
    dom.window[cbName] = (v) => {
      if (done) return;
      done = true;
      clearTimeout(t);
      const newXhrs = (dom.window.__xhrLog || []).slice(xhrsBefore);
      info(`nid_kb3 [${instance}] generated (${(v||"").length} chars); XHRs: ${newXhrs.length}`);
      newXhrs.forEach(x => info(`   → ${x.method} ${x.url}`));
      resolve(v);
    };
    try {
      dom.window.eval(`window["${instance}"].f(window["${cbName}"]);`);
    } catch (e) {
      clearTimeout(t);
      warn(`nid_kb3 [${instance}] threw: ${e.message}`);
      resolve("");
    }
  });
}

// ── Direct HTTP helpers for nid_kb3 / ncpt side-channel — identical to ref ──
// These bypass the jsdom/SDK route (which works but adds latency & jsdom noise)
// and call ncpt.naver.com directly with the same payload the real SDK sends.
// nid_kb2 still goes through the bvsd jsdom SDK (user requirement).

const NCPT_SITEKEY =
  "7750d1c2936995e9d1c0a3948f1414b2eb5f99fb96c04f48dec3ccb48fd08ae2" +
  "1b79353fa6d161fd5bf4e628";

function generateCipherText() {
  const raw = require("crypto").randomBytes(800 + Math.floor(Math.random() * 400));
  const b64 = raw.toString("base64url");
  const splitAt = Math.floor(b64.length * 0.55);
  return b64.substring(0, splitAt) + "==" + b64.substring(splitAt);
}

async function fetchNcptTokenDirect(refererUrl, siteKey) {
  // PATCHED v2.4: replaced native https.request with proxiedFetch so this
  // call to ncpt.naver.com is guaranteed to exit through the residential
  // proxy IP (previously this was the single biggest IP-leak in the tool).
  const sk    = siteKey || NCPT_SITEKEY;
  const traceId = "si" + require("crypto").randomBytes(5).toString("hex");
  const q = String(Date.now());
  const cipherText = generateCipherText();
  const payload = JSON.stringify({ cipherText, siteKey: sk, t: "0|0|0|0|0" });
  const url = `https://ncpt.naver.com/v2/tokens?q=${q}&tid=${traceId}`;

  let body;
  try {
    const resp = await proxiedFetch(url, {
      method: "POST",
      headers: {
        "user-agent": NAVER_UA,
        "accept": "*/*",
        "accept-language": SESSION_LANG.accept,
        "accept-encoding": "gzip, deflate, br, zstd",
        "content-type": "text/plain",
        "origin": "https://nid.naver.com",
        "referer": refererUrl || "https://nid.naver.com/",
        "x-requested-with": "com.nhn.android.search",
        "sec-ch-ua": SEC_CH_UA,
        "sec-ch-ua-mobile": "?1",
        "sec-ch-ua-platform": '"Android"',
        "sec-fetch-site": "same-site",
        "sec-fetch-mode": "cors",
        "sec-fetch-dest": "empty",
      },
      body: payload,
    });
    // undici auto-decompresses gzip/br/deflate — no manual zlib needed.
    body = await resp.text();
  } catch (e) {
    throw new Error(`ncpt v2/tokens fetch failed: ${e.message}`);
  }

  let tokenId;
  try {
    const parsed = JSON.parse(body);
    const raw = parsed.tokenId || parsed._0xr1;
    if (raw && typeof raw === "string" && raw.length > 10) {
      // normalizeTokenId — decode base64 → if hex64 → re-encode as base64url
      try {
        const dec = Buffer.from(raw, "base64").toString("ascii");
        if (/^[0-9a-f]{64}$/i.test(dec)) {
          tokenId = Buffer.from(dec, "hex").toString("base64url") + "=";
        }
      } catch {}
      if (!tokenId) tokenId = raw;
    }
  } catch {}
  if (!tokenId) throw new Error(`ncpt v2/tokens returned no tokenId: ${body.slice(0, 200)}`);

  info(`nid_kb3 direct: ${tokenId.slice(0, 20)}... (traceId=${traceId})`);
  // Fire accessLog right away (same as ref — getFreshToken returns only tokenId,
  // accessLog is called separately in sendAuthno/joinEnd)
  return { tokenId, traceId, q };
}

async function callNcptAccessLogDirect(refererUrl, cookieStr) {
  const https = require("https");
  const traceId = Math.random().toString(36).slice(2, 12);
  const now     = Date.now();
  const fpDur   = 900 + Math.floor(Math.random() * 400);
  const hashDur = 1   + Math.floor(Math.random() * 5);
  const compDur = 20  + Math.floor(Math.random() * 20);
  const encDur  = 25  + Math.floor(Math.random() * 15);
  const feDur   = 80  + Math.floor(Math.random() * 60);
  const netDur  = 280 + Math.floor(Math.random() * 200);

  const msg = JSON.stringify({
    version: "1.8.0-wasm",
    accessCode: "acs-001",
    message: `requestUrl: https://ncpt.naver.com/v2/tokens?q=${now}&tid=${traceId} - fpDuration: ${fpDur}ms - hashing: ${hashDur}ms - compression: ${compDur}ms - encryption: ${encDur}ms - feProcessTime: ${feDur}ms - networkDuration: ${netDur}ms | TraceID: ${traceId}`,
  });
  const payload = JSON.stringify({ message: msg, version: "1.8.0" });
  return _ncptPost("/client-logger/accessLog", payload, refererUrl, cookieStr, "u=4, i");
}

async function callNcptErrorLogDirect(refererUrl, cookieStr) {
  const timeout = 500 + Math.floor(Math.random() * 200);
  const payload = JSON.stringify({
    message: JSON.stringify({
      version: "1.8.0_Stub",
      error: {
        code: "err-999",
        message: `f: executionTimeout {"executionTimeout":${timeout},"requestTimeout":10000,"issueTokenTimeout":10000,"timeout":10000,"fingerprintTimeout":4000,"bfTimeout":4000}`,
        name: "err-999",
      },
    }),
    version: "1.8.0",
  });
  return _ncptPost("/client-logger/errorLog", payload, refererUrl, cookieStr, "u=4, i");
}

async function callNcptEtkDirect(refererUrl, cookieStr) {
  const now     = Math.floor(Date.now() / 1000);
  const hash88  = require("crypto").randomBytes(44).toString("hex");
  const shortId = require("crypto").randomBytes(4).toString("hex");
  const payload = JSON.stringify({ _0x1a: "err-999", _0x2b: hash88, _0x5t: now, _0x4c: shortId });
  return _ncptPost("/static/etk", payload, refererUrl, cookieStr, "u=1, i");
}

async function callNcptJoinSignalsDirect(refererUrl, cookieStr) {
  await Promise.allSettled([
    callNcptErrorLogDirect(refererUrl, cookieStr),
    callNcptEtkDirect(refererUrl, cookieStr),
  ]);
  info("ncpt joinSignals (errorLog + etk) fired");
}

async function _ncptPost(path, payloadStr, refererUrl, cookieStr, priority) {
  // PATCHED v2.4: replaced native https.request with proxiedFetch so all
  // logger/etk calls to ncpt.naver.com also go through the residential
  // proxy. Naver's anti-bot correlates the IP of these calls with the IP
  // of nid.naver.com calls — any mismatch silently drops SMS dispatch.
  const url = `https://ncpt.naver.com${path}`;
  const hdrs = {
    "user-agent": NAVER_UA,
    "accept": "*/*",
    "accept-language": SESSION_LANG.accept,
    "accept-encoding": "gzip, deflate, br, zstd",
    "content-type": "application/json",
    "origin": "https://nid.naver.com",
    "x-requested-with": "com.nhn.android.search",
    "sec-ch-ua": SEC_CH_UA,
    "sec-ch-ua-mobile": "?1",
    "sec-ch-ua-platform": '"Android"',
    "sec-fetch-site": "same-site",
    "sec-fetch-mode": "cors",
    "sec-fetch-dest": "empty",
  };
  if (refererUrl) hdrs["referer"]  = refererUrl;
  if (cookieStr)  hdrs["cookie"]   = cookieStr;
  if (priority)   hdrs["priority"] = priority;
  // 8 s soft timeout — same as the original native impl.
  const ctl = new AbortController();
  const t = setTimeout(() => ctl.abort(), 8000);
  try {
    const resp = await proxiedFetch(url, {
      method: "POST",
      headers: hdrs,
      body: payloadStr,
      signal: ctl.signal,
    });
    // Drain the body to free the socket back to the pool.
    try { await resp.arrayBuffer(); } catch {}
    return resp.status;
  } catch {
    return null;
  } finally {
    clearTimeout(t);
  }
}

// Simulate continuous user activity for `durationMs` milliseconds.
// Real users spend ~30s on the phone-number section; bvsd collects mouse moves,
// scroll events, focus/blur and timing data during that window.  Without this
// the encData is ~2 350 chars instead of the ~3 000 chars seen in real HAR captures.
async function simulateFormActivity(dom, durationMs = 30000) {
  const w = dom.window;
  const doc = w.document;
  const deadline = Date.now() + durationMs;
  const fields = ["phoneNo", "name", "email", "birthdayInput", "id"].map(id => doc.getElementById(id)).filter(Boolean);
  let tick = 0;
  info(`simulateFormActivity: warming bvsd for ${(durationMs / 1000).toFixed(0)}s…`);
  while (Date.now() < deadline) {
    tick++;
    const x = 80 + Math.floor(Math.random() * 220);
    const y = 200 + Math.floor(Math.random() * 400);
    // Mouse move on document
    try {
      doc.dispatchEvent(new w.MouseEvent("mousemove", { bubbles: true, cancelable: true, clientX: x, clientY: y }));
    } catch {}
    // Touch move (Android users touch the screen)
    if (tick % 3 === 0) {
      try {
        const t = { identifier: 1, target: doc.body, clientX: x, clientY: y, pageX: x, pageY: y, screenX: x * 2, screenY: y * 2, radiusX: 5, radiusY: 5, rotationAngle: 0, force: 0.4 };
        doc.dispatchEvent(new w.TouchEvent("touchmove", { bubbles: true, cancelable: true, touches: [t], changedTouches: [t], targetTouches: [t] }));
      } catch {}
    }
    // Scroll (user scrolls the form)
    if (tick % 5 === 0) {
      try {
        w.dispatchEvent(new w.Event("scroll", { bubbles: true }));
        doc.body.scrollTop = 200 + Math.floor(Math.random() * 100);
      } catch {}
    }
    // Focus / blur cycle on a random field
    if (tick % 8 === 0 && fields.length) {
      const el = fields[tick % fields.length];
      try { el.dispatchEvent(new w.FocusEvent("focus", { bubbles: true })); } catch {}
      await new Promise(r => setTimeout(r, 80 + Math.random() * 60));
      try { el.dispatchEvent(new w.FocusEvent("blur", { bubbles: true })); } catch {}
    }
    await new Promise(r => setTimeout(r, 180 + Math.floor(Math.random() * 120)));
  }
  info(`simulateFormActivity done (${tick} ticks)`);
}

function encryptPassword(dom, sessionKey, keyName, eValue, nValue, id, pw) {
  return dom.window.eval(`
    (function(){
      var rsa = new RSAKey();
      rsa.setPublic(${JSON.stringify(eValue)}, ${JSON.stringify(nValue)});
      function L(s){ return String.fromCharCode(s.length); }
      var sk = ${JSON.stringify(sessionKey)};
      var id = ${JSON.stringify(id)};
      var pw = ${JSON.stringify(pw)};
      var comVal = L(sk)+sk+L(id)+id;
      return rsa.encrypt(comVal + L(pw) + pw);
    })();
  `);
}

// --------------------------------------------------------------------------
//  Seed Naver cookies — DA_DD + BMR + POST nlog.naver.com for NNB/SRT
//  Matches the real Android app's pre-registration cookie state (HAR analysis).
//  Without this, nid.naver.com joinAjax endpoints see an empty cookie jar and
//  silently suppress SMS dispatch even though they return NNNNS.
// --------------------------------------------------------------------------
function uuidV4() {
  const b = webcrypto.getRandomValues(new Uint8Array(16));
  b[6] = (b[6] & 0x0f) | 0x40;
  b[8] = (b[8] & 0x3f) | 0x80;
  const h = Array.from(b).map((x) => x.toString(16).padStart(2, "0")).join("");
  return `${h.slice(0,8)}-${h.slice(8,12)}-${h.slice(12,16)}-${h.slice(16,20)}-${h.slice(20)}`;
}

async function setCookieOnNaver(name, value, domain = ".naver.com") {
  const expires = "Sat, 01 Jan 2050 09:00:00 GMT";
  const cookieStr = `${name}=${value}; expires=${expires}; path=/; domain=${domain}; SameSite=None; Secure`;
  // Set on all naver subdomains we'll be hitting
  for (const origin of [
    "https://nid.naver.com",
    "https://nlog.naver.com",
    "https://ncpt.naver.com",
  ]) {
    try { await jar.setCookie(cookieStr, origin); } catch { /* ignore */ }
  }
}

async function seedNaverCookies() {
  // 0 — m_loc (empty, always present in HAR for all nid.naver.com requests)
  await setCookieOnNaver("m_loc", "");

  // 1 — Device ID (persistent per physical device in real app; we generate once per run).
  //     Format is lowercase UUID v4. Real value: a593e830-df67-4e93-a975-315919bdea15
  const DA_DD = uuidV4();
  await setCookieOnNaver("DA_DD", DA_DD);
  info(`DA_DD seeded: ${DA_DD}`);

  // 2 — Bounce Measurement Record (BMR).
  //     Real format: s=<unix_ms>&r=http%3A%2F%2Fmain%2F%3FpCode%3DTODAY%26cCode%3DENT&r2=
  const bmrTs = Date.now() - Math.floor(Math.random() * 60000 + 30000); // ~30-90s ago (realistic)
  const BMR = `s=${bmrTs}&r=http%3A%2F%2Fmain%2F%3FpCode%3DTODAY%26cCode%3DENT&r2=`;
  await setCookieOnNaver("BMR", BMR);
  info(`BMR seeded: s=${bmrTs}`);

  // 3 — NNB: persistent device cookie — set by lcs.naver.com in real HAR (expires 2050),
  //     NOT from nlog.naver.com (which would mark it as a new/bot session).
  //     HAR analysis: NNB always comes from lcs.naver.com/m?u=client://naver.android
  try {
    const ni = require("crypto").randomBytes(8).toString("hex");
    const lcsResp = await proxiedFetch(
      `https://lcs.naver.com/m?u=client%3A%2F%2Fnaver.android&ni=${ni}`,
      {
        headers: {
          "User-Agent": NAVER_UA,
          Accept: "*/*",
          "Accept-Language": SESSION_LANG.accept,
          "Accept-Encoding": "gzip, deflate, br, zstd",
          "x-requested-with": "com.nhn.android.search",
        },
      }
    );
    const lcsCooki = lcsResp.headers.getSetCookie ? lcsResp.headers.getSetCookie() : [];
    for (const c of lcsCooki) {
      for (const origin of ["https://nid.naver.com", "https://nlog.naver.com", "https://ncpt.naver.com", "https://lcs.naver.com"]) {
        try { await jar.setCookie(c, origin); } catch {}
      }
    }
    const nnb = lcsCooki.find(c => c.startsWith("NNB="))?.match(/NNB=([^;]+)/)?.[1] || "";
    if (nnb) ok(`NNB seeded from lcs.naver.com: ${nnb} (expires 2050)`);
    else warn("lcs.naver.com did not return NNB — using fallback");
    // Also seed SRT30/SRT5 (timing cookies) from nlog — without a prior pageview event
    const srtTs = Math.floor(Date.now() / 1000) - Math.floor(Math.random() * 120 + 60);
    await setCookieOnNaver("SRT30", String(srtTs));
    await setCookieOnNaver("SRT5",  String(srtTs + Math.floor(Math.random() * 300 + 600)));
    info(`SRT30/SRT5 seeded locally: ${srtTs}`);
  } catch (e) {
    warn(`lcs seed failed (non-fatal): ${e.message}`);
  }

  // 4 — NID_JST: Naver session token, set by nid.naver.com/nidlogin.login.
  //     CRITICAL for Romania (HAR1 has NID_JST; HAR2/Indonesia works without it but Romania needs it).
  //     A simple GET to /nidlogin.login sets it without any credentials.
  try {
    const loginResp = await proxiedFetch(`${NAVER_HOST}/nidlogin.login`, {
      method: "GET",
      headers: {
        "User-Agent": NAVER_UA,
        Accept: "text/html,application/xhtml+xml,*/*",
        "Accept-Language": SESSION_LANG.accept,
        "Accept-Encoding": "gzip, deflate, br, zstd",
        "sec-ch-ua": SEC_CH_UA,
        "sec-ch-ua-mobile": "?1",
        "sec-ch-ua-platform": '"Android"',
        "sec-fetch-site": "none",
        "sec-fetch-mode": "navigate",
        "sec-fetch-dest": "document",
        "Upgrade-Insecure-Requests": "1",
      },
      redirect: "manual",
    });
    const nidjstCookies = loginResp.headers.getSetCookie ? loginResp.headers.getSetCookie() : [];
    for (const c of nidjstCookies) {
      for (const origin of ["https://nid.naver.com", "https://nlog.naver.com", "https://ncpt.naver.com"]) {
        try { await jar.setCookie(c, origin); } catch {}
      }
    }
    const nidjst = nidjstCookies.find(c => c.startsWith("NID_JST="))?.match(/NID_JST=([^;]+)/)?.[1] || "";
    if (nidjst) ok(`NID_JST seeded from nidlogin.login (len=${nidjst.length})`);
    else warn(`nidlogin.login returned no NID_JST — cookies: ${nidjstCookies.map(c=>c.split("=")[0]).join(", ") || "none"}`);
  } catch (e) {
    warn(`NID_JST seed failed (non-fatal): ${e.message}`);
  }

}

// Post the click-event nlog that the real Naver Android app fires
// exactly 2 seconds before sendAuthno — click_area "input.sendFrgn".
// HAR shows: nlog POST → v2/tokens → sendAuthno (gap ~2s each).
// Without this, Naver may silently skip the SMS dispatch.
async function postNlogClickEvent(tokenSjoin, clickArea = "input.sendFrgn") {
  const evtTs = Date.now();
  const pageUrl =
    `${NAVER_HOST}/user2/join/begin?token_sjoin=${tokenSjoin}` +
    `&langSelect=en_US&checkRealname=&termsLocation=Y&termsEmail=Y`;
  // Per-field realistic click coordinates (relative to the form layout)
  const FIELD_COORDS = {
    "input#id":         { x: 200, y: 240 },
    "input#password":   { x: 200, y: 320 },
    "input#name":       { x: 200, y: 400 },
    "input#birthYear":  { x: 200, y: 480 },
    "select#gender":    { x: 200, y: 560 },
    "input#phoneNo":    { x: 200, y: 620 },
    "input.sendFrgn":   { x: 95,  y: 640 },
    "input#authNo":     { x: 200, y: 700 },
  };
  const base = FIELD_COORDS[clickArea] || { x: 95, y: 640 };
  const px = base.x + Math.floor(Math.random() * 20);
  const py = base.y + Math.floor(Math.random() * 30);
  const body = JSON.stringify({
    corp: "naver",
    svc: "nid",
    location: "korea_real/korea",
    svc_tags: {},
    send_ts: evtTs,
    tool: { name: "ntm-web", ver: "nlogLibVersion=v0.1.61; verName=v1.1; ntmVersion=v1.4.3" },
    usr: {},
    env: {
      os: SESSION_DEV.platform === "Linux armv7l" ? "Linux armv7l" : "Linux armv8l",
      br_ln: SESSION_LANG.code,
      br_sr: `${SESSION_DEV.w}x${SESSION_DEV.bh}`,
      device_sr: `${SESSION_DEV.w}x${SESSION_DEV.dh}`,
      platform_type: "web",
      device_pr: String(SESSION_DEV.pr),
      timezone: SESSION_TZ,
      ch_pltf: "Android",
      ch_mob: true,
      ch_mdl: SESSION_DEV.model,
      ch_arch: "",
      ch_pltfv: SESSION_DEV.androidVer,
      ch_brs: [
        { brand: "Chromium",        version: SESSION_CHR.major },
        { brand: "Not-A.Brand",     version: "24" },
        { brand: "Android WebView", version: SESSION_CHR.major },
      ],
      ch_bit: "",
      ch_ffs: ["Mobile"],
      ch_wow64: false,
      ch_fvls: [
        { brand: "Chromium",        version: SESSION_CHR.full },
        { brand: "Not-A.Brand",     version: "24.0.0.0" },
        { brand: "Android WebView", version: SESSION_CHR.full },
      ],
    },
    evts: [{
      click_targeturl: "about:blank",
      click_px: px,
      click_py: py,
      click_sx: px,
      click_sy: py - 20,
      click_sz_w: SESSION_DEV.w,
      click_sz_h: SESSION_DEV.bh,
      page_url: pageUrl,
      page_ref: "",
      click_area: clickArea,
      type: "click",
      click_nsc: "nid.join",
      evt_ts: evtTs - Math.floor(Math.random() * 80 + 20),
      nlog_id: uuidV4(),
    }],
  });

  const nlogUrl = "https://nlog.naver.com/n";
  // Send the full cookie jar — matches the reference tool that successfully
  // triggers SMS dispatch.
  const nlogCookies = await jar.getCookieString(nlogUrl);
  try {
    const resp = await proxiedFetch(nlogUrl, {
      method: "POST",
      headers: {
        "User-Agent": NAVER_UA,
        "Content-Type": "text/plain",
        Accept: "*/*",
        "Accept-Language": SESSION_LANG.accept,
        "Accept-Encoding": "gzip, deflate, br, zstd",
        Origin: NAVER_HOST,
        Referer: pageUrl,
        "x-requested-with": "com.nhn.android.search",
        "sec-ch-ua": SEC_CH_UA,
        "sec-ch-ua-mobile": "?1",
        "sec-ch-ua-platform": '"Android"',
        "sec-fetch-site": "same-site",
        "sec-fetch-mode": "no-cors",
        "sec-fetch-dest": "empty",
        priority: "u=4, i",
        ...(nlogCookies ? { Cookie: nlogCookies } : {}),
      },
      body,
    });
    info(`nlog click event: HTTP ${resp.status} (cookies: ${nlogCookies.split(";").map(c=>c.trim().split("=")[0]).join("+") || "none"})`);
  } catch (e) {
    warn(`nlog click event failed (non-fatal): ${e.message}`);
  }
}

// --------------------------------------------------------------------------
//  IMAP/SMTP activation on freshly created account
//  Re-uses the global `jar` (already authenticated post-registration via
//  NID_AUT/NID_SES set by /user2/join/end). Mirrors the exact 2-step flow
//  captured in HAR ProxyPin4-24:
//    1. GET  https://mail.naver.com/v2/settings/smtp/imap   (seeds NAC/NACT)
//    2. POST https://mail.naver.com/json/option/imap/set/   (Result: OK)
// --------------------------------------------------------------------------
// Helper — describes a "fetch failed" error from undici with its real cause
// (DNS, ECONNREFUSED, ECONNRESET, TLS handshake, proxy 502, etc.) so the
// log shows WHY the connection died, not just the generic message.
function describeFetchError(e) {
  const parts = [e.message || String(e)];
  let c = e.cause;
  while (c) {
    if (c.code) parts.push(`code=${c.code}`);
    if (c.errno) parts.push(`errno=${c.errno}`);
    if (c.syscall) parts.push(`syscall=${c.syscall}`);
    if (c.message && c.message !== e.message) parts.push(c.message);
    c = c.cause;
  }
  return parts.join(" | ");
}

// Helper — wraps naverFetch with retries + exponential backoff for transient
// network errors. The residential proxy may have closed the keep-alive socket
// after registration finished, so the very first mail.naver.com request can
// hit ECONNRESET / "fetch failed" — a single retry almost always recovers.
async function naverFetchRetry(url, opts, label, maxAttempts = 4) {
  let lastErr;
  for (let attempt = 1; attempt <= maxAttempts; attempt++) {
    try {
      return await naverFetch(url, opts);
    } catch (e) {
      lastErr = e;
      const detail = describeFetchError(e);
      warn(`${label} attempt ${attempt}/${maxAttempts} failed: ${detail}`);
      if (attempt < maxAttempts) {
        const wait = 1500 * attempt + Math.floor(Math.random() * 800);
        info(`  …retrying in ${wait}ms`);
        await sleep(wait);
      }
    }
  }
  throw lastErr;
}

// Detects errors that mean "the proxy itself refuses to tunnel to this host"
// (residential proxies often blacklist mail.naver.com / IMAP / SMTP domains).
// In that case there's no point retrying through proxy — switch to direct IP.
function isProxyBlockingError(e) {
  const msg = describeFetchError(e);
  return /Proxy response \(\d+\)|UND_ERR_ABORTED|ECONNREFUSED|EHOSTUNREACH/.test(msg);
}

// Smart fetch for the IMAP step: tries the proxy first (so users whose proxy
// allows mail.naver.com keep a clean single-IP session), and on a clear
// proxy-block error transparently falls back to a direct (no-proxy) dispatcher
// so IMAP activation still completes from the server's real IP.
async function imapFetch(url, opts, label, directAgent, allowDirectFallback) {
  // 1) Try via the global (proxy) dispatcher — short retry budget so we don't
  //    burn 4 attempts when the proxy is hard-blocking the host.
  if (_proxyDispatcher) {
    try {
      return await naverFetchRetry(url, opts, label + " (via proxy)", 2);
    } catch (e) {
      if (!allowDirectFallback || !directAgent) throw e;
      if (!isProxyBlockingError(e)) throw e;
      warn(`Proxy is refusing mail.naver.com — falling back to direct IP for IMAP`);
    }
  }
  // 2) Fall back (or go straight) to direct dispatcher with full retry budget.
  return await naverFetchRetry(
    url,
    { ...opts, dispatcher: directAgent },
    label + " (direct IP)",
    4,
  );
}

// Dump every cookie currently in the jar, grouped by host. Used for diagnosing
// session-state issues across naver.com subdomains (mail.naver.com, etc.).
async function dumpJarCookies(label) {
  const hosts = [
    "https://nid.naver.com",
    "https://www.naver.com",
    "https://naver.com",
    "https://mail.naver.com",
  ];
  info(`[cookie-dump @ ${label}]`);
  for (const h of hosts) {
    const ck = await jar.getCookieString(h);
    const names = ck ? ck.split(";").map(c => c.trim().split("=")[0]).join(", ") : "(none)";
    info(`  ${h.padEnd(28)} → ${names}`);
  }
}

// ===========================================================================
//  xAuth Mobile Login (Naver Android app endpoint)
//  ---------------------------------------------------------------------------
//  After /user2/join/end the WEB session is NOT authenticated (no NID_AUT).
//  Instead of trying to POST /nidlogin.login (CAPTCHA-prone for fresh accounts)
//  we use the MOBILE app xAuth endpoint /naver.oauth which:
//    • returns NID_AUT + NID_SES directly in Set-Cookie
//    • is much more tolerant of brand-new accounts (no CAPTCHA wall)
//    • requires OAuth 1.0 HMAC-SHA1 signing with the APK consumer key/secret
//
//  All HTTP calls below go through proxiedFetch → same proxy as registration.
//  Reverse-engineered from the official Naver Android app.
// ===========================================================================

// OAuth consumer credentials extracted from the Naver Android APK
const XAUTH_CONSUMER_KEY    = "kqbJYsj035JR";
const XAUTH_CONSUMER_SECRET = "4EE81426ewcSpNzbjul1";
const XAUTH_RSA_KEYS_URL    = "https://nid.naver.com/login/ext/keys2.nhn";
const XAUTH_URL             = "https://nid.naver.com/naver.oauth";

// Real Android device fingerprints per locale (matches what real users send)
const XAUTH_DEVICE_PROFILES = {
  en_US: { model: "SM-S901B",   os: "Android12", appVer: "9.3.1(90301,uid:10306)", loginMod: "6.6.0" },
  en_GB: { model: "SM-A525F",   os: "Android11", appVer: "9.1.8(90108,uid:10306)", loginMod: "6.6.0" },
  ko_KR: { model: "SM-G996B",   os: "Android12", appVer: "9.3.0(90300,uid:10306)", loginMod: "6.6.0" },
  ja_JP: { model: "SO-52B",     os: "Android11", appVer: "9.0.6(90006,uid:10306)", loginMod: "6.6.0" },
  vi_VN: { model: "M2101K9G",   os: "Android11", appVer: "9.0.6(90006,uid:10306)", loginMod: "6.6.0" },
  id_ID: { model: "M2012K11AG", os: "Android11", appVer: "9.0.6(90006,uid:10306)", loginMod: "6.6.0" },
  th_TH: { model: "M2101K9G",   os: "Android11", appVer: "9.0.6(90006,uid:10306)", loginMod: "6.6.0" },
  zh_CN: { model: "M2012K11AG", os: "Android11", appVer: "9.0.6(90006,uid:10306)", loginMod: "6.6.0" },
  default:{ model: "SM-G991B",  os: "Android12", appVer: "9.3.1(90301,uid:10306)", loginMod: "6.6.0" },
};
const XAUTH_COUNTRY_TO_LOCALE = {
  US: "en_US", PR: "en_US", GU: "en_US",
  GB: "en_GB", IE: "en_GB",
  KR: "ko_KR",
  JP: "ja_JP",
  VN: "vi_VN",
  ID: "id_ID",
  TH: "th_TH",
  CN: "zh_CN", TW: "zh_CN", HK: "zh_CN",
  PH: "en_US",
  HT: "en_US",
};

const XAUTH_DA_DD   = "a593e830-df67-4e93-a975-315919bdea15";
const XAUTH_BMR_REF = "http%3A%2F%2Fmain%2F%3FpCode%3DTODAY%26cCode%3DENT";

// OAuth 1.0 percent-encoding (RFC 5849 §3.6 — stricter than encodeURIComponent)
function _oauthEncode(s) {
  return encodeURIComponent(String(s == null ? "" : s))
    .replace(/!/g, "%21").replace(/'/g, "%27")
    .replace(/\(/g, "%28").replace(/\)/g, "%29")
    .replace(/%7E/g, "~");
}
function _oauthNonce20() {
  const alpha = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz123456789";
  const buf = webcrypto.getRandomValues(new Uint8Array(20));
  let s = "";
  for (let i = 0; i < 20; i++) s += alpha[buf[i] % alpha.length];
  return s;
}
function _xmlTag(text, tag) {
  const m = String(text).match(new RegExp(`<${tag}(?:\\s[^>]*)?>([\\s\\S]*?)<\\/${tag}>`, "i"));
  return m ? m[1].replace(/<!\[CDATA\[|\]\]>/g, "").trim() : null;
}
function _deviceIdForUser(username) {
  return crypto.createHash("sha256")
    .update("naver-device-v1:" + username.toLowerCase().trim())
    .digest("hex").slice(0, 32);
}

// RSA-PKCS1 encrypt: chr(len(sk))+sk+chr(len(user))+user+chr(len(pass))+pass
// Uses Node's native crypto (no jsdom needed) — same scheme as the APK.
function _xauthRsaEncrypt(nHex, eHex, sessionKey, username, password) {
  let n = nHex.replace(/^0+/, "") || "00"; if (n.length % 2) n = "0" + n;
  let e = eHex.replace(/^0+/, "") || "00"; if (e.length % 2) e = "0" + e;
  const pub = crypto.createPublicKey({
    key: { kty: "RSA",
      n: Buffer.from(n, "hex").toString("base64url"),
      e: Buffer.from(e, "hex").toString("base64url") },
    format: "jwk",
  });
  const skB = Buffer.from(sessionKey, "utf8");
  const uB  = Buffer.from(username,   "utf8");
  const pB  = Buffer.from(password,   "utf8");
  const msg = Buffer.concat([
    Buffer.from([skB.length]), skB,
    Buffer.from([uB.length]),  uB,
    Buffer.from([pB.length]),  pB,
  ]);
  return crypto.publicEncrypt(
    { key: pub, padding: crypto.constants.RSA_PKCS1_PADDING }, msg
  ).toString("hex");
}
function _oauthSign(params, tokenSecret) {
  const normParams = Object.entries(params)
    .filter(([, v]) => v != null && v !== "")
    .map(([k, v]) => [_oauthEncode(k), _oauthEncode(String(v))])
    .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0))
    .map(([k, v]) => `${k}=${v}`).join("&");
  const base = "GET&" + _oauthEncode(XAUTH_URL) + "&" + _oauthEncode(normParams);
  const key  = _oauthEncode(XAUTH_CONSUMER_SECRET) + "&" + _oauthEncode(tokenSecret || "");
  return crypto.createHmac("sha1", key).update(base, "utf8").digest("base64");
}

// Detect the country of the OUTBOUND IP (i.e. what the proxy IP looks like to
// Naver). Goes through the proxy so we get the proxy's exit-IP country, not
// the server's real IP. Used to pick a matching device profile/locale.
async function _xauthDetectGeo() {
  try {
    const r = await proxiedFetch("https://ip-api.com/json/?fields=status,country,countryCode,query", {
      headers: { "User-Agent": "curl/7.88.0", "Accept": "application/json" },
    });
    const j = await r.json();
    if (j.status === "success") {
      return { ip: j.query, country: j.country, countryCode: j.countryCode };
    }
  } catch (_) {}
  return { ip: "unknown", country: "Unknown", countryCode: "" };
}

// Persist a Set-Cookie list (Headers.getSetCookie() result) into the global
// tough-cookie jar for the given URL. Mirrors what naverFetch does.
async function _persistSetCookies(headers, urlForJar) {
  const list = headers.getSetCookie ? headers.getSetCookie() : [];
  for (const sc of list) {
    try { await jar.setCookie(sc, urlForJar); } catch { /* malformed */ }
  }
}

// ===========================================================================
//  Strategy 1 — WEB login via /nidlogin.login
//  ---------------------------------------------------------------------------
//  Reuses the EXISTING browser session (same NNB/ASES cookies, same proxy IP)
//  that was used to create the account moments ago. This is by far the most
//  reliable path for fresh accounts: Naver sees a continuous browser session
//  on the same IP, so no CAPTCHA wall is triggered.
//
//  Flow:
//    GET  www.naver.com                                      (warm-up)
//    GET  nid.naver.com/nidlogin.login?mode=form             (form + cookies)
//    GET  nid.naver.com/login/ext/keys.nhn                   (RSA pubkey)
//    POST nid.naver.com/nidlogin.login                       (encrypted creds)
//
//  Returns true if NID_AUT lands in the jar after POST.
// ===========================================================================
async function loginViaWeb(userId, password) {
  const bareId = userId.replace(/@naver\.com$/, "").trim();
  const fullId = bareId + "@naver.com";

  // 0) Warm-up: visit www.naver.com to look like a normal browser landing on
  //    the homepage before clicking "Sign in".
  try {
    await naverFetchRetry(
      "https://www.naver.com/",
      { headers: { Accept: "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8" },
        referer: "https://nid.naver.com/" },
      "warm-up www.naver.com", 2,
    );
  } catch (_) { /* warm-up best-effort */ }

  // 1) GET the login form page — sets additional session cookies and may
  //    expose a dynamicKey hidden field that some SDK versions check.
  const formUrl = "https://nid.naver.com/nidlogin.login?mode=form&url=https%3A%2F%2Fwww.naver.com%2F";
  let dynamicKey = "";
  try {
    const formResp = await naverFetchRetry(
      formUrl,
      { headers: { Accept: "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8" },
        referer: "https://www.naver.com/" },
      "GET nidlogin form", 3,
    );
    const m = (formResp.text || "").match(/name=["']dynamicKey["']\s+value=["']([^"']*)["']/);
    if (m) dynamicKey = m[1];
    info(`web login form loaded (dynamicKey=${dynamicKey ? "yes" : "none"})`);
  } catch (e) {
    warn(`web login form fetch failed: ${e.message}`);
  }

  // 2) GET the RSA public key (web endpoint — keys.nhn, NOT keys2.nhn)
  //    Format returned: ",sessionkey,keyname,evalue,nvalue,"
  let sessionKey, keyName, eValue, nValue;
  try {
    const keysResp = await naverFetchRetry(
      "https://nid.naver.com/login/ext/keys.nhn",
      { headers: { Accept: "*/*" }, referer: formUrl },
      "GET web RSA keys", 3,
    );
    const parts = (keysResp.text || "").trim().split(",");
    if (parts.length < 5) {
      warn(`web keys.nhn returned unexpected format: ${(keysResp.text || "").slice(0, 80)}`);
      return false;
    }
    sessionKey = parts[1];
    keyName    = parts[2];
    eValue     = parts[3];
    nValue     = parts[4];
    info(`web login RSA keyname=${keyName}, sk len=${sessionKey.length}`);
  } catch (e) {
    warn(`web RSA keys fetch failed: ${e.message}`);
    return false;
  }

  // 3) Encrypt credentials. Uses the SAME RSA-PKCS1 layout as xAuth/registration:
  //    chr(len(sk))+sk+chr(len(id))+id+chr(len(pw))+pw
  //    Naver web login accepts both bareId and full email — we use bareId
  //    because that's what the form normally sends.
  const encpw = _xauthRsaEncrypt(nValue, eValue, sessionKey, bareId, password);

  // 4) POST credentials. Field set matches what the web form submits.
  const body = new URLSearchParams({
    enctp: "1",
    encnm: keyName,
    svctype: "0",
    enc_url: "",
    url: "https://www.naver.com/",
    smart_LEVEL: "-1",
    encpw,
    nvlong: "on",
    locale: "en_US",
    dynamicKey,
    id: "",
    pw: "",
  }).toString();

  let r;
  try {
    r = await naverFetchRetry(
      "https://nid.naver.com/nidlogin.login",
      {
        method: "POST",
        body,
        referer: formUrl,
        headers: {
          "Content-Type": "application/x-www-form-urlencoded",
          Accept: "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
          Origin: "https://nid.naver.com",
          "sec-fetch-dest": "document",
          "sec-fetch-mode": "navigate",
          "sec-fetch-site": "same-origin",
          "sec-fetch-user": "?1",
          "upgrade-insecure-requests": "1",
        },
      },
      "POST nidlogin.login", 2,
    );
    info(`web login: HTTP ${r.status}`);
  } catch (e) {
    warn(`web login POST failed: ${e.message}`);
    return false;
  }

  // 5) Verify NID_AUT actually landed in the jar
  const ck = await jar.getCookieString("https://www.naver.com");
  if (/(?:^|;\s*)NID_AUT=/.test(ck)) {
    ok(`web login OK — NID_AUT seeded for ${fullId}`);
    return true;
  }

  // Diagnose common failure reasons from the response body
  const t = r ? (r.text || "") : "";
  let reason;
  if (/captcha|chptchaimg|nccaptcha/i.test(t))             reason = "CAPTCHA required";
  else if (/locked|차단|일시적|sec_blocked|blocked/i.test(t)) reason = "account locked / temporary block";
  else if (/잘못된|wrong\s*password|incorrect/i.test(t))     reason = "wrong password";
  else                                                       reason = "no NID_AUT (likely login form returned)";
  warn(`web login did not seed NID_AUT — reason: ${reason}`);
  return false;
}

// ===========================================================================
//  Strategy 2 — xAuth mobile login
//  ---------------------------------------------------------------------------
//  Falls back to the Naver Android app xAuth endpoint if web login fails.
//  Note: for FRESH accounts, xAuth often returns code=RequireInfo because the
//  device_id is brand-new from Naver's perspective (the account was created
//  via a browser, not the mobile app). In that case we surface the verify URL
//  so it can be inspected manually.
// ===========================================================================
async function loginViaXAuth(userId, password) {
  const bareId = userId.replace(/@naver\.com$/, "").trim();
  const fullId = bareId + "@naver.com";

  // 1) Detect outbound geo via proxy → pick matching device profile/locale
  const geo     = await _xauthDetectGeo();
  const locale  = XAUTH_COUNTRY_TO_LOCALE[geo.countryCode] || "en_US";
  const profile = XAUTH_DEVICE_PROFILES[locale] || XAUTH_DEVICE_PROFILES.default;
  info(`xAuth geo: ${geo.ip} → ${geo.country} (${geo.countryCode}) → locale=${locale}`);

  const deviceId = _deviceIdForUser(bareId);
  const appId    = XAUTH_CONSUMER_KEY + deviceId.slice(0, 28);
  const mobileUA = `Android/${profile.os.replace("Android", "")} Model/${profile.model} ` +
                   `com.nhn.android.search/${profile.appVer} LoginMod/${profile.loginMod}`;
  info(`xAuth device: ${profile.model} | ${profile.os} | deviceId=${deviceId.slice(0, 12)}…`);

  // 2) Fetch RSA pubkey from the MOBILE keys endpoint (keys2.nhn)
  //    Format returned: "sessionKey,keyname,nvalue,evalue"
  let rsaKey;
  {
    const r = await proxiedFetch(XAUTH_RSA_KEYS_URL, {
      headers: { "User-Agent": mobileUA },
    });
    const text = await r.text();
    const parts = text.trim().split(",");
    if (parts.length < 3) {
      warn(`xAuth keys2.nhn returned unexpected format: ${text.slice(0, 80)}`);
      return false;
    }
    rsaKey = {
      sessionKey: parts[0],
      keyname:    parts[1],
      nvalue:     parts[2],
      evalue:     parts[3] || "010001",
    };
    info(`xAuth RSA keyname=${rsaKey.keyname}, sk len=${rsaKey.sessionKey.length}`);
  }

  // 3) Encrypt credentials and build OAuth 1.0 signed query
  const encpw = _xauthRsaEncrypt(
    rsaKey.nvalue, rsaKey.evalue, rsaKey.sessionKey, fullId, password,
  );
  const params = {
    app_id:                 appId,
    device:                 profile.model,
    device_id:              deviceId,
    encnm:                  rsaKey.keyname,
    encpw,
    locale,
    mode:                   "req_ac_xauth",
    network:                "cell",
    nvlong:                 "on",
    oauth_consumer_key:     XAUTH_CONSUMER_KEY,
    oauth_nonce:            _oauthNonce20(),
    oauth_signature_method: "HMAC_SHA1",
    oauth_timestamp:        String(Math.floor(Date.now() / 1000)),
    oauth_version:          "1.0",
    os:                     profile.os,
    smart_LEVEL:            "-1",
    svc:                    "naverapp",
    version:                "2.6",
  };
  params.oauth_signature = _oauthSign(params, "");
  const qs  = Object.entries(params)
    .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0))
    .map(([k, v]) => `${_oauthEncode(k)}=${_oauthEncode(v)}`).join("&");
  const bmr = `BMR=s=${Date.now() - 60000}&r=${XAUTH_BMR_REF}&r2=`;

  // 4) Fire the xAuth request through the proxy
  const xRes = await proxiedFetch(`${XAUTH_URL}?${qs}`, {
    headers: {
      "User-Agent":      mobileUA,
      "Cookie":          `${bmr}; DA_DD=${XAUTH_DA_DD}`,
      "Accept-Encoding": "identity",
      "Connection":      "Keep-Alive",
    },
  });
  const body = await xRes.text();
  const code = _xmlTag(body, "code");
  const idTag = _xmlTag(body, "id");
  info(`xAuth response: HTTP ${xRes.status}, code=${code || "?"}, id=${idTag || "?"}`);

  if (code !== "Success") {
    if (code === "RequireInfo") {
      warn(`xAuth requires verification (RequireInfo) — new IP/device challenge`);
      const inapp = _xmlTag(body, "inapp_view") || "";
      if (inapp) info(`Verify URL: ${inapp}`);
    } else {
      warn(`xAuth login failed — code: ${code || "?"}`);
      warn(`response (first 300 chars): ${body.slice(0, 300)}`);
    }
    return false;
  }

  // 5) Persist the auth cookies (NID_AUT, NID_SES, etc.) into the global jar
  //    on .naver.com — this is what mail.naver.com needs.
  await _persistSetCookies(xRes.headers, XAUTH_URL);
  // Belt-and-braces: also pull NID_AUT/NID_SES from the response and explicitly
  // set them on .naver.com (in case Set-Cookie omitted the Domain attribute).
  const setCkRaw = xRes.headers.getSetCookie ? xRes.headers.getSetCookie() : [];
  const ckMap = {};
  for (const sc of setCkRaw) {
    const part = sc.split(";")[0].trim();
    const eq = part.indexOf("=");
    if (eq > 0) ckMap[part.slice(0, eq).trim()] = part.slice(eq + 1).trim();
  }
  for (const name of ["NID_AUT", "NID_SES", "NID_JKL"]) {
    if (ckMap[name] && ckMap[name] !== "deleted") {
      await setCookieOnNaver(name, ckMap[name], ".naver.com");
    }
  }

  const verify = await jar.getCookieString("https://www.naver.com");
  if (/(?:^|;\s*)NID_AUT=/.test(verify)) {
    ok(`xAuth login OK — NID_AUT seeded (${(ckMap.NID_AUT || "").slice(0, 16)}…)`);
    return true;
  }
  warn("xAuth returned Success but NID_AUT did not land in jar");
  return false;
}

// ===========================================================================
//  Orchestrator — try strategies in order of likelihood for fresh accounts
//  ---------------------------------------------------------------------------
//    1. WEB login    (best for fresh accounts in the same browser session)
//    2. xAuth mobile (fallback; may hit RequireInfo for new device_id)
//
//  Returns true as soon as NID_AUT is seeded by either strategy.
// ===========================================================================
async function loginForImap(userId, password) {
  info("Login strategy 1/2: web /nidlogin.login (browser session reuse)");
  try {
    if (await loginViaWeb(userId, password)) return true;
  } catch (e) {
    warn(`web login threw: ${e.message}`);
  }

  info("Login strategy 2/2: xAuth mobile (Naver Android app endpoint)");
  try {
    if (await loginViaXAuth(userId, password)) return true;
  } catch (e) {
    warn(`xAuth login threw: ${e.message}`);
  }

  warn("All login strategies failed — IMAP activation will likely return login page");
  return false;
}

async function activateImap(userId, password) {
  // Build a direct undici Agent (no proxy) up front so we can fall back to it
  // when the residential proxy refuses to tunnel mail.naver.com:443.
  // Always closed in finally{} so we never leak open sockets.
  const directAgent = new UndiciAgent();
  const allowDirectFallback = true;

  try {
    // -------- Diagnostic: what cookies do we have right after registration? --
    await dumpJarCookies("before IMAP");

    // -------- Pre-flight: ensure we actually have NID_AUT/NID_SES. If not,
    // mail.naver.com will return the login page. We perform an explicit
    // mobile-app xAuth login (Naver Android endpoint) which:
    //   • doesn't trigger CAPTCHA on fresh accounts (unlike /nidlogin.login)
    //   • returns NID_AUT/NID_SES directly
    //   • runs through the SAME proxy as registration (single-IP session)
    // ------------------------------------------------------------------------
    const naverCk = await jar.getCookieString("https://www.naver.com");
    const haveAuth = /(?:^|;\s*)NID_AUT=/.test(naverCk);
    if (!haveAuth) {
      warn("NID_AUT missing after registration — performing xAuth mobile login");
      const loggedIn = await loginForImap(userId, password);
      if (!loggedIn) {
        warn("xAuth login failed — IMAP will likely fail");
      } else {
        await dumpJarCookies("after xAuth login");
      }
    } else {
      ok("NID_AUT already present in jar — no extra login needed");
    }

    // -------- Step 13a — load the IMAP/SMTP settings page so mail.naver.com
    // sets its own session/CSRF cookies (NAC, NACT) on the cookie jar. -------
    const settingsUrl = "https://mail.naver.com/v2/settings/smtp/imap";
    let r = await imapFetch(
      settingsUrl,
      {
        referer: "https://mail.naver.com/",
        headers: {
          Accept:
            "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
          "sec-fetch-dest": "document",
          "sec-fetch-mode": "navigate",
          "sec-fetch-site": "none",
          "sec-fetch-user": "?1",
          "upgrade-insecure-requests": "1",
        },
      },
      "GET mail settings page",
      directAgent,
      allowDirectFallback,
    );
    info(`mail.naver.com settings page: HTTP ${r.status}`);

    // Detect the case where post-registration session didn't carry over to
    // mail.naver.com — the page would 200-redirect to nidlogin.
    if (/nidlogin\.login|loginForm/.test(r.text)) {
      warn("mail.naver.com returned login page — NID_AUT/NID_SES not active for mail subdomain");
      return false;
    }

    // Confirm mail-specific cookies were actually issued
    const mailCk = await jar.getCookieString("https://mail.naver.com");
    const haveNac = /(?:^|;\s*)NAC=/.test(mailCk);
    info(`mail cookies after settings load: ${mailCk.split(";").map(c=>c.trim().split("=")[0]).join("+") || "none"}`);
    if (!haveNac) {
      warn("NAC cookie not set by mail.naver.com — IMAP request may be rejected");
    }

    await humanPause(900, 1800);

    // -------- Step 13b — POST /json/option/imap/set/ — actually flip the
    // server-side IMAP/SMTP flag. Body is byte-for-byte identical to the HAR.
    const imapBody = `isImapSmtp=true&limitCount=1000&u=${encodeURIComponent(userId)}`;
    r = await imapFetch(
      "https://mail.naver.com/json/option/imap/set/",
      {
        method: "POST",
        body: imapBody,
        referer: settingsUrl,
        headers: {
          Accept: "application/json, text/plain, */*",
          "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
          charset: "utf-8",
          Origin: "https://mail.naver.com",
          "sec-fetch-site": "same-origin",
          "sec-fetch-mode": "cors",
          "sec-fetch-dest": "empty",
        },
      },
      "POST imap/set",
      directAgent,
      allowDirectFallback,
    );
    info(`IMAP set: HTTP ${r.status} — ${(r.text || "").trim().slice(0, 200)}`);

    let parsed;
    try {
      parsed = JSON.parse(r.text);
    } catch {
      warn(`IMAP response is not JSON — first 200 chars: ${(r.text || "").slice(0, 200)}`);
      return false;
    }
    if (parsed && parsed.Result === "OK") {
      ok("IMAP/SMTP activated on Naver mail ✅  (Result: OK)");
      return true;
    }
    warn(`IMAP server replied non-OK: ${JSON.stringify(parsed)}`);
    return false;
  } finally {
    try { await directAgent.close(); } catch {}
  }
}

// ===========================================================================
//  STEP 14 — Naver 2-Step Verification + Application Password generation
//  ---------------------------------------------------------------------------
//  Reverse-engineered from HAR ProxyPin4-26_03:49:25 (full working flow).
//
//  Naver REQUIRES 2FA to be active on the account before allowing
//  createApplicationPassword. Activation requires a real device with the
//  Naver mobile app logged in to the same account, which receives a push
//  notification that the user must approve manually.
//
//  Full sequence (all on nid.naver.com, all desktop Chrome / Edge UA):
//
//    A. GET  /user2/help/myInfoV2?m=viewSecurity&lang=en_US
//          → Security page; token_help embedded in every link.
//    B. GET  /user2/help/2StepVerif?m=viewGuide&token_help=<TOK>&lang=en_US
//          → 2FA setup guide; form action points to actionCheckPasswd.
//    C. POST /user2/help/2StepVerif?m=actionCheckPasswd
//          Body: token_help=<TOK>
//          → 302 redirect to viewInputPasswdForMyInfo. Sets fresh NID_SES.
//    D. GET  /user2/help/myInfoPasswd?m=viewInputPasswdForMyInfo
//            &menu=security&token_help=<TOK>
//          → re-auth password form. Inline JS exposes RSA params:
//            sessionKey, keyName, eValue (modulus), nValue (exp 010001), id.
//    E. POST /user2/help/myInfoPasswd?m=actionInputPasswd
//          Body: token_help=<TOK>&encPasswd=<HEX>&encNm=<KEYNAME>&upw=
//          → returns Base64-redirect HTML pointing at showDeviceList.
//    F. GET  /user2/help/2StepVerif?m=showDeviceList&token_help=<TOK>
//          → lists devices that have the Naver app logged in. Each device
//            embeds an FCM pushToken in a hidden input.
//
//    ⚠ At step F the user must already have the Naver mobile app installed
//      AND be logged in with this exact ID/PW. Otherwise the device list
//      is empty and the flow cannot proceed. The tool prompts the user
//      to log in on phone, then re-fetches showDeviceList.
//
//    G. POST /user2/help/2StepVerif?m=sendPushMessageToRegist
//          Body: token_help=<TOK>&delete_index=&pushToken=<URLENC_FCM>&device=on
//          → triggers Naver to send an FCM push to the chosen device.
//    H. POST /user2/help/2StepVerif?m=checkPushStatus&token_help=<TOK>
//          Empty body, polled every 2s. Returns
//            {"resultCode":1,"resultMsg":"… not been completed …"}  while waiting
//            {"resultCode":0,"resultMsg":""}                         when approved
//    I. GET  /user2/help/2StepVerif?m=setUp&token_help=<TOK>
//          → "Setup Complete" page, confirms 2FA is now active.
//    J. GET  /user2/help/2StepVerif?m=viewManageSettings&token_help=<TOK>
//          → Management page; now opens because 2FA is active.
//    K. POST /user2/help/2StepVerif?m=createApplicationPassword&token_help=<TOK>
//          Body: appName=<NAME>
//          → JSON: {"passwd":"WCCQBVS5VGTH","resultCode":0,"seq":N}
// ===========================================================================

// Extract token_help value from the Security page HTML. The token appears
// inside hrefs/form actions like `?token_help=MGJPbRPDtfUlCtG0`. Picks the
// first hex/base64-ish token (8-32 chars).
function _extractTokenHelp(html) {
  const m = html && html.match(/[?&]token_help=([A-Za-z0-9_-]{8,64})/);
  return m ? m[1] : null;
}

// Extract Naver re-auth RSA params from the inline JS embedded in the
// /mobile/user/help/myInfoPasswd?m=viewInputPasswd page. Naver does NOT
// use /login/ext/keys.nhn for re-auth — instead, $.createRsaKey defines
// sessionKey, keyName, eValue, nValue, id INLINE on the page, like:
//   var sessionKey = "JqXqbCtFtf274qm2";
//   var keyName    = "100021893";
//   var eValue     = "a36e9c6c69592fd97..."   ← MODULUS (Naver's naming)
//   var nValue     = "010001"                  ← EXPONENT (Naver's naming)
//   var id         = "xnlibd850";              ← bare user ID
// The JS then does: rsa.encrypt( chr(len(sk))+sk + chr(len(id))+id +
//                                chr(len(pw))+pw )
//
// Returns { sessionKey, keyName, eValue, nValue, id } or null on no match.
function _parseReauthRsaParams(html) {
  if (!html) return null;
  const grab = (name) => {
    const re = new RegExp(`var\\s+${name}\\s*=\\s*["']([^"']*)["']`, "i");
    const m = html.match(re);
    return m ? m[1] : null;
  };
  const out = {
    sessionKey: grab("sessionKey"),
    keyName   : grab("keyName"),
    eValue    : grab("eValue"),    // ← modulus per Naver naming
    nValue    : grab("nValue"),    // ← exponent per Naver naming
    id        : grab("id"),        // ← bare username (already on the page)
  };
  // All five must be present and non-empty for the flow to work.
  if (!out.sessionKey || !out.keyName || !out.eValue || !out.nValue || !out.id) {
    return null;
  }
  return out;
}

// Parse the showDeviceList HTML and return [{pushToken, name}, ...] for every
// Naver-mobile-app device registered to this account. The page embeds
// each device in a <li> like:
//   <input type="hidden" name="pushToken" id="device_0_token" value="<FCM>" disabled/>
//   <input type="radio" id="device_0" name="device" data-android="true">
//   <label for="device_0"><span class="txt_radio">Redmi 9C NFC <em>(Login...)</em></span></label>
function _parseDeviceList(html) {
  const out = [];
  if (!html) return out;
  // Match every block from a pushToken hidden input through its label text.
  // Tolerant of either single or double quotes, extra whitespace, and any
  // attribute order around the inputs.
  const re = /name=["']pushToken["'][^>]*value=["']([^"']+)["'][\s\S]*?<span[^>]*class=["'][^"']*txt_radio[^"']*["'][^>]*>([\s\S]*?)<\/span>/g;
  const decode = (s) => s
    .replace(/&amp;/g, "&")
    .replace(/&lt;/g, "<")
    .replace(/&gt;/g, ">")
    .replace(/&quot;/g, '"')
    .replace(/&#39;/g, "'")
    .replace(/&nbsp;/g, " ")
    .replace(/&#(\d+);/g, (_, n) => String.fromCharCode(parseInt(n, 10)));
  let m;
  while ((m = re.exec(html)) !== null) {
    const token = m[1];
    // Strip inner <em> "Login : ..." annotation and any other tags.
    const rawName = m[2].replace(/<em[\s\S]*?<\/em>/g, "").replace(/<[^>]+>/g, "").trim();
    const name = decode(rawName).replace(/\s+/g, " ").trim() || "Phone";
    out.push({ pushToken: token, name });
  }
  return out;
}

async function generateAppPassword(userId, password, appName = "Direct") {
  const bareId = userId.replace(/@naver\.com$/, "").trim();

  // -------- Pre-flight: must have NID_AUT in the jar --------------------
  const nidCk = await jar.getCookieString("https://nid.naver.com");
  if (!/(?:^|;\s*)NID_AUT=/.test(nidCk)) {
    warn(`No NID_AUT in jar — cannot generate App Password (login required)`);
    return null;
  }

  // -------- Header overrides: plain DESKTOP Chrome / Edge profile --------
  // The captured HAR (ProxyPin4-26 03:49:25) used MS Edge desktop on Linux
  // (Mozilla/5.0 X11 Linux x86_64 + Chrome/146 + Edg/146). Naver routes
  // the request to the /user2/help/* endpoints (NOT /mobile/user/help/*)
  // when it sees a desktop UA. The /mobile/* paths return tiny placeholder
  // pages, which is what was breaking the previous implementation. We mirror
  // the HAR's headers exactly here.
  const desktopHeaders = {
    "User-Agent":
      `Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) ` +
      `Chrome/${SESSION_CHR.major}.0.0.0 Safari/537.36 Edg/${SESSION_CHR.major}.0.${SESSION_CHR.full.split(".")[2] || "0"}.${SESSION_CHR.full.split(".")[3] || "0"}`,
    "sec-ch-ua": `"Chromium";v="${SESSION_CHR.major}", "Not-A.Brand";v="24", "Microsoft Edge";v="${SESSION_CHR.major}"`,
    "sec-ch-ua-full-version": `"${SESSION_CHR.full}"`,
    "sec-ch-ua-full-version-list":
      `"Chromium";v="${SESSION_CHR.full}", "Not-A.Brand";v="24.0.0.0", "Microsoft Edge";v="${SESSION_CHR.full}"`,
    "sec-ch-ua-mobile": "?0",
    "sec-ch-ua-platform": '"Linux"',
    "sec-ch-ua-platform-version": '""',
    "sec-ch-ua-model": '""',
    "sec-ch-ua-arch": '"x86"',
    "Accept-Language": "ro",
  };

  // ===================================================================
  //  Step A — GET viewSecurity → token_help
  // ===================================================================
  let r = await naverFetchRetry(
    "https://nid.naver.com/user2/help/myInfoV2?m=viewSecurity&lang=en_US",
    {
      referer: "https://www.naver.com/",
      headers: {
        ...desktopHeaders,
        Accept: "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
        "sec-fetch-dest": "document",
        "sec-fetch-mode": "navigate",
        "sec-fetch-site": "none",
        "sec-fetch-user": "?1",
        "upgrade-insecure-requests": "1",
      },
    },
    "GET viewSecurity",
    3,
  );
  info(`viewSecurity: HTTP ${r.status} (len ${(r.text || "").length})`);
  const tokenHelp = _extractTokenHelp(r.text || "");
  if (!tokenHelp) {
    warn(`No token_help found in viewSecurity HTML`);
    try {
      const dbg = `naver_viewSecurity_${Date.now()}.html`;
      fs.writeFileSync(dbg, r.text || "");
      warn(`  saved ${dbg}`);
    } catch {}
    return null;
  }
  info(`token_help = ${tokenHelp}`);
  const tokQS = `token_help=${encodeURIComponent(tokenHelp)}`;
  await humanPause(800, 1800);

  // ===================================================================
  //  Step B — GET viewGuide (the 2FA setup intro page)
  // ===================================================================
  const guideUrl =
    `https://nid.naver.com/user2/help/2StepVerif?m=viewGuide&${tokQS}&lang=en_US`;
  r = await naverFetchRetry(
    guideUrl,
    {
      referer: "https://nid.naver.com/user2/help/myInfoV2?m=viewSecurity&lang=en_US",
      headers: {
        ...desktopHeaders,
        Accept: "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
        "sec-fetch-dest": "document",
        "sec-fetch-mode": "navigate",
        "sec-fetch-site": "same-origin",
        "sec-fetch-user": "?1",
        "upgrade-insecure-requests": "1",
      },
    },
    "GET viewGuide (2FA intro)",
    3,
  );
  info(`viewGuide: HTTP ${r.status} (len ${(r.text || "").length})`);
  await humanPause(700, 1500);

  // ===================================================================
  //  Step C — POST actionCheckPasswd (302 → viewInputPasswdForMyInfo)
  //  naverFetch auto-follows the 302, so r.text below holds the
  //  re-auth password form HTML directly.
  // ===================================================================
  r = await naverFetchRetry(
    "https://nid.naver.com/user2/help/2StepVerif?m=actionCheckPasswd",
    {
      method: "POST",
      body: `token_help=${encodeURIComponent(tokenHelp)}`,
      referer: guideUrl,
      headers: {
        ...desktopHeaders,
        Accept: "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
        "Content-Type": "application/x-www-form-urlencoded",
        Origin: "https://nid.naver.com",
        "sec-fetch-dest": "document",
        "sec-fetch-mode": "navigate",
        "sec-fetch-site": "same-origin",
        "sec-fetch-user": "?1",
        "upgrade-insecure-requests": "1",
      },
    },
    "POST actionCheckPasswd (→ re-auth form)",
    3,
  );
  const inputPageHtml = r.text || "";
  info(`actionCheckPasswd→form: HTTP ${r.status} (len ${inputPageHtml.length})`);

  // ===================================================================
  //  Step D — Parse RSA params from re-auth form HTML
  // ===================================================================
  const rsaParams = _parseReauthRsaParams(inputPageHtml);
  if (!rsaParams) {
    warn(`Could not extract RSA params from viewInputPasswdForMyInfo HTML`);
    try {
      const dbg = `naver_viewInputPasswd_${Date.now()}.html`;
      fs.writeFileSync(dbg, inputPageHtml);
      warn(`  saved ${dbg}`);
    } catch {}
    return null;
  }
  const { sessionKey, keyName, eValue, nValue, id: pageId } = rsaParams;
  info(`re-auth RSA: keyName=${keyName} sk_len=${sessionKey.length} ` +
       `id=${pageId} mod_len=${eValue.length} exp=${nValue}`);
  // _xauthRsaEncrypt(modulus, exponent, sessionKey, user, pw); Naver's
  // eValue is the modulus, nValue is the exponent (backwards naming).
  const encPasswd = _xauthRsaEncrypt(eValue, nValue, sessionKey, pageId, password);
  await humanPause(900, 1800);

  // ===================================================================
  //  Step E — POST actionInputPasswd (re-auth submit)
  //  Body order matches HAR: token_help & encPasswd & encNm & upw=
  //  Response is a Base64-redirect HTML pointing at showDeviceList.
  // ===================================================================
  const actionUrl =
    "https://nid.naver.com/user2/help/myInfoPasswd?m=actionInputPasswd";
  const inputUrl =
    `https://nid.naver.com/user2/help/myInfoPasswd?m=viewInputPasswdForMyInfo&menu=security&${tokQS}`;
  const reauthBody =
    `token_help=${encodeURIComponent(tokenHelp)}` +
    `&encPasswd=${encodeURIComponent(encPasswd)}` +
    `&encNm=${encodeURIComponent(keyName)}` +
    `&upw=`;
  r = await naverFetchRetry(
    actionUrl,
    {
      method: "POST",
      body: reauthBody,
      referer: inputUrl,
      headers: {
        ...desktopHeaders,
        Accept: "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
        "Content-Type": "application/x-www-form-urlencoded",
        Origin: "https://nid.naver.com",
        "sec-fetch-dest": "document",
        "sec-fetch-mode": "navigate",
        "sec-fetch-site": "same-origin",
        "sec-fetch-user": "?1",
        "upgrade-insecure-requests": "1",
      },
    },
    "POST actionInputPasswd (re-auth)",
    3,
  );
  const reauthRespHtml = r.text || "";
  info(`actionInputPasswd: HTTP ${r.status} (len ${reauthRespHtml.length})`);
  // Detect failure: the re-auth response should be the small Base64-redirect
  // HTML pointing at showDeviceList. If it's a long page or contains an
  // error message, re-auth failed.
  if (!/Base64\.decode/.test(reauthRespHtml)) {
    warn(`Re-auth did NOT return a Base64 redirect — likely password-rejected`);
    info(`  body preview: ${reauthRespHtml.replace(/\s+/g, " ").slice(0, 400)}`);
    try {
      const dbg = `naver_reauth_fail_${Date.now()}.html`;
      fs.writeFileSync(dbg, reauthRespHtml);
      warn(`  saved ${dbg}`);
    } catch {}
    return null;
  }
  ok(`Re-authentication accepted ✅`);
  await humanPause(600, 1300);

  // ===================================================================
  //  Step F — GET showDeviceList (find user's phone)
  //  Critical: if the user has NOT logged into the Naver mobile app on
  //  their phone with this account, the device list is empty. We must
  //  prompt the user, wait for them to log in, then re-fetch.
  // ===================================================================
  const sdlUrl =
    `https://nid.naver.com/user2/help/2StepVerif?m=showDeviceList&${tokQS}`;
  const fetchDeviceList = async (label) => {
    const rr = await naverFetchRetry(
      sdlUrl,
      {
        referer: actionUrl,
        headers: {
          ...desktopHeaders,
          Accept: "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
          "sec-fetch-dest": "document",
          "sec-fetch-mode": "navigate",
          "sec-fetch-site": "same-origin",
          "sec-fetch-user": "?1",
          "upgrade-insecure-requests": "1",
        },
      },
      `GET showDeviceList (${label})`,
      3,
    );
    info(`showDeviceList (${label}): HTTP ${rr.status} (len ${(rr.text || "").length})`);
    return _parseDeviceList(rr.text || "");
  };

  let devices = await fetchDeviceList("first");

  if (devices.length === 0) {
    // Prompt the user — show the credentials they need to enter on the
    // Naver app, then wait for them to press Enter and re-poll.
    console.log("");
    console.log(`  ${C.bold}${C.ylw}┌──────────────────────────────────────────────────────────────┐${C.reset}`);
    console.log(`  ${C.bold}${C.ylw}│  ACTION REQUIRED — Take the credentials below and log into   │${C.reset}`);
    console.log(`  ${C.bold}${C.ylw}│  the Naver app on your phone (the app must already be        │${C.reset}`);
    console.log(`  ${C.bold}${C.ylw}│  installed):                                                 │${C.reset}`);
    console.log(`  ${C.bold}${C.ylw}│                                                              │${C.reset}`);
    console.log(`  ${C.bold}${C.ylw}│      ID:        ${C.reset}${C.bold}${bareId.padEnd(45)}${C.ylw}│${C.reset}`);
    console.log(`  ${C.bold}${C.ylw}│      Password:  ${C.reset}${C.bold}${password.padEnd(45)}${C.ylw}│${C.reset}`);
    console.log(`  ${C.bold}${C.ylw}│                                                              │${C.reset}`);
    console.log(`  ${C.bold}${C.ylw}│  Open the Naver app, sign in with the credentials above,     │${C.reset}`);
    console.log(`  ${C.bold}${C.ylw}│  then press ENTER here.                                      │${C.reset}`);
    console.log(`  ${C.bold}${C.ylw}└──────────────────────────────────────────────────────────────┘${C.reset}`);
    console.log("");
    await ask(`  ${C.bold}Press ENTER after you have signed in to the Naver app${C.reset}`);

    // Try a few times — sometimes the device shows up after a short delay
    // because Naver's backend takes a moment to register the FCM push token.
    for (let attempt = 1; attempt <= 5; attempt++) {
      await humanPause(2000, 4000);
      devices = await fetchDeviceList(`retry ${attempt}/5`);
      if (devices.length > 0) break;
      if (attempt < 5) {
        info(`No device detected yet — waiting and retrying (${attempt}/5)…`);
      }
    }
  }

  if (devices.length === 0) {
    warn(`No devices found in showDeviceList. Cannot proceed with 2FA setup.`);
    warn(`Make sure the Naver app is installed AND logged in with this account on your phone.`);
    return null;
  }

  const dev = devices[0];
  ok(`Found device: ${dev.name}`);

  // ===================================================================
  //  Step G — POST sendPushMessageToRegist (sends FCM push to phone)
  // ===================================================================
  await humanPause(1000, 2000);
  const pushUrl =
    "https://nid.naver.com/user2/help/2StepVerif?m=sendPushMessageToRegist";
  const pushBody =
    `token_help=${encodeURIComponent(tokenHelp)}` +
    `&delete_index=` +
    `&pushToken=${encodeURIComponent(dev.pushToken)}` +
    `&device=on`;
  r = await naverFetchRetry(
    pushUrl,
    {
      method: "POST",
      body: pushBody,
      referer: sdlUrl,
      headers: {
        ...desktopHeaders,
        Accept: "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
        "Content-Type": "application/x-www-form-urlencoded",
        Origin: "https://nid.naver.com",
        "sec-fetch-dest": "document",
        "sec-fetch-mode": "navigate",
        "sec-fetch-site": "same-origin",
        "sec-fetch-user": "?1",
        "upgrade-insecure-requests": "1",
      },
    },
    "POST sendPushMessageToRegist",
    3,
  );
  info(`sendPushMessageToRegist: HTTP ${r.status} (len ${(r.text || "").length})`);

  // Tell the user what to do on their phone
  console.log("");
  console.log(`  ${C.bold}${C.cyn}┌──────────────────────────────────────────────────────────────┐${C.reset}`);
  console.log(`  ${C.bold}${C.cyn}│  Push notification sent — open the Naver app on              │${C.reset}`);
  console.log(`  ${C.bold}${C.cyn}│  ${dev.name.slice(0, 32).padEnd(32)} and tap ${C.reset}${C.bold}${C.grn}YES${C.reset}${C.cyn}                       │${C.reset}`);
  console.log(`  ${C.bold}${C.cyn}│  (waiting indefinitely — press Ctrl+C to abort)              │${C.reset}`);
  console.log(`  ${C.bold}${C.cyn}└──────────────────────────────────────────────────────────────┘${C.reset}`);
  console.log("");

  // ===================================================================
  //  Step H — POST checkPushStatus (poll every 2s, no timeout)
  //  Returns {"resultCode":1, ...} while waiting; {"resultCode":0,...}
  //  when the user has approved on the phone.
  //
  //  HAR shows the captured user took 82s to approve and the browser
  //  re-sent the push via retrySendPushMessage every ~45s during the
  //  wait. We mirror the re-send cadence here, but poll FOREVER — the
  //  user explicitly asked us never to time out (only Ctrl+C aborts).
  // ===================================================================
  const cpsUrl =
    `https://nid.naver.com/user2/help/2StepVerif?m=checkPushStatus&${tokQS}`;
  const retryPushUrl =
    `https://nid.naver.com/user2/help/2StepVerif?m=retrySendPushMessage&${tokQS}`;
  const POLL_INTERVAL_MS = 2000;
  const RETRY_PUSH_EVERY_S = 45;
  let approved = false;
  let lastRetryAt = 0;
  let elapsedS = 0;
  // Infinite poll — no upper bound. User can Ctrl+C at any time.
  while (!approved) {
    await sleep(POLL_INTERVAL_MS);
    elapsedS += 2;

    // Periodic re-send of the push (fire-and-forget; HAR uses empty body).
    if (elapsedS - lastRetryAt >= RETRY_PUSH_EVERY_S) {
      lastRetryAt = elapsedS;
      try {
        await naverFetch(retryPushUrl, {
          method: "POST",
          body: "",
          referer: pushUrl,
          headers: {
            ...desktopHeaders,
            Accept: "*/*",
            "Content-Type": "application/x-www-form-urlencoded",
            "x-requested-with": "XMLHttpRequest",
            Origin: "https://nid.naver.com",
            "sec-fetch-dest": "empty",
            "sec-fetch-mode": "cors",
            "sec-fetch-site": "same-origin",
          },
        });
        info(`  …re-sent push notification at ${elapsedS}s`);
      } catch { /* ignore — main poll continues */ }
    }

    let cr;
    try {
      cr = await naverFetch(cpsUrl, {
        method: "POST",
        body: "",
        referer: pushUrl,
        headers: {
          ...desktopHeaders,
          Accept: "*/*",
          "Content-Type": "application/x-www-form-urlencoded",
          "x-requested-with": "XMLHttpRequest",
          Origin: "https://nid.naver.com",
          "sec-fetch-dest": "empty",
          "sec-fetch-mode": "cors",
          "sec-fetch-site": "same-origin",
        },
      });
    } catch {
      // Transient network errors during polling — keep trying forever.
      continue;
    }
    let parsed;
    try { parsed = JSON.parse(cr.text); } catch { continue; }
    if (parsed && parsed.resultCode === 0) {
      approved = true;
      ok(`User approved on phone ✅  (after ${elapsedS}s)`);
      break;
    }
    // Status update every 30 seconds so the user knows we're still waiting.
    if (elapsedS % 30 === 0) {
      info(`  …still waiting for push approval (${elapsedS}s elapsed — press YES on your phone)`);
    }
  }

  // ===================================================================
  //  Step I — GET setUp (Setup Complete page; confirms 2FA active)
  // ===================================================================
  await humanPause(800, 1500);
  const setupUrl =
    `https://nid.naver.com/user2/help/2StepVerif?m=setUp&${tokQS}`;
  r = await naverFetchRetry(
    setupUrl,
    {
      referer: pushUrl,
      headers: {
        ...desktopHeaders,
        Accept: "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
        "sec-fetch-dest": "document",
        "sec-fetch-mode": "navigate",
        "sec-fetch-site": "same-origin",
        "upgrade-insecure-requests": "1",
      },
    },
    "GET setUp (2FA active)",
    3,
  );
  info(`setUp: HTTP ${r.status} (len ${(r.text || "").length})`);
  ok(`2-Step Verification activated ✅`);
  await humanPause(1500, 3000);

  // ===================================================================
  //  Step J — GET viewManageSettings (now opens because 2FA is active)
  // ===================================================================
  const manageUrl =
    `https://nid.naver.com/user2/help/2StepVerif?m=viewManageSettings&${tokQS}`;
  r = await naverFetchRetry(
    manageUrl,
    {
      referer: setupUrl,
      headers: {
        ...desktopHeaders,
        Accept: "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
        "sec-fetch-dest": "document",
        "sec-fetch-mode": "navigate",
        "sec-fetch-site": "same-origin",
        "sec-fetch-user": "?1",
        "upgrade-insecure-requests": "1",
      },
    },
    "GET viewManageSettings",
    3,
  );
  info(`viewManageSettings: HTTP ${r.status} (len ${(r.text || "").length})`);
  // HAR shows ~20s of human dwell time on this page before submitting.
  info(`Pausing 12-22s to mimic human reading time before App Password submit…`);
  await humanPause(12000, 22000);

  // ===================================================================
  //  Step K — POST createApplicationPassword (the actual goal!)
  // ===================================================================
  const createUrl =
    `https://nid.naver.com/user2/help/2StepVerif?m=createApplicationPassword&${tokQS}`;
  r = await naverFetchRetry(
    createUrl,
    {
      method: "POST",
      body: `appName=${encodeURIComponent(appName)}`,
      referer: manageUrl,
      headers: {
        ...desktopHeaders,
        Accept: "*/*",
        "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
        "x-requested-with": "XMLHttpRequest",
        Origin: "https://nid.naver.com",
        "sec-fetch-dest": "empty",
        "sec-fetch-mode": "cors",
        "sec-fetch-site": "same-origin",
      },
    },
    "POST createApplicationPassword",
    3,
  );
  info(`createApplicationPassword: HTTP ${r.status} body="${(r.text || "").slice(0, 200)}"`);

  let parsed;
  try { parsed = JSON.parse(r.text); }
  catch {
    warn(`createApplicationPassword: non-JSON response: ${(r.text || "").slice(0, 200)}`);
    return null;
  }
  if (parsed && parsed.resultCode === 0 && parsed.passwd) {
    ok(`App Password generated ✅  ${parsed.passwd}  (seq ${parsed.seq})`);
    return parsed.passwd;
  }
  warn(`createApplicationPassword: unexpected response — ${JSON.stringify(parsed)}`);
  return null;
}

// --------------------------------------------------------------------------
//  Naver flow
// --------------------------------------------------------------------------
async function runNaverFlow(user) {
  // -------- Seed cookies — DA_DD, BMR, NNB (via nlog.naver.com) ----------
  info("Seeding device cookies (DA_DD, BMR, NNB via nlog)…");
  await seedNaverCookies();

  // -------- Step 1 — mobileUrlMapper.nhn (the OFFICIAL Naver Android-app
  // entry point for signup; using V2Join.nhn signals "web browser" which the
  // anti-bot uses to silently drop the SMS). ---------------------------------
  const deviceIdHex = require("crypto").randomBytes(16).toString("hex");
  const mapperUrl =
    `/login/ext/mobileUrlMapper.nhn?lang=en_US&device_id=${deviceIdHex}&mode=signup`;
  step(1, `GET ${mapperUrl}`);
  let r = await naverFetch(mapperUrl, {
    referer: `${NAVER_HOST}/`,
    headers: {
      Accept: "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
      "x-requested-with": "com.nhn.android.search",
      "sec-fetch-dest": "document",
      "sec-fetch-mode": "navigate",
      "sec-fetch-site": "none",
      "sec-fetch-user": "?1",
      "upgrade-insecure-requests": "1",
    },
  });
  if (r.status >= 400) throw new Error(`mobileUrlMapper failed: HTTP ${r.status}`);
  await humanPause(600, 1500);

  // -------- Step 2 — agree page contains a hidden form with token_sjoin --
  step(2, "GET /user2/join/agree?lang=en_US");
  r = await naverFetch(
    `/user2/join/agree?lang=en_US&device_id=${deviceIdHex}&realname=N&svc=&url=&rurl=`,
    {
      referer: `${NAVER_HOST}${mapperUrl}`,
      headers: {
        Accept: "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "x-requested-with": "com.nhn.android.search",
        "sec-fetch-dest": "document",
        "sec-fetch-mode": "navigate",
        "sec-fetch-site": "none",
        "sec-fetch-user": "?1",
        "upgrade-insecure-requests": "1",
      },
    }
  );
  if (r.status >= 400) throw new Error(`join/agree failed: HTTP ${r.status}`);

  // Extract token_sjoin from the hidden form on the agree page.
  const tokMatch = r.text.match(/name=["']token_sjoin["']\s+value=["']([^"']+)["']/);
  if (!tokMatch) throw new Error("token_sjoin not found in agree page");
  const tokenFromAgree = tokMatch[1];
  ok(`Extracted token_sjoin from agree page: ${tokenFromAgree}`);
  await humanPause(800, 2000);

  // -------- Step 3 — GET begin with the extracted token (mimics form submit) --
  step(3, "GET /user2/join/begin?token_sjoin=...");
  const beginQS = new URLSearchParams({
    token_sjoin: tokenFromAgree,
    langSelect: "en_US",
    checkRealname: "",
    termsLocation: "Y",
    termsEmail: "Y",
  }).toString();
  r = await naverFetch(`/user2/join/begin?${beginQS}`, {
    referer: `${NAVER_HOST}/user2/join/agree?lang=en_US&device_id=${deviceIdHex}&realname=N&svc=&url=&rurl=`,
    headers: {
      Accept: "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
      "x-requested-with": "com.nhn.android.search",
      "sec-fetch-dest": "document",
      "sec-fetch-mode": "navigate",
      "sec-fetch-site": "same-origin",
      "sec-fetch-user": "?1",
      "upgrade-insecure-requests": "1",
    },
  });
  if (r.status >= 400) throw new Error(`join/begin failed: HTTP ${r.status}`);

  // -------- Step 4 — parse begin page ---------------------------------
  step(4, "Parse begin page (token_sjoin + RSA + siteKeys)");
  const cfg = parseBeginPage(r.text);
  ok(`token_sjoin = ${cfg.token_sjoin}`);
  ok(`RSA keyName = ${cfg.keyName}, sessionKey len=${cfg.sessionKey.length}`);
  ok(`siteKey1 (sendAuthno) ...${cfg.siteKey1.slice(-12)}`);
  ok(`siteKey2 (final submit) ...${cfg.siteKey2.slice(-12)}`);

  const beginFullUrl =
    `${NAVER_HOST}/user2/join/begin?token_sjoin=${cfg.token_sjoin}` +
    `&langSelect=en_US&checkRealname=&termsLocation=Y&termsEmail=Y`;
  const referer = beginFullUrl;

  // -------- Step 5 — boot SDK sandbox ---------------------------------
  step(5, "Boot jsdom sandbox + load bvsd/ncaptcha/RSA");
  const dom = createSandbox(beginFullUrl);
  await initBvsd(dom);
  ok(`bvsd v${dom.window.sofa.VERSION} ready`);
  // Init TWO Koop instances: ncap1 for sendAuthno (siteKey1), ncap2 for join/end (siteKey2)
  const haveNcaptcha = await initNcaptcha(dom, cfg.siteKey1, cfg.siteKey2);
  if (haveNcaptcha) ok("ncaptcha2 ready (ncap1=sendAuthno siteKey1, ncap2=join/end siteKey2)");
  // Give the SDK a moment for any async XHR (to ncpt.naver.com) to settle
  await new Promise((r) => setTimeout(r, 800));
  const xhrs = dom.window.__xhrLog || [];
  if (xhrs.length === 0) {
    warn("ncaptcha SDK fired ZERO XHRs — running in local-fallback mode.");
    warn("Server-side nid_kb3 validation will likely fail silently.");
  } else {
    info(`SDK fired ${xhrs.length} XHR(s) during init:`);
    for (const x of xhrs) info(`   → ${x.method} ${x.url}`);
  }

  // Simulate the operator typing into the form (so bvsd captures real events).
  // CRITICAL: bvsd needs a rich stream of keydown/keypress/keyup/input/mouse/touch
  // events across multiple fields over ~12+ seconds to produce encData ≥ 3000 chars
  // (matching real HAR: 3021 chars). Without that, Naver silently drops SMS.
  await simulateTyping(dom, "id", user.id);
  await humanPause(400, 900);
  await simulateTyping(dom, "pswd1", user.pw);
  await humanPause(500, 1000);
  // Also type name/email/birthday — real user fills entire form before phone
  await simulateTyping(dom, "name",          user.name);
  await humanPause(300, 700);
  await simulateTyping(dom, "email",         user.email);
  await humanPause(300, 700);
  await simulateTyping(dom, "birthdayInput", user.birthday);
  await humanPause(500, 1200);

  // -------- Step 6 — checkId (TWICE, like real HAR) -------------------
  // HAR shows the real app does a first checkId with a slightly-wrong ID
  // (gets NNNNN = taken), then a second one with the final ID (NNNNY = free).
  // Without this double-check, Naver's bot-detection may flag the session.
  // The reference tool fires an nlog click event for input#id BEFORE checkId
  // so Naver's anti-bot sees a real "user clicked the field" signal.
  await postNlogClickEvent(cfg.token_sjoin, "input#id");
  await humanPause(600, 1200);
  step(6, `Check ID availability: ${user.id}`);
  const probeId = user.id.slice(0, -2) + Math.random().toString(36).slice(2, 4);
  const r6probe = await naverFetch(
    `/user2/joinAjax?m=checkId&id=${encodeURIComponent(probeId)}&key=${cfg.token_sjoin}`,
    { referer }
  );
  info(`checkId probe (${probeId}): ${r6probe.text.trim()}`);
  await humanPause(800, 1500);

  // Auto-retry loop: if the chosen username is already in use on Naver and we
  // have more candidates in the username.txt pool, pick the next one and try
  // again BEFORE we lease an SMS number (cheap retry, no money spent).
  while (true) {
    r = await naverFetch(
      `/user2/joinAjax?m=checkId&id=${encodeURIComponent(user.id)}&key=${cfg.token_sjoin}`,
      { referer }
    );
    const idResult = r.text.trim();
    info(`checkId final (${user.id}): ${idResult}`);
    if (idResult.endsWith("Y")) {
      ok("ID is available");
      break;
    }
    // Username is taken — surface a clear English message.
    warn(`Username "${user.id}" is already in use on Naver (response ${idResult}).`);
    const nextId = pickNextUsernameFromPool();
    if (!nextId) {
      throw new Error(
        `Username "${user.id}" is already in use on Naver and no more candidates ` +
        `are available${HAS_USERNAME_FILE ? " in username.txt" : ""}. Please add ` +
        `more usernames or try again later.`
      );
    }
    info(`Trying next username from username.txt: ${nextId}`);
    user.id = nextId;
    // Keep the email aligned with the new id (auto-generated style).
    user.email = `${nextId}${Math.floor(Math.random() * 9000 + 1000)}@gmail.com`;
    await humanPause(800, 1500);
    await postNlogClickEvent(cfg.token_sjoin, "input#id");
    await humanPause(600, 1200);
  }
  await humanPause(500, 1500);

  // -------- Step 7 — checkPswd ----------------------------------------
  // Reference tool fires nlog click for input#password BEFORE checkPswd.
  await postNlogClickEvent(cfg.token_sjoin, "input#password");
  await humanPause(800, 1500);
  step(7, "Check password strength");
  const pwBody = new URLSearchParams({
    id: user.id,
    pw: user.pw,
    service: "CHECK_JOIN",
  }).toString();
  r = await naverFetch("/user2/joinAjax?m=checkPswd", {
    method: "POST",
    body: pwBody,
    referer,
  });
  const pwResult = r.text.trim();
  info(`checkPswd response: ${pwResult}`);
  // Status digit 4 means strong, 2 means weak/etc. We accept >=2.
  if (!/^NNNN[1-9]$/.test(pwResult)) {
    warn(`Password score "${pwResult}" — proceeding anyway`);
  } else {
    ok(`Password accepted (score ${pwResult.slice(-1)})`);
  }
  await humanPause(800, 2000);

  // -------- Step 8 — get Polish phone from HeroSMS --------------------
  step(8, `Lease phone number from HeroSMS (country=${HEROSMS_COUNTRY}, +${HEROSMS_NATION_NO})`);
  const balance = await heroBalance();
  info(`HeroSMS balance: ${balance.toFixed(2)} RUB`);

  // DRY-RUN mode: verify the bvsd/ncaptcha/RSA payloads work end-to-end without
  // actually consuming a HeroSMS number. Used by the integration smoke test.
  if (process.env.NAVER_DRY_RUN === "1") {
    info("DRY_RUN=1 -> generating sample payloads and exiting before SMS lease");
    const fakePhone = "501234567";
    await simulateTyping(dom, "phoneNo", fakePhone);
    await humanPause(300, 600);
    const k2 = await generateNidKb2(dom);
    const { tokenId: k3 } = await fetchNcptTokenDirect(referer, cfg.siteKey1);
    const ep = encryptPassword(dom, cfg.sessionKey, cfg.keyName, cfg.eValue, cfg.nValue, user.id, user.pw);
    ok(`nid_kb2 generated (${k2.length} chars)`);
    ok(`nid_kb3 generated (${k3.length} chars) -> ${k3.slice(0, 60)}`);
    ok(`encPswd generated (${ep.length} chars)`);
    ok("DRY-RUN passed — full flow ready for real SMS lease.");
    dom.window.close();
    return true;
  }

  // ----- Phone source: HeroSMS auto-lease OR user-supplied number ----------
  let lease, phoneNo, nationNoToUse;
  if (user.smsSource === "manual") {
    info(`MANUAL phone mode — skipping HeroSMS lease`);
    phoneNo = user.phone;
    nationNoToUse = user.nation || POLAND_NATION_NO;
    lease = { id: null, phone: phoneNo, manual: true };
    ok(`Using your phone +${nationNoToUse} ${phoneNo}`);
  } else {
    const balance = await heroBalance();
    info(`HeroSMS balance: ${balance.toFixed(2)} RUB`);
    lease = await heroGetNumber();
    phoneNo = lease.phone;
    nationNoToUse = HEROSMS_NATION_NO;
    // Strip the country dialing prefix that HeroSMS includes in the phone number
    if (nationNoToUse === "48" && phoneNo.startsWith("48")) phoneNo = phoneNo.slice(2);
    else if (nationNoToUse === "40" && phoneNo.startsWith("40")) phoneNo = phoneNo.slice(2);
    else if (phoneNo.startsWith(nationNoToUse)) phoneNo = phoneNo.slice(nationNoToUse.length);
    ok(`Got number +${nationNoToUse} ${phoneNo} (activation #${lease.id})`);
  }

  // HAR analysis: real user spends ~33s between checkPswd and sendAuthno
  // (typing the phone number, scrolling, looking at the UI).  bvsd accumulates
  // mouse moves / touch events / scroll events during that window, which is why
  // real HAR encData is ~3 000 chars vs our former ~2 350 chars.
  // We now type the phone number first, then keep bvsd warm for the remainder.
  // Reference tool fires nlog clicks for name / birthYear / gender BEFORE
  // sendAuthno so the anti-bot sees the user filling out every field, not
  // just the phone number. Without these, Naver returns NNNNS but silently
  // drops the SMS dispatch.
  await postNlogClickEvent(cfg.token_sjoin, "input#name");
  await humanPause(800, 1400);
  await postNlogClickEvent(cfg.token_sjoin, "input#birthYear");
  await humanPause(600, 1100);
  await postNlogClickEvent(cfg.token_sjoin, "select#gender");
  await humanPause(600, 1300);
  await postNlogClickEvent(cfg.token_sjoin, "input#phoneNo");
  await humanPause(500, 1000);
  await simulateTyping(dom, "phoneNo", phoneNo);
  // Reference tool fires sendAuthno only ~12-20 s after page load (no
  // additional warm-up). Long warm-ups make Naver's anti-bot suspicious that
  // a "user" is sitting idle without interacting → silently drops SMS.
  // We keep a brief 5 s window so bvsd still captures a few touch/scroll
  // events but stay close to the reference tool's natural timing.
  const WARM_UP_MS = 5000;
  await simulateFormActivity(dom, WARM_UP_MS);

  try {
    // -------- Step 9 — sendAuthno (with nid_kb2 AND nid_kb3) -----------
    // CRITICAL: real Naver app sends BOTH nid_kb2 and nid_kb3 here.
    // Sending only nid_kb2 makes Naver respond NNNNS (success-looking) but
    // silently DROP the SMS dispatch. This is their anti-bot measure.
    step(9, "POST /user2/joinAjax?m=sendAuthno (nid_kb2 + nid_kb3)");
    // HAR: nlog click event fires ~2s BEFORE sendAuthno (exact same order every time).
    // click_area "input.sendFrgn" = the user tapped the "Send verification code" button.
    await postNlogClickEvent(cfg.token_sjoin);
    await humanPause(900, 1400);  // ~1s gap: nlog → v2/tokens → sendAuthno
    // nid_kb2: dynamic bvsd SDK (jsdom) — user requirement
    // nid_kb3: direct HTTP to ncpt.naver.com identical to reference tool
    const [nid_kb2_send, ncptSend] = await Promise.all([
      generateNidKb2(dom),
      fetchNcptTokenDirect(referer, cfg.siteKey1),
    ]);
    const nid_kb3_send = ncptSend.tokenId;
    // After token fetch, fire accessLog (same as ref: fetchNcptToken → callNcptAccessLog)
    const sendCookies = await jar.getCookieString("https://ncpt.naver.com");
    await callNcptAccessLogDirect(referer, sendCookies).catch(() => {});
    info(`nid_kb2 length=${nid_kb2_send.length}, nid_kb3 length=${nid_kb3_send.length}`);
    if (!nid_kb3_send || nid_kb3_send.length < 20) {
      throw new Error(`nid_kb3 looks invalid (${nid_kb3_send?.length} chars) — Naver will silently drop SMS. Aborting.`);
    }
    const sendUrl =
      `/user2/joinAjax?m=sendAuthno&tp=normal&nationNo=${nationNoToUse}` +
      `&mobno=${encodeURIComponent(phoneNo)}&lang=en_US&key=${cfg.token_sjoin}&id=${encodeURIComponent(user.id)}`;
    const sendBody = new URLSearchParams({
      nid_kb2: nid_kb2_send,
      nid_kb3: nid_kb3_send,
    }).toString();

    const tSent = Date.now();
    r = await naverFetch(sendUrl, { method: "POST", body: sendBody, referer });
    const dt = Date.now() - tSent;
    const respText = r.text.trim();
    info(`sendAuthno HTTP ${r.status} in ${dt}ms — body: "${respText}"`);

    // Naver response format: 5 chars XXXXX where:
    //   pos 1-4: validation flags (N=no error)
    //   pos 5  : action result (S=SMS sent, Y=ok, N=fail)
    if (respText.length !== 5 || !/^[NY]{4}[SYN]$/.test(respText)) {
      throw new Error(`Unexpected sendAuthno response shape: "${respText}"`);
    }
    const lastChar = respText[4];
    if (lastChar !== "S" && lastChar !== "Y") {
      throw new Error(`Naver REFUSED to send SMS (response "${respText}"). ` +
        `Possible causes: phone format wrong, country blocked, IP banned, daily quota.`);
    }
    if (respText.startsWith("NNNN") && lastChar === "S") {
      ok(`✅ SMS DISPATCH CONFIRMED by Naver at ${new Date(tSent).toISOString()}`);
      ok(`   Target: +${nationNoToUse} ${phoneNo}  (response NNNNS = real send)`);
    } else {
      warn(`Partial accept: "${respText}". SMS may or may not arrive — watch your phone.`);
    }
    if (!lease.manual) await heroSetStatus(lease.id, 1); // mark "SMS sent"

    // -------- Step 10 — get SMS code ----------------------------------
    let code;
    if (lease.manual) {
      step(10, `Waiting for SMS on +${nationNoToUse} ${phoneNo}`);
      if (process.env.NV_SMS_CODE) {
        code = process.env.NV_SMS_CODE.replace(/\D/g, "");
        info(`Using NV_SMS_CODE from env: ${code}`);
      } else {
        // Interactive: ask the user to type the code directly in the terminal
        console.log("");
        console.log(`  ${C.bold}${C.ylw}╔══════════════════════════════════════════════════════╗${C.reset}`);
        console.log(`  ${C.bold}${C.ylw}║  SMS sent to: +${(nationNoToUse + " " + phoneNo).padEnd(37)}║${C.reset}`);
        console.log(`  ${C.bold}${C.ylw}║  Check your phone and type the 6-digit code below.  ║${C.reset}`);
        console.log(`  ${C.bold}${C.ylw}╚══════════════════════════════════════════════════════╝${C.reset}`);
        console.log("");
        let rawCode = "";
        while (true) {
          rawCode = await ask("Enter the SMS code you received");
          const clean = rawCode.replace(/\D/g, "");
          if (/^\d{4,6}$/.test(clean)) {
            code = clean;
            break;
          }
          console.log(`  ${C.ylw}✗ Code must be 4-6 digits. Try again.${C.reset}`);
        }
        console.log(`  ${C.grn}✓ Code accepted: ${code}${C.reset}`);
        console.log("");
      }
    } else {
      step(10, "Poll HeroSMS for 4-digit code (timeout 10 min)");
      code = await heroPollCode(lease.id);
    }
    ok(`Got SMS code: ${code}`);
    await humanPause(1000, 2500);

    // Refresh timing cookies to simulate that the session has been alive
    // long enough for the user to receive an SMS and type the code in.
    // The reference tool does this exact step right before checkAuthno.
    {
      const nowSec = Math.floor(Date.now() / 1000);
      try {
        await jar.setCookie(
          `SRT5=${nowSec - 120}; Domain=.naver.com; Path=/; Secure; Max-Age=300`,
          "https://naver.com"
        );
        await jar.setCookie(
          `SRT30=${nowSec - 300}; Domain=.naver.com; Path=/; Secure; Max-Age=1800`,
          "https://naver.com"
        );
        await jar.setCookie(
          `BMR=s=${Date.now()}&r=&r2=; Domain=.naver.com; Path=/; Secure`,
          "https://naver.com"
        );
        info("Refreshed SRT5/SRT30/BMR timing cookies before checkAuthno");
      } catch (e) {
        warn(`cookie refresh failed (non-fatal): ${e.message}`);
      }
    }

    // Reference tool fires nlog click for input#authNo before checkAuthno.
    await postNlogClickEvent(cfg.token_sjoin, "input#authNo");
    await humanPause(600, 1200);

    // -------- Step 11 — checkAuthno -----------------------------------
    step(11, `GET /user2/joinAjax?m=checkAuthno&authno=${code}`);
    r = await naverFetch(
      `/user2/joinAjax?m=checkAuthno&authno=${code}&key=${cfg.token_sjoin}`,
      { referer }
    );
    info(`checkAuthno response: ${r.text.trim()}`);
    if (!r.text.trim().endsWith("S")) {
      throw new Error(`checkAuthno failed: ${r.text}`);
    }
    ok("Code accepted by Naver");
    await humanPause(800, 2000);

    // -------- Step 12 — final POST /user2/join/end --------------------
    step(12, "POST /user2/join/end (final submission)");
    // nid_kb2: dynamic bvsd SDK (jsdom) — user requirement
    // nid_kb3: direct HTTP to ncpt.naver.com identical to reference tool
    const [nid_kb2_final, ncptJoin] = await Promise.all([
      generateNidKb2(dom),
      fetchNcptTokenDirect(referer, cfg.siteKey2),
    ]);
    const nid_kb3_join = ncptJoin.tokenId;
    const encPswd = encryptPassword(
      dom,
      cfg.sessionKey,
      cfg.keyName,
      cfg.eValue,
      cfg.nValue,
      user.id,
      user.pw
    );

    const endParams = new URLSearchParams();
    endParams.set("token_sjoin", cfg.token_sjoin);
    endParams.set("nid_kb2", nid_kb2_final);
    endParams.set("nid_kb3", nid_kb3_join);
    endParams.set("joinMode", "joinOccupancy");
    endParams.set("encPswd", encPswd);
    endParams.set("encKey", cfg.keyName);
    endParams.set("telecom", "");
    endParams.set("birthday", user.birthday);
    endParams.set("id", user.id);
    endParams.set("pswd1", user.pw);
    endParams.set("email", user.email);
    endParams.set("name", user.name);
    endParams.set("foreigner", "K");
    endParams.set("gender", user.gender);
    endParams.set("nationNo", nationNoToUse);
    endParams.set("phoneNo", phoneNo);
    endParams.set("authNo6", "");
    endParams.set("authNo4", code);

    info(`encPswd length=${encPswd.length}, nid_kb3 length=${nid_kb3_join.length}`);

    // Fire errorLog + etk (joinSignals) + accessLog before joinEnd POST.
    // Confirmed from HAR: errorLog → etk → accessLog → POST /user2/join/end
    const joinCookies = await jar.getCookieString("https://ncpt.naver.com");
    await callNcptJoinSignalsDirect(referer, joinCookies);
    await callNcptAccessLogDirect(referer, joinCookies).catch(() => {});
    info("ncpt signals fired before joinEnd");

    // joinEnd uses navigate mode (not xhr/cors) — confirmed from ref HAR capture.
    // viewport-width must be 980 (WebView desktop mode) for this endpoint.
    const joinEndUrl = `${NAVER_HOST}/user2/join/end`;
    r = await naverFetch(joinEndUrl, {
      method: "POST",
      body: endParams.toString(),
      referer,
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
        "cache-control": "max-age=0",
        "x-requested-with": "com.nhn.android.search",
        "sec-fetch-dest": "document",
        "sec-fetch-mode": "navigate",
        "sec-fetch-user": "?1",
        "sec-fetch-site": "same-origin",
        "upgrade-insecure-requests": "1",
        "viewport-width": "980",
        "priority": "u=0, i",
      },
    });

    const success = r.text.includes("Welcome,") || r.text.includes("welcome_wrap");
    if (success) {
      ok("Account created successfully ✅");
      if (!lease.manual) {
        await heroSetStatus(lease.id, 6);
        ok(`HeroSMS activation marked complete`);
      }

      // -------- Step 13 — IMAP/SMTP activation on the freshly created
      // account, using the same authenticated cookie jar (NID_AUT/NID_SES
      // were set by /user2/join/end). Wrapped in try/catch so a mail-side
      // failure NEVER invalidates the successful registration above. -----
      let imapStatus = "skipped";
      let imapOk = false;
      try {
        await humanPause(1500, 3000);
        step(13, "Activate IMAP/SMTP on the new account");
        imapOk = await activateImap(user.id, user.pw);
        imapStatus = imapOk ? "ACTIVATED ✅" : "FAILED ❌";
      } catch (e) {
        err(`IMAP activation threw: ${e.message}`);
        imapStatus = `ERROR: ${e.message}`;
      }

      // -------- Step 14 — generate Naver Application Password (the actual
      // credential mail clients need to log into IMAP/SMTP). Only attempted
      // if Step 13 returned OK — no point if IMAP isn't even active. Goes
      // through the SAME proxy/session as registration. Wrapped in try/catch
      // so a failure here NEVER invalidates the successful steps above. ----
      let appPassword = null;
      let appPassStatus = "skipped";
      if (imapOk) {
        try {
          await humanPause(1500, 3000);
          step(14, "Generate Application Password (re-auth + create)");
          appPassword = await generateAppPassword(user.id, user.pw, "Direct");
          appPassStatus = appPassword ? `${appPassword} ✅` : "FAILED ❌";
        } catch (e) {
          err(`App Password generation threw: ${e.message}`);
          appPassStatus = `ERROR: ${e.message}`;
        }
      } else {
        appPassStatus = "skipped (IMAP not active)";
      }

      const proxyDisplayFinal = PROXY_URL
        ? PROXY_URL.replace(/\/\/([^:@]+):([^@]+)@/, "//$1:***@")
        : "none (direct)";
      console.log(`\n${C.bold}${C.grn}=== SUMMARY ===${C.reset}`);
      console.log(`  ID:           ${user.id}`);
      console.log(`  Password:     ${user.pw}     (web/Naver login)`);
      console.log(`  Phone:        +${nationNoToUse} ${phoneNo}`);
      console.log(`  Email:        ${user.email}`);
      console.log(`  Name:         ${user.name}`);
      console.log(`  Birthday:     ${user.birthday}`);
      console.log(`  Gender:       ${user.gender}`);
      console.log(`  Proxy:        ${proxyDisplayFinal}`);
      console.log(`  IMAP:         ${imapStatus}`);
      console.log(`  App Password: ${appPassStatus}${appPassword ? "     (use for IMAP/SMTP)" : ""}`);

      // Persist the full account record to accounts.json (append-mode)
      const record = {
        id:          user.id,
        loginEmail:  `${user.id}@naver.com`,
        password:    user.pw,
        name:        user.name,
        birthday:    user.birthday,
        gender:      user.gender,
        recoveryEmail: user.email,
        phone:       `+${nationNoToUse}${phoneNo}`,
        proxy:       PROXY_URL || null,
        imap:        imapStatus,
        appPassword: appPassword,
        createdAt:   new Date().toISOString(),
      };
      if (appendAccountRecord(record)) {
        ok(`Account saved to ${path.basename(ACCOUNTS_FILE)}`);
      } else {
        warn(`Failed to save account to ${path.basename(ACCOUNTS_FILE)} — check file permissions`);
      }
      return true;
    } else {
      // Try to extract error message from the response
      const m = r.text.match(/<title>([^<]+)<\/title>/);
      err(`join/end did not return success page (title: ${m ? m[1] : "?"})`);
      // Save response for debugging
      const debugFile = `naver_join_end_${Date.now()}.html`;
      fs.writeFileSync(debugFile, r.text);
      err(`Full response saved to ${debugFile}`);
      return false;
    }
  } catch (e) {
    err(`Flow error: ${e.message}`);
    if (!lease.manual) {
      try {
        await heroSetStatus(lease.id, 8); // cancel activation, refund
        info("HeroSMS activation cancelled");
      } catch {}
    }
    throw e;
  } finally {
    dom.window.close();
  }
}

// --------------------------------------------------------------------------
//  Entry point
// --------------------------------------------------------------------------
(async () => {
  try {
    const user = await askInputs();
    // Apply HeroSMS API key if user provided one interactively
    if (user.heroKey) HEROSMS_KEY = user.heroKey;
    await runNaverFlow(user);
    closeRl();
  } catch (e) {
    err(e.message);
    closeRl();
    process.exit(1);
  }
})();
