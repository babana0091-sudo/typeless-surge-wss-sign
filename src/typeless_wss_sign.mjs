import CryptoJS from 'crypto-js';

installCryptoJsRandomFallback();

(function main() {
  const DEFAULTS = {
    appVersion: 'android_1.11.0',
    apiPath: '',
    mode: '',
    debug: '0',
  };

  const req = typeof $request !== 'undefined' ? $request : null;
  if (!req || !req.url) {
    doneUntouched('missing_request');
    return;
  }

  const cfg = Object.assign({}, DEFAULTS, parseArgument(typeof $argument === 'string' ? $argument : ''));
  cfg.debug = /^(1|true|yes|on)$/i.test(String(cfg.debug || ''));

  const missing = ['userId', 'refreshToken', 'deviceId', 'aesKey', 'sm3Key'].filter((k) => !cfg[k]);
  if (missing.length) {
    log('skip: missing argument(s): ' + missing.join(','));
    doneUntouched('missing_config');
    return;
  }

  try {
    const rewritten = rewriteTypelessWsUrl(req.url, cfg);
    if (!rewritten || !rewritten.url) {
      doneUntouched('no_rewrite');
      return;
    }
    log('rewrote WSS t: source=Date.now, ts=' + rewritten.timestamp + ', version=' + rewritten.appVersion + ', apiPath=' + rewritten.apiPath + ', encLen=' + rewritten.encryptedLength);
    $done({ url: rewritten.url, headers: req.headers });
  } catch (e) {
    log('rewrite error: ' + (e && e.stack ? e.stack : e));
    doneUntouched('rewrite_error');
  }

  function rewriteTypelessWsUrl(url, cfg) {
    const parsed = parseUrl(url);
    if (!parsed || !/\/ws\//.test(parsed.path || '')) return null;

    const query = parseQuery(parsed.query || '');
    const apiPath = normalizeApiPath(cfg.apiPath || parsed.path.replace(/^\/ws/, '') || '/rt_voice_flow');
    const appVersion = normalizeAndroidVersion(cfg.appVersion || query.v || 'android_1.11.0');
    const mode = cfg.mode !== '' ? String(cfg.mode) : (query.m != null ? String(query.m) : '0');

    // 获取时间戳：不再调用任何第三方时间 API，在签名前立刻读取 Surge JS 运行环境系统时间。
    const timestamp = Date.now();

    const signString = `${timestamp}:${appVersion}:/ws${apiPath}:${cfg.userId}`;
    const signKey = `${timestamp}:${cfg.sm3Key}`;
    const signature = CryptoJS.HmacSHA1(signString, signKey).toString(CryptoJS.enc.Hex);
    const payload = {
      token: cfg.refreshToken,
      s: signature,
      t: timestamp,
      d: cfg.deviceId,
    };
    const encrypted = CryptoJS.AES.encrypt(JSON.stringify(payload), cfg.aesKey).toString();

    query.v = appVersion;
    query.t = encrypted;
    query.m = mode;

    const outQuery = buildQuery(query);
    return {
      url: `${parsed.scheme}//${parsed.host}/ws${apiPath}${outQuery ? '?' + outQuery : ''}`,
      timestamp,
      appVersion,
      apiPath,
      encryptedLength: encrypted.length,
    };
  }

  function parseArgument(argument) {
    const out = {};
    const raw = String(argument || '').trim();
    if (!raw) return out;
    if (raw[0] === '{') {
      try { return JSON.parse(raw); } catch (_) { return out; }
    }
    raw.split('&').forEach((part) => {
      if (!part) return;
      const idx = part.indexOf('=');
      const k = decodeURIComponent(idx >= 0 ? part.slice(0, idx) : part).trim();
      if (!k) return;
      const v = idx >= 0 ? part.slice(idx + 1) : '';
      out[k] = decodeURIComponent(v.replace(/\+/g, '%20'));
    });
    return out;
  }

  function parseUrl(url) {
    const m = String(url).match(/^([a-z][a-z0-9+.-]*:)\/\/([^/?#]+)([^?#]*)(?:\?([^#]*))?(?:#(.*))?$/i);
    if (!m) return null;
    return { scheme: m[1], host: m[2], path: m[3] || '/', query: m[4] || '', fragment: m[5] || '' };
  }

  function parseQuery(qs) {
    const out = {};
    String(qs || '').split('&').forEach((part) => {
      if (!part) return;
      const idx = part.indexOf('=');
      const k = decodeURIComponent(idx >= 0 ? part.slice(0, idx) : part);
      const v = idx >= 0 ? part.slice(idx + 1) : '';
      out[k] = decodeURIComponent(v.replace(/\+/g, '%20'));
    });
    return out;
  }

  function buildQuery(query) {
    const keys = Object.keys(query).filter((k) => query[k] !== undefined && query[k] !== null);
    return keys.map((k) => encodeURIComponent(k) + '=' + encodeURIComponent(String(query[k]))).join('&');
  }

  function normalizeApiPath(path) {
    let p = String(path || '/rt_voice_flow');
    if (p.indexOf('/ws/') === 0) p = p.slice(3);
    if (p[0] !== '/') p = '/' + p;
    return p;
  }

  function normalizeAndroidVersion(v) {
    let s = String(v || 'android_1.11.0').split('-')[0];
    s = s.replace(/^ios_/i, 'android_');
    if (!/^android_/i.test(s)) {
      const m = s.match(/(\d+(?:\.\d+){1,3})/);
      s = 'android_' + (m ? m[1] : '1.11.0');
    }
    return s;
  }

  function log(msg) {
    if (cfg && cfg.debug) console.log('[TypelessSign] ' + msg);
  }

  function doneUntouched(reason) {
    try { console.log('[TypelessSign] pass-through: ' + reason); } catch (_) {}
    $done({});
  }
})();

function installCryptoJsRandomFallback() {
  // Surge's JavaScriptCore environment may not expose WebCrypto/Node crypto.
  // CryptoJS passphrase AES only needs this for the OpenSSL salt. The salt is not
  // secret; it just must vary so the encrypted `t` blob is not deterministic.
  CryptoJS.lib.WordArray.random = function randomWordArray(nBytes) {
    const words = [];
    const useNative = typeof globalThis !== 'undefined'
      && globalThis.crypto
      && typeof globalThis.crypto.getRandomValues === 'function'
      && typeof Uint8Array !== 'undefined';
    let bytes = null;
    if (useNative) {
      try {
        bytes = new Uint8Array(nBytes);
        globalThis.crypto.getRandomValues(bytes);
      } catch (_) {
        bytes = null;
      }
    }
    for (let i = 0; i < nBytes; i++) {
      const b = bytes ? bytes[i] : Math.floor(Math.random() * 256) & 0xff;
      words[i >>> 2] |= b << (24 - (i % 4) * 8);
    }
    return CryptoJS.lib.WordArray.create(words, nBytes);
  };
}
