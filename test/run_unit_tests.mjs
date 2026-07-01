import fs from 'node:fs';
import vm from 'node:vm';
import assert from 'node:assert/strict';
import CryptoJS from 'crypto-js';

const bundle = fs.readFileSync(new URL('../dist/typeless_wss_sign.js', import.meta.url), 'utf8');

function encArg(obj) {
  return Object.entries(obj).map(([k, v]) => `${encodeURIComponent(k)}=${encodeURIComponent(String(v))}`).join('&');
}

const cfg = {
  userId: 'user-123',
  refreshToken: 'refresh-token-abc',
  deviceId: '00000000-0000-4000-8000-000000000001',
  aesKey: 'test-passphrase',
  sm3Key: 'sm3-secret',
  appVersion: 'android_1.11.0',
  debug: '1',
};

let doneValue;
const logs = [];
const before = Date.now();
const context = {
  console: { log: (msg) => logs.push(String(msg)) },
  Date,
  Math,
  Uint8Array,
  globalThis,
  $argument: encArg(cfg),
  $request: {
    url: 'wss://api.typeless.com/ws/rt_voice_flow?v=ios_1.11.0&t=old&m=0',
    headers: { Upgrade: 'websocket' },
  },
  $persistentStore: {
    read: () => { throw new Error('persistent store should not be used'); },
    write: () => { throw new Error('persistent store should not be used'); },
  },
  $httpClient: {
    get: () => { throw new Error('third-party/API time lookup should not be used'); },
  },
  $done: (value) => { doneValue = value; },
};
vm.createContext(context);
vm.runInContext(bundle, context, { timeout: 3000 });
const after = Date.now();

assert.ok(doneValue && doneValue.url, 'script returned rewritten URL');
assert.match(doneValue.url, /^wss:\/\/api\.typeless\.com\/ws\/rt_voice_flow\?/);
const url = new URL(doneValue.url);
assert.equal(url.searchParams.get('v'), 'android_1.11.0');
assert.equal(url.searchParams.get('m'), '0');
assert.notEqual(url.searchParams.get('t'), 'old');
const encrypted = url.searchParams.get('t');
assert.ok(encrypted && encrypted.length > 50, 'encrypted t exists');
const plain = CryptoJS.AES.decrypt(encrypted, cfg.aesKey).toString(CryptoJS.enc.Utf8);
assert.ok(plain, 'encrypted t decrypts');
const payload = JSON.parse(plain);
assert.equal(payload.token, cfg.refreshToken);
assert.equal(payload.d, cfg.deviceId);
assert.equal(typeof payload.t, 'number');
assert.ok(payload.t >= before && payload.t <= after, 'timestamp came directly from local Date.now during request rewrite');
const expectedSig = CryptoJS.HmacSHA1(`${payload.t}:android_1.11.0:/ws/rt_voice_flow:${cfg.userId}`, `${payload.t}:${cfg.sm3Key}`).toString(CryptoJS.enc.Hex);
assert.equal(payload.s, expectedSig);
console.log(JSON.stringify({ ok: true, rewritten: true, timestampSource: 'Date.now', deviceId: payload.d, payloadKeys: Object.keys(payload).sort(), logs: logs.length }, null, 2));
