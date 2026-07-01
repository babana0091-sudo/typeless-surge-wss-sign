# Typeless Surge WSS Fresh Sign

Generic Surge JavaScript for rewriting the Typeless `/ws/rt_voice_flow` WebSocket handshake `t` query parameter.

## What is public here

This repository contains only generic code:

- `src/typeless_wss_sign.mjs` — source script.
- `dist/typeless_wss_sign.js` — bundled Surge-ready script.
- `templates/typeless_wss_fresh_sign.sgmodule.template` — module template with placeholders.

## What must stay private

Do **not** commit your live values:

- Typeless refresh token
- user ID
- device ID
- extracted Android AES/signing keys if you treat them as private
- packet captures or replay data

Those values should be kept in your private local `.sgmodule` only.

## Surge module shape

Use the template in `templates/` and replace placeholders locally. The deployed script reads private values from Surge `$argument`:

```text
userId=...&refreshToken=...&deviceId=...&aesKey=...&sm3Key=...
```

The script then:

1. reads `Date.now()` immediately before signing,
2. computes HMAC-SHA1 signature `s`,
3. builds `{ token, s, t, d }`,
4. encrypts that JSON with `CryptoJS.AES.encrypt(..., aesKey)`,
5. writes the encrypted result back to the URL query parameter `t`,
6. forces `v=android_1.11.0` by default.

## Build and test

```bash
npm install
npm run build
npm test
```
