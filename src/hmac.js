"use strict";
// HMAC signing/verification for x-agent-games-signature.
// SPEC §3: the exact digest/encoding is UNVERIFIED, so both are config
// switches (HMAC_ALGO / HMAC_ENCODING). Verification optionally accepts the
// alternate encoding too and reports which one matched, so the first real
// preflight reveals the platform's choice in the logs.
const crypto = require("crypto");

function digestStr(cfg, bodyBuffer, encoding) {
  // digest(encoding) returns a string for hex/base64.
  return crypto.createHmac(cfg.hmacAlgo, cfg.hmacSecret).update(bodyBuffer).digest(encoding);
}

function sign(cfg, bodyBuffer) {
  return digestStr(cfg, bodyBuffer, cfg.hmacEncoding);
}

function safeEqualStr(a, b) {
  const ba = Buffer.from(String(a));
  const bb = Buffer.from(String(b));
  if (ba.length !== bb.length) return false;
  return crypto.timingSafeEqual(ba, bb);
}

// Returns { ok, encoding } — encoding is the one that matched (or null).
function verify(cfg, headerValue, bodyBuffer) {
  if (!headerValue || typeof headerValue !== "string") return { ok: false, encoding: null };
  if (safeEqualStr(headerValue, digestStr(cfg, bodyBuffer, cfg.hmacEncoding))) {
    return { ok: true, encoding: cfg.hmacEncoding };
  }
  if (cfg.hmacAcceptAlt) {
    const alt = cfg.hmacEncoding === "hex" ? "base64" : "hex";
    if (safeEqualStr(headerValue, digestStr(cfg, bodyBuffer, alt))) return { ok: true, encoding: alt };
  }
  return { ok: false, encoding: null };
}

module.exports = { sign, verify };
