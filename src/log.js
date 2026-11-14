"use strict";
// Tiny structured logger. NEVER pass secrets (HMAC secret, API keys, salt,
// strategy params) to it — call sites log ids, decisions and timings only.
function makeLogger(level = "info") {
  const levels = { debug: 0, info: 1, warn: 2, error: 3 };
  const min = levels[level] !== undefined ? levels[level] : 1;
  return function log(lvl, msg, meta) {
    if ((levels[lvl] || 1) < min) return;
    const line = { t: new Date().toISOString(), lvl, msg, ...(meta || {}) };
    process.stderr.write(JSON.stringify(line) + "\n");
  };
}
module.exports = { makeLogger };
