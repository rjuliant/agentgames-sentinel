"use strict";
// Groth16 proof generation + local verification via snarkjs.
// VK JSONs are exported once from the .zkey files into data/ (startup,
// via the snarkjs CLI) and cached in memory.
const fs = require("fs");
const path = require("path");
const { execFile } = require("child_process");
const snarkjs = require("snarkjs");

const CIRCUITS = {
  gatekeeper: { wasm: "gatekeeper.wasm", zkey: "gatekeeper_final.zkey", vkJson: "gatekeeper_vk.json" },
  "vfy-policy": { wasm: "vfy-policy.wasm", zkey: "vfy-policy_final.zkey", vkJson: "vfy-policy_vk.json" },
};

const vkCache = new Map();

function circuitPaths(cfg, name) {
  const c = CIRCUITS[name];
  if (!c) throw new Error(`unknown circuit: ${name}`);
  return {
    wasm: path.join(cfg.circuitsDir, c.wasm),
    zkey: path.join(cfg.circuitsDir, c.zkey),
    vkJson: path.join(cfg.dataDir, c.vkJson),
    vkJsonName: c.vkJson,
  };
}

async function ensureVk(cfg, name, log) {
  if (vkCache.has(name)) return vkCache.get(name);
  const p = circuitPaths(cfg, name);
  if (!fs.existsSync(p.vkJson)) {
    const cli = path.join(__dirname, "..", "node_modules", ".bin", "snarkjs");
    await new Promise((resolve, reject) => {
      execFile(cli, ["zkey", "export", "verificationkey", p.zkey, p.vkJson],
        (err, _out, stderr) => (err ? reject(new Error("VK export failed: " + stderr)) : resolve()));
    });
    if (log) log("info", `exported VK for ${name} -> data/${p.vkJsonName}`);
  }
  const vk = JSON.parse(fs.readFileSync(p.vkJson, "utf8"));
  vkCache.set(name, vk);
  return vk;
}

// fullProve with an outer timeout race (snarkjs itself is not cancellable;
// a late proof is simply ignored by the caller when the race is lost).
async function fullProve(cfg, name, input, timeoutMs) {
  const p = circuitPaths(cfg, name);
  const started = Date.now();
  const prove = snarkjs.groth16.fullProve(input, p.wasm, p.zkey);
  let timer;
  const timeout = new Promise((_, reject) => {
    timer = setTimeout(() => reject(Object.assign(new Error(`proof generation timed out after ${timeoutMs}ms`), { code: "PROOF_TIMEOUT" })), timeoutMs);
    if (timer.unref) timer.unref();
  });
  try {
    const { proof, publicSignals } = await Promise.race([prove, timeout]);
    return { proof, publicSignals, ms: Date.now() - started };
  } finally {
    clearTimeout(timer);
  }
}

async function verifyLocal(cfg, name, publicSignals, proof, log) {
  const vk = await ensureVk(cfg, name, log);
  return snarkjs.groth16.verify(vk, publicSignals, proof);
}

module.exports = { fullProve, verifyLocal, ensureVk, circuitPaths, CIRCUITS };
