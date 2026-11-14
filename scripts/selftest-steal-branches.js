#!/usr/bin/env node
"use strict";
// Steal branch self-test for the DEPLOYED strategy params (reads
// STRATEGY_PARAMS / STRATEGY_SALT from config/env; never prints the salt).
// Verifies Groth16 proofs against the exported vfy-policy VK for all three
// circuit branches reachable under the deployed params:
//   EXTRACT (self >= params[1], opp > params[2])
//   FORTIFY (self <  params[1])
//   HOLD    (opp <= params[2])
// Also prints the strategy commitment = Poseidon(params, salt) — the value
// that must be registered on the dashboard. Exit 0 iff all proofs verify.
const { loadConfig } = require("../src/config");
const { makeLogger } = require("../src/log");
const { buildWitness } = require("../src/witness");
const proofMod = require("../src/proof");
const { buildPoseidon } = require("circomlibjs");

const log = makeLogger("info");
let failures = 0;

async function check(label, fn) {
  try {
    const detail = await fn();
    console.log(`PASS  ${label}${detail ? " — " + detail : ""}`);
  } catch (e) {
    failures++;
    console.log(`FAIL  ${label} — ${e.message}`);
  }
}

(async () => {
  const cfg = loadConfig({ proofTimeoutMs: 60000 });
  const params = JSON.parse(cfg.strategyParamsJson);
  const salt = cfg.strategySalt;
  if (!salt) throw new Error("STRATEGY_SALT not configured");
  console.log(`params=${JSON.stringify(params)}`);

  const poseidon = await buildPoseidon();
  const commitment = poseidon.F.toObject(poseidon([...params.map(BigInt), BigInt(salt)])).toString();
  const commitmentHex = "0x" + BigInt(commitment).toString(16).padStart(64, "0");
  console.log(`commitment=${commitmentHex}`);

  const mkEnvelope = (self, opp) => ({
    matchId: "9f4e1b2a-1111-2222-3333-444455556666", turn: 3,
    state: { selfBalance: String(self), opponentBalance: String(opp) },
    strategyCommitment: { hash: commitmentHex },
  });
  const prove = async (self, opp, actionCode, actionAmount) => {
    const { input } = buildWitness("steal", {
      envelope: mkEnvelope(self, opp), actionCode, actionAmount,
      env: { STRATEGY_SALT: salt, STRATEGY_PARAMS: cfg.strategyParamsJson },
    });
    const { proof, publicSignals, ms } = await proofMod.fullProve(cfg, "vfy-policy", input, 60000);
    const ok = await proofMod.verifyLocal(cfg, "vfy-policy", publicSignals, proof, log);
    if (!ok) throw new Error("groth16.verify returned false");
    return `proved in ${ms}ms`;
  };

  await check("steal EXTRACT branch proof verifies vs VK", () => prove(100, 100, "2", String(params[0])));
  await check("steal FORTIFY branch proof verifies vs VK", () => prove(params[1] - 10, 100, "1", "0"));
  await check("steal HOLD branch proof verifies vs VK", () => prove(100, 0, "0", "0"));

  console.log(failures === 0 ? "\nBRANCH SELFTEST OK" : `\nBRANCH SELFTEST FAILURES: ${failures}`);
  process.exit(failures === 0 ? 0 : 1);
})().catch((e) => { console.error(e); process.exit(1); });
