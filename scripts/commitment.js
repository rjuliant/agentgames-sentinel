#!/usr/bin/env node
"use strict";
// Compute the Steal the VFY strategy commitment hash for dashboard
// registration:  commitment = Poseidon(strategyParams[0..7], salt)
// (arrangement VERIFIED against the vfy-policy circuit's line-72 assert —
// see WITNESS-NOTES.md; POSEIDON_INPUT_ORDER can switch it if the dashboard
// helper disagrees).
//
// Reads STRATEGY_PARAMS (JSON array of 8 field values) and STRATEGY_SALT
// from the environment / .env. Prints ONLY the commitment hash — the
// params and salt are never printed or logged.
const { buildPoseidon } = require("circomlibjs");
const { loadConfig } = require("../src/config");

(async () => {
  const cfg = loadConfig();
  if (!cfg.strategyParamsJson) {
    console.error("STRATEGY_PARAMS is not set (expected a JSON array of 8 values)");
    process.exit(2);
  }
  if (!cfg.strategySalt) {
    console.error("STRATEGY_SALT is not set");
    process.exit(2);
  }
  const params = JSON.parse(cfg.strategyParamsJson);
  if (!Array.isArray(params) || params.length !== 8) {
    console.error(`STRATEGY_PARAMS must be an array of exactly 8 values (got ${Array.isArray(params) ? params.length : "non-array"})`);
    process.exit(2);
  }
  const p = params.map((x) => BigInt(x));
  const salt = BigInt(cfg.strategySalt);
  const poseidon = await buildPoseidon();
  let inputs;
  switch (cfg.poseidonInputOrder) {
    case "saltThenParams": inputs = [salt, ...p]; break;
    case "paramsOnly": inputs = p; break;
    case "paramsThenSalt": inputs = [...p, salt]; break;
    default:
      console.error(`unknown POSEIDON_INPUT_ORDER: ${cfg.poseidonInputOrder}`);
      process.exit(2);
  }
  const hash = poseidon.F.toObject(poseidon(inputs));
  console.log("commitment (decimal):", hash.toString());
  console.log("commitment (hex):    ", "0x" + hash.toString(16).padStart(64, "0"));
})().catch((e) => { console.error("commitment computation failed:", e.message); process.exit(1); });
