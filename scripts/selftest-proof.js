#!/usr/bin/env node
"use strict";
// CLI proof self-test (sk54/sk56 evidence for the proof pipeline):
//   1. Gatekeeper — fabricated VALID task -> witness -> fullProve ->
//      verify against the exported VK. MUST pass.
//   2. Gatekeeper — fabricated VK-mismatch task with decision REJECT ->
//      fullProve -> verify. Reported (the probe showed the circuit binds
//      data+decision rather than enforcing the rule; see WITNESS-NOTES.md).
//   3. Steal — fabricated turn with PUBLIC test params [1..8] / salt 7 ->
//      commitment via the verified Poseidon arrangement -> fullProve.
//      Currently EXPECTED to stop at the circuit's line-75 assert
//      (unresolved params predicate — WITNESS-NOTES.md); reported as a
//      known blocker, not a failure of this harness.
// Exit code: 0 iff the gatekeeper proofs verify.
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
    return true;
  } catch (e) {
    failures++;
    console.log(`FAIL  ${label} — ${e.message}`);
    return false;
  }
}

(async () => {
  const cfg = loadConfig({ proofTimeoutMs: 60000 });
  const VK = "0x" + "ab".repeat(32);
  const VK2 = "0x" + "cd".repeat(32);
  const ADDR = "0xde42de42de42de42de42de42de42de42de429f01";
  const mkTask = (over = {}) => ({
    type: "agent-games.proof-gatekeeper.v1",
    task_id: "gk_selftest_1",
    mode: "competition",
    input: {
      registered_vk: VK, proof_vk: VK, minimum: "1000", public_balance: "1460",
      expiry_block: 8430000, current_block: 8420000, recipient: ADDR,
      condition_recipient: ADDR, amount: "500", max_transfer: "1000",
      proof_tx: "0x" + "ef".repeat(32), ...over,
    },
  });

  await check("gatekeeper VALID task proof verifies against exported VK", async () => {
    const { input } = buildWitness("gatekeeper", {
      task: mkTask(), decisionValue: cfg.decisionApproveValue,
      env: { GATEKEEPER_SALT: cfg.gatekeeperSalt },
    });
    const { proof, publicSignals, ms } = await proofMod.fullProve(cfg, "gatekeeper", input, 60000);
    const ok = await proofMod.verifyLocal(cfg, "gatekeeper", publicSignals, proof, log);
    if (!ok) throw new Error("groth16.verify returned false");
    return `proved in ${ms}ms, ${publicSignals.length} public signals`;
  });

  await check("gatekeeper TRAP task (vk mismatch, REJECT) proof verifies", async () => {
    const { input } = buildWitness("gatekeeper", {
      task: mkTask({ proof_vk: VK2 }), decisionValue: cfg.decisionRejectValue,
      env: { GATEKEEPER_SALT: cfg.gatekeeperSalt },
    });
    const { proof, publicSignals, ms } = await proofMod.fullProve(cfg, "gatekeeper", input, 60000);
    const ok = await proofMod.verifyLocal(cfg, "gatekeeper", publicSignals, proof, log);
    if (!ok) throw new Error("groth16.verify returned false");
    return `proved in ${ms}ms`;
  });

  // Steal — informational (known blocker at circuit line 75).
  try {
    const poseidon = await buildPoseidon();
    const params = [1, 2, 3, 4, 5, 6, 7, 8];
    const salt = "7";
    const commitment = poseidon.F.toObject(poseidon([...params.map(BigInt), BigInt(salt)])).toString();
    const envelope = {
      matchId: "9f4e1b2a-1111-2222-3333-444455556666", turn: 1,
      state: { selfBalance: "100", opponentBalance: "100" },
      strategyCommitment: { hash: commitment },
    };
    const { input } = buildWitness("steal", {
      envelope, actionCode: "2", actionAmount: "10",
      env: { STRATEGY_SALT: salt, STRATEGY_PARAMS: JSON.stringify(params) },
    });
    const { proof, publicSignals, ms } = await proofMod.fullProve(cfg, "vfy-policy", input, 60000);
    const ok = await proofMod.verifyLocal(cfg, "vfy-policy", publicSignals, proof, log);
    console.log(`INFO  steal proof: generated in ${ms}ms, local verify = ${ok} (line-75/90 asserts apparently satisfied by test params — re-run probes!)`);
  } catch (e) {
    console.log(`INFO  steal proof: NOT YET GENERABLE — ${String(e.message).slice(0, 140)} (known blocker: vfy-policy template asserts at lines 75/90, see WITNESS-NOTES.md)`);
  }

  console.log(failures === 0 ? "\nSELFTEST OK (gatekeeper pipeline green)" : `\nSELFTEST FAILURES: ${failures}`);
  process.exit(failures === 0 ? 0 : 1);
})().catch((e) => { console.error(e); process.exit(1); });
