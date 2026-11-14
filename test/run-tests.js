#!/usr/bin/env node
"use strict";
// sk56 EVAL harness — scored, not a smoke test.
// Boots the real HTTP service on an ephemeral port with .env.test values
// and replays fabricated envelopes end-to-end (HMAC, routing, decision
// engine, proof generation, seen-set persistence).
// Prints a Gatekeeper accuracy scorecard per trap type + Steal behavior
// summary. Exit code 1 if any case fails.
const fs = require("fs");
const os = require("os");
const path = require("path");
const crypto = require("crypto");
const { keccak256 } = require("js-sha3");

// --- load .env.test into process.env BEFORE config ---
const envTest = fs.readFileSync(path.join(__dirname, "..", ".env.test"), "utf8");
for (const line of envTest.split(/\r?\n/)) {
  const m = line.match(/^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)\s*$/);
  if (m && !line.trim().startsWith("#")) process.env[m[1]] = m[2];
}
const TEST_SECRET = process.env.AGENT_GAMES_HMAC_SECRET;

const { loadConfig } = require("../src/config");
const { createApp } = require("../src/server");
const { makeLogger } = require("../src/log");
const proofMod = require("../src/proof");

const results = [];
function record(name, ok, detail = "") {
  results.push({ name, ok, detail });
  console.log(`${ok ? "PASS" : "FAIL"}  ${name}${detail ? " — " + detail : ""}`);
}

function signBody(secret, buf) {
  return crypto.createHmac("sha256", secret).update(buf).digest("hex");
}

async function post(base, route, obj, { badSig = false } = {}) {
  const raw = Buffer.from(JSON.stringify(obj), "utf8");
  const sig = badSig ? "0".repeat(64) : signBody(TEST_SECRET, raw);
  const res = await fetch(base + route, {
    method: "POST",
    headers: { "content-type": "application/json", "x-agent-games-signature": sig },
    body: raw,
  });
  const text = await res.text();
  const respSig = res.headers.get("x-agent-games-signature");
  const sigOk = respSig === signBody(TEST_SECRET, Buffer.from(text, "utf8"));
  let json = null;
  try { json = JSON.parse(text); } catch (e) { /* keep null */ }
  return { status: res.status, json, sigOk };
}

// Independent publicInputsHash implementation straight from SPEC §5.4,
// used to cross-check the service's hash byte-for-byte.
function specHash({ commitment, matchId, turn, self, opp, actionCode, amount }) {
  const f = (v) => Buffer.from(BigInt(v).toString(16).padStart(64, "0"), "hex");
  const pre = Buffer.concat([
    f(commitment), f("0x" + matchId.replace(/-/g, "")), f(turn), f(self), f(opp),
    f(actionCode), f(amount), f(1),
  ]);
  return "0x" + keccak256(pre);
}

(async () => {
  const t0 = Date.now();
  // Keccak sanity: js-sha3 must be real Keccak-256 (empty-string vector).
  const emptyK = keccak256("");
  if (emptyK !== "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470") {
    console.error("keccak256 implementation mismatch on empty-string vector");
    process.exit(1);
  }

  const tmpData = fs.mkdtempSync(path.join(os.tmpdir(), "agentgames-eval-"));
  const cfg = loadConfig({ port: 0, host: "127.0.0.1", dataDir: tmpData, kurierApiKey: "" });
  const log = makeLogger("error");
  const { server } = createApp(cfg, log);
  await new Promise((r) => server.listen(0, "127.0.0.1", r));
  const base = `http://127.0.0.1:${server.address().port}`;
  console.log(`eval server on ${base} (data dir ${tmpData})\n`);

  try {
    // ---- transport / protocol ----
    {
      const res = await fetch(base + "/health");
      const j = await res.json();
      record("health endpoint", res.status === 200 && j.ok === true);
    }
    {
      const r = await post(base, "/agent/gatekeeper", { type: "agent-games.preflight.v1", agent_id: "agt_eval", nonce: "n1" });
      record("preflight -> {ok:true, protocolVersion:'v1'} + signed",
        r.status === 200 && r.json && r.json.ok === true && r.json.protocolVersion === "v1" && r.sigOk,
        `sigOk=${r.sigOk}`);
    }
    {
      const r = await post(base, "/agent/gatekeeper", { type: "agent-games.preflight.v1" }, { badSig: true });
      record("bad HMAC -> 401", r.status === 401, `status=${r.status}`);
    }

    // ---- gatekeeper decision eval (scorecard) ----
    const VK = "0x" + "ab".repeat(32);
    const VK2 = "0x" + "cd".repeat(32);
    const ADDR = "0xde42de42de42de42de42de42de42de42de429f01";
    const ADDR2 = "0x1111111111111111111111111111111111111111";
    let txSeq = 0;
    const freshTx = () => "0x" + (0xf0 + txSeq++).toString(16).padStart(2, "0").repeat(32).slice(0, 64);
    const mkTask = (over = {}, taskOver = {}) => ({
      type: "agent-games.proof-gatekeeper.v1", task_id: "gk_eval", mode: "competition",
      input: {
        registered_vk: VK, proof_vk: VK, minimum: "1000", public_balance: "1460",
        expiry_block: 8430000, current_block: 8420000, recipient: ADDR,
        condition_recipient: ADDR, amount: "500", max_transfer: "1000",
        proof_tx: freshTx(), ...over,
      },
      ...taskOver,
    });

    const scorecard = {}; // trapType -> {correct, total}
    async function gkCase(type, task, expectDecision, expectCode, { expectProof = null } = {}) {
      const r = await post(base, "/agent/gatekeeper", task);
      const got = r.json || {};
      let ok = r.status === 200 && got.decision === expectDecision && got.reason_code === expectCode && r.sigOk;
      let detail = `got ${got.decision}/${got.reason_code}`;
      if (expectProof === true) {
        const hasProof = !!got.proof && Array.isArray(got.public_signals);
        ok = ok && hasProof;
        detail += hasProof ? `, proof+${got.public_signals.length} signals` : ", NO PROOF";
        if (hasProof && expectDecision === "APPROVE") {
          const v = await proofMod.verifyLocal(cfg, "gatekeeper", got.public_signals, got.proof, log);
          ok = ok && v === true;
          detail += `, localVerify=${v}`;
        }
      }
      if (expectProof === false) {
        const noProof = !got.proof && !got.public_signals;
        ok = ok && noProof;
        detail += noProof ? ", no proof (correct)" : ", proof present (WRONG)";
      }
      scorecard[type] = scorecard[type] || { correct: 0, total: 0 };
      scorecard[type].total++;
      if (ok) scorecard[type].correct++;
      record(`gatekeeper[${type}]`, ok, detail);
      return r;
    }

    // (a) SPEC §4.1 sample envelope, verbatim abbreviated values.
    await gkCase("VK_SUBSTITUTION (SPEC sample)", {
      type: "agent-games.proof-gatekeeper.v1", task_id: "gk_8d31_sample", mode: "competition",
      input: {
        registered_vk: "0x7d...91", proof_vk: "0x13...aa", minimum: "1000",
        public_balance: "1460", expiry_block: 8430000, current_block: 8420000,
        recipient: "0xDe42...9f01", condition_recipient: "0xDe42...9f01",
        amount: "500", max_transfer: "1000", proof_tx: "0xa8...2c",
      },
    }, "REJECT", "VK_SUBSTITUTION");

    // (b) valid -> approve with verifiable proof
    await gkCase("VALID_CONDITION", mkTask(), "APPROVE", "VALID_CONDITION", { expectProof: true });
    // (c) one fabricated case per trap type
    await gkCase("VK_SUBSTITUTION", mkTask({ proof_vk: VK2 }), "REJECT", "VK_SUBSTITUTION", { expectProof: true });
    await gkCase("THRESHOLD_MISMATCH", mkTask({ public_balance: "999" }), "REJECT", "THRESHOLD_MISMATCH", { expectProof: true });
    await gkCase("EXPIRED_CONDITION", mkTask({ current_block: 8430001 }), "REJECT", "EXPIRED_CONDITION", { expectProof: true });
    await gkCase("RECIPIENT_MISMATCH", mkTask({ recipient: ADDR2 }), "REJECT", "RECIPIENT_MISMATCH", { expectProof: true });
    await gkCase("AMOUNT_OVERFLOW", mkTask({ amount: "1001" }), "REJECT", "AMOUNT_OVERFLOW", { expectProof: true });
    // PROOF_REUSED: same proof_tx twice — first approves, second must reject without proof.
    const reusedTx = freshTx();
    await gkCase("VALID_CONDITION (reuse setup)", mkTask({ proof_tx: reusedTx }), "APPROVE", "VALID_CONDITION", { expectProof: true });
    await gkCase("PROOF_REUSED", mkTask({ proof_tx: reusedTx }), "REJECT", "PROOF_REUSED", { expectProof: false });
    // malformed envelope -> fail-closed reject
    {
      const r = await post(base, "/agent/gatekeeper", { type: "agent-games.proof-gatekeeper.v1", task_id: "gk_bad" });
      record("gatekeeper malformed envelope -> fail-closed REJECT",
        r.status === 200 && r.json && r.json.decision === "REJECT", `got ${r.json && r.json.decision}/${r.json && r.json.reason_code}`);
    }

    console.log("\n--- Gatekeeper decision scorecard ---");
    let totC = 0, totT = 0;
    for (const [type, s] of Object.entries(scorecard)) {
      console.log(`  ${type.padEnd(34)} ${s.correct}/${s.total}`);
      totC += s.correct; totT += s.total;
    }
    console.log(`  ${"TOTAL".padEnd(34)} ${totC}/${totT}`);

    // ---- steal eval ----
    const COMMITMENT = "0x128e6024b2ab0e8981bd91ed53c0e253c2efbe29a0fa1a5ee7c8dceb49e1d650";
    const mkTurn = (stateOver = {}) => ({
      protocolVersion: "v1", eventId: "steal-the-vfy", mode: "competition",
      matchId: "9f4e1b2a-1111-2222-3333-444455556666", turn: 3,
      state: { selfBalance: "95", opponentBalance: "105", selfFortifiedUntilTurn: null, opponentFortifiedUntilTurn: null, ...stateOver },
      strategyCommitment: { hash: COMMITMENT }, resolverVersion: "v1", nonce: "n-3",
    });
    {
      const turn = mkTurn();
      const r1 = await post(base, "/agent/steal", turn);
      const j = r1.json || {};
      const expectedHash = specHash({ commitment: COMMITMENT, matchId: turn.matchId, turn: 3, self: "95", opp: "105", actionCode: 2, amount: 10 });
      record("steal turn (opp=105) -> EXTRACT 10, echo + hash + key",
        r1.status === 200 && j.action && j.action.type === "EXTRACT" && j.action.amount === 10 &&
        j.matchId === turn.matchId && j.turn === 3 &&
        j.policyProof && j.policyProof.publicInputsHash === expectedHash &&
        typeof j.idempotencyKey === "string" && j.idempotencyKey.length > 0 && r1.sigOk,
        `hash match=${j.policyProof && j.policyProof.publicInputsHash === expectedHash}, proof attached=${!!j.proof} (known line-75 blocker if false)`);
      const r2 = await post(base, "/agent/steal", turn);
      record("steal idempotencyKey unique per response",
        !!(r2.json && r2.json.idempotencyKey && r2.json.idempotencyKey !== j.idempotencyKey));
    }
    {
      const r = await post(base, "/agent/steal", mkTurn({ opponentBalance: "0" }));
      const j = r.json || {};
      record("steal turn (opp=0) -> HOLD, amount field omitted",
        r.status === 200 && j.action && j.action.type === "HOLD" && !("amount" in j.action),
        `got ${j.action && j.action.type}`);
    }
    {
      const r = await post(base, "/agent/steal", mkTurn({ opponentBalance: "4" }));
      const j = r.json || {};
      record("steal turn (opp=4) -> EXTRACT capped by balance (4)",
        r.status === 200 && j.action && j.action.type === "EXTRACT" && j.action.amount === 4,
        `got ${j.action && j.action.type} ${j.action && j.action.amount}`);
    }
    {
      const r = await post(base, "/agent/steal", { protocolVersion: "v1", eventId: "steal-the-vfy" });
      const j = r.json || {};
      record("steal malformed envelope -> fail-closed HOLD",
        r.status === 200 && j.action && j.action.type === "HOLD", `got ${j.action && j.action.type}`);
    }
  } finally {
    server.close();
  }

  const failed = results.filter((r) => !r.ok);
  console.log(`\n=== EVAL SUMMARY: ${results.length - failed.length}/${results.length} passed in ${((Date.now() - t0) / 1000).toFixed(1)}s ===`);
  if (failed.length) {
    console.log("FAILURES:");
    for (const f of failed) console.log(`  - ${f.name}: ${f.detail}`);
    process.exit(1);
  }
  process.exit(0);
})().catch((e) => { console.error("eval crashed:", e); process.exit(1); });
