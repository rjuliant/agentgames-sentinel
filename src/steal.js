"use strict";
// Steal the VFY: committed policy + publicInputsHash + turn handler.
// Policy = STEAL-STRATEGY.md's shipped policy, which is EXACTLY the
// vfy-policy circuit's decision list with STRATEGY_PARAMS=[10,0,0,0,0,0,0,0]
// (circuit semantics reverse-engineered 13 Nov 2026 — see WITNESS-NOTES.md):
//   circuit: if selfBalance < params[1] -> FORTIFY;
//            elif opponentBalance <= params[2] || params[3]==1 -> HOLD;
//            else EXTRACT with amount == params[0] (exactly, NOT capped
//            by the opponent balance — the resolver caps the actual take;
//            the circuit rejects amount != params[0] at its line 149).
//   With params[1..3] = 0 that reduces to: EXTRACT 10 every turn;
//   HOLD only when opponent balance == 0. FORTIFY branches exist ONLY
//   behind cfg.fortifyBlocks (FORTIFY_BLOCKS env, default false) and are
//   DISABLED in the registered commitment (params[1]=0) — enabling them
//   without re-registering a commitment with params[1] > selfBalance
//   semantics would produce unprovable turns.
//
// Schema fixes made permanent 13 Nov 2026 (post-practice; both were
// proven against the live platform in practice session 2):
//   (a) idempotencyKey is a PLAIN UUID — the platform rejects the old
//       "matchId:turn:uuid" composite with "idempotencyKey: Invalid UUID".
//   (b) policyProof.publicInputsHash is ALWAYS a string — including the
//       fail-closed HOLD path. When the envelope carries no strategy
//       commitment (practice envelopes don't), the hash is computed with
//       the zero commitment, which is exactly what the platform
//       recomputed and VERIFIED in practice. An absent field is rejected
//       with "publicInputsHash: expected string, received undefined".
const crypto = require("crypto");
const { keccak256 } = require("js-sha3");
const proofMod = require("./proof");
const { buildWitness } = require("./witness");
const { parseBig } = require("./gatekeeper");

const ACTION_CODES = { HOLD: 0, FORTIFY: 1, EXTRACT: 2 };

function policy(state, cfg) {
  const turn = state.turn;
  const self = state.selfBalance;
  const opp = state.opponentBalance;
  if (opp <= 0n) return { type: "HOLD" };
  if (cfg.fortifyBlocks) {
    const E = BigInt(cfg.stealExtractCap);
    const C = BigInt(cfg.stealFortifyCost);
    const minE = self < E ? self : E;
    if (turn === 20 && self > opp && C < minE) return { type: "FORTIFY" };
    if (turn >= 18 && self > opp && self < E && C < self) return { type: "FORTIFY" };
  }
  // EXTRACT amount is EXACTLY the cap (= circuit params[0] = 10): the
  // circuit asserts amount == params[0] even when the opponent balance is
  // smaller (verified: opp=5, amount=10 proves; amount=5 fails line 149).
  // The game resolver steals "up to N", so naming the full cap is also
  // the game-correct action (SPEC §5.1).
  const cap = BigInt(cfg.stealExtractCap);
  return { type: "EXTRACT", amount: cap };
}

function bytes32(v) {
  let x = BigInt(v);
  if (x < 0n || x >= (1n << 256n)) throw new Error("value out of 32-byte range");
  const hex = x.toString(16).padStart(64, "0");
  return Buffer.from(hex, "hex");
}

// SPEC §5.4 — field order is critical:
// commitment, matchId (dashes stripped), turn, selfBalance, opponentBalance,
// action code, amount (0 for HOLD/FORTIFY), circuitVersion (v1 -> 1).
// commitmentOverride lets the fail-closed path hash with the zero
// commitment when the envelope carries none (see header note (b)).
function publicInputsHash(envelope, actionType, amount, commitmentOverride) {
  let commitment = commitmentOverride;
  if (commitment === undefined) {
    commitment = envelope && envelope.strategyCommitment && envelope.strategyCommitment.hash;
  }
  if (commitment === undefined || commitment === null) {
    throw new Error("envelope.strategyCommitment.hash missing");
  }
  const fields = [
    BigInt(commitment),
    BigInt("0x" + String(envelope.matchId).replace(/-/g, "")),
    BigInt(envelope.turn),
    parseBig(envelope.state.selfBalance),
    parseBig(envelope.state.opponentBalance),
    BigInt(ACTION_CODES[actionType]),
    BigInt(amount || 0),
    1n,
  ];
  return "0x" + keccak256(Buffer.concat(fields.map(bytes32)));
}

function baseResponse(envelope) {
  return {
    matchId: envelope && envelope.matchId,
    turn: envelope && envelope.turn,
    agentTimestamp: new Date().toISOString(),
    idempotencyKey: crypto.randomUUID(),
  };
}

function holdFallback(envelope, cfg, log, why) {
  if (log) log("warn", `steal fail-closed HOLD: ${why}`);
  const resp = baseResponse(envelope);
  resp.action = { type: "HOLD" };
  resp.policyProof = { circuitVersion: "v1" };
  try {
    resp.policyProof.publicInputsHash = publicInputsHash(envelope, "HOLD", 0);
  } catch (e) {
    // No commitment in the envelope — fall back to the zero commitment so
    // the field is still a string (header note (b)). Only a structurally
    // broken envelope (no matchId/state to hash) leaves the field unset.
    try {
      resp.policyProof.publicInputsHash = publicInputsHash(envelope, "HOLD", 0, 0n);
    } catch (e2) { /* envelope too broken to hash — policyProof stays minimal */ }
  }
  return resp;
}

async function handleStealTurn(envelope, deps) {
  const { cfg, kurier, log } = deps;
  const t0 = Date.now();
  const elapsed = () => Date.now() - t0;
  try {
    if (!envelope || typeof envelope !== "object") throw new Error("envelope not an object");
    if (typeof envelope.matchId !== "string" || envelope.matchId === "") throw new Error("matchId missing");
    if (!envelope.state || typeof envelope.state !== "object") throw new Error("state missing");
    const state = {
      turn: Number(envelope.turn),
      selfBalance: parseBig(envelope.state.selfBalance),
      opponentBalance: parseBig(envelope.state.opponentBalance),
    };
    if (!Number.isInteger(state.turn)) throw new Error("turn not an integer");

    const action = policy(state, cfg);
    const amount = action.type === "EXTRACT" ? action.amount : 0n;
    const hash = publicInputsHash(envelope, action.type, amount);

    const resp = baseResponse(envelope);
    resp.action = action.type === "EXTRACT"
      ? { type: "EXTRACT", amount: Number(action.amount) }
      : { type: action.type }; // amount omitted entirely for HOLD/FORTIFY (SPEC §5.7)
    resp.policyProof = { circuitVersion: "v1", publicInputsHash: hash };

    // --- policy proof (best effort inside the turn budget) ---
    if (!cfg.strategySalt || !cfg.strategyParamsJson) {
      log("warn", "steal: STRATEGY_SALT/STRATEGY_PARAMS not set — responding without proof");
      return resp;
    }
    try {
      const witnessCtx = {
        envelope,
        actionCode: String(ACTION_CODES[action.type]),
        actionAmount: String(amount),
        env: { STRATEGY_SALT: cfg.strategySalt, STRATEGY_PARAMS: cfg.strategyParamsJson },
      };
      const { input } = buildWitness("steal", witnessCtx);
      const proveBudget = Math.min(cfg.proofTimeoutMs, Math.max(1000, cfg.stealRespondByMs - elapsed()));
      const { proof, publicSignals, ms } = await proofMod.fullProve(cfg, "vfy-policy", input, proveBudget);
      resp.proof = proof;
      resp.public_signals = publicSignals;
      log("info", `steal match=${envelope.matchId} turn=${state.turn} proof in ${ms}ms`);
      if (kurier && kurier.enabled) {
        const waitBudget = Math.min(cfg.kurierWaitBudgetMs, Math.max(0, cfg.stealRespondByMs - elapsed() - 500));
        if (waitBudget > 0) {
          try {
            const { jobId } = await kurier.submitProof({ vkHash: cfg.stealVkHash, proof, publicSignals });
            const res = await kurier.waitFinalized(jobId, waitBudget);
            if (res.ref) resp.policyProof.proofReference = res.ref;
            log("info", `steal match=${envelope.matchId} turn=${state.turn} kurier job=${jobId} status=${res.status}`);
          } catch (e) {
            log("warn", `steal kurier failed (${e.code || e.message}) — local proof only`);
          }
        }
      }
    } catch (e) {
      // Proof pipeline failure (the vfy-policy semantics are SOLVED — see
      // WITNESS-NOTES.md — so this is now a genuine pipeline/env failure,
      // e.g. envelope commitment != Poseidon(env params, salt)).
      // STEAL_PROOF_REQUIRED=true turns this into a strict HOLD; default
      // keeps the policy action (the platform scores a proof-less turn as
      // HOLD either way) so the eval can see it.
      log("error", `steal proof pipeline failed (${e.code || e.message})`);
      if (cfg.stealProofRequired) return holdFallback(envelope, cfg, log, "proof required but pipeline failed");
      delete resp.proof;
      delete resp.public_signals;
    }
    log("info", `steal match=${envelope.matchId} turn=${state.turn} -> ${action.type}${action.type === "EXTRACT" ? " " + action.amount : ""} in ${elapsed()}ms`);
    return resp;
  } catch (e) {
    return holdFallback(envelope, cfg, log, e.message);
  }
}

module.exports = { policy, publicInputsHash, handleStealTurn, ACTION_CODES, bytes32 };
