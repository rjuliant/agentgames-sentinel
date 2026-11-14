"use strict";
// Proof Gatekeeper: decision engine (pure, fail-closed) + task handler
// (decision -> seen-set -> proof -> Kurier -> signed response payload).
// Check ORDER follows SPEC §4.3's trap table and yields its reason_codes.
const proofMod = require("./proof");
const { buildWitness } = require("./witness");

function parseBig(v) {
  if (typeof v === "bigint") return v;
  if (typeof v === "number") {
    if (!Number.isFinite(v)) throw new Error("non-finite number");
    return BigInt(Math.trunc(v));
  }
  if (typeof v === "string" && v.trim() !== "") return BigInt(v.trim());
  throw new Error("not a numeric value");
}

function eqStr(a, b) {
  return typeof a === "string" && typeof b === "string" && a.toLowerCase() === b.toLowerCase();
}

// Pure decision. store is consulted for PROOF_REUSED only.
// Returns { decision, reason_code, checks: [...] }.
function decide(task, store, cfg) {
  const checks = [];
  const reject = (code, why) => {
    checks.push(why);
    return { decision: "REJECT", reason_code: code, checks };
  };
  const input = task && typeof task === "object" ? task.input : undefined;
  if (!input || typeof input !== "object") {
    return reject(cfg.fallbackRejectReasonCode, "envelope has no input object");
  }
  // 1) VK substitution — string comparison, before any numeric parsing,
  //    so the SPEC §4.1 sample (abbreviated values) resolves here.
  if (typeof input.registered_vk !== "string" || typeof input.proof_vk !== "string") {
    return reject(cfg.fallbackRejectReasonCode, "registered_vk/proof_vk missing or not strings");
  }
  if (!eqStr(input.registered_vk, input.proof_vk)) {
    return reject("VK_SUBSTITUTION", "proof_vk != registered_vk");
  }
  checks.push("vk match");
  // Numeric fields
  let minimum, publicBalance, expiryBlock, currentBlock, amount, maxTransfer;
  try {
    minimum = parseBig(input.minimum);
    publicBalance = parseBig(input.public_balance);
    expiryBlock = parseBig(input.expiry_block);
    currentBlock = parseBig(input.current_block);
    amount = parseBig(input.amount);
    maxTransfer = parseBig(input.max_transfer);
  } catch (e) {
    return reject(cfg.fallbackRejectReasonCode, "numeric field unparsable: " + e.message);
  }
  // 2) Threshold
  if (publicBalance < minimum) return reject("THRESHOLD_MISMATCH", "public_balance < minimum");
  checks.push("threshold ok");
  // 3) Proof reuse
  if (typeof input.proof_tx !== "string" || input.proof_tx === "") {
    return reject(cfg.fallbackRejectReasonCode, "proof_tx missing");
  }
  const reused = cfg.seenRule === "all" ? store.hasAll(input.proof_tx) : store.hasAccepted(input.proof_tx);
  if (reused) return reject("PROOF_REUSED", `proof_tx already seen (rule=${cfg.seenRule})`);
  checks.push("proof_tx fresh");
  // 4) Expiry
  if (currentBlock > expiryBlock) return reject("EXPIRED_CONDITION", "current_block > expiry_block");
  checks.push("not expired");
  // 5) Recipient
  if (typeof input.recipient !== "string" || typeof input.condition_recipient !== "string") {
    return reject(cfg.fallbackRejectReasonCode, "recipient fields missing or not strings");
  }
  if (!eqStr(input.recipient, input.condition_recipient)) {
    return reject("RECIPIENT_MISMATCH", "recipient != condition_recipient");
  }
  checks.push("recipient ok");
  // 6) Amount cap
  if (amount > maxTransfer) return reject("AMOUNT_OVERFLOW", "amount > max_transfer");
  checks.push("amount within cap");
  return { decision: "APPROVE", reason_code: cfg.approveReasonCode, checks };
}

// Full task flow with deadline budgeting (sk54: every failure mode has an
// explicit, tested fallback — the DECISION is always returned, signed;
// the proof is attached only when the whole pipeline lands in budget).
async function handleGatekeeperTask(task, deps) {
  const { cfg, store, kurier, log } = deps;
  const t0 = Date.now();
  const elapsed = () => Date.now() - t0;
  const taskId = task && task.task_id;
  const d = decide(task, store, cfg);
  const proofTx = task && task.input ? task.input.proof_tx : undefined;

  // Seen-set bookkeeping: every processed reference goes to `all`;
  // APPROVEs additionally go to `accepted` (SPEC §4.3 semantics).
  try {
    if (proofTx) store.recordAll(proofTx);
    if (d.decision === "APPROVE" && proofTx) store.recordAccepted(proofTx);
  } catch (e) {
    log("error", `seen-store write failed: ${e.message}`);
  }

  const response = { decision: d.decision, reason_code: d.reason_code };
  if (proofTx) response.proof_tx = proofTx;

  // PROOF_REUSED tasks carry no proof (SPEC §4.2) — done.
  if (d.reason_code === "PROOF_REUSED") {
    log("info", `gatekeeper task=${taskId} REJECT/PROOF_REUSED (no proof per spec) ${elapsed()}ms`);
    return response;
  }

  // --- proof pipeline (best effort inside the response budget) ---
  try {
    const witnessCtx = {
      task,
      decisionValue: d.decision === "APPROVE" ? cfg.decisionApproveValue : cfg.decisionRejectValue,
      env: { GATEKEEPER_SALT: cfg.gatekeeperSalt },
    };
    const { input } = buildWitness("gatekeeper", witnessCtx);
    const proveBudget = Math.min(cfg.proofTimeoutMs, Math.max(1000, cfg.gkRespondByMs - elapsed()));
    const { proof, publicSignals, ms } = await proofMod.fullProve(cfg, "gatekeeper", input, proveBudget);

    let verified = null;
    try { verified = await proofMod.verifyLocal(cfg, "gatekeeper", publicSignals, proof, log); }
    catch (e) { log("warn", `gatekeeper local verify errored: ${e.message}`); }
    if (verified === false) {
      log("error", `gatekeeper task=${taskId} proof FAILED local verification — omitting proof`);
    } else {
      response.proof = proof;
      response.public_signals = publicSignals;
      log("info", `gatekeeper task=${taskId} proof generated in ${ms}ms (local verify: ${verified})`);
      // Kurier submission + Finalized wait, inside whatever budget remains.
      if (kurier && kurier.enabled) {
        const waitBudget = Math.min(cfg.kurierWaitBudgetMs, Math.max(0, cfg.gkRespondByMs - elapsed() - 1000));
        if (waitBudget > 0) {
          try {
            const { jobId } = await kurier.submitProof({ vkHash: cfg.gatekeeperVkHash, proof, publicSignals });
            const res = await kurier.waitFinalized(jobId, waitBudget);
            log("info", `gatekeeper task=${taskId} kurier job=${jobId} status=${res.status}${res.ref ? " ref=" + res.ref : ""}`);
          } catch (e) {
            log("warn", `gatekeeper task=${taskId} kurier failed (${e.code || e.message}) — responding with local proof only`);
          }
        } else {
          log("warn", `gatekeeper task=${taskId} no budget left for kurier — responding with local proof only`);
        }
      }
    }
  } catch (e) {
    // Witness/proof failure (incl. PROOF_TIMEOUT): decision still returned.
    log("error", `gatekeeper task=${taskId} proof pipeline failed (${e.code || e.message}) — responding without proof`);
  }

  log("info", `gatekeeper task=${taskId} -> ${d.decision}/${d.reason_code} in ${elapsed()}ms`);
  return response;
}

module.exports = { decide, handleGatekeeperTask, parseBig };
