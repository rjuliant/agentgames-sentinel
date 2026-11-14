"use strict";
// Central configuration. Everything comes from env (see .env.example);
// secrets are only ever read here and never logged.
const fs = require("fs");
const path = require("path");

const AGENT_DIR = path.join(__dirname, "..");

function loadDotEnv(file) {
  try {
    const text = fs.readFileSync(file, "utf8");
    for (const line of text.split(/\r?\n/)) {
      const m = line.match(/^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)\s*$/);
      if (!m || line.trim().startsWith("#")) continue;
      if (process.env[m[1]] === undefined) process.env[m[1]] = m[2];
    }
  } catch (e) { /* no .env file — fine */ }
}
loadDotEnv(path.join(AGENT_DIR, ".env"));

function str(name, dflt) {
  const v = process.env[name];
  return v === undefined || v === "" ? dflt : v;
}
function int(name, dflt) {
  const v = parseInt(process.env[name], 10);
  return Number.isFinite(v) ? v : dflt;
}
function bool(name, dflt) {
  const v = process.env[name];
  if (v === undefined || v === "") return dflt;
  return /^(1|true|yes|on)$/i.test(v);
}

function loadConfig(overrides = {}) {
  const cfg = {
    port: int("PORT", 8080),
    host: str("HOST", "0.0.0.0"),

    hmacSecret: str("AGENT_GAMES_HMAC_SECRET", ""),
    hmacAlgo: str("HMAC_ALGO", "sha256"),          // sha256 | sha512
    hmacEncoding: str("HMAC_ENCODING", "hex"),     // hex | base64
    hmacAcceptAlt: bool("HMAC_ACCEPT_ALT", true),  // accept the other encoding on verify
    hmacHeader: str("HMAC_HEADER", "x-agent-games-signature"),

    circuitsDir: path.resolve(AGENT_DIR, str("CIRCUITS_DIR", "../circuits")),
    dataDir: path.resolve(AGENT_DIR, str("DATA_DIR", "./data")),
    seenFile: str("SEEN_FILE", "seen-proof-tx.json"),

    // Gatekeeper
    approveReasonCode: str("APPROVE_REASON_CODE", "VALID_CONDITION"),
    fallbackRejectReasonCode: str("FALLBACK_REJECT_REASON_CODE", "INVALID_INPUT"),
    seenRule: str("SEEN_RULE", "accepted"),        // accepted | all
    decisionApproveValue: str("DECISION_APPROVE_VALUE", "1"),
    decisionRejectValue: str("DECISION_REJECT_VALUE", "0"),
    gatekeeperSalt: str("GATEKEEPER_SALT", "0"),
    gatekeeperVkHash: str("GATEKEEPER_VK_HASH", "0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0"),
    gkRespondByMs: int("GK_RESPOND_BY_MS", 50000), // hard platform deadline is 60s

    // Kurier (zkVerify submission)
    kurierApiKey: str("KURIER_API_KEY", ""),
    kurierBaseUrl: str("KURIER_BASE_URL", "https://api.kurier.xyz/api/v1"),
    kurierWaitBudgetMs: int("KURIER_WAIT_BUDGET_MS", 40000),
    kurierPollIntervalMs: int("KURIER_POLL_INTERVAL_MS", 2000),
    kurierRequestTimeoutMs: int("KURIER_REQUEST_TIMEOUT_MS", 10000),

    proofTimeoutMs: int("PROOF_TIMEOUT_MS", 30000),

    // Steal the VFY
    stealVkHash: str("STEAL_VK_HASH", "0x6c56509f1c56fd1fd4e9737f906d2220f4b95f1adf6899085bd74be047"),
    stealRespondByMs: int("STEAL_RESPOND_BY_MS", 25000), // platform window ~30s
    stealProofRequired: bool("STEAL_PROOF_REQUIRED", false),
    strategySalt: str("STRATEGY_SALT", ""),
    strategyParamsJson: str("STRATEGY_PARAMS", ""),
    fortifyBlocks: bool("FORTIFY_BLOCKS", false),
    stealExtractCap: int("STEAL_EXTRACT_CAP", 10),
    stealFortifyCost: int("STEAL_FORTIFY_COST", 2),
    poseidonInputOrder: str("POSEIDON_INPUT_ORDER", "paramsThenSalt"), // paramsThenSalt | saltThenParams | paramsOnly

    logLevel: str("LOG_LEVEL", "info"),
  };
  Object.assign(cfg, overrides);
  return cfg;
}

function validateConfig(cfg, { requireSecret = true } = {}) {
  const errors = [];
  if (requireSecret && !cfg.hmacSecret) errors.push("AGENT_GAMES_HMAC_SECRET is not set");
  if (!["sha256", "sha512"].includes(cfg.hmacAlgo)) errors.push(`HMAC_ALGO must be sha256|sha512 (got ${cfg.hmacAlgo})`);
  if (!["hex", "base64"].includes(cfg.hmacEncoding)) errors.push(`HMAC_ENCODING must be hex|base64 (got ${cfg.hmacEncoding})`);
  if (!["accepted", "all"].includes(cfg.seenRule)) errors.push(`SEEN_RULE must be accepted|all (got ${cfg.seenRule})`);
  for (const f of ["gatekeeper.wasm", "gatekeeper_final.zkey", "vfy-policy.wasm", "vfy-policy_final.zkey"]) {
    if (!fs.existsSync(path.join(cfg.circuitsDir, f))) errors.push(`circuit artifact missing: ${path.join(cfg.circuitsDir, f)}`);
  }
  return errors;
}

module.exports = { loadConfig, validateConfig, AGENT_DIR };
