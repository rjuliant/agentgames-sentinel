"use strict";
// HTTP service for zkVerify Agent Games.
//   POST /agent/gatekeeper   Proof Gatekeeper tasks (+ preflight)
//   POST /agent/steal        Steal the VFY turns (+ preflight)
//   POST /agent              type-sniffed alias for either
//   GET  /health
// Inbound: x-agent-games-signature verified over the RAW body BEFORE JSON
// parsing (401 on mismatch). Outbound: EVERY JSON response is signed over
// its raw body with the same header. Fail closed everywhere.
const http = require("http");
const path = require("path");
const { loadConfig, validateConfig } = require("./config");
const hmac = require("./hmac");
const { makeLogger } = require("./log");
const { SeenStore } = require("./seenstore");
const { KurierClient } = require("./kurier");
const proofMod = require("./proof");
const { handleGatekeeperTask } = require("./gatekeeper");
const { handleStealTurn } = require("./steal");

const MAX_BODY_BYTES = 1024 * 1024;

function createApp(cfg, log) {
  const store = new SeenStore(path.join(cfg.dataDir, cfg.seenFile), log);
  const kurier = new KurierClient(cfg, log);
  const deps = { cfg, store, kurier, log };

  function sendJson(res, status, obj) {
    const body = Buffer.from(JSON.stringify(obj), "utf8");
    const headers = { "content-type": "application/json", "content-length": body.length };
    if (cfg.hmacSecret) headers[cfg.hmacHeader] = hmac.sign(cfg, body);
    res.writeHead(status, headers);
    res.end(body);
  }

  function readBody(req) {
    return new Promise((resolve, reject) => {
      const chunks = [];
      let size = 0;
      req.on("data", (c) => {
        size += c.length;
        if (size > MAX_BODY_BYTES) {
          reject(Object.assign(new Error("body too large"), { status: 413 }));
          req.destroy();
          return;
        }
        chunks.push(c);
      });
      req.on("end", () => resolve(Buffer.concat(chunks)));
      req.on("error", reject);
    });
  }

  async function handlePost(req, res, route) {
    let raw;
    try {
      raw = await readBody(req);
    } catch (e) {
      return sendJson(res, e.status || 400, { error: "unreadable_body", detail: e.message });
    }
    // HMAC BEFORE parse — reject on mismatch.
    const verdict = hmac.verify(cfg, req.headers[cfg.hmacHeader], raw);
    if (!verdict.ok) {
      log("warn", `rejected unsigned/badly-signed POST ${route}`);
      return sendJson(res, 401, { error: "invalid_signature" });
    }
    if (verdict.encoding !== cfg.hmacEncoding) {
      log("info", `inbound signature matched ALT encoding=${verdict.encoding} (configured ${cfg.hmacEncoding}) — flip HMAC_ENCODING`);
    }
    let body;
    try {
      body = JSON.parse(raw.toString("utf8"));
    } catch (e) {
      return sendJson(res, 400, { error: "invalid_json" });
    }
    // Preflight is honoured on every POST route.
    if (body && body.type === "agent-games.preflight.v1") {
      log("info", `preflight ok (agent_id=${body.agent_id || "?"})`);
      return sendJson(res, 200, { ok: true, protocolVersion: "v1" });
    }
    const isSteal = route === "steal" || (route === "any" && (body.eventId === "steal-the-vfy" || body.matchId !== undefined));
    const isGatekeeper = route === "gatekeeper" || (route === "any" && typeof body.type === "string" && body.type.includes("proof-gatekeeper"));
    try {
      if (isSteal) return sendJson(res, 200, await handleStealTurn(body, deps));
      if (isGatekeeper) return sendJson(res, 200, await handleGatekeeperTask(body, deps));
      // Unknown payload shape: fail closed per route default.
      if (route === "steal") return sendJson(res, 200, await handleStealTurn(body, deps));
      return sendJson(res, 200, await handleGatekeeperTask(body, deps));
    } catch (e) {
      // Handlers are designed not to throw; last-resort fail-closed.
      log("error", `handler crashed on ${route}: ${e.stack || e.message}`);
      if (route === "steal") {
        return sendJson(res, 200, await handleStealTurn(null, deps).catch(() => ({ action: { type: "HOLD" } })));
      }
      return sendJson(res, 200, { decision: "REJECT", reason_code: cfg.fallbackRejectReasonCode });
    }
  }

  const server = http.createServer((req, res) => {
    const url = new URL(req.url, "http://localhost");
    if (req.method === "GET" && url.pathname === "/health") {
      return sendJson(res, 200, {
        ok: true,
        service: "agentgames-agent",
        kurier: kurier.enabled ? "configured" : "disabled",
        seenRule: cfg.seenRule,
        fortifyBlocks: cfg.fortifyBlocks,
        time: new Date().toISOString(),
      });
    }
    if (req.method === "POST" && url.pathname === "/agent/gatekeeper") return void handlePost(req, res, "gatekeeper");
    if (req.method === "POST" && url.pathname === "/agent/steal") return void handlePost(req, res, "steal");
    if (req.method === "POST" && url.pathname === "/agent") return void handlePost(req, res, "any");
    return sendJson(res, 404, { error: "not_found" });
  });

  return { server, deps };
}

async function main() {
  const cfg = loadConfig();
  const log = makeLogger(cfg.logLevel);
  const errors = validateConfig(cfg);
  if (errors.length) {
    for (const e of errors) log("error", "config: " + e);
    process.exit(1);
  }
  const { server } = createApp(cfg, log);
  // Warm the VK exports so the first task never pays for it.
  for (const name of ["gatekeeper", "vfy-policy"]) {
    try { await proofMod.ensureVk(cfg, name, log); }
    catch (e) { log("warn", `VK warm-up failed for ${name}: ${e.message}`); }
  }
  server.listen(cfg.port, cfg.host, () => {
    log("info", `agent service listening on ${cfg.host}:${cfg.port} (kurier ${cfg.kurierApiKey ? "configured" : "disabled"}, seenRule=${cfg.seenRule}, fortifyBlocks=${cfg.fortifyBlocks})`);
  });
  // Graceful shutdown (sk16).
  let closing = false;
  const shutdown = (sig) => {
    if (closing) return;
    closing = true;
    log("info", `received ${sig}, shutting down`);
    server.close(() => process.exit(0));
    setTimeout(() => process.exit(0), 5000).unref();
  };
  process.on("SIGTERM", () => shutdown("SIGTERM"));
  process.on("SIGINT", () => shutdown("SIGINT"));
}

if (require.main === module) {
  main().catch((e) => { console.error(e); process.exit(1); });
}

module.exports = { createApp };
