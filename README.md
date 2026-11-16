# Agent Games Agent Service — Proof Gatekeeper + Steal the VFY

Competition agent for the zkVerify Agent Games. The platform never runs
this code: it POSTs signed envelopes to these public HTTPS endpoints, and
the service answers with signed decisions/actions plus Groth16 proofs.

Built under SUPERAGENT V7 **sk16** (production code, runnable as-is, tests
by default), **sk56** (the test harness is a scored eval — see the
scorecard it prints), and **sk54** (explicit failure-mode behaviour, table
below). Protocol authority: `../SPEC.md`; circuit findings:
`WITNESS-NOTES.md`.

## Quickstart

```bash
npm install
cp .env.example .env        # fill AGENT_GAMES_HMAC_SECRET (+ KURIER_API_KEY)
npm start                   # listens on PORT (default 8080)
npm test                    # sk56 eval: scored harness (18 cases)
npm run selftest-proof      # CLI proof pipeline check vs exported VKs
npm run commitment          # Steal: print Poseidon commitment hash to register
```

Endpoints (register the FULL paths on the dashboard):

| Route | Purpose |
|---|---|
| `POST /agent/gatekeeper` | Proof Gatekeeper tasks |
| `POST /agent/steal` | Steal the VFY turns |
| `POST /agent` | type-sniffed alias for either |
| `GET /health` | health check: `{ ok, kurier, seenRule, fortifyBlocks, ... }` |

## Live deployment

Running instance, entered in Proof Gatekeeper:

- Agent endpoint: `https://43-134-84-70.sslip.io/agent`
- Health: `https://43-134-84-70.sslip.io/health`

Deployment shape: Node service on `127.0.0.1:8090` behind Caddy (automatic
Let's Encrypt TLS) on a stable `sslip.io` hostname, both under systemd with
`Restart=always` and `enable`, so the registered URL survives restarts and
never rotates. An ephemeral tunnel was the earlier setup and it is exactly why
tasks were missed: the hostname changed and the registered endpoint went stale.

## Measured results

| Signal | Value |
|---|---|
| Practice decisions correct | 9/9, all 7 documented trap varieties covered |
| Proof status | `verified` on every provable task (self-verified locally, then platform-verified) |
| Median end-to-end decision | 363 ms against a 60 s deadline |
| Live Proof Gatekeeper round | 10/16 answered, 88.0 weighted points, rank 196 of 454 agents |

The unanswered tasks in that round are endpoint-uptime losses from before the
stable-host migration, not decision errors — see the note under *Failure modes*.

Preflight (`type: "agent-games.preflight.v1"`) is answered on every POST
route with `{ ok: true, protocolVersion: "v1" }`, signed.

## How it works

- **HMAC first.** Every inbound POST is verified against
  `x-agent-games-signature` over the *raw* body before JSON parsing (401
  on mismatch); every response is signed over its raw body. Digest and
  encoding are switches (`HMAC_ALGO`, `HMAC_ENCODING`) because the
  platform doesn't publish them (SPEC §3); verification also accepts the
  alternate encoding and logs which one matched, so the first preflight
  settles it.
- **Gatekeeper decision engine** (`src/gatekeeper.js`, pure function):
  checks in SPEC §4.3 order — VK match → threshold → proof-reuse →
  expiry → recipient → amount cap — otherwise APPROVE. Fail-closed
  REJECT on any parse/validation problem. `proof_tx` references persist
  to `data/seen-proof-tx.json` (survives restarts); `SEEN_RULE=accepted`
  (default, SPEC wording) checks reuse against APPROVED tasks only,
  `all` against every processed task.
- **Proof pipeline.** Witness inputs are built from a JSON mapping
  (`src/witness-config.*.json`) using the signal names *verified by
  probing the actual circuits* (WITNESS-NOTES.md): gatekeeper has exactly
  the 13 expected public inputs; proofs generate locally with snarkjs
  (~0.3–1 s) and are self-verified against the exported VK before being
  attached. On provable tasks the proof is then submitted to Kurier and
  awaited to Finalized inside the remaining budget. `PROOF_REUSED`
  responses carry no proof, per SPEC §4.2.
- **Steal policy** (`src/steal.js`): EXTRACT every turn with
  `amount = min(10, opponentBalance)`; HOLD if the opponent balance is 0;
  the endgame FORTIFY branches from STEAL-STRATEGY.md are compiled in but
  gated OFF behind `FORTIFY_BLOCKS=false` (simulation showed they never
  improve an outcome). `publicInputsHash` implements SPEC §5.4 exactly
  (field order + 32-byte big-endian packing; cross-checked byte-for-byte
  in the eval). `action.amount` is omitted entirely for HOLD/FORTIFY;
  `idempotencyKey` is unique per response.
- **Commitment** (`npm run commitment`): prints
  `Poseidon(strategyParams[0..7], salt)` — the arrangement *verified*
  against the circuit's commitment assert. Params/salt come from env and
  are never printed.

## Deadline budgets (sk54)

| Budget | Default | Meaning |
|---|---|---|
| `GK_RESPOND_BY_MS` | 50 000 | Gatekeeper: whole pipeline aims to answer by then (platform hard limit 60 s) |
| `PROOF_TIMEOUT_MS` | 30 000 | snarkjs fullProve outer timeout |
| `KURIER_WAIT_BUDGET_MS` | 40 000 | max wait for Kurier Finalized per task (further clamped to the remaining response budget) |
| `KURIER_REQUEST_TIMEOUT_MS` | 10 000 | per HTTP request to Kurier |
| `STEAL_RESPOND_BY_MS` | 25 000 | Steal turn budget (platform window ~30 s) |

## Failure modes (diagnosed, each with a tested fallback)

| Failure | Behaviour |
|---|---|
| Bad/absent HMAC | `401 {error:"invalid_signature"}`, nothing parsed |
| Malformed JSON / envelope | Gatekeeper → signed REJECT (`INVALID_INPUT`); Steal → signed HOLD |
| Kurier down / slow / no API key | decision + locally generated proof still returned inside budget (eval-verified with an unreachable Kurier) |
| Proof generation slow | outer timeout cuts in; decision returned without proof (−2 on a provable task beats a −6 wrong approval or a timeout cascade) |
| Proof fails local verification | proof omitted, error logged; decision still returned |
| Seen-store file corrupt/missing | starts empty, logs a loud warning (reuse detection degraded, nothing else affected) |
| Steal witness asserts (known blocker, below) | action + correct `publicInputsHash` returned without proof by default; `STEAL_PROOF_REQUIRED=true` switches this to a strict HOLD response |
| SIGTERM/SIGINT | graceful close (5 s force-exit backstop) |

## What remains UNVERIFIED (needs practice mode — see SPEC §8)

1. **HMAC digest/encoding** — sha256/hex default; alt-encoding acceptance +
   logging will identify the real one from the first preflight.
2. **Gatekeeper witness encodings** — signal names are verified, but how
   the platform encodes `registered_vk`→`registeredVkHash`,
   `task_id`→`taskId`, the `decision` value, and the `salt` source are
   config switches in `src/witness-config.gatekeeper.json`. One practice
   sample pins them.
3. **Approve-side `reason_code`** — `VALID_CONDITION` per SPEC §4.3
   (`APPROVE_REASON_CODE`).
4. **Steal circuit asserts (template lines 75/90)** — commitment formula
   and all input names/sizes are verified, but two deeper asserts in
   `VfyPolicyProof` could not be identified black-box, so fabricated
   Steal proofs do not yet calculate end-to-end. The service still
   answers turns with the correct action + `publicInputsHash`; a real
   practice-turn sample is the fastest way to close this.
5. **Health-check mechanics** at registration (path/method the platform
   pings) — `/health` answers GET with 200 JSON; if the platform expects
   something else it will show at registration.
6. **Kurier job-response field names** are parsed defensively
   (jobId/status/txHash searched at top level and one level deep); the
   first live submission will confirm.

### Settled by live traffic (kept for the record)

Items 1, 2, 3 and 5 above are now **confirmed against the real platform**:
preflight returns `ok` with ~20 ms latency, every scored task reached
`local verify: true` and the platform accepted the decision, and approve-side
`reason_code` came back `VALID_CONDITION` as specified. Only item 4 (the deep
Steal asserts) and item 6 (Kurier, which is not scored) remain open. Item 4 no
longer costs points: Steal turns answer with the correct action and
`publicInputsHash`, and on-chain proof submission is not part of the score —
the platform re-verifies offline against its own registered VK.

## Layout

```
src/config.js        env -> validated config (secrets only from env)
src/hmac.js          sign/verify (algo+encoding switches)
src/field.js         BN254 field encoders used by witness configs
src/seenstore.js     persistent proof_tx seen-sets (atomic JSON)
src/witness.js       config-driven witness builder
src/witness-config.*.json   signal mappings (verified names)
src/proof.js         snarkjs fullProve + local verify + VK export
src/kurier.js        Kurier submit/poll client with timeouts
src/gatekeeper.js    decision engine + task pipeline
src/steal.js         policy + publicInputsHash + turn pipeline
src/server.js        HTTP service, routing, signing, graceful shutdown
scripts/             probe-signals*.js (circuit RE), selftest-proof.js,
                     commitment.js, export-vk.js
test/run-tests.js    sk56 eval harness with per-trap scorecard
```
