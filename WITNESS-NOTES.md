# Witness / Circuit Reverse-Engineering Notes — Agent Games

Compiled 13 Nov 2026 from local analysis of the downloaded artifacts in
`~/workspace/agentgames/circuits/` (snarkjs 0.7.5, Node 24). Methods:
`strings` on the wasm binaries, `snarkjs zkey export verificationkey`,
FNV-1a-64 signal-name probing through snarkjs's own witness calculator
(error classification), element counters (`getInputSize()`), and targeted
assert-line fuzzing. Probe scripts: `scripts/probe-signals*.js`; raw results:
`data/signal-probe-results.json`, `data/signal-probe2-results.json`.

## What did NOT work

- `strings` on either `.wasm`: Circom 2.x witness calculators do not embed
  signal names — inputs are resolved by FNV-1a-64(name) → signal map.
  `strings` only surfaces runtime export names.
- Calling the wasm export `getInputSignalSize(hMSB, hLSB)` from a bare
  WebAssembly instantiation returns `0` for every plausible name and `-1`
  only for gibberish — unreliable standalone. The reliable oracle is
  snarkjs's own calculator: a real scalar input increments the
  "Not all inputs have been set. Only X out of N" counter; a real array
  input answers "Not enough values…"; anything else is not a signal.

## VERIFIED — gatekeeper circuit (13 public inputs, 0 private)

`getInputSize()` = 13 = `nPublic` from the exported VK → the input set below
is COMPLETE (all inputs are public, all size 1). A witness with all 13 set
calculates successfully.

| # | Signal name | Value source (our mapping) | Confidence |
|---|---|---|---|
| 1 | `taskId` | task.task_id (encoding unverified) | name: certain |
| 2 | `registeredVkHash` | task.input.registered_vk | name: certain |
| 3 | `proofVkHash` | task.input.proof_vk | name: certain |
| 4 | `minimum` | task.input.minimum | name: certain |
| 5 | `publicBalance` | task.input.public_balance | name: certain |
| 6 | `expiryBlock` | task.input.expiry_block | name: certain |
| 7 | `currentBlock` | task.input.current_block | name: certain |
| 8 | `recipient` | task.input.recipient | name: certain |
| 9 | `conditionRecipient` | task.input.condition_recipient | name: certain |
| 10 | `amount` | task.input.amount | name: certain |
| 11 | `maxTransfer` | task.input.max_transfer | name: certain |
| 12 | `decision` | our decision (encoding unverified) | name: certain |
| 13 | `salt` | ??? (we default to 0 via env) | name: certain, source unknown |

Notable: `proof_tx` is NOT a circuit input (the reuse binding is presumably
via `taskId`/`salt` platform-side). The circuit did NOT assert-fail on a
deliberately inconsistent input (registeredVkHash ≠ proofVkHash with
decision=0): the witness calculated. So the circuit appears to *bind* the
data + decision into the proof (platform re-verifies and scores the decision
itself) rather than enforcing the decision rule in-circuit — at least for
the combinations probed. Full-prove + local VK verify results are in the
project README / self-test output.

Still UNVERIFIED for gatekeeper (resolve from ONE practice-mode sample):
- Field encodings: how `registered_vk` (a 0x… string) becomes
  `registeredVkHash` (we use BigInt(value) mod BN254 p; switchable in
  `src/witness-config.gatekeeper.json` — encoder `hashField`), how
  `task_id` ("gk_…") becomes `taskId` (encoder `taskId`: hex→int, digits→int,
  else keccak256(utf8) mod p), and what `salt` is (default "0").
- `decision` encoding: we use APPROVE=1 / REJECT=0 (config
  `DECISION_APPROVE_VALUE` / `DECISION_REJECT_VALUE`).
- Public-signal ORDER in the response array: we pass snarkjs's
  `public_signals` through verbatim (declaration order); if the platform
  expects a different order it will show up as a practice verification
  failure, not a witness failure.

## VERIFIED — vfy-policy circuit (Steal the VFY)

- Input signals (names certain, via the counter oracle):
  scalars `commitment`, `matchId`, `turnNumber`, `selfBalance`,
  `opponentBalance`, `action`, `amount`, `circuitVersion`, `salt`, plus
  array `strategyParams` with **exactly 8 elements** (found by length scan:
  len<8 → "Not enough values"; len=8 → proceeds to asserts).
  Total input elements: 9 + 8 = 17 = `getInputSize()`. `nPublic` = 9.
  (Which 9 of the 17 elements are the public ones cannot be determined
  locally; snarkjs returns `public_signals` in the right order regardless.)
- **Commitment formula VERIFIED:** with
  `commitment = Poseidon(strategyParams[0..7], salt)` (circomlibjs Poseidon,
  params first, salt last), the circuit's first assert (template
  `VfyPolicyProof`, line 72) PASSES. Arrangements
  `Poseidon(salt, params…)`, `Poseidon(params…)`,
  `Poseidon(Poseidon(params…), salt)` all fail at line 72.
  → `scripts/commitment.js` uses exactly this arrangement (order switchable
  via `POSEIDON_INPUT_ORDER`).
- Template name leaked by assert errors: `VfyPolicyProof` (instance `_154`).

## SOLVED 13 Nov 2026 — vfy-policy policy semantics (probes 7–12)

Method (SUPERAGENT sk57): single-position param scans from the all-zero
base + structured pairs, then single-dimension scans around the first
successful witnesses, then fullProve + VK verification. Probe scripts:
`scripts/probe-signals7.js` … `probe-signals12.js`; raw logs in /tmp
(probe7–probe10 results). The earlier "line 75 / line 90" framing was a
misread caused by probing only uniform param vectors: the all-zero
vector is simply INVALID (params[0] = 0 breaks the range assert), and
lines 75–78 are four separate asserts, one per params[4..7].

### Params semantics (all verified by witness calculation)

- `strategyParams[4]`, `[5]`, `[6]`, `[7]` must be exactly **0** —
  asserted individually at template lines 75, 76, 77, 78 (any nonzero
  value, including p−1, fails its line).
- `strategyParams[0]` = **EXTRACT amount**, valid range **1..10**:
  ≥1 enforced ~line 89/90 (GreaterEqThan component), ≤10 ~line 95
  (LessThan); values ≥ ~20 fail inside the comparator's Num2Bits
  (line 38 of the comparator template). This was the real "line 90"
  blocker: params[0]=0 can never witness.
- `strategyParams[3]` ∈ {0,1} — boolean, asserted ~line 98
  (value ≥2 fails there).
- `strategyParams[1]`, `[2]` — thresholds (no tight validity bound
  found; 1000 works).

### The circuit's policy is a decision list (line ~140 = branch assert,
### line ~149 = EXTRACT amount assert)

Evaluated in strict priority order (verified by overlap tests):

1. `selfBalance < strategyParams[1]` → action must be **FORTIFY**
   (amount 0). Wins over every other branch — fires even at
   opponentBalance = 0 and even when params[3] = 1. Strict `<`:
   params[1]=10, self=10 does NOT fortify; self=5 does.
2. else `opponentBalance <= strategyParams[2]` **OR**
   `strategyParams[3] == 1` → action must be **HOLD** (amount 0).
   Boundary: opponentBalance == params[2] holds; params[2]+1 extracts.
3. else → action must be **EXTRACT** with `amount == strategyParams[0]`
   EXACTLY (line 149) — NOT min(params[0], opponentBalance): with
   params[0]=10 and opponentBalance=5, amount=10 proves and amount=5
   fails. The game resolver caps the actual take ("steals up to N").

Any (params, state, action, amount) combination that is not the
decision-list output for that state fails the line-140 assert. The
circuit therefore forces exactly one provable action per state — there
is no freedom to deviate, by design.

Free inputs (no in-circuit validity constraint found): `matchId`,
`turnNumber` (0..100 probed), `circuitVersion` (0..2^32 probed), `salt`.

### Public signals layout (from fullProve output, verified)

`public_signals` (9) = `[digest, commitment, matchId, turnNumber,
selfBalance, opponentBalance, action, amount, circuitVersion]`.
Private inputs: `salt` + `strategyParams[8]` (9 elements). `digest` is a
circuit-computed output binding the turn; six Poseidon arrangements
over the public fields were tested and none matched (probe12) — its
exact formula is undetermined and unnecessary (snarkjs emits it).

### Registered strategy (post-fix)

`STRATEGY_PARAMS = [10,0,0,0,0,0,0,0]` — decision list reduces to
EXTRACT 10 whenever opponentBalance > 0, HOLD at opponentBalance = 0:
exactly STEAL-STRATEGY.md's shipped policy (the game's real EXTRACT cap
is 10, SPEC §5.1). The previously registered all-zero commitment
(0x052a5902…cd287d3d) could NEVER produce a valid proof (params[0]=0);
it was superseded 13 Nov 2026 by the commitment for the new params
(0x158073b6…0d95119f, dashboard-verified ACTIVE, circuit v1 · policy v1,
computed in the box from the existing salt).

### End-to-end evidence

Groth16 proofs generated with `vfy-policy_final.zkey` and VERIFIED
against the official VK for: EXTRACT (100/100 and opp=5 cases), HOLD
(opponentBalance=0), HOLD via params[3]=1, FORTIFY (params[1]=100,
self=5) — `scripts/probe-signals11.js`. The agent's own HTTP service
generates + attaches verifying proofs for EXTRACT and HOLD turns
(`npm test`, 19/19, local + box).

## HMAC (from SPEC §3, still UNVERIFIED)

Digest/encoding of `x-agent-games-signature` is not published. Service
default: HMAC-SHA256 / hex, switchable via `HMAC_ALGO` / `HMAC_ENCODING`;
verification also accepts the alternate encoding (`HMAC_ACCEPT_ALT=true`)
and logs which one matched — the first preflight/practice request will
reveal the right combination in the logs.

## Redeploy 13 Nov 2026 (post Swiss R1)

Strategy params changed to `[10,70,0,0,0,0,0,0]` (FORTIFY below
selfBalance 70, else EXTRACT 10). New commitment
`0x122c6face993fed090ff91667fc3ace3fefae175919e6302636c3670ce4996d4`
registered on the dashboard (readback: ACTIVE COMMITMENT REGISTERED,
circuit v1 · policy v1). Branch proofs (EXTRACT / FORTIFY / HOLD) under
the deployed params verified against the official VK —
`scripts/selftest-steal-branches.js`; npm test 19/19 (box + local).
Match 805886cc record: all 20 turns substituted HOLD by the platform
(`HH_NO_TRANSFER_TIMEOUT_SUBSTITUTE`) despite timely EXTRACT responses
with locally verified proofs — see STEAL-STRATEGY.md addendum in the
working repo for the full analysis.
