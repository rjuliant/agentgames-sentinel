"use strict";
// Offline check: every documented trap variety maps to the right decision.
// Run: node scripts/check-traps.js   (no network, no proofs)
const { decide } = require("../src/gatekeeper");
const { loadConfig } = require("../src/config");
const cfg = loadConfig();

const store = {
  _all: new Set(["0xreused"]),
  hasAll(x) { return this._all.has(x); },
  hasAccepted(x) { return this._all.has(x); },
};

const base = {
  registered_vk: "0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0",
  proof_vk: "0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0",
  minimum: "1000",
  public_balance: "1460",
  expiry_block: 8430000,
  current_block: 8420000,
  recipient: "0xabcdef1234567890abcdef1234567890abcdef12",
  condition_recipient: "0xabcdef1234567890abcdef1234567890abcdef12",
  amount: "500",
  max_transfer: "1000",
  proof_tx: "0xfresh1",
};

const cases = [
  ["VALID_CONDITION", "APPROVE", {}],
  ["VK_SUBSTITUTION", "REJECT", { proof_vk: "0xdeadbeef" }],
  ["THRESHOLD_MISMATCH", "REJECT", { public_balance: "999" }],
  ["PROOF_REUSED", "REJECT", { proof_tx: "0xreused" }],
  ["EXPIRED_CONDITION", "REJECT", { current_block: 8430001 }],
  ["RECIPIENT_MISMATCH", "REJECT", { recipient: "0x1111111111111111111111111111111111111111" }],
  ["AMOUNT_OVERFLOW", "REJECT", { amount: "1001" }],
];

let fail = 0;
for (const [want, wantDecision, override] of cases) {
  const task = { task_id: "t1", input: { ...base, ...override } };
  const d = decide(task, store, cfg);
  const ok = d.reason_code === want && d.decision === wantDecision;
  if (!ok) fail++;
  console.log(`${ok ? "PASS" : "FAIL"}  ${want.padEnd(20)} -> ${d.decision}/${d.reason_code}`);
}
console.log(fail === 0 ? "ALL 7 TRAP VARIETIES CORRECT" : `${fail} MISMATCH`);
process.exit(fail === 0 ? 0 : 1);
