"use strict";
// Persistent seen-set of proof_tx references for PROOF_REUSED detection.
// Two sets on disk (JSON, atomic rewrite):
//   accepted: proof_tx of tasks we APPROVED (SPEC §4.3 wording: "already
//             accepted in a previous task")
//   all:      every proof_tx we have processed, any outcome
// SEEN_RULE config picks which set the reuse check consults (default:
// accepted). Recording is synchronous — task volume is tiny (8/round).
const fs = require("fs");
const path = require("path");

class SeenStore {
  constructor(filePath, log) {
    this.filePath = filePath;
    this.log = log || (() => {});
    this.accepted = new Set();
    this.all = new Set();
    this._load();
  }

  _load() {
    try {
      const raw = fs.readFileSync(this.filePath, "utf8");
      const data = JSON.parse(raw);
      for (const x of data.accepted || []) this.accepted.add(String(x));
      for (const x of data.all || []) this.all.add(String(x));
      this.log("info", `seen-store loaded: ${this.accepted.size} accepted, ${this.all.size} all`);
    } catch (e) {
      if (e.code !== "ENOENT") {
        this.log("warn", `seen-store unreadable (${e.message}); starting empty — reuse detection degraded`);
      }
    }
  }

  _persist() {
    fs.mkdirSync(path.dirname(this.filePath), { recursive: true });
    const tmp = this.filePath + ".tmp";
    fs.writeFileSync(tmp, JSON.stringify({ accepted: [...this.accepted], all: [...this.all] }));
    fs.renameSync(tmp, this.filePath);
  }

  hasAccepted(tx) { return this.accepted.has(String(tx)); }
  hasAll(tx) { return this.all.has(String(tx)); }

  recordAll(tx) {
    if (tx === undefined || tx === null || tx === "") return;
    const k = String(tx);
    if (!this.all.has(k)) { this.all.add(k); this._persist(); }
  }

  recordAccepted(tx) {
    if (tx === undefined || tx === null || tx === "") return;
    const k = String(tx);
    let changed = false;
    if (!this.accepted.has(k)) { this.accepted.add(k); changed = true; }
    if (!this.all.has(k)) { this.all.add(k); changed = true; }
    if (changed) this._persist();
  }
}

module.exports = { SeenStore };
