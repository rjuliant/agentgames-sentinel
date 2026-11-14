"use strict";
// Kurier (zkVerify) REST client — SPEC §6.
//   POST {base}/submit-proof/{API_KEY}   body per SPEC §6 verbatim example
//   GET  {base}/job-status/{API_KEY}/{jobId}  -> poll until Finalized
// The API key travels in the URL path, so URLs are NEVER logged here.
// Every request has its own timeout (AbortController); polling is bounded
// by a caller-supplied deadline. All failures are structured errors.

function dig(obj, keys) {
  for (const k of keys) {
    if (obj && typeof obj === "object" && obj[k] !== undefined) return obj[k];
  }
  return undefined;
}
function digDeep(obj, keys) {
  const top = dig(obj, keys);
  if (top !== undefined) return top;
  if (obj && typeof obj === "object") {
    for (const v of Object.values(obj)) {
      if (v && typeof v === "object") {
        const inner = dig(v, keys);
        if (inner !== undefined) return inner;
      }
    }
  }
  return undefined;
}

class KurierClient {
  constructor(cfg, log) {
    this.cfg = cfg;
    this.log = log || (() => {});
    this.base = cfg.kurierBaseUrl.replace(/\/+$/, "");
    this.key = cfg.kurierApiKey;
  }

  get enabled() { return !!this.key; }

  async _fetch(url, opts, timeoutMs) {
    const ctrl = new AbortController();
    const t = setTimeout(() => ctrl.abort(), timeoutMs);
    if (t.unref) t.unref();
    try {
      const res = await fetch(url, { ...opts, signal: ctrl.signal });
      const text = await res.text();
      let json = null;
      try { json = JSON.parse(text); } catch (e) { /* non-JSON response */ }
      if (!res.ok) {
        throw Object.assign(new Error(`Kurier HTTP ${res.status}`), { code: "KURIER_HTTP", status: res.status, body: json || text.slice(0, 200) });
      }
      return json;
    } catch (e) {
      if (e.name === "AbortError") throw Object.assign(new Error("Kurier request timed out"), { code: "KURIER_TIMEOUT" });
      throw e;
    } finally {
      clearTimeout(t);
    }
  }

  // Submit a proof for an already-registered VK (vkRegistered: true).
  // Returns { jobId, raw }.
  async submitProof({ vkHash, proof, publicSignals }) {
    if (!this.enabled) throw Object.assign(new Error("KURIER_API_KEY not set"), { code: "KURIER_DISABLED" });
    const body = {
      proofType: "groth16",
      vkRegistered: true,
      proofOptions: { library: "snarkjs", curve: "bn128" },
      proofData: { proof, publicSignals, vk: vkHash },
    };
    const json = await this._fetch(`${this.base}/submit-proof/${this.key}`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(body),
    }, this.cfg.kurierRequestTimeoutMs);
    const jobId = digDeep(json, ["jobId", "job_id", "id"]);
    if (!jobId) throw Object.assign(new Error("Kurier submit-proof response carried no jobId"), { code: "KURIER_BAD_RESPONSE", body: json });
    return { jobId: String(jobId), raw: json };
  }

  async jobStatus(jobId) {
    const json = await this._fetch(`${this.base}/job-status/${this.key}/${encodeURIComponent(jobId)}`,
      { method: "GET" }, this.cfg.kurierRequestTimeoutMs);
    const status = digDeep(json, ["status", "jobStatus", "state"]);
    const ref = digDeep(json, ["txHash", "transactionHash", "proofReference", "hash"]);
    return { status: status ? String(status) : "Unknown", ref: ref ? String(ref) : null, raw: json };
  }

  // Poll until Finalized / Failed / deadline. Returns
  // { status: "Finalized", ref } or { status: "timeout"|"Failed", ... }.
  async waitFinalized(jobId, deadlineMs) {
    const started = Date.now();
    let last = null;
    for (;;) {
      try {
        last = await this.jobStatus(jobId);
        if (/final/i.test(last.status)) return { status: "Finalized", ref: last.ref, jobId };
        if (/fail|error|reject/i.test(last.status)) return { status: "Failed", ref: last.ref, jobId };
      } catch (e) {
        this.log("warn", `kurier poll error: ${e.code || ""} ${e.message}`);
        last = { status: "Error", ref: null };
      }
      const remaining = deadlineMs - (Date.now() - started);
      if (remaining <= 0) return { status: "timeout", ref: last && last.ref, jobId, lastStatus: last && last.status };
      await new Promise((r) => setTimeout(r, Math.min(this.cfg.kurierPollIntervalMs, remaining)));
    }
  }
}

module.exports = { KurierClient };
