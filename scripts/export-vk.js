#!/usr/bin/env node
"use strict";
// Export both circuits' verification keys from the .zkey artifacts into
// data/ (the server also does this lazily at startup; this is the manual
// path). Usage: npm run export-vk
const { loadConfig } = require("../src/config");
const { makeLogger } = require("../src/log");
const proofMod = require("../src/proof");

(async () => {
  const cfg = loadConfig();
  const log = makeLogger(cfg.logLevel);
  for (const name of ["gatekeeper", "vfy-policy"]) {
    const vk = await proofMod.ensureVk(cfg, name, log);
    console.log(`${name}: protocol=${vk.protocol} curve=${vk.curve} nPublic=${vk.nPublic}`);
  }
})().catch((e) => { console.error(e); process.exit(1); });
