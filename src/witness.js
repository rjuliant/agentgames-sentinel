"use strict";
// Witness builder driven by JSON mapping configs:
//   src/witness-config.gatekeeper.json / src/witness-config.steal.json
// Each entry: { "name": <signal>, "from": <source>, "encoder": <encoder> }
// Sources:
//   "task.input.registered_vk"  dotted path over the context object
//   "decisionValue"             context key
//   "env:GATEKEEPER_SALT"       string from the env map in the context
//   "envJson:STRATEGY_PARAMS"   JSON-parsed env value (arrays)
//   "const:1"                   literal
// Signal names in these configs are the ones VERIFIED by probing
// (see WITNESS-NOTES.md). Encodings stay switchable here.
const fs = require("fs");
const path = require("path");
const { encode } = require("./field");

const cache = new Map();

function loadWitnessConfig(which) {
  if (cache.has(which)) return cache.get(which);
  const file = path.join(__dirname, `witness-config.${which}.json`);
  const cfg = JSON.parse(fs.readFileSync(file, "utf8"));
  cache.set(which, cfg);
  return cfg;
}

function resolveSource(from, ctx) {
  if (from.startsWith("const:")) return from.slice("const:".length);
  if (from.startsWith("envJson:")) {
    const name = from.slice("envJson:".length);
    const raw = ctx.env ? ctx.env[name] : undefined;
    if (raw === undefined || raw === "") throw new Error(`witness source missing: env ${name} not set`);
    return JSON.parse(raw);
  }
  if (from.startsWith("env:")) {
    const name = from.slice("env:".length);
    const raw = ctx.env ? ctx.env[name] : undefined;
    if (raw === undefined) throw new Error(`witness source missing: env ${name} not set`);
    return raw;
  }
  let cur = ctx;
  for (const part of from.split(".")) {
    if (cur === null || cur === undefined || !(part in Object(cur))) {
      throw new Error(`witness source missing: ${from}`);
    }
    cur = cur[part];
  }
  if (cur === undefined || cur === null || cur === "") throw new Error(`witness source empty: ${from}`);
  return cur;
}

function buildWitness(which, ctx) {
  const cfg = loadWitnessConfig(which);
  const input = {};
  for (const entry of cfg.signals) {
    const raw = resolveSource(entry.from, ctx);
    input[entry.name] = encode(entry.encoder, raw);
  }
  return { input, circuit: cfg.circuit, vkHash: cfg.vkHash };
}

module.exports = { buildWitness, loadWitnessConfig };
