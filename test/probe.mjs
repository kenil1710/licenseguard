/**
 * STEP 1 - the source probe. Deploys contracts/_probe.py and asks real Studio
 * Dev validators to read every GitHub source LicenseGuard might depend on.
 * Raw results go to docs/probe/<key>.json; docs/PROBE.md is written from them.
 *
 *   node probe.mjs                     # deploy fresh probe lanes, run every job
 *   node probe.mjs --only=k1,k2 --lanes=0x..,0x..
 *
 * Lanes: one probe contract AND one signer per lane (a Studio node holds one
 * transaction slot per recipient contract; lanes sharing a wallet race nonces).
 */
import { readFileSync, writeFileSync, mkdirSync } from "node:fs";
import { connect, deploy, fundOnStudio, argOf, accounts } from "./harness.mjs";

const S = "3b17b2e84b97624a683aafaa38184bf2746fab22";     // sindresorhus/slugify main, 2026-09-29
const FORK = "2014476d54bfa6ba4ec15618b5c845fff16f6af3";  // a commit that exists only in a fork (anneeeee/slugify)
const LODASH = "LODASH_SHA";
const R = "https://raw.githubusercontent.com";
const A = "https://api.github.com";

const JOBS = [
  { key: "raw_file", url: `${R}/sindresorhus/slugify/${S}/index.js`, ua: false, strict: true },
  { key: "raw_license", url: `${R}/sindresorhus/slugify/${S}/license`, ua: false, strict: true },
  { key: "raw_missing_path", url: `${R}/sindresorhus/slugify/${S}/NOTICE`, ua: false, strict: true },
  { key: "raw_missing_repo", url: `${R}/kenil1710/no-such-repo-licenseguard/${S}/index.js`, ua: false, strict: true },
  { key: "raw_fork_sha_via_parent", url: `${R}/sindresorhus/slugify/${FORK}/index.js`, ua: false, strict: true },
  { key: "raw_big_lodash", url: `${R}/lodash/lodash/${LODASH}/lodash.js`, ua: false, strict: true },
  { key: "api_commit_noua", url: `${A}/repos/sindresorhus/slugify/commits/${S}`, ua: false, strict: false },
  { key: "api_commit_ua", url: `${A}/repos/sindresorhus/slugify/commits/${S}`, ua: true, strict: false },
  { key: "api_commit_fork_via_parent", url: `${A}/repos/sindresorhus/slugify/commits/${FORK}`, ua: true, strict: false },
  { key: "api_compare_in_history", url: `${A}/repos/sindresorhus/slugify/compare/${S}...HEAD?per_page=1`, ua: true, strict: false },
  { key: "api_compare_fork", url: `${A}/repos/sindresorhus/slugify/compare/${FORK}...HEAD?per_page=1`, ua: true, strict: false },
  { key: "api_repo", url: `${A}/repos/sindresorhus/slugify`, ua: true, strict: false },
  { key: "api_commit_missing_sha", url: `${A}/repos/sindresorhus/slugify/commits/${"0".repeat(40)}`, ua: true, strict: false },
  { key: "raw_8mb", url: `${R}/kenil1710/licenseguard-fixture-oversize/OVS/data-8mb.js`, ua: false, strict: false },
  { key: "raw_30mb", url: `${R}/kenil1710/licenseguard-fixture-oversize/OVS/data-30mb.js`, ua: false, strict: false },
  { key: "raw_90mb", url: `${R}/kenil1710/licenseguard-fixture-oversize/OVS/data-90mb.js`, ua: false, strict: false },
  { key: "api_rate_limit", url: `${A}/rate_limit`, ua: true, strict: false },
];

const only = argOf("only");
const jobs = (only ? JOBS.filter((j) => only.split(",").includes(j.key)) : JOBS)
  .map((j) => ({ ...j, url: j.url.replace("LODASH_SHA", process.env.LODASH || "").replace("OVS", process.env.OVS || "") }));
let lanes = argOf("lanes") ? argOf("lanes").split(",") : null;
const laneCount = Number(argOf("n", "4"));
const LANE_ROLES = ["owner", "proj1", "proj2", "proj3", "chal1", "chal2"];
const acc = accounts();
const base = connect({ address: "0x0000000000000000000000000000000000000000" });
for (const role of LANE_ROLES) await fundOnStudio(base.chain, acc[role].address, 200n * 10n ** 18n);

if (!lanes) {
  lanes = [];
  const code = readFileSync(new URL("../contracts/_probe.py", import.meta.url));
  for (let i = 0; i < laneCount; i++) {
    const res = await deploy({ chain: base.chain, wallet: base.wallet, read: base.read, code, args: [], label: `probe ${i}` });
    if (!res.ok) { console.error("deploy failed", res.out?.status, res.out?.stderr?.slice(-1500), res.reason); process.exit(1); }
    console.log(`lane ${i}: ${res.address}`);
    lanes.push(res.address);
  }
}
mkdirSync(new URL("../docs/probe/", import.meta.url), { recursive: true });

async function run(address, job, lane) {
  const c = connect({ address, role: LANE_ROLES[lane % LANE_ROLES.length] });
  const t0 = Date.now();
  const out = await c.send("probe", [job.key, job.url, job.ua, job.strict], 0n);
  const secs = Math.round((Date.now() - t0) / 1000);
  let stored = "";
  for (let k = 0; k < 5 && !stored; k++) {
    try { stored = await c.view("get", [job.key]); } catch { stored = ""; }
  }
  const record = {
    key: job.key, url: job.url, user_agent: job.ua, strict: job.strict,
    probe_contract: address, tx: out.hash, status: out.status, ok: out.ok, seconds: secs,
    measured_at: new Date().toISOString(),
    failure: out.failure ?? null, stderr_tail: out.stderr ? out.stderr.slice(-600) : "",
    result: stored ? JSON.parse(stored) : null,
  };
  writeFileSync(new URL(`../docs/probe/${job.key}.json`, import.meta.url), JSON.stringify(record, null, 2) + "\n");
  const r = record.result || {};
  console.log(`${job.key.padEnd(28)} ${String(out.status).padEnd(10)} ${String(secs).padStart(4)}s http=${r.status ?? "-"} len=${r.len ?? "-"} ${r.j_status ? "cmp=" + r.j_status + "/" + r.j_behind_by : ""} ${r.headers ? "hdr=" + r.headers.slice(0, 120) : ""} ${r.err ? "err=" + r.err.slice(0, 80) : ""}`);
}

const queues = lanes.map(() => []);
jobs.forEach((j, i) => queues[i % lanes.length].push(j));
await Promise.all(queues.map(async (q, i) => { for (const job of q) await run(lanes[i], job, i); }));
console.log("lanes:", lanes.join(","));
