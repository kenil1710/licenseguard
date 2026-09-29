/**
 * STEP 4 - the seed. Real public GitHub content, pinned commits, real Studio
 * Dev validators. Two lanes run in parallel, one per DEMO instance (same bytes
 * as the canonical instance, windows in minutes):
 *
 *   Lane A (LicenseGuardDemo)
 *     ATTRIBUTION_MISSING  sindresorhus/slugify index.js copied into
 *                          kenil1710/licenseguard-fixture-stripped without its notice
 *     COMPLIANT            the same file vendored WITH its MIT notice
 *                          (kenil1710/licenseguard-fixture-attributed/vendor/slugify.js)
 *     NOT_DERIVED          an unrelated file (…-attributed/src/app.js)
 *     CONTEST HELD         the NOT_DERIVED challenger contests; the re-read holds
 *     refusals on chain    a path outside the bonded repo (threat 1), a duplicate pair (threat 3)
 *   Lane B (LicenseGuardDemoStall)
 *     FETCH FAILURE        kenil1710/licenseguard-fixture-vanishing is made PRIVATE after
 *                          the challenge; judging RETRYs until the deadline; settle_stalled
 *                          ends it INCONCLUSIVE and releases both bonds
 *   then both lanes finalize, withdraw, claim: books drain to 0.
 *
 *   node seed.mjs            (writes docs/seed-evidence.json and docs/seed-run.log)
 */
import { readFileSync, writeFileSync, appendFileSync } from "node:fs";
import { execSync } from "node:child_process";
import { connect, accounts, fundOnStudio, returnedJson, sleep, gen } from "./harness.mjs";

const dep = JSON.parse(readFileSync(new URL("../deployments.json", import.meta.url))).deployments.studiodev;
const acc = accounts();
const GEN = 10n ** 18n;
const ORIG = ["sindresorhus/slugify", "3b17b2e84b97624a683aafaa38184bf2746fab22", "index.js"];
const FX = {
  stripped: ["kenil1710/licenseguard-fixture-stripped", "9c3bce920042fc5ca0b4219b84ed725370e5d13f"],
  attributed: ["kenil1710/licenseguard-fixture-attributed", "b26192a8e7df4495e9092724610fa30e7c5bb21a"],
  vanishing: ["kenil1710/licenseguard-fixture-vanishing", "85a0d6c543af0df5650b7eaf869e8193b07c2715"],
};
const LOG = new URL("../docs/seed-run.log", import.meta.url);
const EVID = new URL("../docs/seed-evidence.json", import.meta.url);
writeFileSync(LOG, `seed started ${new Date().toISOString()}\n`);
const evidence = { started_at: new Date().toISOString(), lanes: {} };
const T0 = Date.now();
const stamp = () => `+${((Date.now() - T0) / 1000).toFixed(0).padStart(4)}s`;
function log(lane, msg) {
  const line = `${stamp()} [${lane}] ${msg}`;
  console.log(line);
  appendFileSync(LOG, line + "\n");
}
const save = () => writeFileSync(EVID, JSON.stringify(evidence, (k, v) => (typeof v === "bigint" ? v.toString() : v), 2) + "\n");
const plain = (v) => JSON.parse(JSON.stringify(v, (k, x) => (typeof x === "bigint" ? x.toString() : x instanceof Map ? Object.fromEntries(x) : x)));

const CHAIN = connect({ address: dep.LicenseGuardDemo.address }).chain;
for (const role of ["proj1", "proj2", "proj3", "chal1", "chal2", "chal3", "trigger"]) {
  await fundOnStudio(CHAIN, acc[role].address, 50n * GEN);
}

function lane(name, contract) {
  evidence.lanes[name] = { contract, address: dep[contract].address, steps: [] };
  const clients = {};
  const as = (role) => (clients[role] ??= connect({ address: dep[contract].address, role }));
  async function tx(role, fn, args = [], value = 0n, label = fn) {
    const c = as(role);
    const out = await c.send(fn, args, value);
    const ret = returnedJson(out) ?? out.returned;
    const step = { label, role, from: acc[role].address, fn, args, value_wei: value.toString(), tx: out.hash,
      status: out.status, ok: out.ok, seconds: out.seconds, returned: ret, failure: out.failure ?? null };
    evidence.lanes[name].steps.push(step);
    save();
    log(name, `${label.padEnd(34)} ${String(out.status).padEnd(9)} ${String(Math.round(out.seconds)).padStart(4)}s ${JSON.stringify(ret)?.slice(0, 190)}`);
    return { ...out, ret };
  }
  const view = async (fn, args = []) => plain(await as("trigger").view(fn, args));
  return { tx, view, as };
}

/** Send until the contract answers with something other than a transient refusal/RETRY. */
async function persist(L, lanename, role, fn, args, value, label, { accept, tries = 6, waitMs = 20_000 } = {}) {
  let last;
  for (let i = 1; i <= tries; i++) {
    last = await L.tx(role, fn, args, value, i === 1 ? label : `${label} (try ${i})`);
    if (last.ok && accept(last.ret)) return last;
    await sleep(waitMs);
  }
  return last;
}

async function waitChain(L, lanename, what, pred, maxMs = 20 * 60_000) {
  const start = Date.now();
  for (;;) {
    const v = await pred();
    if (v) return v;
    if (Date.now() - start > maxMs) throw new Error(`timed out waiting for ${what}`);
    await sleep(10_000);
  }
}

const nowS = () => Math.floor(Date.now() / 1000);
async function sleepUntil(lanename, epoch, why) {
  const ms = (epoch - nowS()) * 1000;
  if (ms > 0) {
    log(lanename, `waiting ${Math.ceil(ms / 1000)}s: ${why}`);
    await sleep(ms);
  }
}

// ---------------------------------------------------------------- lane A
async function laneA() {
  const N = "A";
  const L = lane(N, "LicenseGuardDemo");
  const cfg = await L.view("get_config");
  const bond = BigInt(cfg.min_bond_wei), stake = BigInt(cfg.challenge_bond_wei), cstake = BigInt(cfg.contest_bond_wei);

  const b1 = (await L.tx("proj1", "post_bond", [...FX.stripped, "MIT"], bond, "post_bond stripped")).ret?.bond_id ?? 1;
  const b2 = (await L.tx("proj2", "post_bond", [...FX.attributed, "MIT"], bond, "post_bond attributed")).ret?.bond_id ?? 2;
  await persist(L, N, "trigger", "verify_bond", [b1], 0n, "verify_bond stripped", { accept: (r) => r?.outcome === "ACTIVE" || r?.outcome === "REJECTED" });
  await persist(L, N, "trigger", "verify_bond", [b2], 0n, "verify_bond attributed", { accept: (r) => r?.outcome === "ACTIVE" || r?.outcome === "REJECTED" });
  log(N, `is_compliant stripped=${await L.view("is_compliant", [FX.stripped[0]])} attributed=${await L.view("is_compliant", [FX.attributed[0]])}`);

  const c1 = (await L.tx("chal1", "challenge", [b1, ...ORIG, "src/slugify.js", "MIT"], stake, "challenge stripped copy")).ret?.challenge_id;
  const c2 = (await L.tx("chal2", "challenge", [b2, ...ORIG, "vendor/slugify.js", "MIT"], stake, "challenge attributed copy")).ret?.challenge_id;
  const c3 = (await L.tx("chal1", "challenge", [b2, ...ORIG, "src/app.js", "MIT"], stake, "challenge unrelated file")).ret?.challenge_id;
  // mechanical refusals on chain: the value sent stays claimable
  await L.tx("chal2", "challenge", [b1, ...ORIG, "../../evil/other/src/slugify.js", "MIT"], stake, "REFUSAL: path outside bonded repo");
  await L.tx("chal2", "challenge", [b1, ORIG[0], "0".repeat(40), ORIG[2], "src/slugify.js", "APACHE_2"], stake, "REFUSAL: duplicate pair (refile)");

  const judged = (r) => r && (r.outcome && r.outcome !== "RETRY");
  await persist(L, N, "trigger", "judge", [c1], 0n, "judge stripped", { accept: judged });
  await persist(L, N, "trigger", "judge", [c2], 0n, "judge attributed", { accept: judged });
  await persist(L, N, "trigger", "judge", [c3], 0n, "judge unrelated", { accept: judged });

  await L.tx("chal1", "contest", [c3], cstake, "contest NOT_DERIVED (challenger)");
  await persist(L, N, "trigger", "judge", [c3], 0n, "judge contest re-read", { accept: (r) => r?.contest === "HELD" || r?.contest === "CHANGED" });

  for (const cid of [c1, c2, c3]) {
    const ch = await L.view("get_challenge", [cid]);
    await sleepUntil(N, Number(ch.contest_until) + 20, `contest window of #${cid}`);
    await persist(L, N, "trigger", "finalize", [cid], 0n, `finalize #${cid} (${ch.outcome})`, { accept: (r) => r?.status === "OK", waitMs: 20_000 });
  }
  log(N, `is_compliant stripped=${await L.view("is_compliant", [FX.stripped[0]])} attributed=${await L.view("is_compliant", [FX.attributed[0]])}`);

  for (const [bid, role] of [[b1, "proj1"], [b2, "proj2"]]) {
    const b = await L.view("get_bond", [bid]);
    const free = Math.max(Number(b.challenge_until), Number(b.last_closed_at) + Number(b.unbond_delay_s));
    await sleepUntil(N, free + 20, `bond #${bid} lock`);
    await persist(L, N, role, "withdraw_bond", [bid], 0n, `withdraw_bond #${bid}`, { accept: (r) => r?.status === "OK" });
  }
  for (const role of ["proj1", "proj2", "chal1", "chal2", "trigger"]) {
    const owed = BigInt(await L.view("get_balance", [acc[role].address]));
    if (owed > 0n) await L.tx(role, "claim", [], 0n, `claim ${role} (${gen(owed)} GEN)`);
  }
  evidence.lanes[N].final = { stats: await L.view("get_stats"), challenges: [], bonds: [] };
  for (const cid of [c1, c2, c3]) {
    evidence.lanes[N].final.challenges.push({ ...(await L.view("get_challenge", [cid])), verify: await L.view("verify_challenge", [cid]) });
  }
  for (const bid of [b1, b2]) evidence.lanes[N].final.bonds.push(await L.view("get_bond", [bid]));
  save();
  log(N, `DONE stats ${JSON.stringify(evidence.lanes[N].final.stats)}`);
}

// ---------------------------------------------------------------- lane B
async function laneB() {
  const N = "B";
  const L = lane(N, "LicenseGuardDemoStall");
  const cfg = await L.view("get_config");
  const bond = BigInt(cfg.min_bond_wei), stake = BigInt(cfg.challenge_bond_wei);
  const repo = FX.vanishing[0];
  execSync(`gh repo edit ${repo} --visibility public --accept-visibility-change-consequences 2>/dev/null || true`);

  const b = (await L.tx("proj3", "post_bond", [...FX.vanishing, "MIT"], bond, "post_bond vanishing")).ret?.bond_id ?? 1;
  await persist(L, N, "trigger", "verify_bond", [b], 0n, "verify_bond vanishing", { accept: (r) => r?.outcome === "ACTIVE" || r?.outcome === "REJECTED" });
  const verifiedAt = nowS();
  const c = (await L.tx("chal3", "challenge", [b, ...ORIG, "src/slugify.js", "MIT"], stake, "challenge vanishing copy")).ret?.challenge_id ?? 1;

  execSync(`gh repo edit ${repo} --visibility private --accept-visibility-change-consequences`);
  log(N, `made ${repo} PRIVATE; raw.githubusercontent.com caches for max-age=300 (measured), so judging waits past it`);
  evidence.lanes[N].made_private_at = new Date().toISOString();

  const ch0 = await L.view("get_challenge", [c]);
  await sleepUntil(N, Math.min(verifiedAt + 330, Number(ch0.judge_deadline) - 60), "CDN cache of the bonded LICENSE to expire");
  const j = await L.tx("trigger", "judge", [c], 0n, "judge (bonded repo now private)");
  if (j.ret?.outcome !== "RETRY") log(N, `NOTE: expected RETRY, got ${JSON.stringify(j.ret)}`);
  await sleepUntil(N, Number(ch0.judge_deadline) + 20, "judge deadline");
  await L.tx("trigger", "judge", [c], 0n, "judge after deadline (refused)");
  await persist(L, N, "trigger", "settle_stalled", [c], 0n, "settle_stalled", { accept: (r) => r?.status === "OK" });
  log(N, `is_compliant vanishing=${await L.view("is_compliant", [repo])}`);

  const bd = await L.view("get_bond", [b]);
  const free = Math.max(Number(bd.challenge_until), Number(bd.last_closed_at) + Number(bd.unbond_delay_s));
  await sleepUntil(N, free + 20, "bond lock");
  await persist(L, N, "proj3", "withdraw_bond", [b], 0n, "withdraw_bond", { accept: (r) => r?.status === "OK" });
  for (const role of ["proj3", "chal3"]) {
    const owed = BigInt(await L.view("get_balance", [acc[role].address]));
    if (owed > 0n) await L.tx(role, "claim", [], 0n, `claim ${role} (${gen(owed)} GEN)`);
  }
  evidence.lanes[N].final = { stats: await L.view("get_stats"),
    challenges: [{ ...(await L.view("get_challenge", [c])), verify: await L.view("verify_challenge", [c]) }],
    bonds: [await L.view("get_bond", [b])] };
  save();
  log(N, `DONE stats ${JSON.stringify(evidence.lanes[N].final.stats)}`);
}

const results = await Promise.allSettled([laneA(), laneB()]);
results.forEach((r, i) => { if (r.status === "rejected") log(i ? "B" : "A", `LANE FAILED: ${r.reason?.stack ?? r.reason}`); });
evidence.finished_at = new Date().toISOString();
evidence.minutes = ((Date.now() - T0) / 60000).toFixed(1);
save();
log("*", `seed finished in ${evidence.minutes} min`);
