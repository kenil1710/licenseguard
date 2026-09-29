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
 *     SQUATTER             an address that does not control the repo posts a bond FIRST;
 *                          it reserves nothing, the owner's bond verifies, and the
 *                          squatter's pending bond is rejected and refunded
 *     refusals on chain    a LICENSE-vs-LICENSE challenge (review A1), the same copied file
 *                          named against a FORK of the original (review A3)
 *   Lane B (LicenseGuardDemoStall) - one bond on kenil1710/licenseguard-fixture-vanishing,
 *   two challenges, then the bonded repo AND the second original are made PRIVATE:
 *     FORFEIT              challenge 1 (original sindresorhus/slugify, still readable): the
 *                          bonded commit is gone while the original is readable - the bonded
 *                          party's doing - so it pays the challenger (review A4)
 *     NOBODY'S FAULT       challenge 2 (original kenil1710/licenseguard-fixture-origin-vanishing,
 *                          also private): neither source can be read - RETRY until the deadline,
 *                          settle_stalled ends it INCONCLUSIVE, both refunded
 *     withdraw refused     while the forfeit is open
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
  stripped: ["kenil1710/licenseguard-fixture-stripped", "00aa5788e36122277595281d639e7467c48c9689"],
  attributed: ["kenil1710/licenseguard-fixture-attributed", "8849b82c36c476486fabf192db22f783c0c781e9"],
  vanishing: ["kenil1710/licenseguard-fixture-vanishing", "112b0766ccbd2d72141c0a374eb2bfc75874db14"],
  originVanishing: ["kenil1710/licenseguard-fixture-origin-vanishing", "4f60c2c60a9c1047349440dfa6b604b3e2d4a975"],
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
for (const role of ["proj1", "proj2", "proj3", "proj4", "chal1", "chal2", "chal3", "trigger", "outsider"]) {
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
  const view = async (fn, args = []) => plain(await as("owner").view(fn, args));
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

  const sq = (await L.tx("chal3", "post_bond", [...FX.stripped, "MIT"], bond, "SQUATTER post_bond on stripped (first)")).ret?.bond_id;
  const b1 = (await L.tx("proj1", "post_bond", [...FX.stripped, "MIT"], bond, "post_bond stripped (owner, second)")).ret?.bond_id ?? 2;
  const b2 = (await L.tx("proj2", "post_bond", [...FX.attributed, "MIT"], bond, "post_bond attributed")).ret?.bond_id ?? 3;
  await persist(L, N, "trigger", "verify_bond", [b1], 0n, "verify_bond stripped", { accept: (r) => r?.outcome === "ACTIVE" || r?.outcome === "REJECTED" });
  await persist(L, N, "trigger", "verify_bond", [b2], 0n, "verify_bond attributed", { accept: (r) => r?.outcome === "ACTIVE" || r?.outcome === "REJECTED" });
  log(N, `is_compliant stripped=${await L.view("is_compliant", [FX.stripped[0]])} attributed=${await L.view("is_compliant", [FX.attributed[0]])}`);
  evidence.lanes[N].squatter = { bond: await L.view("get_bond", [sq]), owner_bond: await L.view("get_bond", [b1]),
                                 slot: await L.view("get_bond_for", [FX.stripped[0]]) };
  log(N, `squatter bond #${sq}: ${evidence.lanes[N].squatter.bond.status} ${evidence.lanes[N].squatter.bond.verify_reason}; slot -> #${evidence.lanes[N].squatter.slot.bond_id}`);

  const c1 = (await L.tx("chal1", "challenge", [b1, ...ORIG, "src/slugify.js", "MIT"], stake, "challenge stripped copy")).ret?.challenge_id;
  const c2 = (await L.tx("chal2", "challenge", [b2, ...ORIG, "vendor/slugify.js", "MIT"], stake, "challenge attributed copy")).ret?.challenge_id;
  const c3 = (await L.tx("chal1", "challenge", [b2, ...ORIG, "src/app.js", "MIT"], stake, "challenge unrelated file")).ret?.challenge_id;
  // mechanical refusals on chain: the value sent stays claimable
  await L.tx("chal2", "challenge", [b1, ...ORIG, "../../evil/other/src/slugify.js", "MIT"], stake, "REFUSAL: path outside bonded repo");
  await L.tx("chal2", "challenge", [b1, "anneeeee/slugify", "2014476d54bfa6ba4ec15618b5c845fff16f6af3", ORIG[2], "src/slugify.js", "MIT"], stake, "REFUSAL: same copied file via a fork (A3)");
  await L.tx("chal2", "challenge", [b2, ORIG[0], ORIG[1], "license", "LICENSE", "MIT"], stake, "REFUSAL: LICENSE vs LICENSE (A1)");

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
  for (const role of ["proj1", "proj2", "chal1", "chal2", "chal3", "trigger"]) {
    const owed = BigInt(await L.view("get_balance", [acc[role].address]));
    if (owed > 0n) await L.tx(role, "claim", [], 0n, `claim ${role} (${gen(owed)} GEN)`);
  }
  evidence.lanes[N].final = { stats: await L.view("get_stats"), challenges: [], bonds: [] };
  for (const cid of [c1, c2, c3]) {
    evidence.lanes[N].final.challenges.push({ ...(await L.view("get_challenge", [cid])), verify: await L.view("verify_challenge", [cid]) });
  }
  for (const bid of [sq, b1, b2]) evidence.lanes[N].final.bonds.push(await L.view("get_bond", [bid]));
  save();
  log(N, `DONE stats ${JSON.stringify(evidence.lanes[N].final.stats)}`);
}

// ---------------------------------------------------------------- lane B
async function laneB() {
  const N = "B";
  const L = lane(N, "LicenseGuardDemoStall");
  const cfg = await L.view("get_config");
  const bond = BigInt(cfg.min_bond_wei), stake = BigInt(cfg.challenge_bond_wei);
  const repo = FX.vanishing[0], orepo = FX.originVanishing[0];
  for (const r of [repo, orepo]) execSync(`gh repo edit ${r} --visibility public --accept-visibility-change-consequences 2>/dev/null || true`);
  await sleep(20_000);

  const b = (await L.tx("proj3", "post_bond", [...FX.vanishing, "MIT"], bond, "post_bond vanishing")).ret?.bond_id ?? 1;
  await persist(L, N, "proj4", "verify_bond", [b], 0n, "verify_bond vanishing", { accept: (r) => r?.outcome === "ACTIVE" || r?.outcome === "REJECTED" });
  const verifiedAt = nowS();
  const c1 = (await L.tx("chal3", "challenge", [b, ...ORIG, "src/slugify.js", "MIT"], stake, "challenge (original readable)")).ret?.challenge_id ?? 1;
  const c2 = (await L.tx("outsider", "challenge", [b, FX.originVanishing[0], FX.originVanishing[1], "index.js", "src/slugify-copy.js", "MIT"], stake, "challenge (original will vanish)")).ret?.challenge_id ?? 2;

  for (const r of [repo, orepo]) execSync(`gh repo edit ${r} --visibility private --accept-visibility-change-consequences`);
  log(N, `made ${repo} and ${orepo} PRIVATE; raw.githubusercontent.com caches for max-age=300 (measured), so judging waits past it`);
  evidence.lanes[N].made_private_at = new Date().toISOString();

  const ch2 = await L.view("get_challenge", [c2]);
  await sleepUntil(N, Math.min(verifiedAt + 330, Number(ch2.judge_deadline) - 120), "CDN cache of the bonded LICENSE to expire");
  await persist(L, N, "proj4", "judge", [c1], 0n, "judge #1 (bonded repo private, original readable)", { accept: (r) => r?.outcome && r.outcome !== "RETRY", tries: 3, waitMs: 15_000 });
  const j2 = await L.tx("proj4", "judge", [c2], 0n, "judge #2 (both private)");
  if (j2.ret?.outcome !== "RETRY") log(N, `NOTE: expected RETRY, got ${JSON.stringify(j2.ret)}`);
  await L.tx("proj3", "withdraw_bond", [b], 0n, "REFUSAL: withdraw while forfeit open");

  await sleepUntil(N, Number(ch2.judge_deadline) + 20, "judge deadline of #2");
  await L.tx("proj4", "judge", [c2], 0n, "judge #2 after deadline (refused)");
  await persist(L, N, "proj4", "settle_stalled", [c2], 0n, "settle_stalled #2", { accept: (r) => r?.status === "OK" });
  const ch1 = await L.view("get_challenge", [c1]);
  await sleepUntil(N, Number(ch1.contest_until) + 20, "contest window of #1");
  await persist(L, N, "proj4", "finalize", [c1], 0n, `finalize #1 (${ch1.outcome})`, { accept: (r) => r?.status === "OK" });
  log(N, `is_compliant vanishing=${await L.view("is_compliant", [repo])}`);

  const bd = await L.view("get_bond", [b]);
  const free = Math.max(Number(bd.challenge_until), Number(bd.last_closed_at) + Number(bd.unbond_delay_s));
  await sleepUntil(N, free + 20, "bond lock");
  await persist(L, N, "proj3", "withdraw_bond", [b], 0n, "withdraw_bond", { accept: (r) => r?.status === "OK" });
  for (const role of ["proj3", "chal3", "outsider", "proj4"]) {
    const owed = BigInt(await L.view("get_balance", [acc[role].address]));
    if (owed > 0n) await L.tx(role, "claim", [], 0n, `claim ${role} (${gen(owed)} GEN)`);
  }
  evidence.lanes[N].final = { stats: await L.view("get_stats"), challenges: [], bonds: [await L.view("get_bond", [b])] };
  for (const cid of [c1, c2]) {
    evidence.lanes[N].final.challenges.push({ ...(await L.view("get_challenge", [cid])), verify: await L.view("verify_challenge", [cid]) });
  }
  save();
  log(N, `DONE stats ${JSON.stringify(evidence.lanes[N].final.stats)}`);
}

const results = await Promise.allSettled([laneA(), laneB()]);
results.forEach((r, i) => { if (r.status === "rejected") log(i ? "B" : "A", `LANE FAILED: ${r.reason?.stack ?? r.reason}`); });
evidence.finished_at = new Date().toISOString();
evidence.minutes = ((Date.now() - T0) / 60000).toFixed(1);
save();
log("*", `seed finished in ${evidence.minutes} min`);
