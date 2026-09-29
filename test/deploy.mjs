/**
 * Deploys LicenseGuard to Studio Dev (chain 61997) - the canonical instance and
 * two DEMO instances of the SAME BYTES whose constructor windows are minutes, so
 * the seed can walk every path in under 20 minutes. Records address, tx and the
 * sha256 of the deployed bytes in deployments.json after EACH deploy.
 *
 *   node deploy.mjs                      # all three
 *   node deploy.mjs --only=LicenseGuardDemo
 */
import { readFileSync, writeFileSync, existsSync } from "node:fs";
import { createHash } from "node:crypto";
import { createClient, createAccount } from "genlayer-js";
import { CHAINS, argOf, accounts, fundOnStudio, deploy, gen } from "./harness.mjs";

const chain = CHAINS.studiodev;
const sha256 = (b) => createHash("sha256").update(b).digest("hex");
const acc = accounts();
const account = createAccount(acc.owner.key);
const wallet = createClient({ chain, account });
const read = createClient({ chain });
const GEN = 10n ** 18n;
const code = readFileSync(new URL("../contracts/LicenseGuard.py", import.meta.url));
const version = String(code).match(/^POLICY_VERSION\s*=\s*"([^"]+)"/m)[1];

await fundOnStudio(chain, account.address, 1000n * GEN);
console.log(`signer ${account.address}  balance ${gen(await read.getBalance({ address: account.address }))} GEN`);
console.log(`source contracts/LicenseGuard.py ${code.length} bytes sha256 ${sha256(code)}`);

// (min_bond, challenge_bond, contest_bond, challenge_window_s, unbond_delay_s, contest_window_s, deadline_s)
const DAY = 86400;
const VARIANTS = {
  LicenseGuard: { label: "canonical", args: [GEN, GEN / 5n, GEN / 10n, 30 * DAY, 7 * DAY, 2 * DAY, DAY] },
  LicenseGuardDemo: { label: "DEMO (outcomes, contest, refusals): windows in minutes", args: [GEN, GEN / 5n, GEN / 10n, 780, 60, 180, 420] },
  LicenseGuardDemoStall: { label: "DEMO (forfeit, unreadable-to-deadline): windows in minutes", args: [GEN, GEN / 5n, GEN / 10n, 780, 60, 180, 480] },
};
const NAMES = ["min_bond_wei", "challenge_bond_wei", "contest_bond_wei", "challenge_window_s", "unbond_delay_s", "contest_window_s", "deadline_s"];

const path = new URL("../deployments.json", import.meta.url);
const doc = existsSync(path) ? JSON.parse(readFileSync(path, "utf8")) : { deployments: {} };
const record = doc.deployments.studiodev || { network: "studiodev", chain_id: chain.id, explorer: "https://explorer-studio-dev.genlayer.com/" };

const only = argOf("only");
for (const name of only ? only.split(",") : Object.keys(VARIANTS)) {
  const { label, args } = VARIANTS[name];
  console.log(`\n${name}: ${label}`);
  const res = await deploy({ chain, wallet, read, code, args, label: `${name} deploy` });
  if (!res.ok) {
    console.error(`${name} deploy FAILED ${res.out?.status} ${res.reason ?? ""}\n${(res.out?.stderr ?? "").slice(-3000)}`);
    process.exit(1);
  }
  console.log(`  address ${res.address}`);
  record[name] = {
    address: res.address, deploy_tx: res.hash, label, source_bytes: code.length, source_sha256: sha256(code),
    policy_version: version, owner: account.address,
    constructor: Object.fromEntries(NAMES.map((n, i) => [n, String(args[i])])),
    deployed_at: new Date().toISOString(),
  };
  doc.deployments.studiodev = record;
  writeFileSync(path, JSON.stringify(doc, null, 2) + "\n");
}
console.log("\nwrote deployments.json");
