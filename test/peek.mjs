import { readFileSync } from "node:fs";
import { connect } from "./harness.mjs";
const dep = JSON.parse(readFileSync(new URL("../deployments.json", import.meta.url))).deployments.studiodev;
const [name, fn, ...args] = process.argv.slice(2);
const c = connect({ address: dep[name].address });
const out = await c.view(fn, args.map((a) => (/^\d+$/.test(a) ? Number(a) : a)));
console.log(JSON.stringify(out, (k, v) => (typeof v === "bigint" ? v.toString() : v instanceof Map ? Object.fromEntries(v) : v), 2));
