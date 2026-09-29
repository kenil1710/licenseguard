import { connect } from "./harness.mjs";
const c = connect({ address: "0x0000000000000000000000000000000000000000" });
const tx = await c.read.getTransaction({ hash: process.argv[2] });
const cd = tx.consensus_data || {};
console.log("status", tx.status, "leader receipts", (cd.leader_receipt || []).length, "validators", (cd.validators || []).length, "votes", JSON.stringify(cd.votes || {}).slice(0, 400));
console.log(Object.keys(tx).join(","));
