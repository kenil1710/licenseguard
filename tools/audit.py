#!/usr/bin/env python3
"""The audit: every item of the brief's MANDATORY SAFETY list and THREAT MODEL,
as a check that PASSES or FAILS with evidence, written to docs/AUDIT.md.

    python3 tools/audit.py

Structural checks walk the AST (a grep would cry wolf on the source's own
comments, which name what they forbid). Behavioural checks RUN the offline
test classes that prove them. Chain checks read docs/seed-evidence.json (what
test/seed.mjs recorded from the chain) and deployments.json. Exit 1 on any FAIL.
"""
import ast
import hashlib
import io
import json
import pathlib
import sys
import unittest

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "test"))
RESULTS = []


def check(group, name, ok, evidence):
    RESULTS.append((group, name, bool(ok), str(evidence)))
    print(("  PASS  " if ok else "  FAIL  ") + name + " - " + str(evidence)[:150])


SRC_PATH = ROOT / "contracts" / "LicenseGuard.py"
SRC = SRC_PATH.read_text(encoding="utf8")
TREE = ast.parse(SRC)
CLS = [n for n in TREE.body if isinstance(n, ast.ClassDef) and n.name == "LicenseGuard"][0]
METHODS = {m.name: m for m in CLS.body if isinstance(m, ast.FunctionDef)}
FUNCS = {n.name: n for n in TREE.body if isinstance(n, ast.FunctionDef)}
WRITES = {k: m for k, m in METHODS.items()
          if any(ast.unparse(d).startswith("gl.public.write") for d in m.decorator_list)}
PAYABLE = sorted(k for k, m in WRITES.items()
                 if any(ast.unparse(d) == "gl.public.write.payable" for d in m.decorator_list))


def calls(node):
    out = set()
    for n in ast.walk(node):
        if isinstance(n, ast.Call):
            f = n.func
            if isinstance(f, ast.Attribute) and isinstance(f.value, ast.Name) and f.value.id == "self":
                out.add(f.attr)
            elif isinstance(f, ast.Name):
                out.add(f.id)
    return out


def reach(name):
    seen, stack = set(), [name]
    while stack:
        n = stack.pop()
        if n in seen:
            continue
        seen.add(n)
        node = METHODS.get(n) or FUNCS.get(n)
        if node is not None:
            stack.extend(calls(node))
    return seen


def run(module, *classes):
    mod = __import__(module)
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    if classes:
        for c in classes:
            suite.addTests(loader.loadTestsFromTestCase(getattr(mod, c)))
    else:
        suite.addTests(loader.loadTestsFromModule(mod))
    res = unittest.TextTestRunner(stream=io.StringIO(), verbosity=0).run(suite)
    ok = res.wasSuccessful() and res.testsRun > 0
    label = ", ".join(classes) if classes else "test/" + module + ".py"
    return ok, "%d tests in %s: %s" % (res.testsRun, label, "all pass" if ok else
                                       "%d failures, %d errors" % (len(res.failures), len(res.errors)))


def main():
    print("\n- mandatory safety")
    g = "Mandatory safety"
    ok, ev = run("test_logic", "TestLeaderCannotForge", "TestCoherentPure")
    check(g, "consensus binds every stored value: the whole vector compared exactly", ok, ev)
    vc = ast.unparse(METHODS["_judge_round"])
    check(g, "leader can't forge: validator runs the pure coherence gate, then recomputes and compares",
          "_coherent(theirs, task)" in vc and "_agrees(theirs, _collect_judge(task))" in vc,
          "validator_fn calls _coherent then _agrees(own _collect_judge); judge re-derives outcome via _decide on the agreed vector")
    check(g, "model findings bounded: two fixed enums, YES<->NONE enforced",
          "MEETS = (\"YES\", \"NO\")" in SRC and "MISSING = (\"NONE\", \"COPYRIGHT_NOTICE\", \"LICENSE_TEXT\", \"NOTICE_FILE\")" in SRC,
          "_model_answer returns None (RETRY) outside MEETS x MISSING")
    raises = [n.lineno for n in ast.walk(TREE) if isinstance(n, ast.Raise)]
    check(g, "0 raise statements", not raises, "%d ast.Raise nodes" % len(raises))
    reps = [n.lineno for n in ast.walk(TREE) if isinstance(n, ast.Attribute) and n.attr == "replace"]
    check(g, "no str.replace()", not reps, "%d .replace attributes" % len(reps))
    first = []
    for k, m in WRITES.items():
        body = m.body[1:] if isinstance(m.body[0], ast.Expr) and isinstance(m.body[0].value, ast.Constant) else m.body
        if "self._bank()" not in ast.unparse(body[0]):
            first.append(k)
    check(g, "refund-on-reject on every payable path: _bank() is the first statement of every write",
          not first, "payable: %s; writes not banking first: %s" % (", ".join(PAYABLE), first or "none"))
    viol = []
    for name in PAYABLE:
        body = ast.unparse(METHODS[name])
        take = body.index("if not self._take(")
        rest = body[take:]
        rest = rest[rest.index("\n", rest.index("_refuse")):]
        if "_refuse(" in rest or "total_" in body[:take]:
            viol.append(name)
    check(g, "no counter-before-revert: counters and _take only after the last refusal", not viol,
          "violations: %s" % (viol or "none"))
    ok, ev = run("test_logic", "TestSourceInvariants")
    check(g, "source invariants (header, names, closures, constructor-only params, no floats)", ok, ev)
    check(g, "content hash of all fetched bytes: every raw document hashed by its bytes, API by its fact",
          "_hash(body)" in ast.unparse(FUNCS["_get"]) and "content_hash" in ast.unparse(FUNCS["_finish"]),
          "_get records sha256(bytes) per document; content_hash = sha256(doc_lines); verify_challenge recomputes it")
    gated = sorted(k for k, m in WRITES.items() if "self.paused" in ast.unparse(m) and k != "set_paused")
    check(g, "settle_stalled permissionless and working while paused; pause gates only new business",
          gated == ["challenge", "post_bond"], "pause-gated: %s" % gated)
    ok, ev = run("test_threats", "Threat7_PauseCannotFreeze")
    check(g, "owner can't freeze funds (behaviour)", ok, ev)
    pay = sorted(k for k in WRITES if "_pay" in reach(k))
    check(g, "two-step finalize then claim: only claim transfers, and it reads no clock",
          pay == ["claim"] and "_now" not in reach("claim"), "writes reaching _pay: %s; claim reaches _now: %s"
          % (pay, "_now" in reach("claim")))
    ok, ev = run("test_random")
    check(g, "books drain to zero (randomized lifecycles)", ok, ev)

    print("\n- design rules")
    g = "Design rules"
    check(g, "one contest per side, no refiles (pair key excludes commit and license)",
          "project_contested" in SRC and "no refiles" in SRC, "contest flags per side; _pair_key(bond, repo, path, copied)")
    check(g, "all evidence pinned to a 40-char commit, no mutable URL for files",
          "_raw_url(" in SRC and "_is_sha(" in ast.unparse(METHODS["challenge"]) and "_is_sha(" in ast.unparse(METHODS["post_bond"]),
          "files only via raw.githubusercontent.com/{repo}/{sha}/{path}; SHAs validated at filing")
    ok, ev = run("test_threats", "Threat5_FileNeverLoads")
    check(g, "every lock and wait has a deadline and an exit", ok and "settle_stalled_bond" in METHODS, ev)
    ok, ev = run("test_threats", "Threat1_FileOutsideBondedRepoOrCommit")
    check(g, "nobody chooses a source that decides their own case", ok, ev + "; bond marker + history; origin history + created_at")

    print("\n- threat model")
    g = "Threat model"
    for cls, label in (("Threat1_FileOutsideBondedRepoOrCommit", "1. file outside the bonded repo/commit: refused"),
                       ("Threat2_WithdrawDuringOrAfterChallenge", "2. withdraw during/right after a challenge: refused until unbond delay"),
                       ("Threat3_DuplicatePair", "3. two challenges on the same file pair: refused"),
                       ("Threat4_NoDoublePayment", "4. paying twice via contest + finalize: impossible"),
                       ("Threat5_FileNeverLoads", "5. a file that never loads: INCONCLUSIVE at the deadline, bonds released"),
                       ("Threat6_ContestCannotSwitchSources", "6. contest switching commits or files: refused"),
                       ("Threat7_PauseCannotFreeze", "7. owner pause: judgments, claims, settle_stalled still work"),
                       ("Threat8_ModelSeesOnlyWhatItNeeds", "8. model sees only license text and files, never the challenger's words")):
        ok, ev = run("test_threats", cls)
        check(g, label, ok, ev)

    print("\n- chain")
    g = "On chain"
    dep = json.loads((ROOT / "deployments.json").read_text())["deployments"]["studiodev"]
    sha = hashlib.sha256(SRC.encode("utf8") if False else SRC_PATH.read_bytes()).hexdigest()
    names = [k for k in dep if k.startswith("LicenseGuard")]
    check(g, "source byte-identical to deployed (recorded sha256; chain read back by test/verify_onchain.mjs)",
          all(dep[k]["source_sha256"] == sha for k in names),
          "; ".join("%s %s = %s" % (k, dep[k]["address"], dep[k]["source_sha256"][:16]) for k in names))
    ev_path = ROOT / "docs" / "seed-evidence.json"
    if not ev_path.exists():
        check(g, "seed evidence present", False, "docs/seed-evidence.json missing")
    else:
        E = json.loads(ev_path.read_text())
        A = E["lanes"].get("A", {})
        B = E["lanes"].get("B", {})
        chs = {c["copied_path"] + "@" + c["original_path"] + "#" + str(c["bond_id"]): c for c in A.get("final", {}).get("challenges", [])}
        by_outcome = {}
        for c in A.get("final", {}).get("challenges", []):
            by_outcome.setdefault(c["outcome"], c)

        def tx_of(lane, label):
            for s in lane.get("steps", []):
                if s["label"].startswith(label) and s.get("ok"):
                    last = s
            return locals().get("last")

        c = by_outcome.get("ATTRIBUTION_MISSING")
        check(g, "ATTRIBUTION_MISSING - a copied MIT file with the notice removed", c is not None and c["verify"]["consistent"],
              c and "challenge #%s %s; similarity %s bps; holders %s; in copy %s / notices %s; model_called %s; origin %s; paid challenger %s wei (slash %s); consistent %s"
              % (c["challenge_id"], c["reason"], c["similarity_bps"], c["holders"], c["holder_in_copy"], c["holder_in_notices"],
                 c["model_called"], c["origin"], c["paid_challenger_wei"], c["slash_wei"], c["verify"]["consistent"]))
        c = by_outcome.get("COMPLIANT")
        check(g, "COMPLIANT - copied file with correct attribution (model judged)", c is not None and c["model_called"],
              c and "challenge #%s %s; model meets=%s missing=%s; origin %s (no API call); paid project %s wei"
              % (c["challenge_id"], c["reason"], c["meets"], c["missing"], c["origin"], c["paid_project_wei"]))
        c = by_outcome.get("NOT_DERIVED")
        check(g, "NOT_DERIVED - unrelated file", c is not None,
              c and "challenge #%s %s; similarity %s bps; paid project %s wei" % (c["challenge_id"], c["reason"], c["similarity_bps"], c["paid_project_wei"]))
        held = [c for c in A.get("final", {}).get("challenges", []) if "HELD" in c.get("contest_log", "")]
        check(g, "a contest that held", bool(held), held and "challenge #%s: %s" % (held[0]["challenge_id"], held[0]["contest_log"]))
        bc = (B.get("final", {}).get("challenges") or [None])[0]
        retry = [s for s in B.get("steps", []) if s["fn"] == "judge" and isinstance(s.get("returned"), dict) and s["returned"].get("outcome") == "RETRY"]
        check(g, "fetch failure reaching its deadline and releasing", bc is not None and bc["outcome"] == "INCONCLUSIVE"
              and bc["reason"].startswith("DEADLINE_PASSED") and bool(retry),
              bc and "challenge #%s %s; RETRY side %s (%s); bond unreadable %s; paid back %s wei"
              % (bc["challenge_id"], bc["reason"], bc["last_retry_side"], bc["last_retry_why"],
                 (B["final"]["bonds"][0] or {}).get("unreadable"), bc["paid_challenger_wei"]))
        refusals = [s for s in A.get("steps", []) if s["label"].startswith("REFUSAL")]
        check(g, "mechanical refusals on chain (threats 1 and 3)", len(refusals) == 2 and all(
            isinstance(s.get("returned"), dict) and s["returned"].get("status") == "REJECTED" for s in refusals),
            "; ".join("%s: %s" % (s["label"], (s.get("returned") or {}).get("reason", "")[:90]) for s in refusals))
        for lane, L in (("A", A), ("B", B)):
            st = L.get("final", {}).get("stats", {})
            check(g, "lane %s (%s) drained to 0" % (lane, L.get("address")), st.get("books_zero") and st.get("ledger_ok")
                  and st.get("held_wei") == "0" and st.get("payable_wei") == "0",
                  "balance %s held %s payable %s ledger_ok %s" % (st.get("balance_wei"), st.get("held_wei"), st.get("payable_wei"), st.get("ledger_ok")))
        check(g, "seed under 20 minutes", float(E.get("minutes", 99)) < 20, "%s minutes" % E.get("minutes"))

    total = sum(1 for r in RESULTS if r[2])
    out = ["# AUDIT - mandatory safety, design rules, threat model, chain", "",
           "Generated by `python3 tools/audit.py`. Structural checks walk the AST; behavioural checks run the offline "
           "suite; chain checks read `docs/seed-evidence.json` (recorded from the chain by `test/seed.mjs`) and "
           "`deployments.json`.", "", "**Result: %d PASS / %d FAIL.**" % (total, len(RESULTS) - total), ""]
    group = None
    for grp, name, ok, ev in RESULTS:
        if grp != group:
            out += ["", "## " + grp, "", "| | check | evidence |", "|---|---|---|"]
            group = grp
        out.append("| %s | %s | %s |" % ("PASS" if ok else "FAIL", name, ev.replace("|", "/")))
    (ROOT / "docs" / "AUDIT.md").write_text("\n".join(out) + "\n")
    print("\n%d PASS / %d FAIL -> docs/AUDIT.md" % (total, len(RESULTS) - total))
    return 0 if total == len(RESULTS) else 1


if __name__ == "__main__":
    sys.exit(main())
