"""Dress rehearsal: the contract's own judging code against REAL GitHub, the
stub's web swapped for real HTTP. The model is scripted (YES) - only the
deterministic path is rehearsed here.   python3 rehearse_live.py"""
import json, sys, urllib.request, urllib.error
import lg_stub
from lg_world import LG

def real(url, method="GET", headers=None, **_k):
    lg_stub.CALLS.append((url, dict(headers or {})))
    req = urllib.request.Request(url, headers=headers or {})
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            return lg_stub._Resp(r.status, r.read())
    except urllib.error.HTTPError as e:
        return lg_stub._Resp(e.code, e.read())
lg_stub._web_request = real
import genlayer; genlayer.gl.nondet.web.request = real
lg_stub.MODEL.serve("YES")

acc = json.load(open(".accounts.json"))
ORIG = ("sindresorhus/slugify", "3b17b2e84b97624a683aafaa38184bf2746fab22", "index.js")
BONDS = {"stripped": ("kenil1710/licenseguard-fixture-stripped", sys.argv[1], "proj1"),
         "attributed": ("kenil1710/licenseguard-fixture-attributed", sys.argv[2], "proj2")}
AT = {}
for name, (repo, sha, role) in BONDS.items():
    b = LG._collect_bond({"kind": "bond", "bond_id": 1, "repo": repo, "sha": sha,
                          "owner": acc[role]["address"].lower()})
    AT[name] = b.get("commit_at", 0)
    print(name, b.get("reason"), "commit_at", b.get("commit_at"), "repo_created", b.get("repo_created_at"))
for label, (bk, path) in {"MISSING": ("stripped", "src/slugify.js"),
                          "COMPLIANT": ("attributed", "vendor/slugify.js"),
                          "NOT_DERIVED": ("attributed", "src/app.js")}.items():
    repo, sha, _r = BONDS[bk]
    facts = {"kind": "judge", "challenge_id": 1, "bond_id": 1, "bonded_repo": repo, "bonded_sha": sha,
             "bonded_license_path": "LICENSE", "copied_path": path, "original_repo": ORIG[0],
             "original_sha": ORIG[1], "original_path": ORIG[2], "license": "MIT",
             "bond_posted_at": 1790700000, "bonded_commit_at": AT[bk]}
    v = LG._collect_judge(facts)
    print(label, "->", v.get("outcome"), v.get("reason"), "sim", v.get("similarity_bps"),
          "holders", v.get("holders"), "in_copy", v.get("holder_in_copy"), "origin", v.get("origin"),
          "docs", len(v.get("doc_lines", "").split("\n")), "coherent", LG._coherent(v, facts))
