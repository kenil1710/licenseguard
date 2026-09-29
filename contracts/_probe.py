# v0.3.0
# { "Depends": "py-genlayer:5jycge4q8k23462jtb0b9fyey1s9qz928sz2nbrd9mg4sxqg2qng" }
import genlayer as gl
from genlayer import *

import json

# Throwaway diagnostic, NOT part of LicenseGuard. It answers, with real
# validators, what LicenseGuard's judging path is allowed to depend on:
#
#   1. Can a validator GET raw.githubusercontent.com/{owner}/{repo}/{sha}/{path}
#      and is the body byte-identical on a second node (strict mode: the
#      validator re-fetches and votes on the hash)?
#   2. Can a validator reach api.github.com (commits, compare, repo metadata)
#      - does it need a User-Agent header, what does the rate limit look like
#      from the validators' address, and how large are the answers?
#   3. What does a missing file / repo look like (status and body)?
#   4. Which response attributes exist (headers?), and is hashlib available?


def _get(url: str, headers: dict) -> tuple:
    try:
        if headers:
            res = gl.nondet.web.request(url, method="GET", headers=headers)
        else:
            res = gl.nondet.web.request(url, method="GET")
    except Exception as e:
        return (-1, "", str(e)[:300], "", "")
    s = getattr(res, "status_code", None)
    if s is None:
        s = getattr(res, "status", None)
    try:
        s = int(s)
    except Exception:
        s = 0
    b = getattr(res, "body", None)
    if b is None:
        b = getattr(res, "text", None)
    if isinstance(b, bytes):
        b = b.decode("utf-8", errors="ignore")
    attrs = ",".join(a for a in dir(res) if not a.startswith("_"))
    hdr = ""
    h = getattr(res, "headers", None)
    if h is not None:
        try:
            keep = {}
            for k in h:
                lk = str(k).lower()
                if lk.startswith("x-ratelimit") or lk in ("content-length", "cache-control", "etag", "x-cache"):
                    keep[lk] = str(h[k])
            hdr = json.dumps(keep, sort_keys=True)
        except Exception as e:
            hdr = "unreadable: " + str(e)[:100]
    return (s, str(b or ""), "", attrs, hdr)


def _fnv(s: str) -> str:
    h = 0xCBF29CE484222325
    for ch in s.encode("utf-8"):
        h ^= ch
        h = (h * 0x100000001B3) & 0xFFFFFFFFFFFFFFFF
    return format(h, "016x")


def _sha(s: str) -> str:
    try:
        import hashlib
        return hashlib.sha256(s.encode("utf-8")).hexdigest()
    except Exception as e:
        return "no hashlib: " + str(e)[:80]


class Probe(gl.contract.Contract):
    results: gl.storage.TreeMap[str, str]

    def __init__(self):
        pass

    @gl.public.write
    def probe(self, key: str, url: str, ua: bool, strict: bool) -> None:
        headers = {"User-Agent": "licenseguard-probe", "Accept": "application/vnd.github+json"} if ua else {}

        def leader_fn() -> str:
            s, body, err, attrs, hdr = _get(url, headers)
            info = {"status": s, "len": len(body), "fnv": _fnv(body),
                    "sha256": _sha(body), "err": err, "attrs": attrs,
                    "headers": hdr, "head": body[:400]}
            if url.startswith("https://api.github.com") and body[:1] == "{":
                try:
                    d = json.loads(body)
                    info["json_keys"] = ",".join(sorted(d.keys()))[:400]
                    for k in ("status", "ahead_by", "behind_by", "created_at", "sha", "message"):
                        if k in d:
                            info["j_" + k] = str(d[k])[:120]
                    if "merge_base_commit" in d:
                        info["j_merge_base"] = str(d["merge_base_commit"].get("sha", ""))
                except Exception as e:
                    info["json_err"] = str(e)[:100]
            return json.dumps(info, sort_keys=True)

        def validator_fn(res) -> bool:
            if not isinstance(res, gl.vm.Return):
                return False
            if not strict:
                return True
            mine = json.loads(leader_fn())
            theirs = json.loads(res.calldata)
            return mine["status"] == theirs["status"] and mine["fnv"] == theirs["fnv"]

        self.results[key] = gl.vm.run_nondet(leader_fn, validator_fn)

    @gl.public.view
    def get(self, key: str) -> str:
        return self.results.get(key, "")
