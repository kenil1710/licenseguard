# PROBE — what Studio Dev validators can actually read from GitHub

Measured on 2026-09-29 with `contracts/_probe.py` (a throwaway contract, not part
of LicenseGuard) deployed to Studio Dev (chain 61997) in four lanes, driven by
`test/probe.mjs`. Raw results: `docs/probe/<key>.json` (one per job: tx hash,
status, seconds, HTTP status, body length, sha256, response headers, the first
400 characters). Run log: `docs/probe/run1.log`.

`strict` jobs make every validator re-fetch and vote on the body hash, so an
ACCEPTED strict job is also a cross-node stability test. API jobs were
non-strict (leader-only) so the probe itself would not burn the rate limit.

Pinned commit used: `sindresorhus/slugify@3b17b2e84b97624a683aafaa38184bf2746fab22`
(HEAD of `main` on the day). Fork-only commit: `2014476d54bfa6ba4ec15618b5c845fff16f6af3`
(exists only in the fork `anneeeee/slugify`).

## Results

| job | URL shape | tx | HTTP | size | what it shows |
|---|---|---|---|---|---|
| raw_file | `raw.githubusercontent.com/{o}/{r}/{sha}/index.js` | ACCEPTED, strict, 13 s | 200 | 5,883 chars | pinned file readable, byte-identical on every validator |
| raw_license | `…/{sha}/license` | ACCEPTED, strict, 21 s | 200 | 1,117 | LICENSE at the pinned commit readable |
| raw_missing_path | `…/{sha}/NOTICE` (absent) | ACCEPTED, strict | 404 | 14 (`404: Not Found`) | a missing file is a clean, identical 404 |
| raw_missing_repo | `raw…/kenil1710/no-such-repo…` | ACCEPTED, strict | 404 | 14 | a missing repo looks exactly like a missing file |
| raw_fork_sha_via_parent | `raw…/sindresorhus/slugify/{fork sha}/index.js` | ACCEPTED, strict | **200** | 5,337 | **GitHub serves a fork's commit through the PARENT's raw URL** |
| raw_big_lodash | `raw…/lodash/lodash/{sha}/lodash.js` | ACCEPTED, strict, 28 s | 200 | 544,096 | half a megabyte is readable and stable |
| api_commit_noua | `api.github.com/repos/{o}/{r}/commits/{sha}` | ACCEPTED | 200 | 4,304 | the API answers without a User-Agent from validators |
| api_commit_ua | same, with `User-Agent` | ACCEPTED | 200 | 4,304 | `headers=` is accepted by `gl.nondet.web.request` |
| api_commit_fork_via_parent | `…/commits/{fork sha}` on the parent | ACCEPTED | **200** | 5,099 | **the commits API ALSO accepts the fork's commit under the parent** — "exists" ≠ "belongs" |
| api_compare_in_history | `…/compare/{sha}...HEAD?per_page=1` | ACCEPTED | 200 | 7,382 | `status: identical, behind_by: 0` |
| api_compare_fork | `…/compare/{fork sha}...HEAD?per_page=1` | ACCEPTED | 200 | 18,267 | `status: diverged, behind_by: 2` — **compare tells them apart** |
| api_repo | `api.github.com/repos/{o}/{r}` | ACCEPTED, 36 s | 200 | 5,407 | `created_at: 2018-04-18T15:34:47Z` |
| api_commit_missing_sha | `…/commits/000…0` | ACCEPTED | **422** | 174 | an unknown SHA is 422 `No commit found for SHA`, not 404 |
| api_rate_limit | `api.github.com/rate_limit` | ACCEPTED | 200 | 427 | see below |

Also measured:

- **Response object:** attributes are exactly `body`, `headers`, `status` (not
  `status_code`). Header values arrive as bytes.
- **hashlib is available** in GenVM: the probe returned a sha256 of the body.
- **Runner exports:** `from genlayer import *` does NOT export `TreeMap` — the
  first probe deploy failed with `NameError: name 'TreeMap' is not defined`.
  Storage must be spelled `gl.storage.TreeMap`. The offline stub was corrected
  to export exactly what the runner exports.
- **Caching:** raw answers carry `cache-control: max-age=300` (Fastly); API
  answers `public, max-age=60`.
- **Validators per round:** 5 (one leader + validators; 3 voted "agree", 2
  idle on the probe tx inspected with `test/txstat.mjs`).
- **Studio RPC:** 30 requests/minute from one client IP (`Rate limit exceeded:
  30 requests per minute`) — the seed polls every 5 s and retries on it.

## Rate limits

| host | limit seen by validators | evidence |
|---|---|---|
| raw.githubusercontent.com | no rate-limit headers; CDN-served | every raw job; lodash 544 KB fine |
| api.github.com | **60 requests / hour, unauthenticated, shared by the whole validator network** | `x-ratelimit-limit: 60`; `x-ratelimit-used` climbed 2 → 3 → 6 → 10 → 15 → 16 → 17 across jobs sent from DIFFERENT lanes, signers and contracts — one shared egress address |

With ~4 validators re-fetching each API document, **every API call a judgement
makes costs about 4 of the network's 60 per hour**, shared with every other
Studio Dev user.

## Design consequences (what LicenseGuard does because of this)

1. **Evidence comes only from `raw.githubusercontent.com/{repo}/{sha}/{path}`.**
   It is immutable for a given SHA, fast, stable across nodes (strict jobs
   agreed), and not rate-limited. Files are hashed byte-for-byte.
2. **"The commit exists" is not "the commit belongs to the repo".** Both the
   raw URL and the commits API serve a fork-only commit through the parent.
   LicenseGuard therefore uses `compare/{sha}...HEAD` and accepts a commit only
   when it is `identical` or `ahead` with `behind_by = 0` — i.e. it is in the
   repository's default-branch history. Unknown SHAs answer 422 or 404, both
   read as "not in history".
3. **The API is used only where it changes who gets paid.**
   - Bond verification: one compare call (is the bonded commit in the bonded
     repo's history?). Without it, anyone could bond a clean fork commit under
     a popular repository's name.
   - Judgement: the origin checks (repository `created_at` before the bond,
     original commit in the original repo's history) run **only when the
     result would otherwise pay the challenger** (a would-be
     ATTRIBUTION_MISSING). A fabricated "original" can only profit anyone in
     that case; for COMPLIANT / NOT_DERIVED / INCONCLUSIVE the project wins or
     both are refunded anyway. So the seed's COMPLIANT and NOT_DERIVED
     judgements make zero API calls.
4. **API answers are hashed by the one fact read, raw files by their bytes.**
   A repository answer carries live counters (stars, `pushed_at`) that can
   change between the leader's and a validator's fetch; its `created_at` is
   what the verdict uses and what is hashed.
5. **403 and 429 are transient** (GitHub's rate-limit answers), as are 0 and
   5xx: RETRY, never a verdict. The deadline turns a RETRY that never ends
   into INCONCLUSIVE with both bonds released.
6. **404 / 410 / 451 are answers.** A path the challenger named that is not at
   the pinned commit is NOT_DERIVED against the challenger. But the bonded
   commit's own LICENSE (read at verification) answering 404 means the bonded
   repository went away (private, deleted): RETRY, then INCONCLUSIVE at the
   deadline, with the bond's badge suspended.
7. **A 544 KB file is readable**, but the similarity measure is bounded at
   200 KB per file (beyond it: INCONCLUSIVE, `FILE_UNREADABLE`) to keep a
   judgement inside the node's budget.
8. **Private-repo demonstration:** raw answers are cached for 300 s, so the
   seed waits past that after making the fixture repository private.
