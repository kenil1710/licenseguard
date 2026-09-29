# LicenseGuard

**Bonded open-source license compliance, judged by GenLayer validators.**

## The trust problem

Companies copy open-source code and strip the license notice. MIT, Apache-2.0,
BSD-3-Clause and GPL-3.0 all require attribution — keep the copyright notice,
carry the license text — but the people who wrote the code can't afford
lawyers to enforce that, and "license compliant" badges are self-declared.
Nobody pays anything for a false one.

## The mechanism

A project that wants its compliance claim to mean something **posts a bond on
one commit** of its repository. Anyone who finds a file in that commit that
was copied from another project without the attribution that project's
license requires **challenges it**, putting up a challenge bond. GenLayer
validators each read both files and the license/notice files at the pinned
commits, and the money follows:

| outcome | what it means | money |
|---|---|---|
| `ATTRIBUTION_MISSING` | copied, and the attribution doesn't meet the license — or the project **took its bonded commit away** (a forfeit, below) | challenger gets their stake back **plus 50% of the project's bond** (once per copied file); the bond becomes `NON_COMPLIANT` |
| `COMPLIANT` | copied, and the attribution meets the license | the challenger's stake goes to the project |
| `NOT_DERIVED` | not copied (or the "original" isn't a real original) | the challenger's stake goes to the project |
| `INCONCLUSIVE` | the question couldn't be answered (license unconfirmed, file too small, a real outage that lasted past the deadline) | both refunded |

> **The model never decides who pays. It only judges whether the attribution
> meets the license; code decides whether the file was copied and moves the
> money.**

Concretely, in `contracts/LicenseGuard.py`:

- **Code decides whether the file was copied.** Both files are tokenized
  (identifiers lower-cased, punctuation kept), cut into 5-token shingles and
  compared by containment in either direction, two ways, and the larger
  wins: **M1** strips comments from both files — `/* … */` anywhere, `//`
  and `#` to end of line — so a shared license header doesn't count; **M2**
  strips comments from the original only and reads the copy *whole*, so no
  comment trick in the copy (`/**/` before every line, a regex that opens a
  fake block comment) can hide copied code. ≥ 50% is `DERIVED`. Integer
  basis points, compared exactly across validators.
- **License texts are never "copied works".** A LICENSE, NOTICE, COPYING or
  THIRD_PARTY file can't be named as the copied or original file (any case,
  any non-code extension), and an original whose code is itself a license
  text is `NOT_DERIVED` — two MIT texts are alike by design, and an honest
  project must not be slashed over its own LICENSE.
- **Code confirms the license and finds the notice.** The original's LICENSE
  file (or SPDX header) must state the license the challenger named; its
  copyright lines are extracted (license prose and templates like
  `Copyright [yyyy] [name of copyright owner]` are excluded) and the holder's
  name is looked for in the copied file and in the bonded commit's
  LICENSE / NOTICE / THIRD_PARTY_NOTICES files and the license files beside
  the copied file — a fixed list.
- **No trace at all → `ATTRIBUTION_MISSING` without asking the model.**
- **The model is asked one question, only when there is a trace:** does the
  attribution present meet this license's requirement? It answers
  `meets_requirement` ∈ {YES, NO} and `missing` ∈ {NONE, COPYRIGHT_NOTICE,
  LICENSE_TEXT, NOTICE_FILE}. Nothing else is accepted; both are compared
  exactly between validators. Its answer can move the outcome only between
  COMPLIANT and ATTRIBUTION_MISSING.
- **The model sees only what it needs:** the license's attribution
  requirement, the original's copyright lines and the start of the original,
  the derived file, and the derived project's license/notice files — framed as
  data. Never a repository name, a path, a commit or an address, and never
  the challenger's words (the challenge has no free-text field at all).

## Small by design

- **One flow. Three money outcomes. One contest per side. A violation is paid
  once.** `post_bond → verify_bond → challenge → judge → (contest) → finalize
  → claim`. The violation is the **copied file** in the bonded commit: one
  open challenge per copied file, and once a copied file has paid it is never
  paid again — not via a fork of the original, not via another commit or
  license (the 50% slash is capped per copied file). A challenge that *lost*
  does not lock the file: otherwise the project's own address could file a
  deliberately wrong challenge first (its stake would come straight back to
  the project) and lock its copied files away from real challengers.
- **Going private is a forfeit, not an escape.** The bonded commit was read
  when the bond was verified. If it later answers 404/410/451 while the
  original is readable, the bonded party took its evidence away: the
  challenge is `ATTRIBUTION_MISSING` (reason `FORFEIT_BONDED_COMMIT_WITHDRAWN`),
  same money, still subject to the origin checks below. A contest re-read
  that finds the bonded commit gone goes the same way, so the project can't
  veto a challenger's contest by going private. The bond can't be withdrawn
  while any challenge — a forfeit included — is open. Only a **real outage**
  (no answer, 403/429 rate limit, 5xx) RETRYs, and past the deadline ends
  `INCONCLUSIVE` with both refunded.
- **All evidence is GitHub content pinned to a full 40-character commit hash,
  fixed at filing.** Files come only from
  `raw.githubusercontent.com/{repo}/{sha}/{path}`. The copied file comes only
  from the bonded repository at the bonded commit; the challenger names a
  path, never a location.
- **Every lock and every wait has a deadline and an exit.** A pending bond
  (`settle_stalled_bond`), a challenge nobody can judge and a contest nobody
  can re-read (`settle_stalled`) all close at their deadline, permissionlessly,
  even while paused. A bond is locked while a challenge is open and for the
  unbond delay after the last one closes — never past its challenge window
  plus that delay.
- **Nobody can choose a source that decides their own case.**
  - The bonded commit must be in the bonded repository's **default-branch
    history** and carry a `.licenseguard` file naming the bonder. GitHub
    serves a fork's commits through the parent repository's URLs (measured —
    `docs/PROBE.md`), so without this anyone could bond a clean fork commit
    under a famous repository's name.
  - When a result would pay the challenger, the original commit must be in
    the original repository's default-branch history, and that repository
    must have been **created before the bond was posted** (GitHub's
    `created_at`, which nobody can edit), and the original **commit must be
    dated before the bonded commit** — otherwise it's `NOT_DERIVED`
    (`ORIGIN_NEWER_THAN_COPY_DIRECTION_UNPROVEN`), no slash. The bonded
    commit's date is set by the project, so it's floored at the bonded
    repository's `created_at` when the bond is verified: backdating the bonded
    commit to 1990 can't make every original look newer. These checks use
    the rate-limited GitHub API, so they run only when the result would pay
    the challenger.

## What's on chain

Studio Dev (chain 61997), explorer <https://explorer-studio-dev.genlayer.com/>.
All three instances are the **same bytes** (sha256 in `deployments.json`,
read back from the chain by `test/verify_onchain.mjs`); the demos only have
minute-scale windows so the seed fits in 20 minutes.

| instance | address | constructor |
|---|---|---|
| LicenseGuard | `0xe8cf318130b9C57BB91D7F67f544bFfACA29fFd7` | challenge window 2592000s, unbond 604800s, contest 172800s, deadline 86400s |
| LicenseGuardDemo | `0x531aE9C6ac7db213dC075123Ab797f594A46E587` | challenge window 780s, unbond 60s, contest 180s, deadline 420s |
| LicenseGuardDemoStall | `0x67960678e52857a3B225275Ff3dDDCFb59a31970` | challenge window 780s, unbond 60s, contest 180s, deadline 480s |

Policy 1.1.0. Source sha256 `7cf70cef27b5e3c39c29d40cf55f888c7a74783777bf3fec3dd8d86e6fd6c7c9` (123063 bytes) on all three. The first deployment (policy 1.0.0, before the independent review) and its evidence are archived in `docs/superseded/v1.0.0/`.

### The seed (15.6 minutes, `test/seed.mjs`, every tx in `docs/seed-evidence.json`)

Original: `sindresorhus/slugify@3b17b2e84b97624a683aafaa38184bf2746fab22` — `index.js`, MIT, notice in its `license` file.

| result | files | how it was decided | money | decisive tx | second tx |
|---|---|---|---|---|---|
| **ATTRIBUTION_MISSING** | `slugify/index.js` → `licenseguard-fixture-stripped/src/slugify.js` | similarity 10000 bps; holder "sindre sorhus" found nowhere in the copy or notice files → code alone, **no model call**; origin checked (repo created 2018, commit in history, dated before the bonded commit) | challenger +0.2 stake +0.5 slash; bond → NON_COMPLIANT | `0x5c9a9fa1ad4140c255cd3076bb10effc547d7664ca7f70ccdb6ed52382699c90` | `0x2faff5bcced50eb4b695995d6280de9651af8c0a9e7edd7eab1faf5bc8281aed` |
| **COMPLIANT** | `slugify/index.js` → `licenseguard-fixture-attributed/vendor/slugify.js` | holder in the file header → **model asked**: meets_requirement YES / missing NONE, agreed by consensus; no GitHub API call | project +0.2 | `0x593651cbd776e53c29324d014a68b84b7381f875deae151e1ee8387f14e84891` | `0x559b53d833a94cace1972b8eac6606824fd4db21c880d73798355ea01e7a9d45` |
| **NOT_DERIVED** | `slugify/index.js` vs `licenseguard-fixture-attributed/src/app.js` | similarity 263 bps (< 5000) → code alone | project +0.2 | `0x571f11ed30482c1ca002bec4a95d257bb95eccb10b397b4a1fa3cdf9ad5abd23` | `0xcaf21f54c05a4d2b039cc2d5a122f93406c60b19d7ebde8de55fafa4b5b60054` |
| **contest HELD** | challenger contests #3 | re-read of the same pinned files: NOT_DERIVED again | contest bond 0.1 → project | `0xb6d84a71e1f8cb219f86661e5815c9a92b45a9a584e6c8801c705d89c9b2d684` | `0x3449f1b02b2b32f37f2e20dbead544be37ff746a68d8e709df890a2af9f912e2` |
| **refusals (A1, A3, threat 1)** | `LICENSE` vs `license`; `src/slugify.js` again via the fork `anneeeee/slugify`; `../../evil/other/…` | refused before any validator: license files are not copied works; the copied file is already challenged; path escape | value sent stays claimable | `0x2e5f07ca6a63fe7f6795b7d36bb6a4e702dc91ff95aac03bef957ae23a41be5f` | `0xdfbec10dd606a6d80a28d4431c5fe483e11c079da165c13855391b9ac4497c00` |
| **FORFEIT (A4)** | `licenseguard-fixture-vanishing` made **private** after the challenge; original `sindresorhus/slugify` still readable | bonded commit answered 404, original 200 → `FORFEIT_BONDED_COMMIT_WITHDRAWN`; origin checks passed; withdraw refused while it was open | challenger +0.2 stake +0.5 slash; bond forfeited | `0xa72afde3469391c4204bcac540ec7a8b9c4fdaaf337bb6cf0275e18b52f3aa85` | `0x3236dd7e17311ba0372123110ba0d436e6a38884cef8896c5c4d8ee4140c3760` |
| **nobody can read → INCONCLUSIVE** | second challenge on the same bond; its original `licenseguard-fixture-origin-vanishing` made private too | both answered 404 → RETRY (`BONDED_UNREADABLE`) → judge refused after the 480 s deadline → `settle_stalled` → INCONCLUSIVE `DEADLINE_PASSED_BONDED_UNREADABLE` | stake refunded, no slash | `0xb530ac958055abb7e1866fc8d27309b579a73e85853efe4a3397e9bf16f3d221` | `0xd23d67ee705cb7f585e6822aff80ad2930fa86fe0dfcc11d09bb64d8961f40a7` |

Then every bond was withdrawn and every balance claimed: both demo instances end at **balance 0 = held 0 + payable 0** (`get_stats`: `books_zero: true`, `ledger_ok: true`), and `verify_challenge` recomputes every judged challenge as consistent.

**A real outage** (GitHub not answering) can't be produced on demand: validators even fetch 90 MB files without failing (`docs/probe/raw_90mb.json`), and the only other lever — exhausting the validators' shared GitHub API budget — would degrade Studio Dev for everyone. The seed therefore shows the RETRY-to-deadline path with both sources unreadable; the outage cases (no answer, 403/429, 5xx on either side) are covered offline (`test_threats.Threat5_FileNeverLoads`, `test_attacks.A4_*`).

**Studio Dev transfers, measured:** each `claim` finalizes and posts a well-formed `on="finalized"` transfer of the exact amount to the right address, but Studio Dev creates no child transaction, so the demo contracts' *native* balances still hold what was claimed. The contract's books are at zero; the undelivered value is a property of the network, not a balance the contract owes anyone.

## Verify it yourself

    cd test && npm install
    node verify_onchain.mjs                       # chain bytes == repo bytes
    node peek.mjs LicenseGuardDemo get_challenge 1
    node peek.mjs LicenseGuardDemo verify_challenge 1   # recomputes hashes, similarity, outcome
    python3 -m unittest -q test_logic test_threats test_random test_attacks
    python3 ../tools/audit.py                     # 44 checks -> docs/AUDIT.md

The offline suite is 619 tests: every threat in the brief has its own class
(`test/test_threats.py`), every finding of the independent review has its
own (`test/test_attacks.py`), and 90 randomized lifecycles — including repos
going private mid-challenge — must each drain to exactly zero
(`test/test_random.py`).

## Honest limits

- **The similarity threshold can miss heavily rewritten code.** Renaming a few
  identifiers still matches (tested: 61% after three renames), but a copy with
  every identifier renamed falls to ~9% and reads as NOT_DERIVED (tested).
  Partial copies — one function lifted out of a large file into another large
  file — can also fall under 50%.
- **Only four licenses:** MIT, Apache-2.0, BSD-3-Clause, GPL-3.0. Only the
  attribution/notice obligation is judged — not source availability, not
  "state your changes", not license compatibility.
- **GitHub availability.** Everything depends on GitHub answering. The GitHub
  API allows 60 unauthenticated requests per hour **for the whole validator
  network** (measured), so the API is used only where it changes who gets
  paid; a rate-limited judgement RETRYs and, past its deadline, ends
  INCONCLUSIVE with both bonds refunded.
- **Forfeit is strict.** A bonded repository that is made private, deleted,
  force-pushed away (or, if GitHub doesn't redirect raw URLs, renamed) while
  a challenge is open forfeits — for every open challenge, each capped at 50%
  per copied file. Retire a repository only after withdrawing its bond.
- **Direction of copying is only partly proven.** The original repository
  must predate the bond and the original commit must be dated before the
  bonded commit, but commit dates are set by whoever commits: a challenger
  who controls an old repository can backdate a commit. Between two
  repositories that both predate the bond, the contract can't truly tell who
  copied whom.
- **Very large files.** Files over 200 KB aren't measured (INCONCLUSIVE, both
  refunded) — so a copier can escape a slash (not win) by burying a copy in a
  file larger than that. Validators fetch even 90 MB files fine (measured);
  the limit is the judging budget.
- **Code files named like notices.** `LICENSE*`, `NOTICE*`, `COPYING*` and
  `THIRD_PARTY*` files with non-code extensions can't be challenged; a copy
  hidden in, say, `NOTICE.txt` is out of reach. Code extensions (`notice.js`)
  stay challengeable.
- **A real outage can't be demonstrated on demand.** The seed shows the
  RETRY-to-deadline path with both sources made unreadable; a GitHub 5xx or
  timeout follows the same path in the offline tests but can't be produced on
  chain without exhausting the validators' shared API budget, which would
  degrade Studio Dev for everyone.
- **Where attribution is looked for is a fixed list** (the file, LICENSE,
  NOTICE, THIRD_PARTY_NOTICES, license files beside the copied file). Credit
  given only in a README or on a website isn't seen. The model sees the first
  6,000 characters of the copied file.
- **Studio Dev value transfers.** `claim` posts a real transfer; on Studio
  Dev it is queued on finalization and was not executed in this seed (see
  "What's on chain"). The contract's own books are what drain to zero.

## Files

| path | what |
|---|---|
| `contracts/LicenseGuard.py` | the contract (the deployed bytes) |
| `contracts/_probe.py` | the throwaway probe contract of step 1 |
| `docs/PROBE.md`, `docs/probe/` | what validators can read from GitHub, measured |
| `docs/TASKS.md` | the work log |
| `docs/AUDIT.md` | the audit table (`tools/audit.py`) |
| `docs/ATTACK_BRIEF.md` | a brief for an independent reviewer |
| `docs/seed-evidence.json`, `docs/seed-run.log` | every seed transaction and the final chain state |
| `docs/superseded/v1.0.0/` | the first deployment's evidence and audit, before the review fixes |
| `test/test_logic.py`, `test/test_threats.py`, `test/test_random.py`, `test/test_attacks.py` | offline suite (`test_attacks.py`: the independent review's findings) |
| `test/lg_stub.py`, `test/lg_world.py` | runtime stub (matched to what the probe measured) and fake GitHub |
| `test/deploy.mjs`, `test/seed.mjs`, `test/verify_onchain.mjs`, `test/peek.mjs` | chain scripts |
| `test/rehearse_live.py` | the judging code run against real GitHub before deploying |
| `deployments.json` | addresses, deploy txs, sha256 of the deployed bytes |

The fixture repositories `kenil1710/licenseguard-fixture-stripped`,
`-attributed` and `-vanishing` were created for this demonstration and say so
in their READMEs. The copied file is `index.js` of
[sindresorhus/slugify](https://github.com/sindresorhus/slugify) (MIT, © Sindre
Sorhus) at commit `3b17b2e84b97624a683aafaa38184bf2746fab22`; the "stripped"
and "vanishing" fixtures carry it **without** its notice on purpose, and
credit it in their READMEs.
