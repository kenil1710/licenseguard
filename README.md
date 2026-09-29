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
| `ATTRIBUTION_MISSING` | copied, and the attribution doesn't meet the license | challenger gets their stake back **plus 50% of the project's bond**; the bond becomes `NON_COMPLIANT` |
| `COMPLIANT` | copied, and the attribution meets the license | the challenger's stake goes to the project |
| `NOT_DERIVED` | not copied (or the "original" isn't a real original) | the challenger's stake goes to the project |
| `INCONCLUSIVE` | the question couldn't be answered (license unconfirmed, file too small, a source never loaded by the deadline) | both refunded |

> **The model never decides who pays. It only judges whether the attribution
> meets the license; code decides whether the file was copied and moves the
> money.**

Concretely, in `contracts/LicenseGuard.py`:

- **Code decides whether the file was copied.** Both files are tokenized
  (identifiers lower-cased, punctuation kept, lines that start as comments
  dropped so a shared license header doesn't count), cut into 5-token
  shingles, and compared by containment in either direction. ≥ 50% is
  `DERIVED`. Integer basis points, compared exactly across validators.
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

- **One flow. Three money outcomes. One contest per side. No refiles.**
  `post_bond → verify_bond → challenge → judge → (contest) → finalize → claim`.
  A file pair challenged once on a bond can't be challenged on it again — not
  with another commit of the original, not with another license.
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
    `created_at`, which nobody can edit). Otherwise it's `NOT_DERIVED`.

## What's on chain

Studio Dev (chain 61997), explorer <https://explorer-studio-dev.genlayer.com/>.
All three instances are the **same bytes** (sha256 in `deployments.json`,
read back from the chain by `test/verify_onchain.mjs`); the demos only have
minute-scale windows so the seed fits in 20 minutes.

| instance | address | constructor |
|---|---|---|
| LicenseGuard | `0xdC8E787215bC21C427141Af6F752479f55944347` | challenge window 2592000s, unbond 604800s, contest 172800s, deadline 86400s |
| LicenseGuardDemo | `0x22C26ADFA8367314aC0E9764c2439d44CfcE08eC` | challenge window 900s, unbond 60s, contest 180s, deadline 420s |
| LicenseGuardDemoStall | `0x7AA93E3649cdC07E3bFB9d9dF83a6F8E0195A0Df` | challenge window 600s, unbond 60s, contest 180s, deadline 420s |

Source sha256 `d8b5fbc8eb9a82369dd64ec39591b0ad797a2b0566de2187f7c7dab331dca492` (107319 bytes) on all three.

### The seed (18.3 minutes, `test/seed.mjs`, every tx in `docs/seed-evidence.json`)

Original: `sindresorhus/slugify@3b17b2e84b97624a683aafaa38184bf2746fab22` — `index.js`, MIT, notice in its `license` file.

| result | files | how it was decided | money | judge / decisive tx | finalize / second tx |
|---|---|---|---|---|---|
| **ATTRIBUTION_MISSING** | `slugify/index.js` → `licenseguard-fixture-stripped/src/slugify.js` | similarity 10000 bps; holder "sindre sorhus" found nowhere in the copy or the notice files → decided by code, **no model call**; origin checked (repo created 2018, commit in history) | challenger +0.2 stake +0.5 slash; bond → NON_COMPLIANT | `0x88244afcc504b5acaf87dedfe83a440174af6e857dd865802093bdf1fcc325ca` | `0xb4aa708fc902f3016146b8206a909c74c07b4b48adc3d2be52e7c8acee57ee86` |
| **COMPLIANT** | `slugify/index.js` → `licenseguard-fixture-attributed/vendor/slugify.js` | similarity 10000 bps; holder in the file header → **model asked**: meets_requirement YES / missing NONE, agreed by consensus; no GitHub API call | project +0.2 | `0xeaf95fc4fa8c2cc55ec8ba81b2c6b0458541dcd6cf25f5e19f4bd305de7c8c40` | `0x0bafd6bddac751e929c72d2ee9ba8674b7de79c3dd2e02b60514840ceed57f0e` |
| **NOT_DERIVED** | `slugify/index.js` vs `licenseguard-fixture-attributed/src/app.js` | similarity 263 bps (< 5000) → code alone | project +0.2 | `0xc158b4bb5651cc34a3b8dbc1615e9c8dffea09a68ef3793838efc33a29251dcd` | `0x85000bde7dd7ec52b4f962f2425412dc9143f050f0f90be44b325177561825c2` |
| **contest HELD** | challenger contests #3 | re-read of the same pinned files: NOT_DERIVED again | contest bond 0.1 → project | `0xc942da485d72cc430de250ffe7bfd829ec476ed44e3d927da24b296f686c9409` | `0x44623655e8dbe20a27ca3ab3abc4f21961f3b4b0e3370ef2a2dba3169c12a063` |
| **fetch failure → deadline** | `licenseguard-fixture-vanishing` made **private** after the challenge | judge → RETRY (side BONDED: "the bonded commit's LICENSE answered 404"); after the 420 s deadline judge is refused; `settle_stalled` → INCONCLUSIVE `DEADLINE_PASSED_BONDED`; bond badge suspended | challenge stake refunded; bond lock released and withdrawn | `0x2c5a60815c7280a2fd8582d9d702f147c4365f2e2cbb37fc7b74ef8450d08236` | `0x9d1fcf423e02bad8c8b052361d0c4621f482ba0caee389408a99e904cd82bf5f` |
| **refusals** | `../../evil/other/src/slugify.js`; same pair with another commit + license | refused before any validator: path escape (threat 1); "already challenged … no refiles" (threat 3) | value sent stays claimable | `0xbeb2bb82c6b1bcb0a9c857922dfedcb5036ba92e5f6154c59d62385b5d07a977` | `0x110d70ba968815f9a9e70cf24963c296d0c1a088091ef9a85a7083b14a328295` |

Then every bond was withdrawn and every balance claimed: both demo instances end at **balance 0 = held 0 + payable 0** (`get_stats`: `books_zero: true`, `ledger_ok: true`). `verify_challenge` recomputes every judged challenge as consistent (facts hash, content hash over every fetched document, similarity from the stored shingle counts, outcome from the stored vector).

**Studio Dev transfers, measured:** each `claim` finalized and posted a well-formed `on="finalized"` transfer of the exact amount to the right address (e.g. 1.5 GEN to proj2, tx `0xdd923fe971d1af88d9563fd1ea522ea71e058527ae1a3b4f31f744161349f910`), but Studio Dev created no child transaction, so the demo contracts' *native* balances still hold 3.1 and 1.2 GEN — exactly the amounts claimed. The contract's books are at zero; the undelivered value is a property of the network, not a balance the contract owes anyone.

## Verify it yourself

    cd test && npm install
    node verify_onchain.mjs                       # chain bytes == repo bytes
    node peek.mjs LicenseGuardDemo get_challenge 1
    node peek.mjs LicenseGuardDemo verify_challenge 1   # recomputes hashes, similarity, outcome
    python3 -m unittest -q test_logic test_threats test_random
    python3 ../tools/audit.py                     # 35 checks -> docs/AUDIT.md

The offline suite is 576 tests: every threat in the brief has its own class
(`test/test_threats.py`), and 90 randomized lifecycles must each drain to
exactly zero (`test/test_random.py`).

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
  INCONCLUSIVE with both bonds refunded. A bonded repository that goes private
  mid-challenge also ends INCONCLUSIVE (and loses its badge) rather than
  slashed — an escape from a slash, stated plainly.
- **Direction of copying isn't proven.** The contract requires the original
  repository to predate the bond, but between two repositories that both
  predate it, it can't tell which copied which.
- **Where attribution is looked for is a fixed list** (the file, LICENSE,
  NOTICE, THIRD_PARTY_NOTICES, license files beside the copied file). Credit
  given only in a README or on a website isn't seen. The model sees the first
  6,000 characters of the copied file.
- **Files over 200 KB aren't measured** (INCONCLUSIVE).
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
| `test/test_logic.py`, `test/test_threats.py`, `test/test_random.py` | offline suite |
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
