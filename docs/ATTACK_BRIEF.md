# ATTACK BRIEF — for a fresh reviewer session

You are reviewing **LicenseGuard**, a GenLayer Intelligent Contract
(`contracts/LicenseGuard.py`, one file, deployed byte-identical on Studio Dev —
addresses in `deployments.json`). Your job is to **take money you should not get,
keep money you should lose, or freeze someone else's money.** Do not trust the
comments or the README; read the code. Report each finding as: the calls in
order (with arguments and values), the state before and after, and the wei that
moved wrongly. A finding without a concrete sequence is not a finding.

## What it does, in one paragraph

A project posts a bond on `owner/repo@<40-hex sha>` (`post_bond`, payable). The
bond is PENDING until `verify_bond` (validators: the sha is in the repo's
default-branch history via `compare/{sha}...HEAD`; the commit has a LICENSE
file; `.licenseguard` names the bonder's address on its own line at the
commit and at the repository's current head). Anyone may
`challenge(bond_id, original_repo, original_sha, original_path, copied_path,
license)` with a challenge bond. `judge` (permissionless) makes validators read
the pinned files from `raw.githubusercontent.com`, measure 5-token shingle
containment (≥ 50% = DERIVED), confirm the original's license and copyright
notice, look for the holder's name in the copied file and the bonded commit's
license/notice files, ask the model **only** whether the attribution present
meets the license (fixed enums), and check the origin via the GitHub API
**only** when the result would pay the challenger. Outcomes: ATTRIBUTION_MISSING
(challenger gets stake + 50% of the bond), COMPLIANT / NOT_DERIVED (project gets
the stake), INCONCLUSIVE (stake refunded). One contest per side re-reads the
same facts. `finalize` credits; `claim` transfers. Deadlines everywhere;
`settle_stalled` / `settle_stalled_bond` are the exits.

## Since the first review (policy 1.1.0)

Round 1 found five breaks (`test/test_attacks.py`, kept in the suite). The
fixes changed these rules - attack them too:

- The violation is the **copied file**: key `(bond, copied_path)`; one open
  challenge per copied file; once it pays, never again; the 50% slash is
  capped per copied file. A LOSING challenge frees the file (anti-sock-puppet)
  - can the project still occupy a file (contests, RETRY loops)?
- **Forfeit:** bonded commit 404/410/451 while the original is readable =
  ATTRIBUTION_MISSING money (origin checks still apply). Both unreadable =
  RETRY `BONDED_UNREADABLE`; a CHALLENGER's contest stalled that way is won
  at the deadline unless the stored reason was ORIGIN_* - can a challenger
  delete its own original to skip the origin checks?
- **Similarity** is max(M1: comments stripped from both, M2: original
  stripped vs the copy read whole without `/ * #`). Can a challenger craft an
  original that matches the bonded file's comments/docs under M2?
- **License-like filenames** (non-code extensions) are refused; an original
  whose code tokens are a license text is NOT_DERIVED.
- **Direction:** the original commit must predate the bonded commit, whose
  date is floored at the bonded repo's `created_at`. Commit dates are
  forgeable by whoever commits.

## Since the identity fixes (policy 1.2.0)

- A PENDING bond reserves nothing; the first to verify takes the slot and
  rival pending bonds are rejected (25 per call, the rest on touch). Can a
  squatter still delay or grief the owner?
- `.licenseguard` must name the bonder on its own line at the bonded commit
  AND at `raw.githubusercontent.com/{repo}/HEAD/.licenseguard` (300 s CDN
  cache). Raw checks run before any API call.

## Rules the contract claims (try to break each)

1. Consensus binds every stored value; the leader cannot forge a field.
2. No `raise`; every refusal leaves the sent value claimable (`_bank` first).
3. No counter moves before the last refusal.
4. Content hash covers every fetched document; `verify_challenge` recomputes.
5. `settle_stalled` works while paused; the owner cannot freeze funds.
6. Books drain to zero: `balance == held + payable`, always.
7. Only `claim` transfers and it reads no clock.
8. Nobody can choose a source that decides their own case.

## Where I would start

- **Forged originals.** Can a challenger manufacture an "original" that makes a
  bonded project pay? Ideas: a repository created before the bond but filled
  later with the project's own file plus a copyright line (the contract checks
  `created_at` and history, not when the file was added — is that exploitable,
  and how cheaply?); a commit on a non-default branch; a force-push that
  rewrites history after judging; GitHub renames/transfers (`owner/repo`
  redirects); case differences in repo names; the same original under two
  names (fork vs parent) to dodge the duplicate-pair rule.
- **The bonded side choosing its own evidence.** The project controls the
  bonded commit's files. Can it plant text that makes the model say YES while
  the notice is really missing (prompt injection inside the file, a NOTICE file
  that names the holder in a misleading sentence)? The deterministic gate only
  requires the holder's name somewhere in the copy or notice files.
- **Escaping a challenge.** Make the bonded repository private or delete it
  mid-challenge: the contract RETRYs to INCONCLUSIVE (refund) and suspends the
  badge. Is that a cheap escape from a slash? Can the challenger do the
  symmetric thing to escape a loss (delete the original repo → what outcome)?
- **Similarity.** 5-token shingles after dropping comment-led lines. Can a
  project pad or reorder a copied file to fall under 50% while keeping it
  functionally identical? Can a challenger push an unrelated file over 50%
  (boilerplate-heavy files, generated code, minified code on one line)?
- **Money paths.** Contest bond routing (`HELD` → other side, `CHANGED` →
  refund), slash capping across several ATTRIBUTION_MISSING challenges on one
  bond, a challenger who is also the bond owner under another address, the
  `unbond_delay_s` window versus `challenge_until`, a contest filed in the
  last second of the window, `settle_stalled` on a contest vs `finalize`.
- **Consensus.** Validators compare the whole vector exactly, including model
  enums. Can a leader cause a permanent disagreement to force the deadline
  (INCONCLUSIVE) when the honest result would slash? What does a RETRY need to
  be agreed (`_agree_retry` requires the SAME side)?
- **Rate limits.** The GitHub API budget is 60/hour for the whole validator
  network (docs/PROBE.md). Can a challenger (or the project) burn it so that
  the would-be ATTRIBUTION_MISSING judgement RETRYs past its deadline?

## How to run things

    cd test && npm install              # genlayer-js for chain scripts
    python3 -m unittest -q test_logic test_threats test_random   # offline, ~2 s
    python3 ../tools/audit.py           # the audit table
    node peek.mjs LicenseGuard get_config

`test/lg_world.py` gives you a fake GitHub (`w.gh.put / repo / history / fail`)
and asserts the ledger after every call; writing an attack as a test there is
the fastest way to prove it. Do not run attacks against the deployed instances
without saying so in your report.
