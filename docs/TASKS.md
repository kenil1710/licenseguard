# LicenseGuard — tasks

Status legend: [ ] todo · [~] in progress · [x] done · [!] blocked (reason inline)

## Step 1 — probe (docs/PROBE.md)
- [x] local: raw + commits + compare sizes; fork-network commits ARE served through the parent repo's raw and commits URLs (compare says `diverged`)
- [x] on chain: raw file, raw LICENSE, missing path/repo, fork sha via parent, 544 KB file, api.github.com with/without User-Agent, compare, repo metadata, rate limit
- [x] docs/PROBE.md: what works, sizes, rate limits, design consequences

## Step 2 — contract (contracts/LicenseGuard.py)
- [x] bonds: post_bond (payable, mechanical) → verify_bond (validators: commit in default-branch history, LICENSE at commit, `.licenseguard` names the bonder) → ACTIVE / REJECTED; one active bond per repo
- [x] withdraw_bond: no open challenge, challenge window over, unbond delay after last close
- [x] challenge: copied file only in the bonded repo at the bonded commit; fixed license vocabulary; mechanical refusals; duplicate pair refused
- [x] judge: deterministic availability / history / similarity / license / copyright; model only on attribution for DERIVED files with evidence present
- [x] RETRY with hard deadline → settle_stalled → INCONCLUSIVE, both released
- [x] contest: one per side, same facts, contest bond, HELD → other side, CHANGED → refund
- [x] finalize (credits) + claim (transfers, no clock)
- [x] views: is_compliant, get_bond, get_challenge, list_challenges, verify_challenge, get_stats, get_config
- [x] mandatory safety list (0 raise, no str.replace, bank-first, counters after refusals, pause gates only new business, ledger identity)

## Step 3 — offline tests (300+)
- [x] stub + harness
- [x] threat model 1–8, one class each
- [x] randomized lifecycles drain to zero
- [x] audit script

## Step 4 — deploy + seed
- [x] fixture repos under kenil1710 (disclosed as fixtures)
- [x] deploy canonical + demo; byte-identical source check
- [x] seed: ATTRIBUTION_MISSING, COMPLIANT, NOT_DERIVED, contest held, fetch failure → deadline → released; drain to 0

- [x] seed on chain in 18.3 min: ATTRIBUTION_MISSING, COMPLIANT (model), NOT_DERIVED, contest HELD, private repo → RETRY → deadline → INCONCLUSIVE; refusals for threats 1 and 3; both demos drained to 0
- [x] measured: claim transfers posted correctly but not executed by Studio Dev (native balances 3.1 / 1.2 GEN remain) - documented

## Step 5 — README
- [x] trust problem and mechanism first; required sentence; honest limits; on-chain table from evidence
## Step 6 — docs/ATTACK_BRIEF.md
- [x] written; attack not run (by instruction)
## Step 7 — push, addresses file, report
- [x] audit 35 PASS / 0 FAIL
- [x] ~/Desktop/licenseguard-addresses.txt
- [x] pushed to github.com/kenil1710/licenseguard; GitHub bytes == chain bytes

## Notes from the work
- [x] judging reordered after the probe: raw files first; model only with an attribution trace; GitHub API only for a would-be ATTRIBUTION_MISSING (API budget is 60/h for the whole validator network)
- [x] live rehearsal of the judging code against real GitHub (test/rehearse_live.py): all three outcomes as expected
- [x] genvm-lint: lint passes; `validate` cannot load this runner pin's SDK (the linter bundles older runners) - the deploy + views on chain are the SDK check
- [x] 576 offline tests (416 logic, 64 threat, 96 randomized incl. coverage of every outcome and exit)
- [x] deployed canonical + 2 demos, byte-identical (test/verify_onchain.mjs)
- [x] docs/ATTACK_BRIEF.md

## Independent review, round 1 (test/test_attacks.py) — five findings
- [ ] A1 license/notice/third-party filenames refused as copied_path or original_path (any case, any extension), before any fetch
- [ ] A1 extra: an original FILE that is itself a license text (after comment stripping) is NOT_DERIVED - closes the same attack under any other filename
- [ ] A2 comments stripped inside lines (string-aware): /* */ anywhere (multi-line too), // and # to end of line
- [ ] A3 one open challenge per (bond, copied_path); a paid copied file is closed for good; slash per copied file capped at SLASH_BPS
- [ ] A3 check: a losing challenge must not lock the path (else a project's sock-puppet burns its own copied files for free)
- [ ] A4 bonded commit 404/410/451 while the original is readable = FORFEIT (ATTRIBUTION_MISSING money); only outages RETRY -> INCONCLUSIVE
- [ ] A4 withdraw blocked while any challenge (incl. a forfeit) is open
- [ ] A5 contest re-read with the bonded commit gone -> forfeit (challenger's contest wins); stalled challenger contest with bonded side unreadable -> settled against the project
- [ ] ALSO original commit must be dated before the bonded commit, on paying paths only; bonded date floored at the bonded repo's created_at (else a backdated bonded commit vetoes every challenge)
- [ ] test_attacks.py kept in the suite; tests whose preconditions the specified fixes change are updated to the specified behaviour, each noted
- [ ] review each fix for new stuck paths / unilateral control
- [ ] redeploy x3, byte-for-byte; reseed (A1 refusal, private-repo forfeit, real outage INCONCLUSIVE); drain to 0; audit; README; push; addresses file
