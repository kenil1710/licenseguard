# LicenseGuard — tasks

Status legend: [ ] todo · [~] in progress · [x] done · [!] blocked (reason inline)

## Step 1 — probe (docs/PROBE.md)
- [x] local: raw + commits + compare sizes; fork-network commits ARE served through the parent repo's raw and commits URLs (compare says `diverged`)
- [~] on chain: raw file, raw LICENSE, missing path/repo, fork sha via parent, 544 KB file, api.github.com with/without User-Agent, compare, repo metadata, rate limit
- [ ] docs/PROBE.md: what works, sizes, rate limits, design consequences

## Step 2 — contract (contracts/LicenseGuard.py)
- [ ] bonds: post_bond (payable, mechanical) → verify_bond (validators: commit in default-branch history, LICENSE at commit, `.licenseguard` names the bonder) → ACTIVE / REJECTED; one active bond per repo
- [ ] withdraw_bond: no open challenge, challenge window over, unbond delay after last close
- [ ] challenge: copied file only in the bonded repo at the bonded commit; fixed license vocabulary; mechanical refusals; duplicate pair refused
- [ ] judge: deterministic availability / history / similarity / license / copyright; model only on attribution for DERIVED files with evidence present
- [ ] RETRY with hard deadline → settle_stalled → INCONCLUSIVE, both released
- [ ] contest: one per side, same facts, contest bond, HELD → other side, CHANGED → refund
- [ ] finalize (credits) + claim (transfers, no clock)
- [ ] views: is_compliant, get_bond, get_challenge, list_challenges, verify_challenge, get_stats, get_config
- [ ] mandatory safety list (0 raise, no str.replace, bank-first, counters after refusals, pause gates only new business, ledger identity)

## Step 3 — offline tests (300+)
- [ ] stub + harness
- [ ] threat model 1–8, one class each
- [ ] randomized lifecycles drain to zero
- [ ] audit script

## Step 4 — deploy + seed
- [ ] fixture repos under kenil1710 (disclosed as fixtures)
- [ ] deploy canonical + demo; byte-identical source check
- [ ] seed: ATTRIBUTION_MISSING, COMPLIANT, NOT_DERIVED, contest held, fetch failure → deadline → released; drain to 0

## Step 5 — README
## Step 6 — docs/ATTACK_BRIEF.md
## Step 7 — push, addresses file, report
