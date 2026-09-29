"""ATTACKS - the independent review's findings, each a reproducible break of a
rule the contract claims. Every test FAILED against contracts/LicenseGuard.py
policy 1.0.0 (sha256 d8b5fbc8...) and passes against the fixed contract.

    cd test && python3 -m unittest -v test_attacks

Where a specified fix changes a PRECONDITION of the reviewer's original test
(the LICENSE challenge is now refused at filing; the fork is now refused as a
duplicate; a private bonded repo is now a forfeit instead of a RETRY), the test
asserts the specified behaviour and keeps the reviewer's original assertion
wherever it still applies. Each such change is marked "UPDATED".
"""

import unittest

import lg_stub
from lg_world import (LG, World, standard, PROJ, CHAL, CHAL2, TRIGGER, OUTSIDER, SHA_B, SHA_O,
                      GEN, ORIGINAL, UNRELATED, COPY_STRIPPED, COPY_HOLDER_ONLY,
                      ORIG_LICENSE, PROJ_LICENSE, iso, raw, T0, API)

DAY = 86400
SHA_X = "e" * 40


class A1_LicenseFileAsTheCopiedFile(unittest.TestCase):
    """HIGH. An honest MIT project that copied nothing was slashed: the
    challenger named the bonded repo's own LICENSE as `copied_path` and any
    other MIT project's LICENSE as the "original"; two license texts are ~97%
    shingle-identical and the original's holder is absent, so the file gates
    returned ATTRIBUTION_MISSING without asking the model.

    FIX: license / notice / third-party filenames are refused as copied_path
    or original_path, any case, any extension, before any fetch; and an
    original FILE that is itself a license text (under any other name) is
    NOT_DERIVED."""

    def world(self):
        w = World()
        w.original(repo="ada/slugify", path="LICENSE", text=ORIG_LICENSE, license_path="LICENSE")
        w.original(repo="bob/leftpad", sha=SHA_X, path="LICENSE",
                   text=ORIG_LICENSE.replace("Ada Lovelace", "Bob Builder"), license_path="LICENSE")
        bid = w.bond(files={"src/app.js": UNRELATED, "docs/legal.txt": PROJ_LICENSE})
        return w, bid

    def test_license_vs_license_refused_before_any_fetch(self):   # UPDATED (was: slashed)
        w, bid = self.world()
        lg_stub.CALLS.clear()
        for orig in (("ada/slugify", SHA_O, "LICENSE"), ("bob/leftpad", SHA_X, "LICENSE")):
            out = w.challenge(bid, "LICENSE", original=orig)
            self.assertEqual(out["status"], "REJECTED")
        self.assertEqual(lg_stub.CALLS, [])
        self.assertEqual(len(w.c.challenges), 0)
        self.assertEqual(int(w.bd(bid).slashed_wei), 0)

    def test_every_license_like_name_refused(self):
        w, bid = self.world()
        for name in ("LICENSE", "license.md", "LICENCE.txt", "COPYING", "copying.lesser",
                     "NOTICE", "notice.txt", "THIRD_PARTY_NOTICES.md", "third-party-licenses.txt",
                     "vendor/x/License", "LICENSE-MIT", "license_apache.txt", "ThirdPartyNotices.txt"):
            out = w.challenge(bid, name)
            self.assertEqual(out["status"], "REJECTED", name)
            out = w.challenge(bid, "src/app.js", original=("ada/slugify", SHA_O, name))
            self.assertEqual(out["status"], "REJECTED", "original " + name)
        self.assertEqual(len(w.c.challenges), 0)

    def test_code_files_with_license_like_words_still_allowed(self):
        w, bid = self.world()
        for name in ("src/licenses_checker.js", "src/notify.js", "src/copy.js"):
            self.assertEqual(w.challenge(bid, name)["status"], "OK", name)

    def test_code_named_like_a_notice_cannot_hide_a_copy(self):
        """Found while checking the fix: refusing `notice.js` would let a copier
        rename a stolen file and make it unchallengeable."""
        w, bid = standard(copied=COPY_STRIPPED, copied_path="src/notice.js")
        cid = w.challenge_ok(bid, "src/notice.js")
        self.assertEqual(w.judge(cid)["outcome"], "ATTRIBUTION_MISSING")

    def test_license_text_under_a_code_name_is_not_derived(self):
        w, bid = self.world()
        w.gh.put("ada/slugify", SHA_O, "src/license.js", ORIG_LICENSE)
        w.gh.put("acme/app", SHA_B, "src/license.js", PROJ_LICENSE)
        w.bonded_repo(files={"src/license.js": PROJ_LICENSE})
        cid = w.challenge_ok(bid, "src/license.js", original=("ada/slugify", SHA_O, "src/license.js"))
        self.assertEqual(w.judge(cid)["reason"], "ORIGINAL_IS_A_LICENSE_TEXT")

    def test_license_text_under_another_name_is_not_derived(self):
        w, bid = self.world()
        w.gh.put("ada/slugify", SHA_O, "docs/mit.txt", ORIG_LICENSE)
        cid = w.challenge_ok(bid, "docs/legal.txt", original=("ada/slugify", SHA_O, "docs/mit.txt"))
        out = w.judge(cid)
        self.assertEqual((out["outcome"], out["reason"]), ("NOT_DERIVED", "ORIGINAL_IS_A_LICENSE_TEXT"))
        w.finalize(cid)
        self.assertEqual(int(w.bd(bid).slashed_wei), 0)      # the reviewer's assertion

    def test_code_file_with_license_header_is_not_a_license_text(self):
        header = "/*\n" + "\n".join(" * " + l for l in ORIG_LICENSE.split("\n")) + "\n */\n"
        w, bid = standard(copied=COPY_STRIPPED)
        w.gh.put("ada/slugify", SHA_O, "index.js", header + ORIGINAL)
        cid = w.challenge_ok(bid, "src/slugify.js")
        self.assertEqual(w.judge(cid)["outcome"], "ATTRIBUTION_MISSING")


class A2_CommentPrefixHidesTheCopy(unittest.TestCase):
    """HIGH. `_code_tokens` dropped every line that STARTED with a comment
    marker; `/**/` before every copied line removed the copy from the measure.
    FIX: comments stripped inside lines, plus a second measure (M2) that reads
    the copy whole, so no comment trick hides tokens."""

    def test_functionally_identical_copy_is_still_derived(self):
        hidden = "\n".join(("/**/ " + l.lstrip()) if l.strip() else l
                           for l in COPY_STRIPPED.split("\n"))
        w, bid = standard(copied=hidden + "\n" + UNRELATED)
        cid = w.challenge_ok(bid, "src/slugify.js")
        out = w.judge(cid)
        self.assertNotIn(out["outcome"], ("NOT_DERIVED", "INCONCLUSIVE"),
                         "verbatim copy with /**/ line prefixes judged %s (%s), similarity %s"
                         % (out["outcome"], out["reason"], out["similarity_bps"]))

    def test_fake_block_comment_cannot_swallow_the_copy(self):
        """A regex like /[ /*]/ opens a "block comment" for a naive stripper
        that only a later */ closes - swallowing everything between."""
        swallowed = "const sep = /[ /*]/;\n" + COPY_STRIPPED + "\n/* end */\n"
        w, bid = standard(copied=swallowed)
        cid = w.challenge_ok(bid, "src/slugify.js")
        self.assertEqual(w.judge(cid)["outcome"], "ATTRIBUTION_MISSING")

    def test_string_hash_cannot_hide_statements(self):
        hidden = "\n".join(("'#'; " + l.lstrip()) if l.strip() else l
                           for l in COPY_STRIPPED.split("\n"))
        w, bid = standard(copied=hidden)
        cid = w.challenge_ok(bid, "src/slugify.js")
        self.assertEqual(w.judge(cid)["outcome"], "ATTRIBUTION_MISSING")

    def test_shared_license_header_alone_is_not_derived(self):
        header = "/*\n" + "\n".join(" * " + l for l in ORIG_LICENSE.split("\n")) + "\n */\n"
        w, bid = standard(copied=header + UNRELATED)
        w.gh.put("ada/slugify", SHA_O, "index.js", header + ORIGINAL)
        cid = w.challenge_ok(bid, "src/slugify.js")
        self.assertEqual(w.judge(cid)["outcome"], "NOT_DERIVED")


class A3_SameViolationPaidTwiceViaAFork(unittest.TestCase):
    """MEDIUM. The pair key was (original_repo, original_path, copied_path),
    so the same copied file against any fork of the original was a new pair.
    FIX: the key is (bond, copied_path); slashing per copied file is capped at
    SLASH_BPS."""

    def test_fork_is_refused_as_a_duplicate(self):                 # UPDATED (was: both judged)
        w, bid = standard()
        w.original(repo="fan/slugify", sha=SHA_O)            # an old fork, same content
        c1 = w.challenge_ok(bid, "src/slugify.js")
        out = w.challenge(bid, "src/slugify.js", who=CHAL2, original=("fan/slugify", SHA_O, "index.js"))
        self.assertEqual(out["status"], "REJECTED")
        self.assertIn("already challenged", out["reason"])
        self.assertEqual(w.judge(c1)["outcome"], "ATTRIBUTION_MISSING")
        w.finalize(c1)
        self.assertLessEqual(int(w.bd(bid).slashed_wei), GEN // 2)   # the reviewer's assertion

    def test_fork_refused_after_the_first_paid(self):
        w, bid = standard()
        w.original(repo="fan/slugify", sha=SHA_O)
        c1 = w.challenge_ok(bid, "src/slugify.js")
        w.judge(c1)
        out = w.challenge(bid, "src/slugify.js", who=CHAL2, original=("fan/slugify", SHA_O, "index.js"))
        self.assertEqual(out["status"], "REJECTED")


class A4_PrivateRepoIsAForfeit(unittest.TestCase):
    """HIGH. Private for one `deadline_s`, public again: the challenge ended
    INCONCLUSIVE, the pair was burned and the full bond withdrawn.
    FIX: bonded commit 404/410/451 while the original is readable = FORFEIT,
    same money as ATTRIBUTION_MISSING. Only outages retry and end
    INCONCLUSIVE. Withdrawal is blocked while any challenge is open."""

    def test_private_repo_pays_the_challenger(self):                # UPDATED (was: refile)
        w, bid = standard()
        cid = w.challenge_ok(bid, "src/slugify.js")
        lic = raw("acme/app", SHA_B, "LICENSE")
        saved = lg_stub.WEB[lic]
        w.gh.fail(lic, 404)                                  # repo goes private
        out = w.judge(cid)
        self.assertEqual((out["outcome"], out["reason"]),
                         ("ATTRIBUTION_MISSING", "FORFEIT_BONDED_COMMIT_WITHDRAWN"))
        lg_stub.WEB[lic] = saved                             # public again: too late
        self.assertEqual(w.call(PROJ, "withdraw_bond", bid)["status"], "REJECTED")
        w.finalize(cid)
        self.assertEqual(int(w.ch(cid).paid_challenger_wei), int(w.c.challenge_bond_wei) + GEN // 2)
        self.assertEqual(w.bd(bid).status, "NON_COMPLIANT")
        self.assertTrue(w.bd(bid).forfeited)
        self.assertFalse(w.view("is_compliant", "acme/app"))

    def test_forfeit_still_needs_a_real_original(self):
        w, bid = standard()
        w.original(repo="new/fake", created=iso(T0 + 10))    # created after the bond
        cid = w.challenge_ok(bid, "src/slugify.js", original=("new/fake", SHA_O, "index.js"))
        w.gh.fail(raw("acme/app", SHA_B, "LICENSE"), 404)
        self.assertEqual(w.judge(cid)["reason"], "ORIGIN_CREATED_AFTER_BOND")

    def test_real_outage_still_inconclusive_both_refunded(self):
        w, bid = standard()
        cid = w.challenge_ok(bid, "src/slugify.js")
        w.gh.fail(raw("acme/app", SHA_B, "LICENSE"), 503)
        self.assertEqual(w.judge(cid)["outcome"], "RETRY")
        w.advance(DAY + 1)
        out = w.call(OUTSIDER, "settle_stalled", cid)
        self.assertEqual(out["outcome"], "INCONCLUSIVE")
        self.assertEqual(w.owed(CHAL), int(w.c.challenge_bond_wei))
        self.assertEqual(int(w.bd(bid).slashed_wei), 0)
        w.advance(30 * DAY)
        self.assertEqual(w.call(PROJ, "withdraw_bond", bid)["status"], "OK")
        self.assertEqual(w.owed(PROJ), GEN)

    def test_withdraw_blocked_while_forfeit_open(self):
        w, bid = standard(challenge_window_s=600)
        cid = w.challenge_ok(bid, "src/slugify.js")
        w.gh.fail(raw("acme/app", SHA_B, "LICENSE"), 404)
        w.judge(cid)
        w.advance(3600)
        out = w.call(PROJ, "withdraw_bond", bid)
        self.assertEqual(out["status"], "REJECTED")
        self.assertIn("open challenge", out["reason"])


class A5_ProjectCannotVetoAContest(unittest.TestCase):
    """MEDIUM. A contest stalled by the bonded side was dropped: the project's
    provisional win stood and it took the stake.
    FIX: the re-read sees the bonded commit gone -> forfeit, the challenger's
    contest wins; a contest stalled with the bonded commit unreadable is
    settled against the project."""

    def test_private_during_contest_favors_the_challenger(self):    # UPDATED (was: stall)
        w, bid = standard(copied=COPY_HOLDER_ONLY)
        lg_stub.MODEL.serve("YES")                           # first reading: COMPLIANT
        cid = w.challenge_ok(bid, "src/slugify.js")
        self.assertEqual(w.judge(cid)["outcome"], "COMPLIANT")
        self.assertEqual(w.call(CHAL, "contest", cid, value=int(w.c.contest_bond_wei))["status"], "OK")
        w.gh.fail(raw("acme/app", SHA_B, "LICENSE"), 404)   # project goes private
        self.assertEqual(w.judge(cid)["contest"], "CHANGED")
        w.finalize(cid)
        self.assertEqual(int(w.ch(cid).paid_project_wei), 0)  # the reviewer's assertion
        self.assertTrue(w.bd(bid).unreadable)
        w.drain(CHAL)
        self.assertEqual(w.paid(CHAL), int(w.c.challenge_bond_wei) + GEN // 2 + int(w.c.contest_bond_wei))

    def test_stalled_contest_with_bonded_commit_gone_goes_against_project(self):
        w, bid = standard(copied=COPY_HOLDER_ONLY)
        lg_stub.MODEL.serve("YES")
        cid = w.challenge_ok(bid, "src/slugify.js")
        w.judge(cid)
        w.call(CHAL, "contest", cid, value=int(w.c.contest_bond_wei))
        w.gh.fail(raw("acme/app", SHA_B, "LICENSE"), 404)
        w.gh.fail(raw("ada/slugify", SHA_O, "index.js"), 404)   # both gone: nobody can read
        self.assertEqual(w.judge(cid)["side"], "BONDED_UNREADABLE")
        w.advance(DAY + 1)
        out = w.call(OUTSIDER, "settle_stalled", cid)
        self.assertEqual(out["contest"], "WON_AT_DEADLINE_BONDED_UNREADABLE")
        w.finalize(cid)
        self.assertEqual(int(w.ch(cid).paid_project_wei), 0)
        self.assertEqual(w.ch(cid).outcome, "ATTRIBUTION_MISSING")
        self.assertTrue(w.view("verify_challenge", cid)["consistent"])

    def test_project_contest_stalled_by_its_own_repo_costs_the_project(self):
        w, bid = standard()
        cid = w.challenge_ok(bid, "src/slugify.js")
        w.judge(cid)                                          # ATTRIBUTION_MISSING
        w.call(PROJ, "contest", cid, value=int(w.c.contest_bond_wei))
        w.gh.fail(raw("acme/app", SHA_B, "LICENSE"), 404)
        w.gh.fail(raw("ada/slugify", SHA_O, "index.js"), 404)
        w.judge(cid)
        w.advance(DAY + 1)
        self.assertEqual(w.call(OUTSIDER, "settle_stalled", cid)["contest"],
                         "LOST_AT_DEADLINE_BONDED_UNREADABLE")
        self.assertEqual(w.owed(CHAL), int(w.c.contest_bond_wei))

    def test_outage_during_contest_is_dropped_not_decided(self):
        w, bid = standard()
        cid = w.challenge_ok(bid, "src/app.js")
        w.judge(cid)
        w.call(CHAL, "contest", cid, value=int(w.c.contest_bond_wei))
        w.gh.fail(raw("acme/app", SHA_B, "LICENSE"), 503)
        w.judge(cid)
        w.advance(DAY + 1)
        self.assertEqual(w.call(OUTSIDER, "settle_stalled", cid)["contest"], "DROPPED_AT_DEADLINE")
        self.assertEqual(w.ch(cid).outcome, "NOT_DERIVED")


class Also_DirectionOfCopying(unittest.TestCase):
    """The original file's commit must be dated before the bonded commit -
    checked only on paths that would pay the challenger."""

    def test_original_newer_than_copy_is_not_derived_no_slash(self):
        w = World()
        w.original(committed=iso(T0 - 3600))                 # original commit: 1 h ago
        bid = w.bond(files={"src/slugify.js": COPY_STRIPPED}, committed=iso(T0 - DAY))
        cid = w.challenge_ok(bid, "src/slugify.js")
        out = w.judge(cid)
        self.assertEqual((out["outcome"], out["reason"]),
                         ("NOT_DERIVED", "ORIGIN_NEWER_THAN_COPY_DIRECTION_UNPROVEN"))
        w.finalize(cid)
        self.assertEqual(int(w.bd(bid).slashed_wei), 0)

    def test_backdated_bonded_commit_cannot_veto(self):
        """The bonded party sets its own commit date. Backdating it to 1990
        would make every original "newer"; the date is floored at the bonded
        repo's GitHub creation time."""
        w = World()
        w.original(committed=iso(T0 - 4 * 365 * DAY))
        bid = w.bond(files={"src/slugify.js": COPY_STRIPPED}, committed="1990-01-01T00:00:00Z",
                     created=iso(T0 - 365 * DAY))
        cid = w.challenge_ok(bid, "src/slugify.js")
        self.assertEqual(w.judge(cid)["outcome"], "ATTRIBUTION_MISSING")

    def test_checked_only_on_paying_paths(self):
        w = World()
        w.original(committed=iso(T0 - 3600))
        bid = w.bond(files={"src/app.js": UNRELATED})
        cid = w.challenge_ok(bid, "src/app.js")
        lg_stub.CALLS.clear()
        self.assertEqual(w.judge(cid)["reason"], "BELOW_SIMILARITY_THRESHOLD")
        self.assertEqual(w.api_calls(), [])


if __name__ == "__main__":
    unittest.main()
