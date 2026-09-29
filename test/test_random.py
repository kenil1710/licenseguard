"""Randomized lifecycles. Each seed is its own test: random bonds, challenges,
judgements (with the model answering YES, NO or failing), transient GitHub
failures, contests from either side, pauses, stalls, finalizations,
withdrawals and claims, in random order and at random times. The ledger
identity is asserted after every call (World.call). At the end everything is
closed out through the public methods only, and the books must be EXACTLY
zero with every wei that came in having gone out."""

import random
import unittest

import lg_stub
from lg_world import (LG, World, OWNER, PROJ, PROJ2, CHAL, CHAL2, TRIGGER, OUTSIDER, SHA_B,
                      SHA_B2, SHA_O, GEN, ORIGINAL, UNRELATED, COPY_STRIPPED, COPY_ATTRIBUTED,
                      COPY_HOLDER_ONLY, PROJ_LICENSE, raw, compare_url, API, addr)

PROJ3 = addr("7")
PROJECTS = [(PROJ, "acme/app", SHA_B), (PROJ2, "beta/lib", SHA_B2), (PROJ3, "gamma/tool", "d" * 40)]
CHALLENGERS = [CHAL, CHAL2, OUTSIDER]
PATHS = ["src/stripped.js", "src/attributed.js", "src/app.js", "src/holder.js", "src/none.js"]
FILES = {"src/stripped.js": COPY_STRIPPED, "src/attributed.js": COPY_ATTRIBUTED,
         "src/app.js": UNRELATED, "src/holder.js": COPY_HOLDER_ONLY}
ORIGINALS = [("ada/slugify", SHA_O, "index.js"), ("ada/slugify", SHA_O, "missing.js")]
FLAKY = [raw("ada/slugify", SHA_O, "index.js"), raw("acme/app", SHA_B, "LICENSE"),
         API + "ada/slugify", compare_url("ada/slugify", SHA_O)]
DAY = 86400


def lifecycle(seed: int, steps: int = 160):
    rng = random.Random(seed)
    w = World(challenge_window_s=rng.choice([600, 3600, 3 * DAY]),
              unbond_delay_s=rng.choice([0, 300, DAY]),
              contest_window_s=rng.choice([120, 900, DAY]),
              deadline_s=rng.choice([300, 1800, DAY]),
              challenge_bond_wei=rng.choice([GEN // 10, GEN // 5, GEN]),
              contest_bond_wei=rng.choice([GEN // 100, GEN // 10]))
    w.original()
    for owner, repo, sha in PROJECTS:
        w.bonded_repo(repo=repo, sha=sha, owner=owner, files=FILES)
    actors = [p for p, _r, _s in PROJECTS] + CHALLENGERS
    bonds = []

    def model():
        r = rng.random()
        if r < 0.45:
            lg_stub.MODEL.serve("YES")
        elif r < 0.85:
            lg_stub.MODEL.serve("NO", rng.choice(["COPYRIGHT_NOTICE", "LICENSE_TEXT", "NOTICE_FILE"]))
        else:
            lg_stub.MODEL.fail(2)

    def flake():
        for u in FLAKY:
            lg_stub.WEB.pop(u, None) if False else None
        if rng.random() < 0.15:
            u = rng.choice(FLAKY)
            lg_stub.SEQ[u] = [(rng.choice([0, 403, 404, 404, 429, 500, 503]), "x")] * rng.choice([1, 2, 4])

    def live(*states):
        ids = [i + 1 for i, c in enumerate(w.c.challenges) if c.status in states]
        if ids and rng.random() < 0.85:
            return rng.choice(ids)
        return rng.randint(1, len(w.c.challenges))

    for _ in range(steps):
        op = rng.random()
        flake()
        if op < 0.10:
            owner, repo, sha = rng.choice(PROJECTS)
            out = w.call(owner, "post_bond", repo, sha, "MIT", value=rng.choice([GEN - 1, GEN, 2 * GEN]))
            if out["status"] == "OK":
                bonds.append(out["bond_id"])
                if rng.random() < 0.8:
                    w.call(TRIGGER, "verify_bond", out["bond_id"])
        elif op < 0.14 and len(w.c.challenges) > 0:
            model()
            w.call(TRIGGER, "judge", len(w.c.challenges))   # the newest, promptly
        elif op < 0.18 and bonds:
            w.call(TRIGGER, "verify_bond", rng.choice(bonds))
        elif op < 0.40 and bonds:
            bid = rng.choice(bonds)
            orig = ORIGINALS[0] if rng.random() < 0.85 else ORIGINALS[1]
            w.call(rng.choice(CHALLENGERS), "challenge", bid, orig[0], orig[1], orig[2],
                   rng.choice(PATHS), rng.choice(["MIT", "MIT", "MIT", "GPL_3"]),
                   value=rng.choice([int(w.c.challenge_bond_wei), int(w.c.challenge_bond_wei) + 7, 1]))
        elif op < 0.52 and len(w.c.challenges) > 0:
            model()
            w.call(rng.choice(actors), "judge", live("FILED", "CONTESTED"))
        elif op < 0.60 and len(w.c.challenges) > 0:
            cid = live("PROVISIONAL")
            c = w.ch(cid)
            who = rng.choice([c.challenger.as_hex, w.bd(int(c.bond_id)).owner.as_hex, OUTSIDER])
            w.call(who, "contest", cid, value=rng.choice([int(w.c.contest_bond_wei), 0]))
        elif op < 0.68 and len(w.c.challenges) > 0:
            w.call(TRIGGER, "finalize", live("PROVISIONAL"))
        elif op < 0.73 and len(w.c.challenges) > 0:
            w.call(TRIGGER, "settle_stalled", rng.randint(1, len(w.c.challenges)))
        elif op < 0.76 and bonds:
            w.call(TRIGGER, "settle_stalled_bond", rng.choice(bonds))
        elif op < 0.80 and bonds:
            bid = rng.choice(bonds)
            w.call(rng.choice([w.bd(bid).owner.as_hex, OUTSIDER]), "withdraw_bond", bid)
        elif op < 0.86:
            w.call(rng.choice(actors), "claim")
        elif op < 0.89:
            w.call(OWNER, "set_paused", rng.random() < 0.5)
        elif op < 0.92:
            _o, repo, sha = rng.choice(PROJECTS)             # a bonded repo goes private / comes back
            url = raw(repo, sha, "LICENSE")
            lg_stub.WEB[url] = (404, "404: Not Found") if rng.random() < 0.6 else (200, PROJ_LICENSE)
        else:
            w.advance(rng.choice([30, 200, 700, 3000, DAY // 2, DAY + 5]))

    # --- close everything out, through public methods only ---------------------
    lg_stub.SEQ.clear()
    lg_stub.MODEL.serve("YES")
    for _o, repo, sha in PROJECTS:
        lg_stub.WEB[raw(repo, sha, "LICENSE")] = (200, PROJ_LICENSE)
    for _round in range(6):
        w.advance(4 * DAY)
        for i in range(1, len(w.c.bonds) + 1):
            if w.bd(i).status == "PENDING":
                w.call(TRIGGER, "settle_stalled_bond", i)
        for cid in range(1, len(w.c.challenges) + 1):
            st = w.ch(cid).status
            if st in ("FILED", "CONTESTED"):
                w.call(TRIGGER, "settle_stalled", cid)
            if w.ch(cid).status == "PROVISIONAL":
                w.advance(max(0, int(w.ch(cid).contest_until) - w.t + 1))
                w.call(TRIGGER, "finalize", cid)
        for i in range(1, len(w.c.bonds) + 1):
            b = w.bd(i)
            if b.status in ("ACTIVE", "NON_COMPLIANT"):
                w.call(b.owner.as_hex, "withdraw_bond", i)
    for a in actors + [TRIGGER, OWNER]:
        if w.owed(a) > 0:
            w.call(a, "claim")
    return w


class TestRandomLifecyclesDrainToZero(unittest.TestCase):
    def check_closed(self, w):
        for c in w.c.challenges:
            self.assertEqual(c.status, "FINAL")
            self.assertIn(c.outcome, LG.OUTCOMES)
            self.assertEqual(int(c.bond_wei), 0)
            self.assertEqual(int(c.contest_bond_wei), 0)
            stake = int(w.c.challenge_bond_wei)
            self.assertEqual(int(c.paid_challenger_wei) + int(c.paid_project_wei),
                             stake + int(c.slash_wei))
            if int(c.judged_at) > 0:
                self.assertTrue(w.view("verify_challenge", int(c.challenge_id))["consistent"])
        for b in w.c.bonds:
            self.assertIn(b.status, ("WITHDRAWN", "REJECTED"))
            self.assertEqual(int(b.remaining_wei), 0)
            self.assertEqual(int(b.open_challenges), 0)
        self.assertEqual(int(w.c.balance_wei), 0)
        self.assertEqual(int(w.c.held_wei), 0)
        self.assertEqual(int(w.c.payable_wei), 0)
        self.assertEqual(sum(v for _a, v in lg_stub.TRANSFERS), w.received)
        self.assertTrue(w.view("get_stats")["books_zero"])


for _seed in range(90):
    def _t(self, seed=_seed):
        self.check_closed(lifecycle(seed))
    _t.__name__ = "test_seed_%03d" % _seed
    setattr(TestRandomLifecyclesDrainToZero, _t.__name__, _t)


class TestRandomCoverage(unittest.TestCase):
    """The random lifecycles are only worth something if they reach every
    outcome and every exit. Measured over the same seeds."""

    @classmethod
    def setUpClass(cls):
        cls.outcomes = set()
        cls.reasons = set()
        cls.contests = set()
        cls.bond_states = set()
        for seed in range(90):
            w = lifecycle(seed)
            for c in w.c.challenges:
                cls.outcomes.add(c.outcome)
                cls.reasons.add(c.reason)
                for piece in str(c.contest_log).split("; "):
                    if piece:
                        cls.contests.add(piece.split(":")[-1])
            for b in w.c.bonds:
                cls.bond_states.add(b.verify_reason)
                if b.found_non_compliant:
                    cls.bond_states.add("NON_COMPLIANT")

    def test_all_four_outcomes_reached(self):
        self.assertEqual(self.outcomes, set(LG.OUTCOMES))

    def test_deadline_exit_reached(self):
        self.assertTrue(any(r.startswith("DEADLINE_PASSED") for r in self.reasons))

    def test_forfeit_reached(self):
        self.assertIn("FORFEIT_BONDED_COMMIT_WITHDRAWN", self.reasons)

    def test_pinned_missing_reached(self):
        self.assertIn("NO_ATTRIBUTION_FOUND", self.reasons)

    def test_model_both_ways(self):
        self.assertIn("ATTRIBUTION_MEETS_LICENSE", self.reasons)
        self.assertTrue(any(r.startswith("ATTRIBUTION_INSUFFICIENT") for r in self.reasons))

    def test_contests_held_and_dropped(self):
        self.assertIn("HELD", self.contests)
        self.assertIn("DROPPED_AT_DEADLINE", self.contests)

    def test_bonds_verified_and_stalled_and_slashed(self):
        self.assertIn("VERIFIED", self.bond_states)
        self.assertIn("NON_COMPLIANT", self.bond_states)


if __name__ == "__main__":
    unittest.main()
