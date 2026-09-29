"""LicenseGuard offline suite.

    cd test && python3 -m unittest -q test_logic test_threats test_random

Every public call goes through `World.call`, which asserts the ledger
identity (balance == held + payable, held == bonds + challenge stakes,
books == value in - value out) after EVERY call.
"""

import ast
import json
import unittest

import lg_stub
from lg_world import (LG, SRC, World, GitHub, standard, OWNER, PROJ, PROJ2, CHAL, CHAL2,
                      TRIGGER, OUTSIDER, SHA_B, SHA_B2, SHA_O, SHA_FORK, T0, GEN, iso,
                      ORIGINAL, UNRELATED, COPY_STRIPPED, COPY_ATTRIBUTED, COPY_HOLDER_ONLY,
                      ORIG_LICENSE, PROJ_LICENSE, mit, raw, compare_url, API)


def _add_cases(cls, prefix, cases, fn):
    """Generate one test method per case, so every case counts and fails alone."""
    for i, case in enumerate(cases):
        def t(self, case=case):
            fn(self, *case) if isinstance(case, tuple) else fn(self, case)
        t.__name__ = "test_%s_%02d" % (prefix, i)
        setattr(cls, t.__name__, t)


# =============================================================================
# pure functions
# =============================================================================


class TestRepoNames(unittest.TestCase):
    pass


_add_cases(TestRepoNames, "valid", [
    "sindresorhus/slugify", "a/b", "Owner-1/repo.name_2", "x/.github-x", "lodash/lodash",
    "o/" + "r" * 100, "o" * 39 + "/r",
], lambda self, r: self.assertEqual(LG._norm_repo(r), (r, "")))

_add_cases(TestRepoNames, "invalid", [
    "", "   ", "noslash", "a/b/c", "/b", "a/", "https://github.com/a/b", "a b/c", "a/b c",
    "a/..", "a/.", "o" * 40 + "/r", "o/" + "r" * 101, "a_b/c", "a/b?x=1", "a/b#frag",
    "a/b\nc", "ä/b", None,
], lambda self, r: self.assertNotEqual(LG._norm_repo(r)[1], ""))


class TestPaths(unittest.TestCase):
    pass


_add_cases(TestPaths, "valid", [
    "index.js", "src/a.js", "vendor/lib/x.min.js", "a+b@c.txt", "LICENSE", ".licenseguard",
    "deep/" * 10 + "f.py",
], lambda self, p: self.assertEqual(LG._norm_path(p), (p, "")))

# Threat 1's mechanical half: nothing that could leave the repository/commit.
_add_cases(TestPaths, "invalid", [
    "", "/etc/passwd", "../other/file.js", "a/../../b", "a//b", "./a", "a/./b",
    "https://raw.githubusercontent.com/x/y/" + SHA_O + "/f", "a b.js", "a?raw=1", "a#L1",
    "a%2e%2e/b", "a\\b", "a/b/", "x" * 301, "C:/x", "~/x", "a\nb", None,
], lambda self, p: self.assertNotEqual(LG._norm_path(p)[1], ""))


class TestShaAndLicenses(unittest.TestCase):
    def test_sha_valid(self):
        self.assertTrue(LG._is_sha("0123456789abcdef" * 2 + "01234567"))

    def test_sha_short(self):
        self.assertFalse(LG._is_sha("a" * 39))

    def test_sha_long(self):
        self.assertFalse(LG._is_sha("a" * 41))

    def test_sha_upper_rejected_raw(self):
        self.assertFalse(LG._is_sha("A" * 40))

    def test_sha_non_hex(self):
        self.assertFalse(LG._is_sha("g" * 40))

    def test_sha_branch_name(self):
        self.assertFalse(LG._is_sha("main"))

    def test_licenses_single(self):
        self.assertEqual(LG._parse_licenses("MIT"), (["MIT"], ""))

    def test_licenses_multi_sorted_unique(self):
        self.assertEqual(LG._parse_licenses("mit, GPL_3,MIT"), (["GPL_3", "MIT"], ""))

    def test_licenses_empty(self):
        self.assertNotEqual(LG._parse_licenses("")[1], "")

    def test_licenses_unknown(self):
        self.assertNotEqual(LG._parse_licenses("MIT,WTFPL")[1], "")

    def test_licenses_spdx_spelling_not_vocab(self):
        self.assertNotEqual(LG._parse_licenses("Apache-2.0")[1], "")


APACHE = """
                                 Apache License
                           Version 2.0, January 2004
                        http://www.apache.org/licenses/

   TERMS AND CONDITIONS FOR USE, REPRODUCTION, AND DISTRIBUTION
   ...
   APPENDIX: How to apply the Apache License to your work.
      Copyright [yyyy] [name of copyright owner]
"""
BSD3 = """Copyright (c) 2015, Jane Roe
All rights reserved.

Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:
1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.
3. Neither the name of the copyright holder nor the names of its contributors may be used to endorse or promote products derived from this software without specific prior written permission.
THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
"""
BSD2 = """Copyright (c) 2015, Jane Roe
Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:
1. Redistributions of source code must retain the above copyright notice.
"""
GPL3 = """                    GNU GENERAL PUBLIC LICENSE
                       Version 3, 29 June 2007

 Copyright (C) 2007 Free Software Foundation, Inc. <https://fsf.org/>
 ...
    <one line to give the program's name and a brief idea of what it does.>
    Copyright (C) <year>  <name of author>
 ... use the GNU Lesser General Public License instead of this License.
 ... Use with the GNU Affero General Public License.
"""
GPL2 = """                    GNU GENERAL PUBLIC LICENSE
                       Version 2, June 1991
"""
LGPL3 = """                   GNU LESSER GENERAL PUBLIC LICENSE
                       Version 3, 29 June 2007
  This version of the GNU Lesser General Public License incorporates
the terms and conditions of version 3 of the GNU General Public
License, supplemented by the additional permissions listed below.
"""
AGPL3 = """                    GNU AFFERO GENERAL PUBLIC LICENSE
                       Version 3, 19 November 2007
"""
GPL_HEADER = """# Copyright (C) 2019 Jo Bloggs
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
"""
APACHE_HEADER = """// Copyright 2020 The Widget Authors
// Licensed under the Apache License, Version 2.0 (the "License");
"""
ISC = """ISC License
Copyright (c) 2004 Someone
Permission to use, copy, modify, and/or distribute this software for any purpose with or without fee is hereby granted
"""


class TestLicenseDetection(unittest.TestCase):
    pass


_add_cases(TestLicenseDetection, "kinds", [
    (ORIG_LICENSE, ["MIT"]), (APACHE, ["APACHE_2"]), (BSD3, ["BSD_3"]), (BSD2, []),
    (GPL3, ["GPL_3"]), (GPL2, []), (LGPL3, []), (AGPL3, []), (GPL_HEADER, ["GPL_3"]),
    (APACHE_HEADER, ["APACHE_2"]), (ISC, []), ("", []),
    ("// SPDX-License-Identifier: MIT\nconst x = 1;", ["MIT"]),
    ("/* SPDX-License-Identifier: Apache-2.0 */", ["APACHE_2"]),
    ("# SPDX-License-Identifier: GPL-3.0-or-later", ["GPL_3"]),
    ("// SPDX-License-Identifier: BSD-3-Clause", ["BSD_3"]),
    ("// SPDX-License-Identifier: MIT OR Apache-2.0", ["APACHE_2", "MIT"]),
    ("// SPDX-License-Identifier: GPL-2.0-only", []),
    (ORIG_LICENSE + "\n" + APACHE, ["APACHE_2", "MIT"]),
], lambda self, text, want: self.assertEqual(LG._license_kinds(text), want))


class TestCopyrightNotices(unittest.TestCase):
    pass


_add_cases(TestCopyrightNotices, "holder", [
    ("Copyright (c) Sindre Sorhus <sindresorhus@gmail.com> (https://sindresorhus.com)",
     "sindre sorhus"),
    ("Copyright (c) 2009-2014 TJ Holowaychuk <tj@vision-media.ca>", "tj holowaychuk"),
    ("Copyright 2010-2016 Mike Bostock", "mike bostock"),
    ("Copyright OpenJS Foundation and other contributors <https://openjsf.org/>",
     "openjs foundation and other contributors"),
    (" * Copyright © 2021 Ümit Kaya. All rights reserved.", "ümit kaya"),
    ("© 2018 Acme Corp", "acme corp"),
    ("// Copyright 2020 The Widget Authors", "the widget authors"),
    ("Copyright (c) 2015, Jane Roe", "jane roe"),
    ("Copyright (c) 2024", ""),
    ("Copyright (c) 12", ""),
], lambda self, line, want: self.assertEqual(LG._holder_of(line), want))

_add_cases(TestCopyrightNotices, "is_notice", [
    ("Copyright (c) Ada Lovelace", True),
    ("Copyright 2019 Ada Lovelace", True),
    ("Copyright Ada Lovelace", True),
    ("The above copyright notice and this permission notice shall be included", False),
    ("IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE", False),
    ("Copyright [yyyy] [name of copyright owner]", False),
    ("Copyright (C) 2007 Free Software Foundation, Inc. <https://fsf.org/>", False),
    ("    Copyright (C) <year>  <name of author>", False),
    ("Copyright (c) <year> <copyright holders>", False),
    ("under copyright law, this is protected", False),
    ("THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS", False),
    ("# Copyright (C) 2019 Jo Bloggs", True),
    ("the copyright owner may", False),
], lambda self, line, want: self.assertEqual(len(LG._copyright_lines(line)) == 1, want))


class TestCopyrightInLicenses(unittest.TestCase):
    def test_mit_file_one_notice(self):
        self.assertEqual(LG._holders(LG._notice_lines_raw(ORIG_LICENSE)), ["ada lovelace"])

    def test_gpl_text_has_no_notice(self):
        self.assertEqual(LG._copyright_lines(GPL3), [])

    def test_apache_text_has_no_notice(self):
        self.assertEqual(LG._copyright_lines(APACHE), [])

    def test_bsd_text_one_notice(self):
        self.assertEqual(LG._holders(LG._notice_lines_raw(BSD3)), ["jane roe"])

    def test_unique_lines(self):
        t = "Copyright (c) Ada\nCopyright (c) Ada\n"
        self.assertEqual(len(LG._copyright_lines(t)), 1)

    def test_two_holders(self):
        t = "Copyright (c) 2019 Ada Lovelace\nCopyright (c) 2020 Grace Hopper\n"
        self.assertEqual(LG._holders(LG._notice_lines_raw(t)), ["ada lovelace", "grace hopper"])


class TestTokensAndSimilarity(unittest.TestCase):
    def sim(self, a, b):
        sa = LG._shingles(LG._code_tokens(a))
        sb = LG._shingles(LG._code_tokens(b))
        return LG._similarity_bps(len(sa), len(sb), len(sa & sb))

    def test_identical_is_10000(self):
        self.assertEqual(self.sim(ORIGINAL, ORIGINAL), 10000)

    def test_header_added_still_derived(self):
        self.assertGreaterEqual(self.sim(ORIGINAL, COPY_ATTRIBUTED), LG.DERIVED_BPS)

    def test_header_comments_ignored_entirely(self):
        self.assertEqual(self.sim(ORIGINAL, COPY_ATTRIBUTED), 10000)

    def test_unrelated_low(self):
        self.assertLess(self.sim(ORIGINAL, UNRELATED), 1000)

    def test_whitespace_and_case_insensitive(self):
        mangled = "\n".join("   " + line.upper() for line in ORIGINAL.split("\n"))
        self.assertEqual(self.sim(ORIGINAL, mangled), 10000)

    def test_part_copied_into_bigger_file(self):
        part = ORIGINAL[:len(ORIGINAL) // 2]
        self.assertGreaterEqual(self.sim(part, UNRELATED + "\n" + part), LG.DERIVED_BPS)

    def test_whole_copied_into_bigger_file(self):
        self.assertGreaterEqual(self.sim(ORIGINAL, ORIGINAL + UNRELATED * 3), LG.DERIVED_BPS)

    def test_light_rename_still_derived(self):
        renamed = ORIGINAL
        for a, b in (("string", "s"), ("options", "o"), ("separator", "sep")):
            renamed = b.join(renamed.split(a))
        self.assertGreaterEqual(self.sim(ORIGINAL, renamed), LG.DERIVED_BPS)

    def test_heavy_rewrite_is_missed(self):
        """The honest limit: rename every identifier and the measure no longer
        sees a copy (README, "Honest limits")."""
        import re
        heavy = ORIGINAL
        for t in sorted(set(re.findall(r"[A-Za-z_][A-Za-z0-9_]*", ORIGINAL)), key=len, reverse=True):
            heavy = re.sub(r"\b%s\b" % t, t + "Q", heavy)
        self.assertLess(self.sim(ORIGINAL, heavy), LG.DERIVED_BPS)

    def test_comment_lines_skipped(self):
        self.assertEqual(LG._code_tokens("// a b c\n# x\n/* y\n * z\n */\nq = 1"), ["q", "=", "1"])

    def test_punctuation_tokens(self):
        self.assertEqual(LG._code_tokens("f(a,b);"), ["f", "(", "a", ",", "b", ")", ";"])

    def test_shingles_short(self):
        self.assertEqual(LG._shingles(["a", "b", "c"]), set())

    def test_shingles_count(self):
        self.assertEqual(len(LG._shingles(list("abcdefg"))), 3)

    def test_similarity_zero_sizes(self):
        self.assertEqual(LG._similarity_bps(0, 10, 0), 0)

    def test_similarity_either_direction(self):
        self.assertEqual(LG._similarity_bps(100, 1000, 100), 10000)

    def test_similarity_floor(self):
        self.assertEqual(LG._similarity_bps(3, 3, 1), 3333)


class TestSmallPure(unittest.TestCase):
    def test_words_copyright_sign(self):
        self.assertEqual(LG._words("© 2020 A-B"), "c 2020 a b")

    def test_words_collapse(self):
        self.assertEqual(LG._words("  Hello,   World!! "), "hello world")

    def test_contains_words_boundary(self):
        self.assertFalse(LG._contains_words("adam lovelaces", "ada lovelace"))

    def test_contains_words_hit(self):
        self.assertTrue(LG._contains_words("by ada lovelace 2020", "ada lovelace"))

    def test_contains_words_empty(self):
        self.assertFalse(LG._contains_words("x", ""))

    def test_decode_ok(self):
        self.assertEqual(LG._decode(b"abc"), ("abc", "OK"))

    def test_decode_binary(self):
        self.assertEqual(LG._decode(b"a\x00b")[1], "BINARY")

    def test_decode_too_large(self):
        self.assertEqual(LG._decode(b"a" * (LG.MAX_FILE_BYTES + 1))[1], "TOO_LARGE")

    def test_decode_at_limit(self):
        self.assertEqual(LG._decode(b"a" * LG.MAX_FILE_BYTES)[1], "OK")

    def test_epoch(self):
        self.assertEqual(LG._epoch_from_iso("2026-09-29T12:00:00Z"), T0)

    def test_epoch_bad(self):
        self.assertEqual(LG._epoch_from_iso("yesterday"), 0)

    def test_epoch_roundtrip(self):
        for e in (0, 86399, 951782400, 1790683200, 4102444800):
            self.assertEqual(LG._epoch_from_iso(iso(e)), e)

    def test_history_fact(self):
        self.assertEqual(LG._history_fact(json.dumps({"status": "identical", "behind_by": 0}).encode()),
                         "identical behind_by=0")

    def test_history_fact_junk(self):
        self.assertEqual(LG._history_fact(b"<html>"), "UNPARSEABLE")

    def test_history_fact_bool_behind(self):
        self.assertEqual(LG._history_fact(b'{"status":"ahead","behind_by":false}'), "UNPARSEABLE")

    def test_history_of(self):
        self.assertEqual(LG._history_of("identical behind_by=0"), "OK")
        self.assertEqual(LG._history_of("ahead behind_by=0"), "OK")
        self.assertEqual(LG._history_of("diverged behind_by=2"), "NOT_IN_HISTORY")
        self.assertEqual(LG._history_of("behind behind_by=3"), "NOT_IN_HISTORY")
        self.assertEqual(LG._history_of(""), "UNPARSEABLE")

    def test_created_fact(self):
        self.assertEqual(LG._created_fact(b'{"created_at":"2018-04-18T15:34:47Z","stars":3}'),
                         "2018-04-18T15:34:47Z")
        self.assertEqual(LG._created_fact(b'{"created_at":"soon"}'), "")

    def test_gen(self):
        self.assertEqual(LG._gen(GEN + GEN // 5), "1.2")
        self.assertEqual(LG._gen(0), "0.0")

    def test_as_int_bool_is_default(self):
        self.assertEqual(LG._as_int(True, 7), 7)

    def test_as_int_str(self):
        self.assertEqual(LG._as_int(" 12 ", 0), 12)
        self.assertEqual(LG._as_int("-3", 0), -3)
        self.assertEqual(LG._as_int("1e3", 5), 5)

    def test_pair_key_ignores_sha_and_license(self):
        self.assertEqual(LG._pair_key(1, "Ada/Slugify", "index.js", "src/x.js"),
                         LG._pair_key(1, "ada/slugify", "index.js", "src/x.js"))

    def test_dir_of(self):
        self.assertEqual(LG._dir_of("a/b/c.js"), "a/b")
        self.assertEqual(LG._dir_of("c.js"), "")


class TestModelAnswer(unittest.TestCase):
    pass


_add_cases(TestModelAnswer, "valid", [
    ({"meets_requirement": "YES", "missing": "NONE"}, ("YES", "NONE")),
    ({"meets_requirement": "no", "missing": "copyright_notice"}, ("NO", "COPYRIGHT_NOTICE")),
    ({"meets_requirement": "NO", "missing": "LICENSE_TEXT"}, ("NO", "LICENSE_TEXT")),
    ({"meets_requirement": "NO", "missing": "NOTICE_FILE"}, ("NO", "NOTICE_FILE")),
    ('```json\n{"meets_requirement": "YES", "missing": "NONE"}\n```', ("YES", "NONE")),
], lambda self, raw, want: self.assertEqual(LG._model_answer(raw), want))

_add_cases(TestModelAnswer, "invalid", [
    {"meets_requirement": "YES", "missing": "LICENSE_TEXT"},
    {"meets_requirement": "NO", "missing": "NONE"},
    {"meets_requirement": "MAYBE", "missing": "NONE"},
    {"meets_requirement": "YES"},
    {"verdict": "COMPLIANT"},
    {"meets_requirement": "NO", "missing": "EVERYTHING"},
    "not json", 42, None, [],
    {"meets_requirement": True, "missing": "NONE"},
], lambda self, raw: self.assertIsNone(LG._model_answer(raw)))


# =============================================================================
# the outcome table: _decide over vectors
# =============================================================================


def vec(**over):
    v = {"original_file": "OK", "copied_file": "OK", "shingles_original": 500,
         "shingles_copied": 500, "shingles_common": 500, "similarity_bps": 10000,
         "licenses_found": "MIT", "holders": "ada lovelace", "holder_in_copy": False,
         "holder_in_notices": False, "meets": "", "missing": "", "origin": "OK"}
    v.update(over)
    return v


class TestDecide(unittest.TestCase):
    pass


_add_cases(TestDecide, "table", [
    (vec(), ("ATTRIBUTION_MISSING", "NO_ATTRIBUTION_FOUND")),
    (vec(original_file="MISSING"), ("NOT_DERIVED", "ORIGINAL_FILE_MISSING")),
    (vec(copied_file="MISSING"), ("NOT_DERIVED", "COPIED_FILE_MISSING")),
    (vec(copied_file="TOO_LARGE"), ("INCONCLUSIVE", "FILE_UNREADABLE")),
    (vec(original_file="BINARY"), ("INCONCLUSIVE", "FILE_UNREADABLE")),
    (vec(shingles_original=39), ("INCONCLUSIVE", "TOO_SMALL_TO_MEASURE")),
    (vec(shingles_copied=39), ("INCONCLUSIVE", "TOO_SMALL_TO_MEASURE")),
    (vec(similarity_bps=4999), ("NOT_DERIVED", "BELOW_SIMILARITY_THRESHOLD")),
    (vec(similarity_bps=5000), ("ATTRIBUTION_MISSING", "NO_ATTRIBUTION_FOUND")),
    (vec(licenses_found="APACHE_2"), ("INCONCLUSIVE", "LICENSE_NOT_CONFIRMED")),
    (vec(licenses_found=""), ("INCONCLUSIVE", "LICENSE_NOT_CONFIRMED")),
    (vec(holders=""), ("INCONCLUSIVE", "NO_COPYRIGHT_NOTICE_IN_ORIGINAL")),
    (vec(holder_in_copy=True, meets="YES", missing="NONE"), ("COMPLIANT", "ATTRIBUTION_MEETS_LICENSE")),
    (vec(holder_in_notices=True, meets="YES", missing="NONE"), ("COMPLIANT", "ATTRIBUTION_MEETS_LICENSE")),
    (vec(holder_in_copy=True, meets="NO", missing="LICENSE_TEXT"),
     ("ATTRIBUTION_MISSING", "ATTRIBUTION_INSUFFICIENT_LICENSE_TEXT")),
    (vec(holder_in_copy=True, meets="", missing=""), ("INCONCLUSIVE", "NO_READING")),
    (vec(holder_in_copy=True, meets="YES", missing="LICENSE_TEXT"), ("INCONCLUSIVE", "NO_READING")),
    (vec(origin="NOT_IN_HISTORY"), ("NOT_DERIVED", "ORIGIN_NOT_IN_HISTORY")),
    (vec(origin="AFTER_BOND"), ("NOT_DERIVED", "ORIGIN_CREATED_AFTER_BOND")),
    (vec(origin="UNAVAILABLE"), ("NOT_DERIVED", "ORIGIN_UNAVAILABLE")),
    (vec(origin="UNCHECKED"), ("INCONCLUSIVE", "NO_READING")),
    (vec(holder_in_copy=True, meets="NO", missing="COPYRIGHT_NOTICE", origin="NOT_IN_HISTORY"),
     ("NOT_DERIVED", "ORIGIN_NOT_IN_HISTORY")),
    # the origin never matters unless the challenger would be paid
    (vec(similarity_bps=100, origin="NOT_IN_HISTORY"), ("NOT_DERIVED", "BELOW_SIMILARITY_THRESHOLD")),
    (vec(holder_in_copy=True, meets="YES", missing="NONE", origin="UNCHECKED"),
     ("COMPLIANT", "ATTRIBUTION_MEETS_LICENSE")),
    (vec(licenses_found="MIT,GPL_3"), ("ATTRIBUTION_MISSING", "NO_ATTRIBUTION_FOUND")),
], lambda self, v, want: self.assertEqual(LG._decide(v, "MIT"), want))


class TestModelIsTheLastStepOnly(unittest.TestCase):
    """The model's answer can change the outcome only between COMPLIANT and
    ATTRIBUTION_MISSING, and only after every file gate passed."""

    def test_model_fields_cannot_rescue_missing_attribution(self):
        self.assertEqual(LG._decide(vec(meets="YES", missing="NONE"), "MIT")[0],
                         "ATTRIBUTION_MISSING")

    def test_model_fields_cannot_make_underived_pay(self):
        self.assertEqual(LG._decide(vec(similarity_bps=10, holder_in_copy=True, meets="NO",
                                        missing="LICENSE_TEXT"), "MIT")[0], "NOT_DERIVED")

    def test_needs_model_only_with_trace(self):
        self.assertFalse(LG._needs_model(vec(), "MIT"))
        self.assertTrue(LG._needs_model(vec(holder_in_copy=True), "MIT"))

    def test_every_model_answer_maps_to_two_outcomes(self):
        outs = set()
        for m in LG.MEETS:
            for x in LG.MISSING:
                outs.add(LG._decide(vec(holder_in_copy=True, meets=m, missing=x), "MIT")[0])
        self.assertEqual(outs, {"COMPLIANT", "ATTRIBUTION_MISSING", "INCONCLUSIVE"})


# =============================================================================
# bonds
# =============================================================================


class TestPostBond(unittest.TestCase):
    def setUp(self):
        self.w = World()

    def post(self, *a, value=GEN, who=PROJ):
        return self.w.call(who, "post_bond", *a, value=value)

    def test_ok_pending(self):
        out = self.post("acme/app", SHA_B, "MIT")
        self.assertEqual(out["bond_status"], "PENDING")
        self.assertEqual(int(self.w.c.held_wei), GEN)

    def test_sha_lowercased(self):
        out = self.post("acme/app", "B" * 40, "MIT")
        self.assertEqual(self.w.bd(out["bond_id"]).commit_sha, "b" * 40)

    def test_bad_sha_refunded(self):
        out = self.post("acme/app", "main", "MIT")
        self.assertEqual(out["status"], "REJECTED")
        self.assertEqual(self.w.owed(PROJ), GEN)

    def test_short_sha(self):
        self.assertEqual(self.post("acme/app", "b" * 7, "MIT")["status"], "REJECTED")

    def test_bad_repo(self):
        self.assertEqual(self.post("https://github.com/acme/app", SHA_B, "MIT")["status"], "REJECTED")

    def test_bad_license(self):
        self.assertEqual(self.post("acme/app", SHA_B, "WTFPL")["status"], "REJECTED")

    def test_missing_license(self):
        self.assertEqual(self.post("acme/app", SHA_B, "")["status"], "REJECTED")

    def test_below_minimum(self):
        out = self.post("acme/app", SHA_B, "MIT", value=GEN - 1)
        self.assertEqual(out["status"], "REJECTED")
        self.assertEqual(self.w.owed(PROJ), GEN - 1)

    def test_zero_value(self):
        self.assertEqual(self.post("acme/app", SHA_B, "MIT", value=0)["status"], "REJECTED")

    def test_one_bond_per_repo(self):
        self.post("acme/app", SHA_B, "MIT")
        out = self.post("ACME/App", SHA_B2, "MIT", who=PROJ2)
        self.assertEqual(out["status"], "REJECTED")
        self.assertEqual(self.w.owed(PROJ2), GEN)

    def test_other_repo_ok(self):
        self.post("acme/app", SHA_B, "MIT")
        self.assertEqual(self.post("acme/other", SHA_B, "MIT")["status"], "OK")

    def test_whole_value_is_bond(self):
        out = self.post("acme/app", SHA_B, "MIT", value=3 * GEN)
        self.assertEqual(int(self.w.bd(out["bond_id"]).amount_wei), 3 * GEN)
        self.assertEqual(self.w.owed(PROJ), 0)

    def test_paused(self):
        self.w.call(OWNER, "set_paused", True)
        out = self.post("acme/app", SHA_B, "MIT")
        self.assertEqual(out["status"], "REJECTED")
        self.assertEqual(self.w.owed(PROJ), GEN)

    def test_no_counter_moves_on_refusal(self):
        self.post("acme/app", "nope", "MIT")
        self.assertEqual(int(self.w.c.total_bonds), 0)
        self.assertEqual(len(self.w.c.bonds), 0)

    def test_not_compliant_while_pending(self):
        self.post("acme/app", SHA_B, "MIT")
        self.assertFalse(self.w.view("is_compliant", "acme/app"))


class TestVerifyBond(unittest.TestCase):
    def setUp(self):
        self.w = World()

    def post(self, repo="acme/app", sha=SHA_B, who=PROJ):
        out = self.w.call(who, "post_bond", repo, sha, "MIT", value=GEN)
        self.assertEqual(out["status"], "OK", out)
        return out["bond_id"]

    def verify(self, bid):
        return self.w.call(TRIGGER, "verify_bond", bid)

    def test_active(self):
        self.w.bonded_repo()
        bid = self.post()
        out = self.verify(bid)
        self.assertEqual(out["outcome"], "ACTIVE")
        b = self.w.bd(bid)
        self.assertEqual(b.license_path, "LICENSE")
        self.assertEqual(b.license_kinds, "MIT")
        self.assertEqual(int(b.challenge_until), self.w.t + 30 * 86400)
        self.assertTrue(self.w.view("is_compliant", "acme/app"))

    def test_fork_commit_rejected_and_refunded(self):
        self.w.bonded_repo(history="diverged", behind=2)
        bid = self.post()
        out = self.verify(bid)
        self.assertEqual(out["outcome"], "REJECTED")
        self.assertEqual(self.w.bd(bid).verify_reason, "COMMIT_NOT_IN_DEFAULT_BRANCH_HISTORY")
        self.assertEqual(self.w.owed(PROJ), GEN)
        self.assertEqual(int(self.w.c.held_wei), 0)

    def test_unknown_commit(self):
        self.w.gh.history("acme/app", SHA_B, http=404)
        bid = self.post()
        self.assertEqual(self.verify(bid)["reason"], "COMMIT_NOT_FOUND")

    def test_422_commit(self):
        self.w.gh.history("acme/app", SHA_B, http=422)
        bid = self.post()
        self.assertEqual(self.verify(bid)["reason"], "COMMIT_NOT_FOUND")

    def test_no_marker(self):
        self.w.bonded_repo(marker=False)
        bid = self.post()
        self.assertEqual(self.verify(bid)["reason"], "NO_LICENSEGUARD_FILE")

    def test_marker_names_someone_else(self):
        self.w.bonded_repo(owner=PROJ2)
        bid = self.post(who=PROJ)
        self.assertEqual(self.verify(bid)["reason"], "LICENSEGUARD_FILE_DOES_NOT_NAME_BONDER")

    def test_no_license_file(self):
        self.w.bonded_repo(license_text=None)
        bid = self.post()
        self.assertEqual(self.verify(bid)["reason"], "NO_LICENSE_FILE")

    def test_license_alt_name(self):
        self.w.bonded_repo(license_path="COPYING")
        bid = self.post()
        self.verify(bid)
        self.assertEqual(self.w.bd(bid).license_path, "COPYING")

    def test_rejected_frees_repo(self):
        self.w.bonded_repo(marker=False)
        bid = self.post()
        self.verify(bid)
        self.w.bonded_repo(sha=SHA_B2)
        self.assertEqual(self.w.call(PROJ, "post_bond", "acme/app", SHA_B2, "MIT", value=GEN)["status"], "OK")

    def test_transient_is_retry(self):
        self.w.bonded_repo()
        self.w.gh.fail(compare_url("acme/app", SHA_B), 503)
        bid = self.post()
        out = self.verify(bid)
        self.assertEqual(out["outcome"], "RETRY")
        self.assertEqual(self.w.bd(bid).status, "PENDING")

    def test_rate_limit_is_retry(self):
        self.w.bonded_repo()
        self.w.gh.fail(compare_url("acme/app", SHA_B), 403)
        bid = self.post()
        self.assertEqual(self.verify(bid)["outcome"], "RETRY")

    def test_retry_then_ok(self):
        self.w.bonded_repo()
        bid = self.post()
        lg_stub.SEQ[raw("acme/app", SHA_B, ".licenseguard")] = [(502, "bad gateway")] * 2
        self.assertEqual(self.verify(bid)["outcome"], "RETRY")
        self.assertEqual(self.verify(bid)["outcome"], "ACTIVE")

    def test_after_deadline_refused(self):
        self.w.bonded_repo()
        bid = self.post()
        self.w.advance(86400 + 1)
        self.assertEqual(self.verify(bid)["status"], "REJECTED")

    def test_settle_stalled_bond(self):
        bid = self.post()
        self.assertEqual(self.w.call(TRIGGER, "settle_stalled_bond", bid)["status"], "REJECTED")
        self.w.advance(86400 + 1)
        out = self.w.call(OUTSIDER, "settle_stalled_bond", bid)
        self.assertEqual(out["outcome"], "REJECTED")
        self.assertEqual(self.w.owed(PROJ), GEN)
        self.w.drain(PROJ)
        self.assertEqual(int(self.w.c.balance_wei), 0)

    def test_verify_twice_refused(self):
        self.w.bonded_repo()
        bid = self.post()
        self.verify(bid)
        self.assertEqual(self.verify(bid)["status"], "REJECTED")

    def test_verify_unknown(self):
        self.assertEqual(self.verify(9)["status"], "REJECTED")

    def test_leader_forging_active_refused(self):
        self.w.bonded_repo(marker=False)
        bid = self.post()
        lg_stub.FORGE["mutate"] = lambda p: dict(p, verdict="ACTIVE", reason="VERIFIED",
                                                 license_path="LICENSE")
        out = self.verify(bid)
        self.assertEqual(out["status"], "REJECTED")
        self.assertEqual(self.w.bd(bid).status, "PENDING")

    def test_no_consensus_changes_nothing(self):
        self.w.bonded_repo()
        bid = self.post()
        lg_stub.FORGE["leader_dies"] = True
        self.assertEqual(self.verify(bid)["status"], "REJECTED")
        self.assertEqual(self.w.bd(bid).status, "PENDING")

    def test_verify_works_while_paused(self):
        self.w.bonded_repo()
        bid = self.post()
        self.w.call(OWNER, "set_paused", True)
        self.assertEqual(self.verify(bid)["outcome"], "ACTIVE")

    def test_uses_one_api_call_per_node(self):
        self.w.bonded_repo()
        bid = self.post()
        lg_stub.CALLS.clear()
        self.verify(bid)
        self.assertEqual(len(self.w.api_calls()), 2)   # leader + validator

    def test_api_sends_user_agent(self):
        self.w.bonded_repo()
        bid = self.post()
        lg_stub.CALLS.clear()
        self.verify(bid)
        heads = [h for u, h in lg_stub.CALLS if u.startswith(API)]
        self.assertTrue(all(h.get("User-Agent") for h in heads))


# =============================================================================
# challenges: mechanical refusals
# =============================================================================


class TestChallengeRefusals(unittest.TestCase):
    def setUp(self):
        self.w, self.bid = standard()

    def ch(self, *a, **k):
        return self.w.challenge(self.bid, *a, **k)

    def refused(self, out):
        self.assertEqual(out["status"], "REJECTED", out)
        self.assertEqual(len(self.w.c.challenges), 0)
        self.assertEqual(int(self.w.c.total_challenges), 0)

    def test_ok(self):
        self.assertEqual(self.ch("src/slugify.js")["status"], "OK")

    def test_bad_original_sha(self):
        self.refused(self.ch("src/slugify.js", original=("ada/slugify", "HEAD", "index.js")))

    def test_short_original_sha(self):
        self.refused(self.ch("src/slugify.js", original=("ada/slugify", "a" * 12, "index.js")))

    def test_missing_original_repo(self):
        self.refused(self.ch("src/slugify.js", original=("", SHA_O, "index.js")))

    def test_missing_original_path(self):
        self.refused(self.ch("src/slugify.js", original=("ada/slugify", SHA_O, "")))

    def test_missing_copied_path(self):
        self.refused(self.ch(""))

    def test_unsupported_license(self):
        self.refused(self.ch("src/slugify.js", license="LGPL_3"))

    def test_license_spdx_spelling(self):
        self.refused(self.ch("src/slugify.js", license="Apache-2.0"))

    def test_license_case_insensitive(self):
        self.assertEqual(self.ch("src/slugify.js", license="mit")["status"], "OK")

    def test_underpaid(self):
        out = self.ch("src/slugify.js", value=int(self.w.c.challenge_bond_wei) - 1)
        self.refused(out)
        self.assertEqual(self.w.owed(CHAL), int(self.w.c.challenge_bond_wei) - 1)

    def test_overpaid_excess_claimable(self):
        need = int(self.w.c.challenge_bond_wei)
        self.assertEqual(self.ch("src/slugify.js", value=need + 5)["status"], "OK")
        self.assertEqual(self.w.owed(CHAL), 5)

    def test_unknown_bond(self):
        self.refused(self.w.challenge(99, "src/slugify.js"))

    def test_pending_bond(self):
        w = World()
        w.call(PROJ, "post_bond", "acme/app", SHA_B, "MIT", value=GEN)
        out = w.challenge(1, "src/slugify.js")
        self.assertEqual(out["status"], "REJECTED")

    def test_window_closed(self):
        self.w.advance(30 * 86400)
        self.refused(self.ch("src/slugify.js"))

    def test_self_challenge(self):
        self.refused(self.ch("src/slugify.js", who=PROJ))

    def test_bonded_repo_as_original(self):
        self.refused(self.ch("src/slugify.js", original=("ACME/app", SHA_B, "src/slugify.js")))

    def test_paused(self):
        self.w.call(OWNER, "set_paused", True)
        self.refused(self.ch("src/slugify.js"))
        self.assertEqual(self.w.owed(CHAL), int(self.w.c.challenge_bond_wei))

    def test_no_model_no_web_at_filing(self):
        lg_stub.CALLS.clear()
        self.ch("src/slugify.js")
        self.assertEqual(lg_stub.CALLS, [])
        self.assertEqual(lg_stub.MODEL.calls, 0)

    def test_bond_open_count(self):
        self.ch("src/slugify.js")
        self.assertEqual(int(self.w.bd(self.bid).open_challenges), 1)

    def test_facts_hash_stored(self):
        cid = self.ch("src/slugify.js")["challenge_id"]
        c = self.w.ch(cid)
        self.assertEqual(c.facts_hash, LG._facts_hash(self.w.c._facts(c, self.w.bd(self.bid))))

    def test_deadline_set(self):
        cid = self.ch("src/slugify.js")["challenge_id"]
        self.assertEqual(int(self.w.ch(cid).judge_deadline), self.w.t + 86400)


# =============================================================================
# judgement outcomes
# =============================================================================


class TestJudgeOutcomes(unittest.TestCase):
    def run_case(self, copied, path="src/slugify.js", model=None, original_kw=None, bond_kw=None,
                 license="MIT", files=None):
        w = World()
        w.original(**(original_kw or {}))
        fs = {path: copied} if copied is not None else {}
        fs.update(files or {})
        bid = w.bond(files=fs, **(bond_kw or {}))
        if model is not None:
            lg_stub.MODEL.serve(*model)
        cid = w.challenge_ok(bid, path, license=license)
        lg_stub.CALLS.clear()
        out = w.judge(cid)
        self.assertEqual(out["status"], "OK", out)
        return w, cid, out

    def test_stripped_copy_missing_without_model(self):
        w, cid, out = self.run_case(COPY_STRIPPED)
        self.assertEqual((out["outcome"], out["reason"]), ("ATTRIBUTION_MISSING", "NO_ATTRIBUTION_FOUND"))
        self.assertEqual(lg_stub.MODEL.calls, 0)
        self.assertEqual(w.ch(cid).origin, "OK")

    def test_attributed_copy_compliant_by_model(self):
        w, cid, out = self.run_case(COPY_ATTRIBUTED, model=("YES",))
        self.assertEqual(out["outcome"], "COMPLIANT")
        self.assertEqual(lg_stub.MODEL.calls, 2)
        self.assertTrue(w.ch(cid).holder_in_copy)
        self.assertEqual(w.ch(cid).origin, "UNCHECKED")

    def test_compliant_uses_no_api(self):
        w, cid, out = self.run_case(COPY_ATTRIBUTED, model=("YES",))
        self.assertEqual([u for u in w.api_calls()], [])

    def test_holder_only_model_says_insufficient(self):
        w, cid, out = self.run_case(COPY_HOLDER_ONLY, model=("NO", "LICENSE_TEXT"))
        self.assertEqual((out["outcome"], out["reason"]),
                         ("ATTRIBUTION_MISSING", "ATTRIBUTION_INSUFFICIENT_LICENSE_TEXT"))

    def test_notice_file_counts(self):
        w, cid, out = self.run_case(COPY_STRIPPED, model=("YES",),
                                    files={"THIRD_PARTY_NOTICES.md": "slugify\n" + ORIG_LICENSE})
        self.assertTrue(w.ch(cid).holder_in_notices)
        self.assertEqual(out["outcome"], "COMPLIANT")

    def test_dir_license_counts(self):
        w, cid, out = self.run_case(COPY_STRIPPED, path="vendor/slugify/index.js", model=("YES",),
                                    files={"vendor/slugify/LICENSE": ORIG_LICENSE})
        self.assertTrue(w.ch(cid).holder_in_notices)
        self.assertIn("vendor/slugify/LICENSE", w.ch(cid).notice_files)

    def test_readme_does_not_count(self):
        w, cid, out = self.run_case(COPY_STRIPPED, files={"README.md": "Thanks Ada Lovelace"})
        self.assertEqual(out["outcome"], "ATTRIBUTION_MISSING")

    def test_unrelated_not_derived(self):
        w, cid, out = self.run_case(UNRELATED)
        self.assertEqual((out["outcome"], out["reason"]), ("NOT_DERIVED", "BELOW_SIMILARITY_THRESHOLD"))
        self.assertEqual(lg_stub.MODEL.calls, 0)
        self.assertEqual(w.api_calls(), [])

    def test_copied_file_missing(self):
        w, cid, out = self.run_case(None, path="src/nope.js")
        self.assertEqual(out["reason"], "COPIED_FILE_MISSING")

    def test_original_file_missing(self):
        w = World()
        w.original()
        bid = w.bond(files={"src/slugify.js": COPY_STRIPPED})
        cid = w.challenge_ok(bid, "src/slugify.js", original=("ada/slugify", SHA_O, "nope.js"))
        self.assertEqual(w.judge(cid)["reason"], "ORIGINAL_FILE_MISSING")

    def test_too_small(self):
        w, cid, out = self.run_case("const a = 1;", original_kw={"text": "const a = 1;\n" + "x" * 0})
        self.assertEqual(out["reason"], "TOO_SMALL_TO_MEASURE")

    def test_binary(self):
        w, cid, out = self.run_case("abc\x00def")
        self.assertEqual(out["reason"], "FILE_UNREADABLE")

    def test_too_large(self):
        w, cid, out = self.run_case("a" * (LG.MAX_FILE_BYTES + 10))
        self.assertEqual(out["reason"], "FILE_UNREADABLE")

    def test_license_not_confirmed(self):
        w, cid, out = self.run_case(COPY_STRIPPED, license="APACHE_2")
        self.assertEqual((out["outcome"], out["reason"]), ("INCONCLUSIVE", "LICENSE_NOT_CONFIRMED"))

    def test_no_license_file_no_spdx(self):
        w, cid, out = self.run_case(COPY_STRIPPED, original_kw={"license_text": None})
        self.assertEqual(out["reason"], "LICENSE_NOT_CONFIRMED")

    def test_spdx_header_confirms(self):
        text = "// SPDX-License-Identifier: MIT\n// Copyright (c) 2020 Ada Lovelace\n" + ORIGINAL
        w, cid, out = self.run_case(COPY_STRIPPED, original_kw={"text": text, "license_text": None})
        self.assertEqual(out["outcome"], "ATTRIBUTION_MISSING")

    def test_no_copyright_notice(self):
        w, cid, out = self.run_case(COPY_STRIPPED, original_kw={
            "license_text": mit("<year> <copyright holders>")})
        self.assertEqual(out["reason"], "NO_COPYRIGHT_NOTICE_IN_ORIGINAL")

    def test_apache_with_notice_file(self):
        w = World()
        text = "// Copyright 2020 The Widget Authors\n// Licensed under the Apache License, Version 2.0\n" + ORIGINAL
        w.original(text=text, license_text=None)
        w.gh.put("ada/slugify", SHA_O, "NOTICE", "Widget\nCopyright 2020 The Widget Authors\n")
        bid = w.bond(files={"src/w.js": ORIGINAL, "NOTICE": "includes Widget, Copyright 2020 The Widget Authors"})
        lg_stub.MODEL.serve("YES")
        cid = w.challenge_ok(bid, "src/w.js", license="APACHE_2")
        out = w.judge(cid)
        self.assertEqual(out["outcome"], "COMPLIANT")
        self.assertIn("NOTICE file", lg_stub.MODEL.prompts[0])

    def test_gpl3(self):
        text = GPL_HEADER + ORIGINAL
        w, cid, out = self.run_case(ORIGINAL, license="GPL_3",
                                    original_kw={"text": text, "license_text": None})
        self.assertEqual((out["outcome"], out["reason"]), ("ATTRIBUTION_MISSING", "NO_ATTRIBUTION_FOUND"))

    def test_bsd3(self):
        w, cid, out = self.run_case(COPY_STRIPPED, license="BSD_3",
                                    original_kw={"license_text": BSD3})
        self.assertEqual(out["outcome"], "ATTRIBUTION_MISSING")
        self.assertEqual(w.ch(cid).holders, "jane roe")

    def test_origin_fork_commit_not_derived(self):
        w, cid, out = self.run_case(COPY_STRIPPED, original_kw={"history": "diverged", "behind": 2})
        self.assertEqual((out["outcome"], out["reason"]), ("NOT_DERIVED", "ORIGIN_NOT_IN_HISTORY"))

    def test_origin_repo_created_after_bond(self):
        w, cid, out = self.run_case(COPY_STRIPPED, original_kw={"created": iso(T0 + 60)})
        self.assertEqual(out["reason"], "ORIGIN_CREATED_AFTER_BOND")

    def test_origin_repo_gone(self):
        w = World()
        w.original()
        lg_stub.WEB.pop(API + "ada/slugify")
        bid = w.bond(files={"src/slugify.js": COPY_STRIPPED})
        cid = w.challenge_ok(bid, "src/slugify.js")
        self.assertEqual(w.judge(cid)["reason"], "ORIGIN_UNAVAILABLE")

    def test_origin_unknown_sha(self):
        w = World()
        w.original()
        w.gh.history("ada/slugify", SHA_O, http=422)
        bid = w.bond(files={"src/slugify.js": COPY_STRIPPED})
        cid = w.challenge_ok(bid, "src/slugify.js")
        self.assertEqual(w.judge(cid)["reason"], "ORIGIN_NOT_IN_HISTORY")

    def test_origin_ahead_ok(self):
        w, cid, out = self.run_case(COPY_STRIPPED, original_kw={"history": "ahead", "behind": 0})
        self.assertEqual(out["outcome"], "ATTRIBUTION_MISSING")

    def test_model_no_on_attributed_checks_origin(self):
        w, cid, out = self.run_case(COPY_HOLDER_ONLY, model=("NO", "COPYRIGHT_NOTICE"),
                                    original_kw={"history": "diverged", "behind": 1})
        self.assertEqual(out["reason"], "ORIGIN_NOT_IN_HISTORY")

    def test_status_provisional(self):
        w, cid, out = self.run_case(COPY_STRIPPED)
        self.assertEqual(w.ch(cid).status, "PROVISIONAL")
        self.assertEqual(int(w.ch(cid).contest_until), w.t + 2 * 86400)

    def test_not_judged_twice(self):
        w, cid, out = self.run_case(COPY_STRIPPED)
        self.assertEqual(w.judge(cid)["status"], "REJECTED")

    def test_judge_unknown(self):
        w = World()
        self.assertEqual(w.judge(3)["status"], "REJECTED")

    def test_content_hash_covers_every_document(self):
        w, cid, out = self.run_case(COPY_STRIPPED)
        c = w.ch(cid)
        self.assertEqual(c.content_hash, LG._hash(c.doc_lines))
        self.assertEqual(len(c.doc_lines.split("\n")), 23)

    def test_content_hash_changes_with_bytes(self):
        _w, c1, _o = self.run_case(COPY_STRIPPED)
        h1 = _w.ch(c1).content_hash
        _w2, c2, _o2 = self.run_case(COPY_STRIPPED + "\n// edit\n")
        self.assertNotEqual(h1, _w2.ch(c2).content_hash)

    def test_api_doc_hash_ignores_live_counters(self):
        _w, c1, _o = self.run_case(COPY_STRIPPED)
        h1 = _w.ch(c1).content_hash
        w2 = World()
        w2.original()
        w2.gh.repo("ada/slugify", created=iso(T0 - 8 * 365 * 86400), stars=9999)
        bid = w2.bond(files={"src/slugify.js": COPY_STRIPPED, "src/app.js": UNRELATED})
        cid = w2.challenge_ok(bid, "src/slugify.js")
        w2.judge(cid)
        self.assertEqual(h1, w2.ch(cid).content_hash)

    def test_verify_challenge_consistent(self):
        for copied, model in ((COPY_STRIPPED, None), (COPY_ATTRIBUTED, ("YES",)), (UNRELATED, None)):
            w, cid, out = self.run_case(copied, model=model)
            self.assertTrue(w.view("verify_challenge", cid)["consistent"])

    def test_verify_challenge_detects_tamper(self):
        w, cid, out = self.run_case(COPY_STRIPPED)
        w.ch(cid).similarity_bps = 4000
        v = w.view("verify_challenge", cid)
        self.assertFalse(v["similarity_ok"])
        self.assertFalse(v["consistent"])

    def test_verify_challenge_detects_doc_tamper(self):
        w, cid, out = self.run_case(COPY_STRIPPED)
        w.ch(cid).doc_lines = w.ch(cid).doc_lines + "\nextra 200 1 x"
        self.assertFalse(w.view("verify_challenge", cid)["content_hash_ok"])

    def test_verify_challenge_unjudged(self):
        w, bid = standard()
        cid = w.challenge_ok(bid, "src/slugify.js")
        v = w.view("verify_challenge", cid)
        self.assertFalse(v["judged"])
        self.assertTrue(v["consistent"])


# =============================================================================
# RETRY paths and the hard deadline
# =============================================================================


class TestRetry(unittest.TestCase):
    def setUp(self):
        self.w, self.bid = standard()
        self.cid = self.w.challenge_ok(self.bid, "src/slugify.js")

    def retry_on(self, url, status=503, side=None):
        self.w.gh.fail(url, status)
        out = self.w.judge(self.cid)
        self.assertEqual(out["outcome"], "RETRY", out)
        c = self.w.ch(self.cid)
        self.assertEqual(c.status, "FILED")
        self.assertEqual(c.outcome, "")
        if side:
            self.assertEqual(c.last_retry_side, side)
        return out

    def test_bonded_license_unreadable(self):
        self.retry_on(raw("acme/app", SHA_B, "LICENSE"), 404, "BONDED")

    def test_bonded_license_5xx(self):
        self.retry_on(raw("acme/app", SHA_B, "LICENSE"), 500, "BONDED")

    def test_original_file_5xx(self):
        self.retry_on(raw("ada/slugify", SHA_O, "index.js"), 502, "ORIGINAL")

    def test_copied_file_5xx(self):
        self.retry_on(raw("acme/app", SHA_B, "src/slugify.js"), 503, "BONDED")

    def test_original_license_429(self):
        self.retry_on(raw("ada/slugify", SHA_O, "LICENSE"), 429, "ORIGINAL")

    def test_bonded_notice_5xx(self):
        self.retry_on(raw("acme/app", SHA_B, "NOTICE"), 500, "BONDED")

    def test_repo_api_rate_limited(self):
        self.retry_on(API + "ada/slugify", 403, "ORIGINAL")

    def test_compare_api_5xx(self):
        self.retry_on(compare_url("ada/slugify", SHA_O), 500, "ORIGINAL")

    def test_connection_error(self):
        lg_stub.WEB[raw("ada/slugify", SHA_O, "index.js")] = ConnectionError("reset")
        self.assertEqual(self.w.judge(self.cid)["outcome"], "RETRY")

    def test_model_down(self):
        w, bid = standard(copied=COPY_ATTRIBUTED)
        cid = w.challenge_ok(bid, "src/slugify.js")
        lg_stub.MODEL.fail(1)
        out = w.judge(cid)
        self.assertEqual((out["outcome"], out["side"]), ("RETRY", "MODEL"))

    def test_model_junk(self):
        w, bid = standard(copied=COPY_ATTRIBUTED)
        cid = w.challenge_ok(bid, "src/slugify.js")
        lg_stub.MODEL.serve_raw({"verdict": "compliant!"})
        self.assertEqual(w.judge(cid)["outcome"], "RETRY")

    def test_models_disagree_no_consensus(self):
        w, bid = standard(copied=COPY_ATTRIBUTED)
        cid = w.challenge_ok(bid, "src/slugify.js")
        lg_stub.MODEL.script({"meets_requirement": "YES", "missing": "NONE"},
                             {"meets_requirement": "NO", "missing": "LICENSE_TEXT"})
        out = w.judge(cid)
        self.assertEqual(out["status"], "REJECTED")
        self.assertEqual(w.ch(cid).status, "FILED")

    def test_leader_retry_but_validator_reads_refused(self):
        lg_stub.SEQ[raw("ada/slugify", SHA_O, "index.js")] = [(503, "x")]
        out = self.w.judge(self.cid)
        self.assertEqual(out["status"], "REJECTED")
        self.assertEqual(self.w.ch(self.cid).status, "FILED")

    def test_retry_then_success(self):
        lg_stub.SEQ[raw("ada/slugify", SHA_O, "index.js")] = [(503, "x"), (503, "x")]
        self.assertEqual(self.w.judge(self.cid)["outcome"], "RETRY")
        self.assertEqual(self.w.judge(self.cid)["outcome"], "ATTRIBUTION_MISSING")

    def test_retry_moves_no_money(self):
        held = int(self.w.c.held_wei)
        self.retry_on(raw("ada/slugify", SHA_O, "index.js"))
        self.assertEqual(int(self.w.c.held_wei), held)
        self.assertEqual(self.w.owed(CHAL), 0)

    def test_attempts_counted(self):
        self.retry_on(raw("ada/slugify", SHA_O, "index.js"))
        self.w.judge(self.cid)
        self.assertEqual(int(self.w.ch(self.cid).attempts), 2)

    def test_judge_refused_after_deadline(self):
        self.w.advance(86400 + 1)
        self.assertEqual(self.w.judge(self.cid)["status"], "REJECTED")

    def test_settle_before_deadline_refused(self):
        self.assertEqual(self.w.call(TRIGGER, "settle_stalled", self.cid)["status"], "REJECTED")

    def test_settle_after_deadline_inconclusive_both_released(self):
        self.retry_on(raw("ada/slugify", SHA_O, "index.js"), side="ORIGINAL")
        self.w.advance(86400 + 1)
        out = self.w.call(OUTSIDER, "settle_stalled", self.cid)
        self.assertEqual(out["outcome"], "INCONCLUSIVE")
        c = self.w.ch(self.cid)
        self.assertEqual((c.status, c.reason), ("FINAL", "DEADLINE_PASSED_ORIGINAL"))
        self.assertEqual(self.w.owed(CHAL), int(self.w.c.challenge_bond_wei))
        self.assertEqual(int(self.w.bd(self.bid).open_challenges), 0)
        self.assertFalse(self.w.bd(self.bid).unreadable)

    def test_bonded_side_stall_suspends_badge(self):
        self.retry_on(raw("acme/app", SHA_B, "LICENSE"), 404, "BONDED")
        self.w.advance(86400 + 1)
        self.w.call(TRIGGER, "settle_stalled", self.cid)
        self.assertTrue(self.w.bd(self.bid).unreadable)
        self.assertFalse(self.w.view("is_compliant", "acme/app"))

    def test_unjudged_stall(self):
        self.w.advance(86400 + 1)
        self.w.call(TRIGGER, "settle_stalled", self.cid)
        self.assertEqual(self.w.ch(self.cid).reason, "DEADLINE_PASSED_UNJUDGED")

    def test_settle_twice_refused(self):
        self.w.advance(86400 + 1)
        self.w.call(TRIGGER, "settle_stalled", self.cid)
        self.assertEqual(self.w.call(TRIGGER, "settle_stalled", self.cid)["status"], "REJECTED")

    def test_settle_provisional_refused(self):
        self.w.judge(self.cid)
        self.w.advance(86400 + 1)
        self.assertEqual(self.w.call(TRIGGER, "settle_stalled", self.cid)["status"], "REJECTED")


# =============================================================================
# forgery: every field of the vector is bound
# =============================================================================


class TestLeaderCannotForge(unittest.TestCase):
    def setUp(self):
        self.w, self.bid = standard()
        self.cid = self.w.challenge_ok(self.bid, "src/slugify.js")

    def forged(self, mutate):
        lg_stub.FORGE["mutate"] = mutate
        out = self.w.judge(self.cid)
        lg_stub.FORGE["mutate"] = None
        self.assertEqual(out["status"], "REJECTED", out)
        self.assertEqual(self.w.ch(self.cid).status, "FILED")
        self.assertEqual(self.w.ch(self.cid).outcome, "")


_FORGERIES = [
    lambda p: dict(p, outcome="COMPLIANT"),
    lambda p: dict(p, outcome="NOT_DERIVED", reason="BELOW_SIMILARITY_THRESHOLD"),
    lambda p: dict(p, similarity_bps=100, shingles_common=5),
    lambda p: dict(p, similarity_bps=100),
    lambda p: dict(p, shingles_common=p["shingles_original"] + 1),
    lambda p: dict(p, holder_in_copy=True),
    lambda p: dict(p, holder_in_notices=True),
    lambda p: dict(p, licenses_found="APACHE_2"),
    lambda p: dict(p, holders=""),
    lambda p: dict(p, copyright_lines="copyright c someone else"),
    lambda p: dict(p, content_hash="0" * 64),
    lambda p: dict(p, doc_lines=p["doc_lines"] + "\nx 200 1 y"),
    lambda p: dict(p, facts_hash="1" * 64),
    lambda p: dict(p, model_called=True, meets="YES", missing="NONE"),
    lambda p: dict(p, meets="NO"),
    lambda p: dict(p, origin="UNCHECKED"),
    lambda p: dict(p, origin="NOT_IN_HISTORY"),
    lambda p: dict(p, origin_created_at=1),
    lambda p: dict(p, original_file="MISSING"),
    lambda p: dict(p, copied_file="TOO_LARGE"),
    lambda p: dict(p, notice_files="NOTICE"),
    lambda p: dict(p, reason="ORIGIN_UNAVAILABLE"),
    lambda p: {"ok": True},
    lambda p: "COMPLIANT",
    lambda p: None,
    lambda p: dict(p, shingles_original=-1),
    lambda p: dict(p, similarity_bps=True),
    lambda p: {"ok": False, "retry": True, "side": "ORIGINAL", "why": "down",
               "facts_hash": p["facts_hash"]},
    lambda p: {"ok": False, "retry": True, "side": "BONDED", "why": "down",
               "facts_hash": p["facts_hash"]},
]
_add_cases(TestLeaderCannotForge, "field", [(f,) for f in _FORGERIES],
           lambda self, f: self.forged(f))


class TestCoherentPure(unittest.TestCase):
    """`_coherent` alone, on a genuine vector, flipping one field at a time."""

    def setUp(self):
        w, bid = standard()
        cid = w.challenge_ok(bid, "src/slugify.js")
        self.facts = w.c._facts(w.ch(cid), w.bd(bid))
        self.v = LG._collect_judge(self.facts)

    def test_genuine_is_coherent(self):
        self.assertTrue(LG._coherent(self.v, self.facts))

    def test_genuine_agrees_with_itself(self):
        self.assertTrue(LG._agrees(self.v, LG._collect_judge(self.facts)))

    def test_every_string_field_bound(self):
        for k in LG.V_STR:
            v = dict(self.v)
            v[k] = str(v[k]) + "x"
            self.assertFalse(LG._coherent(v, self.facts) and LG._agrees(v, self.v), k)

    def test_every_int_field_bound(self):
        for k in LG.V_INT:
            v = dict(self.v)
            v[k] = int(v[k]) + 1
            self.assertFalse(LG._coherent(v, self.facts) and LG._agrees(v, self.v), k)

    def test_every_bool_field_bound(self):
        for k in LG.V_BOOL:
            v = dict(self.v)
            v[k] = not v[k]
            self.assertFalse(LG._coherent(v, self.facts) and LG._agrees(v, self.v), k)

    def test_every_stored_field_is_compared(self):
        stored = set(World().c._vector_of(type("C", (), {k: 0 for k in []})) if False else [])
        vector_keys = set(LG._empty_vector(self.facts).keys()) - {"ok"}
        compared = set(LG.V_STR) | set(LG.V_INT) | set(LG.V_BOOL)
        self.assertEqual(vector_keys - compared, set())

    def test_retry_agreement_needs_same_side(self):
        a = {"retry": True, "side": "ORIGINAL", "facts_hash": LG._facts_hash(self.facts)}
        self.assertTrue(LG._agree_retry(a, dict(a), self.facts))
        self.assertFalse(LG._agree_retry(a, dict(a, side="BONDED"), self.facts))
        self.assertFalse(LG._agree_retry(a, self.v, self.facts))
        self.assertFalse(LG._agree_retry(dict(a, facts_hash="x"), dict(a), self.facts))


# =============================================================================
# contests
# =============================================================================


class TestContest(unittest.TestCase):
    def setUp(self):
        self.w, self.bid = standard()
        self.cid = self.w.challenge_ok(self.bid, "src/app.js")   # NOT_DERIVED
        self.w.judge(self.cid)
        self.cb = int(self.w.c.contest_bond_wei)

    def contest(self, who, value=None):
        return self.w.call(who, "contest", self.cid, value=self.cb if value is None else value)

    def test_challenger_contest_held_bond_to_project(self):
        self.assertEqual(self.contest(CHAL)["status"], "OK")
        out = self.w.judge(self.cid)
        self.assertEqual(out["contest"], "HELD")
        self.assertEqual(self.w.owed(PROJ), self.cb)
        self.assertEqual(self.w.ch(self.cid).contest_log, "CHALLENGER:NOT_DERIVED->NOT_DERIVED:HELD")

    def test_project_contest_held_bond_to_challenger(self):
        self.contest(PROJ)
        self.w.judge(self.cid)
        self.assertEqual(self.w.owed(CHAL), self.cb)

    def test_changed_refunds_contester_and_replaces_vector(self):
        # the bonded file changes under the same commit? Impossible on GitHub;
        # simulated here to exercise the CHANGED branch.
        self.contest(CHAL)
        self.w.gh.put("acme/app", SHA_B, "src/app.js", COPY_STRIPPED)
        out = self.w.judge(self.cid)
        self.assertEqual(out["contest"], "CHANGED")
        self.assertEqual(self.w.ch(self.cid).outcome, "ATTRIBUTION_MISSING")
        self.assertEqual(self.w.owed(CHAL), self.cb)

    def test_one_per_side(self):
        self.contest(CHAL)
        self.w.judge(self.cid)
        out = self.contest(CHAL)
        self.assertEqual(out["status"], "REJECTED")
        self.assertEqual(self.w.owed(CHAL), self.cb)

    def test_other_side_may_contest_after(self):
        self.contest(CHAL)
        self.w.judge(self.cid)
        self.assertEqual(self.contest(PROJ)["status"], "OK")

    def test_after_both_final_window_closes(self):
        self.contest(CHAL)
        self.w.judge(self.cid)
        self.contest(PROJ)
        self.w.judge(self.cid)
        self.assertEqual(int(self.w.ch(self.cid).contest_until), self.w.t)
        self.w.advance(1)
        self.assertEqual(self.w.call(TRIGGER, "finalize", self.cid)["status"], "OK")

    def test_outsider_refused(self):
        self.assertEqual(self.contest(OUTSIDER)["status"], "REJECTED")
        self.assertEqual(self.w.owed(OUTSIDER), self.cb)

    def test_underpaid(self):
        self.assertEqual(self.contest(CHAL, value=self.cb - 1)["status"], "REJECTED")

    def test_after_window(self):
        self.w.advance(2 * 86400 + 1)
        self.assertEqual(self.contest(CHAL)["status"], "REJECTED")

    def test_while_filed_refused(self):
        w, bid = standard()
        cid = w.challenge_ok(bid, "src/app.js")
        self.assertEqual(w.call(CHAL, "contest", cid, value=self.cb)["status"], "REJECTED")

    def test_while_contested_refused(self):
        self.contest(CHAL)
        self.assertEqual(self.contest(PROJ)["status"], "REJECTED")

    def test_finalize_refused_while_contested(self):
        self.contest(CHAL)
        self.w.advance(3 * 86400)
        self.assertEqual(self.w.call(TRIGGER, "finalize", self.cid)["status"], "REJECTED")

    def test_contest_works_while_paused(self):
        self.w.call(OWNER, "set_paused", True)
        self.assertEqual(self.contest(CHAL)["status"], "OK")
        self.assertEqual(self.w.judge(self.cid)["contest"], "HELD")

    def test_contest_rereads_same_facts(self):
        self.contest(CHAL)
        before = self.w.ch(self.cid).facts_hash
        lg_stub.CALLS.clear()
        self.w.judge(self.cid)
        urls = {u for u, _h in lg_stub.CALLS}
        self.assertIn(raw("acme/app", SHA_B, "src/app.js"), urls)
        self.assertIn(raw("ada/slugify", SHA_O, "index.js"), urls)
        self.assertEqual(self.w.ch(self.cid).facts_hash, before)

    def test_contest_deadline_dropped_refund(self):
        self.contest(CHAL)
        self.w.gh.fail(raw("ada/slugify", SHA_O, "index.js"), 503)
        self.assertEqual(self.w.judge(self.cid)["outcome"], "RETRY")
        self.w.advance(86400 + 1)
        self.assertEqual(self.w.judge(self.cid)["status"], "REJECTED")
        out = self.w.call(OUTSIDER, "settle_stalled", self.cid)
        self.assertEqual(out["contest"], "DROPPED")
        self.assertEqual(self.w.owed(CHAL), self.cb)
        self.assertEqual(self.w.ch(self.cid).outcome, "NOT_DERIVED")
        self.assertEqual(self.w.ch(self.cid).status, "PROVISIONAL")

    def test_contest_settle_early_refused(self):
        self.contest(CHAL)
        self.assertEqual(self.w.call(TRIGGER, "settle_stalled", self.cid)["status"], "REJECTED")

    def test_contest_bond_released_once(self):
        self.contest(CHAL)
        self.w.judge(self.cid)
        self.assertEqual(int(self.w.ch(self.cid).contest_bond_wei), 0)
        self.w.finalize(self.cid)
        self.w.drain(PROJ, CHAL)
        self.assertEqual(self.w.paid(PROJ), self.cb + int(self.w.c.challenge_bond_wei))


# =============================================================================
# finalize, money, withdraw
# =============================================================================


class TestFinalizeMoney(unittest.TestCase):
    def test_attribution_missing_pays_challenger_and_slashes(self):
        w, bid = standard()
        cid = w.challenge_ok(bid, "src/slugify.js")
        w.judge(cid)
        out = w.finalize(cid)
        stake = int(w.c.challenge_bond_wei)
        self.assertEqual(int(out["paid_challenger_wei"]), stake + GEN // 2)
        self.assertEqual(w.bd(bid).status, "NON_COMPLIANT")
        self.assertEqual(int(w.bd(bid).remaining_wei), GEN // 2)
        self.assertFalse(w.view("is_compliant", "acme/app"))

    def test_compliant_pays_project(self):
        w, bid = standard(copied=COPY_ATTRIBUTED)
        lg_stub.MODEL.serve("YES")
        cid = w.challenge_ok(bid, "src/slugify.js")
        w.judge(cid)
        w.finalize(cid)
        self.assertEqual(w.owed(PROJ), int(w.c.challenge_bond_wei))
        self.assertEqual(w.bd(bid).status, "ACTIVE")
        self.assertTrue(w.view("is_compliant", "acme/app"))

    def test_not_derived_pays_project(self):
        w, bid = standard()
        cid = w.challenge_ok(bid, "src/app.js")
        w.judge(cid)
        w.finalize(cid)
        self.assertEqual(w.owed(PROJ), int(w.c.challenge_bond_wei))

    def test_inconclusive_refunds_challenger(self):
        w, bid = standard()
        cid = w.challenge_ok(bid, "src/slugify.js", license="GPL_3")
        self.assertEqual(w.judge(cid)["outcome"], "INCONCLUSIVE")
        w.finalize(cid)
        self.assertEqual(w.owed(CHAL), int(w.c.challenge_bond_wei))
        self.assertEqual(w.owed(PROJ), 0)

    def test_finalize_early_refused(self):
        w, bid = standard()
        cid = w.challenge_ok(bid, "src/slugify.js")
        w.judge(cid)
        self.assertEqual(w.call(TRIGGER, "finalize", cid)["status"], "REJECTED")

    def test_finalize_filed_refused(self):
        w, bid = standard()
        cid = w.challenge_ok(bid, "src/slugify.js")
        w.advance(10 * 86400)
        self.assertEqual(w.call(TRIGGER, "finalize", cid)["status"], "REJECTED")

    def test_finalize_twice_refused(self):
        w, bid = standard()
        cid = w.challenge_ok(bid, "src/slugify.js")
        w.judge(cid)
        w.finalize(cid)
        self.assertEqual(w.call(TRIGGER, "finalize", cid)["status"], "REJECTED")

    def test_finalize_permissionless(self):
        w, bid = standard()
        cid = w.challenge_ok(bid, "src/slugify.js")
        w.judge(cid)
        self.assertEqual(w.finalize(cid, who=OUTSIDER)["status"], "OK")

    def test_finalize_reads_stored_vector_not_label(self):
        w, bid = standard()
        cid = w.challenge_ok(bid, "src/app.js")
        w.judge(cid)
        w.ch(cid).outcome = "ATTRIBUTION_MISSING"   # a label cannot move money
        out = w.finalize(cid)
        self.assertEqual(out["outcome"], "NOT_DERIVED")

    def test_two_missing_slash_capped(self):
        w = World()
        w.original()
        w.gh.put("ada/slugify", SHA_O, "other.js", ORIGINAL + "\n// v2\n")
        bid = w.bond(files={"src/a.js": COPY_STRIPPED, "src/b.js": COPY_STRIPPED})
        c1 = w.challenge_ok(bid, "src/a.js")
        c2 = w.challenge_ok(bid, "src/b.js", who=CHAL2)
        c3 = w.challenge_ok(bid, "src/b.js", original=("ada/slugify", SHA_O, "other.js"))
        for c in (c1, c2, c3):
            self.assertEqual(w.judge(c)["outcome"], "ATTRIBUTION_MISSING")
        for c in (c1, c2, c3):
            w.finalize(c)
        self.assertEqual(int(w.bd(bid).remaining_wei), 0)
        self.assertEqual(int(w.ch(c3).slash_wei), 0)
        w.drain(CHAL, CHAL2, PROJ)
        self.assertEqual(int(w.c.balance_wei), 0)

    def test_claim_nothing(self):
        w = World()
        self.assertEqual(w.call(OUTSIDER, "claim")["status"], "REJECTED")

    def test_claim_transfers_exact(self):
        w, bid = standard()
        cid = w.challenge_ok(bid, "src/app.js")
        w.judge(cid)
        w.finalize(cid)
        out = w.call(PROJ, "claim")
        self.assertEqual(int(out["paid_wei"]), int(w.c.challenge_bond_wei))
        self.assertEqual(w.paid(PROJ), int(w.c.challenge_bond_wei))
        self.assertEqual(w.call(PROJ, "claim")["status"], "REJECTED")

    def test_refused_value_is_claimable(self):
        w = World()
        w.call(CHAL, "challenge", 1, "a/b", SHA_O, "x.js", "y.js", "MIT", value=12345)
        self.assertEqual(w.call(CHAL, "claim")["paid_wei"], "12345")


class TestWithdraw(unittest.TestCase):
    def setUp(self):
        self.w, self.bid = standard()

    def withdraw(self, who=PROJ):
        return self.w.call(who, "withdraw_bond", self.bid)

    def test_locked_during_window(self):
        out = self.withdraw()
        self.assertEqual(out["status"], "REJECTED")
        self.assertIn("unlocks_at", out)

    def test_after_window(self):
        self.w.advance(30 * 86400)
        out = self.withdraw()
        self.assertEqual(out["status"], "OK")
        self.assertEqual(self.w.owed(PROJ), GEN)
        self.assertEqual(self.w.bd(self.bid).status, "WITHDRAWN")
        self.assertFalse(self.w.view("is_compliant", "acme/app"))

    def test_only_owner(self):
        self.w.advance(30 * 86400)
        self.assertEqual(self.withdraw(OUTSIDER)["status"], "REJECTED")

    def test_owner_of_contract_cannot(self):
        self.w.advance(30 * 86400)
        self.assertEqual(self.withdraw(OWNER)["status"], "REJECTED")

    def test_twice(self):
        self.w.advance(30 * 86400)
        self.withdraw()
        self.assertEqual(self.withdraw()["status"], "REJECTED")

    def test_frees_repo_for_new_bond(self):
        self.w.advance(30 * 86400)
        self.withdraw()
        self.w.bonded_repo(sha=SHA_B2)
        self.assertEqual(self.w.call(PROJ, "post_bond", "acme/app", SHA_B2, "MIT", value=GEN)["status"], "OK")

    def test_pending_cannot_withdraw(self):
        w = World()
        w.call(PROJ, "post_bond", "acme/app", SHA_B, "MIT", value=GEN)
        self.assertEqual(w.call(PROJ, "withdraw_bond", 1)["status"], "REJECTED")

    def test_non_compliant_remainder_withdrawable(self):
        cid = self.w.challenge_ok(self.bid, "src/slugify.js")
        self.w.judge(cid)
        self.w.finalize(cid)
        self.w.advance(30 * 86400)
        self.assertEqual(self.withdraw()["status"], "OK")
        self.assertEqual(self.w.owed(PROJ), GEN // 2)

    def test_withdraw_while_paused(self):
        self.w.call(OWNER, "set_paused", True)
        self.w.advance(30 * 86400)
        self.assertEqual(self.withdraw()["status"], "OK")


# =============================================================================
# source invariants (AST)
# =============================================================================

TREE = ast.parse(SRC.read_text(encoding="utf8"))
CLS = [n for n in TREE.body if isinstance(n, ast.ClassDef) and n.name == "LicenseGuard"][0]
METHODS = {m.name: m for m in CLS.body if isinstance(m, ast.FunctionDef)}
FUNCS = {n.name: n for n in TREE.body if isinstance(n, ast.FunctionDef)}


def _is_write(m):
    return any(ast.unparse(d).startswith("gl.public.write") for d in m.decorator_list)


def _is_payable(m):
    return any(ast.unparse(d) == "gl.public.write.payable" for d in m.decorator_list)


def _calls(node):
    out = set()
    for n in ast.walk(node):
        if isinstance(n, ast.Call):
            f = n.func
            if isinstance(f, ast.Attribute) and isinstance(f.value, ast.Name) and f.value.id == "self":
                out.add(f.attr)
            elif isinstance(f, ast.Name):
                out.add(f.id)
    return out


def _reach(name):
    seen, stack = set(), [name]
    while stack:
        n = stack.pop()
        if n in seen:
            continue
        seen.add(n)
        node = METHODS.get(n) or FUNCS.get(n)
        if node is not None:
            stack.extend(_calls(node))
    return seen


WRITES = {k: m for k, m in METHODS.items() if _is_write(m)}
CONSTRUCTOR_ONLY = ("min_bond_wei", "challenge_bond_wei", "contest_bond_wei", "challenge_window_s",
                    "unbond_delay_s", "contest_window_s", "deadline_s", "owner")


class TestSourceInvariants(unittest.TestCase):
    def test_zero_raise(self):
        self.assertEqual([n.lineno for n in ast.walk(TREE) if isinstance(n, ast.Raise)], [])

    def test_no_str_replace(self):
        bad = [n.lineno for n in ast.walk(TREE) if isinstance(n, ast.Attribute) and n.attr == "replace"]
        self.assertEqual(bad, [])

    def test_header_two_lines(self):
        lines = SRC.read_text(encoding="utf8").split("\n")
        self.assertEqual(lines[0], "# v0.3.0")
        self.assertTrue(lines[1].startswith('# { "Depends": "py-genlayer:'))
        self.assertFalse(lines[2].startswith("#"))
        self.assertNotIn("latest", lines[1])
        self.assertNotIn("test", lines[1])

    def test_no_undefined_names(self):
        self.assertEqual(lg_stub.undefined_names(SRC), [])

    def test_no_bare_treemap(self):
        src = SRC.read_text(encoding="utf8")
        for bad in (": TreeMap[", ": DynArray[", " TreeMap(", " DynArray("):
            self.assertNotIn(bad, src)

    def test_every_write_banks_first(self):
        for name, m in WRITES.items():
            first = m.body[0]
            if isinstance(first, ast.Expr) and isinstance(first.value, ast.Constant):
                first = m.body[1]
            self.assertIn("self._bank()", ast.unparse(first), name)

    def test_payable_methods(self):
        self.assertEqual(sorted(k for k, m in WRITES.items() if _is_payable(m)),
                         ["challenge", "contest", "post_bond"])

    def test_take_after_last_refusal(self):
        """S4/S5: in every payable method, no `_refuse` follows the `_take` that
        succeeded, and no counter moves before the last refusal."""
        for name in ("post_bond", "challenge", "contest"):
            body = ast.unparse(METHODS[name])
            take = body.index("if not self._take(")
            after = body[take:]
            first_line_end = after.index("\n", after.index("_refuse"))
            rest = after[first_line_end:]
            self.assertNotIn("_refuse(", rest, name)
            self.assertNotIn("total_", body[:take], name)

    def test_only_claim_reaches_pay(self):
        self.assertEqual(sorted(k for k in WRITES if "_pay" in _reach(k)), ["claim"])

    def test_claim_reads_no_clock(self):
        self.assertNotIn("_now", _reach("claim"))

    def test_pause_gates_only_new_business(self):
        gated = sorted(k for k, m in WRITES.items() if "self.paused" in ast.unparse(m) and k != "set_paused")
        self.assertEqual(gated, ["challenge", "post_bond"])

    def test_constructor_only_fields(self):
        for name, m in METHODS.items():
            if name == "__init__":
                continue
            for n in ast.walk(m):
                if isinstance(n, (ast.Assign, ast.AugAssign)):
                    targets = n.targets if isinstance(n, ast.Assign) else [n.target]
                    for t in targets:
                        if isinstance(t, ast.Attribute) and isinstance(t.value, ast.Name) and t.value.id == "self":
                            self.assertNotIn(t.attr, CONSTRUCTOR_ONLY, name)

    def test_no_owner_withdraw(self):
        for name, m in WRITES.items():
            src = ast.unparse(m)
            if "self.owner" in src:
                self.assertIn(name, ("set_paused",), name)

    def test_nondet_closures_do_not_capture_self(self):
        for name in ("_judge_round", "_bond_round"):
            for fn in ast.walk(METHODS[name]):
                if isinstance(fn, ast.FunctionDef) and fn.name in ("leader_fn", "validator_fn"):
                    names = {n.id for n in ast.walk(fn) if isinstance(n, ast.Name)}
                    self.assertNotIn("self", names, name + "." + fn.name)

    def test_no_float_literals(self):
        self.assertEqual([n.lineno for n in ast.walk(TREE)
                          if isinstance(n, ast.Constant) and isinstance(n.value, float)], [])

    def test_required_sentence(self):
        src = SRC.read_text(encoding="utf8")
        self.assertIn("THE MODEL NEVER DECIDES WHO PAYS", src)
        self.assertIn("The model never decides who pays.", src)

    def test_no_self_capture_in_facts(self):
        facts = World().c._facts(type("C", (), dict(challenge_id=1, copied_path="a", original_repo="a/b",
                                                    original_sha="a" * 40, original_path="p",
                                                    license="MIT"))(),
                                 type("B", (), dict(bond_id=1, repo="c/d", commit_sha="b" * 40,
                                                    license_path="LICENSE", posted_at=5))())
        for v in facts.values():
            self.assertIsInstance(v, (str, int))


class TestViews(unittest.TestCase):
    def test_config(self):
        w = World()
        cfg = w.view("get_config")
        self.assertFalse(cfg["demo"])
        self.assertEqual(cfg["licenses"], ["MIT", "APACHE_2", "BSD_3", "GPL_3"])
        self.assertIn("never decides who pays", cfg["model_rule"])

    def test_demo_label(self):
        self.assertTrue(World(challenge_window_s=600).view("get_config")["demo"])

    def test_constructor_clamps(self):
        w = World(min_bond_wei=1, challenge_window_s=1, deadline_s=10 ** 12)
        self.assertEqual(int(w.c.min_bond_wei), 10 ** 15)
        self.assertEqual(int(w.c.challenge_window_s), 60)
        self.assertEqual(int(w.c.deadline_s), 30 * 86400)

    def test_is_compliant_unknown(self):
        self.assertFalse(World().view("is_compliant", "nobody/none"))

    def test_is_compliant_bad_name(self):
        self.assertFalse(World().view("is_compliant", "not a repo"))

    def test_is_compliant_case_insensitive(self):
        w, bid = standard()
        self.assertTrue(w.view("is_compliant", "ACME/App"))

    def test_is_compliant_expires_with_window(self):
        w, bid = standard()
        w.advance(30 * 86400)
        self.assertFalse(w.view("is_compliant", "acme/app"))

    def test_get_bond_for(self):
        w, bid = standard()
        self.assertEqual(w.view("get_bond_for", "acme/app")["bond_id"], bid)

    def test_get_bond_missing(self):
        self.assertFalse(World().view("get_bond", 4)["found"])

    def test_get_challenge_missing(self):
        self.assertFalse(World().view("get_challenge", 4)["found"])

    def test_list_challenges(self):
        w, bid = standard()
        w.challenge_ok(bid, "src/slugify.js")
        w.challenge_ok(bid, "src/app.js")
        self.assertEqual(w.view("list_challenges", bid), [1, 2])
        self.assertEqual(w.view("list_challenges", 0), [1, 2])
        self.assertEqual(w.view("list_challenges", 7), [])

    def test_stats_ledger(self):
        w, bid = standard()
        st = w.view("get_stats")
        self.assertTrue(st["ledger_ok"])
        self.assertEqual(st["held_in_bonds_wei"], str(GEN))

    def test_get_balance(self):
        w = World()
        w.call(CHAL, "claim", value=7)
        self.assertEqual(w.view("get_balance", CHAL), "0")
        self.assertEqual(w.view("get_balance", "garbage"), "0")

    def test_set_paused_owner_only(self):
        w = World()
        self.assertEqual(w.call(OUTSIDER, "set_paused", True)["status"], "REJECTED")
        self.assertFalse(bool(w.c.paused))


if __name__ == "__main__":
    unittest.main()
