"""Test world for LicenseGuard: a fake GitHub, a clock, actors, and the ledger
identity asserted after EVERY call.

The fixtures are synthetic (written for this suite), shaped like the real
sources the seed uses: a small MIT-licensed JavaScript module whose notice
lives in its LICENSE file, and a bonded project that copies it.
"""

import json
from pathlib import Path

import lg_stub

lg_stub._install_stub()

ROOT = Path(__file__).resolve().parent.parent
SRC = ROOT / "contracts" / "LicenseGuard.py"
LG = lg_stub.load_full(SRC, "licenseguard_contract")

RAW = LG.RAW
API = LG.API
GEN = 10 ** 18


def addr(ch: str) -> str:
    return "0x" + ch * 40


OWNER = addr("0")[:-1] + "1"
PROJ = addr("b")
PROJ2 = addr("c")
CHAL = addr("d")
CHAL2 = addr("e")
TRIGGER = addr("f")
OUTSIDER = addr("9")

SHA_B = "b" * 40          # bonded commit
SHA_B2 = "c" * 40
SHA_O = "a" * 40          # original commit
SHA_FORK = "f" * 40       # a fork-only commit, served through the parent

T0 = 1790683200           # 2026-09-29T12:00:00Z


def iso(epoch: int) -> str:
    days, rem = divmod(int(epoch), 86400)
    z = days + 719468
    era = (z if z >= 0 else z - 146096) // 146097
    doe = z - era * 146097
    yoe = (doe - doe // 1460 + doe // 36524 - doe // 146096) // 365
    y = yoe + era * 400
    doy = doe - (365 * yoe + yoe // 4 - yoe // 100)
    mp = (5 * doy + 2) // 153
    d = doy - (153 * mp + 2) // 5 + 1
    m = mp + (3 if mp < 10 else -9)
    y += 1 if m <= 2 else 0
    h, rem = divmod(rem, 3600)
    mi, s = divmod(rem, 60)
    return "%04d-%02d-%02dT%02d:%02d:%02dZ" % (y, m, d, h, mi, s)


# --- fixture texts ------------------------------------------------------------

MIT_TEMPLATE = """MIT License

Copyright (c) {holder}

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
"""


def mit(holder: str) -> str:
    return MIT_TEMPLATE.format(holder=holder)


ORIG_HOLDER = "Ada Lovelace <ada@example.org> (https://ada.example.org)"
ORIG_LICENSE = mit(ORIG_HOLDER)
PROJ_LICENSE = mit("2026 Acme Corp")

ORIGINAL = """import escapeStringRegexp from 'escape-string-regexp';
import transliterate from '@sindresorhus/transliterate';
import builtinOverridableReplacements from './overridable-replacements.js';

const decamelize = string => {
	return string
		// Separate capitalized words.
		.replaceAll(/([A-Z]{2,})(\\d+)/g, '$1 $2')
		.replaceAll(/([a-z\\d]+)([A-Z]{2,})/g, '$1 $2')
		.replaceAll(/([a-z\\d])([A-Z])/g, '$1 $2')
		.replaceAll(/([A-Z]+)([A-Z][a-rt-z\\d]+)/g, '$1 $2');
};

const removeMootSeparators = (string, separator) => {
	const escapedSeparator = escapeStringRegexp(separator);
	return string
		.replaceAll(new RegExp(`${escapedSeparator}{2,}`, 'g'), separator)
		.replaceAll(new RegExp(`^${escapedSeparator}|${escapedSeparator}$`, 'g'), '');
};

const buildPatternSlug = options => {
	let negationSetPattern = 'a-z\\\\d';
	negationSetPattern += options.lowercase ? '' : 'A-Z';
	if (options.preserveCharacters.length > 0) {
		for (const character of options.preserveCharacters) {
			if (character === options.separator) {
				throw new Error(`The separator character \\`${options.separator}\\` cannot be included in preserved characters.`);
			}
			negationSetPattern += escapeStringRegexp(character);
		}
	}
	return new RegExp(`[^${negationSetPattern}]+`, 'g');
};

export default function slugify(string, options) {
	if (typeof string !== 'string') {
		throw new TypeError(`Expected a string, got \\`${typeof string}\\``);
	}
	options = {
		separator: '-',
		lowercase: true,
		decamelize: true,
		customReplacements: [],
		preserveLeadingUnderscore: false,
		preserveTrailingDash: false,
		preserveCharacters: [],
		...options,
	};
	const shouldPrependUnderscore = options.preserveLeadingUnderscore && string.startsWith('_');
	const shouldAppendDash = options.preserveTrailingDash && string.endsWith('-');
	const customReplacements = new Map([
		...builtinOverridableReplacements,
		...options.customReplacements,
	]);
	string = transliterate(string, {customReplacements});
	if (options.decamelize) {
		string = decamelize(string);
	}
	const patternSlug = buildPatternSlug(options);
	if (options.lowercase) {
		string = string.toLowerCase();
	}
	string = string.replaceAll(/([a-zA-Z\\d]+)'([ts])(\\s|$)/g, '$1$2$3');
	string = string.replace(patternSlug, options.separator);
	string = string.replaceAll('\\\\', '');
	if (options.separator) {
		string = removeMootSeparators(string, options.separator);
	}
	if (shouldPrependUnderscore) {
		string = `_${string}`;
	}
	if (shouldAppendDash) {
		string = `${string}-`;
	}
	return string;
}
"""

UNRELATED = """import express from 'express';
import {readFile} from 'node:fs/promises';

const app = express();
const port = Number(process.env.PORT ?? 3000);

app.get('/health', (request, response) => {
	response.json({ok: true, uptime: process.uptime()});
});

app.get('/orders/:id', async (request, response) => {
	const raw = await readFile(new URL('./orders.json', import.meta.url), 'utf8');
	const orders = JSON.parse(raw);
	const order = orders.find(item => item.id === request.params.id);
	if (!order) {
		response.status(404).json({error: 'no such order'});
		return;
	}
	response.json(order);
});

app.post('/orders', express.json(), (request, response) => {
	const {sku, quantity} = request.body ?? {};
	if (typeof sku !== 'string' || !Number.isInteger(quantity) || quantity < 1) {
		response.status(400).json({error: 'sku and a positive quantity are required'});
		return;
	}
	response.status(201).json({sku, quantity, createdAt: new Date().toISOString()});
});

app.listen(port, () => {
	console.log(`listening on ${port}`);
});
"""

ATTRIBUTION_HEADER = """/*
 * slugify - Copyright (c) Ada Lovelace <ada@example.org> (https://ada.example.org)
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy of this
 * software and associated documentation files (the "Software"), to deal in the Software
 * without restriction, subject to the following conditions: The above copyright notice
 * and this permission notice shall be included in all copies or substantial portions.
 */
"""

COPY_STRIPPED = ORIGINAL                               # the notice lives in LICENSE; not carried
COPY_ATTRIBUTED = ATTRIBUTION_HEADER + ORIGINAL        # full notice in the file
COPY_HOLDER_ONLY = "// based on slugify by Ada Lovelace\n" + ORIGINAL  # a trace, not the notice


def raw(repo, sha, path):
    return RAW + repo + "/" + sha + "/" + path


def compare_url(repo, sha):
    return API + repo + "/compare/" + sha + "...HEAD?per_page=1"


class GitHub:
    """A fake GitHub on the stub web. Unconfigured URLs answer 404."""

    def put(self, repo, sha, path, text, status=200):
        lg_stub.WEB[raw(repo, sha, path)] = (status, text)

    def gone(self, repo, sha, path):
        lg_stub.WEB.pop(raw(repo, sha, path), None)

    def repo(self, repo, created=iso(T0 - 3 * 365 * 86400), status=200, stars=17):
        body = json.dumps({"full_name": repo, "created_at": created,
                           "stargazers_count": stars, "pushed_at": iso(T0)})
        lg_stub.WEB[API + repo] = (status, body)

    def history(self, repo, sha, status="identical", behind=0, http=200,
                date=iso(T0 - 5 * 365 * 86400)):
        if http != 200:
            lg_stub.WEB[compare_url(repo, sha)] = (http, '{"message":"Not Found"}')
            return
        body = json.dumps({"status": status, "ahead_by": 0, "behind_by": behind,
                           "base_commit": {"sha": sha, "commit": {
                               "author": {"date": date}, "committer": {"date": date}}},
                           "merge_base_commit": {"sha": sha}, "commits": [], "files": []})
        lg_stub.WEB[compare_url(repo, sha)] = (200, body)

    def fail(self, url, status=503, times=None):
        if times is None:
            lg_stub.WEB[url] = (status, "upstream error")
        else:
            lg_stub.SEQ[url] = [(status, "upstream error")] * times


class World:
    def __init__(self, **ctor):
        lg_stub.WEB.clear()
        lg_stub.SEQ.clear()
        lg_stub.CALLS.clear()
        lg_stub.MODEL.reset()
        lg_stub.TRANSFERS.clear()
        lg_stub.LAST.clear()
        lg_stub.FORGE["payload"] = None
        lg_stub.FORGE["leader_dies"] = False
        lg_stub.FORGE["mutate"] = None
        self.gh = GitHub()
        self.t = T0
        self.received = 0
        self.log = []
        defaults = dict(min_bond_wei=GEN, challenge_bond_wei=GEN // 5,
                        contest_bond_wei=GEN // 10, challenge_window_s=30 * 86400,
                        unbond_delay_s=7 * 86400, contest_window_s=2 * 86400,
                        deadline_s=86400)
        defaults.update(ctor)
        self._as(OWNER, 0)
        self.c = LG.LicenseGuard(**defaults)
        self.check()

    # --- clock and messages
    def _as(self, who, value):
        lg_stub.MESSAGE.sender_address = lg_stub._Addr(who)
        lg_stub.MESSAGE.value = value
        lg_stub.MESSAGE.raw = {"datetime": iso(self.t)}

    def advance(self, seconds):
        self.t += int(seconds)
        lg_stub.MESSAGE.raw = {"datetime": iso(self.t)}

    def call(self, who, method, *args, value=0):
        self._as(who, value)
        self.received += value
        out = getattr(self.c, method)(*args)
        self.log.append((method, out))
        self.check()
        lg_stub.MESSAGE.value = 0
        return out

    def view(self, method, *args):
        self._as(OUTSIDER, 0)
        return getattr(self.c, method)(*args)

    # --- the ledger identity (S10), after every call
    def check(self):
        c = self.c
        bonds = sum(int(b.remaining_wei) for b in c.bonds)
        chs = sum(int(x.bond_wei) + int(x.contest_bond_wei) for x in c.challenges)
        payable = sum(int(v) for v in c.payout_wei.values())
        sent = sum(v for _a, v in lg_stub.TRANSFERS)
        assert int(c.balance_wei) == int(c.held_wei) + int(c.payable_wei), "balance != held + payable"
        assert int(c.held_wei) == bonds + chs, "held != bonds + challenge stakes"
        assert int(c.payable_wei) == payable, "payable != sum of balances"
        assert int(c.balance_wei) == self.received - sent, "books != value in - value out"

    def owed(self, who):
        return int(self.c.payout_wei.get(lg_stub._Addr(who)) or 0)

    def paid(self, who):
        return sum(v for a, v in lg_stub.TRANSFERS if a == who.lower())

    def drain(self, *who):
        for w in who:
            if self.owed(w) > 0:
                out = self.call(w, "claim")
                assert out["status"] == "OK", out

    # --- scenario helpers
    def original(self, repo="ada/slugify", sha=SHA_O, path="index.js", text=ORIGINAL,
                 license_text=ORIG_LICENSE, license_path="license",
                 created=iso(T0 - 8 * 365 * 86400), history="identical", behind=0,
                 committed=iso(T0 - 5 * 365 * 86400)):
        self.gh.put(repo, sha, path, text)
        if license_text is not None:
            self.gh.put(repo, sha, license_path, license_text)
        self.gh.repo(repo, created=created)
        self.gh.history(repo, sha, status=history, behind=behind, date=committed)
        return (repo, sha, path)

    def bonded_repo(self, repo="acme/app", sha=SHA_B, owner=PROJ, files=None,
                    license_text=PROJ_LICENSE, license_path="LICENSE", marker=True,
                    history="identical", behind=0, committed=iso(T0 - 86400),
                    created=iso(T0 - 2 * 365 * 86400)):
        self.gh.history(repo, sha, status=history, behind=behind, date=committed)
        self.gh.repo(repo, created=created)
        if marker:
            self.gh.put(repo, sha, ".licenseguard", "licenseguard bonder: " + owner + "\n")
        if license_text is not None:
            self.gh.put(repo, sha, license_path, license_text)
        for p, t in (files or {}).items():
            self.gh.put(repo, sha, p, t)
        return (repo, sha)

    def bond(self, repo="acme/app", sha=SHA_B, owner=PROJ, files=None, value=GEN,
             declared="MIT", **kw):
        self.bonded_repo(repo, sha, owner, files, **kw)
        out = self.call(owner, "post_bond", repo, sha, declared, value=value)
        assert out["status"] == "OK", out
        bid = out["bond_id"]
        out = self.call(TRIGGER, "verify_bond", bid)
        assert out["status"] == "OK" and out["outcome"] == "ACTIVE", out
        return bid

    def challenge(self, bid, copied_path, who=CHAL, original=("ada/slugify", SHA_O, "index.js"),
                  license="MIT", value=None):
        v = int(self.c.challenge_bond_wei) if value is None else value
        return self.call(who, "challenge", bid, original[0], original[1], original[2],
                         copied_path, license, value=v)

    def challenge_ok(self, *a, **k):
        out = self.challenge(*a, **k)
        assert out["status"] == "OK", out
        return out["challenge_id"]

    def judge(self, cid, who=TRIGGER):
        return self.call(who, "judge", cid)

    def ch(self, cid):
        return self.c.challenges[cid - 1]

    def bd(self, bid):
        return self.c.bonds[bid - 1]

    def past_contest(self, cid):
        self.advance(int(self.ch(cid).contest_until) - self.t + 1)

    def finalize(self, cid, who=TRIGGER):
        self.past_contest(cid)
        out = self.call(who, "finalize", cid)
        assert out["status"] == "OK", out
        return out

    def api_calls(self):
        return [u for u, _h in lg_stub.CALLS if u.startswith(API)]


def standard(world=None, copied=COPY_STRIPPED, copied_path="src/slugify.js", **kw):
    """A world with the original published and one ACTIVE bond whose commit
    carries `copied` at `copied_path` (plus an unrelated src/app.js)."""
    w = world or World(**kw)
    w.original()
    bid = w.bond(files={copied_path: copied, "src/app.js": UNRELATED})
    return w, bid
