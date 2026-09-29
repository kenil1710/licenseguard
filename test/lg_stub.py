"""Runtime stub for the LicenseGuard offline suite.

Ported from the CoverClaim / GrantJudge harness and corrected against what the
LicenseGuard probe MEASURED on Studio Dev (docs/PROBE.md):

  * `from genlayer import *` does NOT export `TreeMap` / `DynArray` - the first
    probe deploy died with `NameError: name 'TreeMap' is not defined`. This stub
    therefore exports neither; the contract must spell `gl.storage.TreeMap`.
  * a web response carries `status`, `body` (bytes) and `headers` - not
    `status_code`. The stub's response has exactly those three.
  * `gl.nondet.web.request(url, method=..., headers=...)` accepts headers.
  * TreeMap answers a missing key with the value type's ZERO, and indexing a
    missing key RAISES (a stub more forgiving than the runner certifies bugs).
  * `Proxy.emit(value=...)` posts nothing; `gl.chain.Account(...).emit_transfer`
    is the transfer.
"""

import ast
import builtins
import json
import sys
import types
from pathlib import Path

_UNSET = object()


class _Return:
    def __init__(self, calldata):
        self.calldata = calldata


class _Addr:
    def __init__(self, value=""):
        v = str(value)
        if not v.startswith("0x") or len(v) != 42:
            raise ValueError("not an address: " + v[:60])
        for ch in v[2:]:
            if ch not in "0123456789abcdefABCDEF":
                raise ValueError("not an address: " + v[:60])
        self._v = v.lower()

    @property
    def as_hex(self):
        return self._v

    def __str__(self):
        return self._v

    def __repr__(self):
        return "Address(" + self._v + ")"

    def __eq__(self, other):
        return isinstance(other, _Addr) and self._v == other._v

    def __ne__(self, other):
        return not self.__eq__(other)

    def __hash__(self):
        return hash(self._v)


def _zero_for(annotation):
    name = getattr(annotation, "__name__", str(annotation))
    if annotation is bool or name == "bool":
        return False
    if annotation is str or name == "str":
        return ""
    if name in ("_Addr", "Address"):
        return _Addr("0x" + "0" * 40)
    if name.startswith("_TreeMap"):
        return annotation() if isinstance(annotation, type) else _TreeMap()
    if name.startswith("_DynArray"):
        return annotation() if isinstance(annotation, type) else _DynArray()
    if hasattr(annotation, "__annotations__") and getattr(annotation, "__annotations__"):
        return _make_struct(annotation)
    return 0


def _make_struct(cls):
    obj = cls.__new__(cls)
    for field, ann in getattr(cls, "__annotations__", {}).items():
        setattr(obj, field, _zero_for(ann))
    return obj


class _TreeMap(dict):
    _value_type = None

    @classmethod
    def __class_getitem__(cls, item):
        vt = item[1] if isinstance(item, tuple) and len(item) > 1 else None
        return type("_TreeMapOf", (cls,), {"_value_type": vt})

    def _k(self, key):
        return str(key) if isinstance(key, _Addr) else key

    def _missing(self):
        vt = type(self)._value_type
        if vt is None:
            return None
        name = getattr(vt, "__name__", str(vt))
        if name.startswith("_TreeMap") or name.startswith("_DynArray"):
            return None
        return _zero_for(vt)

    def get(self, key, default=_UNSET):
        k = self._k(key)
        if dict.__contains__(self, k):
            return dict.__getitem__(self, k)
        if default is not _UNSET:
            return default
        return self._missing()

    def __contains__(self, key):
        return dict.__contains__(self, self._k(key))

    def __setitem__(self, key, value):
        dict.__setitem__(self, self._k(key), value)

    def __getitem__(self, key):
        return dict.__getitem__(self, self._k(key))

    def get_or_insert_default(self, key):
        k = self._k(key)
        if not dict.__contains__(self, k):
            vt = type(self)._value_type
            dict.__setitem__(self, k, _zero_for(vt) if vt is not None else _DynArray())
        return dict.__getitem__(self, k)


class _DynArray(list):
    _elem_type = None

    @classmethod
    def __class_getitem__(cls, item):
        return type("_DynArrayOf", (cls,), {"_elem_type": item})

    def append_new_get(self):
        elem = type(self)._elem_type
        value = _make_struct(elem) if elem is not None and hasattr(elem, "__annotations__") \
            else _zero_for(elem)
        list.append(self, value)
        return value


class _Contract:
    def __getattr__(self, name):
        anns = {}
        for klass in reversed(type(self).__mro__):
            anns.update(getattr(klass, "__annotations__", {}))
        if name in anns:
            value = _zero_for(anns[name])
            object.__setattr__(self, name, value)
            return value
        raise AttributeError(name)


TRANSFERS = []   # (address, wei)


class _Account:
    def __init__(self, address):
        self.address = address

    def emit_transfer(self, value, **_k):
        if int(value) <= 0:
            raise ValueError("value must be greater than 0 for emit_transfer")
        TRANSFERS.append((str(self.address), int(value)))


class _Proxy:
    def __init__(self, address):
        self.address = address

    def emit(self, **_k):
        return None


MESSAGE = types.SimpleNamespace(sender_address=_Addr("0x" + "a" * 40), value=0,
                                raw={"datetime": "2026-09-29T12:00:00Z"})


# ---------------------------------------------------------------------------
# the web and the model
# ---------------------------------------------------------------------------


class _Resp:
    """Exactly the attributes the runner's response has (measured)."""

    def __init__(self, status, body):
        self.status = status
        self.body = body.encode("utf8") if isinstance(body, str) else bytes(body)
        self.headers = {}


WEB = {}        # url -> (status, body) | Exception   (sticky)
SEQ = {}        # url -> [answers...] consumed first (leader, then validator, ...)
CALLS = []      # (url, headers) in order


def _web_request(url, method="GET", headers=None, **_k):
    CALLS.append((url, dict(headers or {})))
    q = SEQ.get(url)
    if q:
        got = q.pop(0)
    elif url in WEB:
        got = WEB[url]
    else:
        got = (404, "404: Not Found")
    if isinstance(got, Exception):
        raise got
    status, body = got
    return _Resp(status, body)


class _Model:
    def __init__(self):
        self.reset()

    def reset(self):
        self.sticky = None
        self.queue = []
        self.prompts = []
        self.raise_next = 0

    @property
    def calls(self):
        return len(self.prompts)

    def serve(self, meets, missing="NONE"):
        self.sticky = {"meets_requirement": meets, "missing": missing}
        self.queue = []

    def serve_raw(self, payload):
        self.sticky = payload
        self.queue = []

    def script(self, *answers):
        self.queue = list(answers)

    def fail(self, times=1):
        self.raise_next = times

    def _next(self, prompt):
        self.prompts.append(prompt)
        if self.raise_next > 0:
            self.raise_next -= 1
            raise RuntimeError("the model endpoint refused the connection")
        if self.queue:
            return self.queue.pop(0)
        if self.sticky is None:
            raise AssertionError("model call with no configured answer")
        return self.sticky


MODEL = _Model()


def _exec_prompt(prompt, **kwargs):
    if kwargs.get("response_format") != "json":
        raise AssertionError("LicenseGuard must ask for response_format='json'")
    return MODEL._next(prompt)


LAST = {}
FORGE = {"payload": None, "leader_dies": False, "mutate": None}


def _run_nondet(leader_fn, validator_fn):
    """The real consensus shape: the leader runs, the validator is handed its
    result as gl.vm.Return and runs the SAME closure. Disagreement settles
    nothing: on chain the round never applies state; here the call answers
    None."""
    LAST.clear()
    if FORGE["leader_dies"]:
        LAST["agreed"] = False
        return None
    try:
        result = leader_fn()
    except Exception as e:  # pragma: no cover - a crash is a finding
        LAST["agreed"] = False
        LAST["leader_error"] = repr(e)
        raise
    LAST["leader"] = result
    if FORGE["payload"] is not None:
        result = FORGE["payload"]
    if FORGE["mutate"] is not None:
        result = FORGE["mutate"](json.loads(json.dumps(result)))
    agreed = validator_fn(_Return(result))
    LAST["agreed"] = bool(agreed)
    if not agreed:
        return None
    return result


def _install_stub():
    if "genlayer" in sys.modules:
        return
    mod = types.ModuleType("genlayer")
    vm = types.SimpleNamespace(Return=_Return, Result=object, run_nondet=_run_nondet,
                               run_nondet_unsafe=_run_nondet)
    web = types.SimpleNamespace(request=_web_request)
    nondet = types.SimpleNamespace(web=web, exec_prompt=_exec_prompt)
    public = types.SimpleNamespace()
    public.view = lambda fn: fn
    write = lambda fn: fn
    write.payable = lambda fn: fn
    public.write = write
    storage = types.SimpleNamespace(TreeMap=_TreeMap, DynArray=_DynArray,
                                    allow=lambda cls: cls)
    contract_ns = types.SimpleNamespace(Contract=_Contract)
    chain_ns = types.SimpleNamespace(Account=_Account)
    mod.gl = types.SimpleNamespace(vm=vm, nondet=nondet, public=public, storage=storage,
                                   message=MESSAGE, contract=contract_ns, chain=chain_ns)
    mod.Address = _Addr
    for name in ("u8", "u16", "u32", "u64", "u128", "u256", "i8", "i16", "i32", "i64",
                 "bigint"):
        mod.__dict__[name] = int
    # Deliberately NOT exported: TreeMap, DynArray (measured on the runner).
    mod.__all__ = ["gl", "Address", "u8", "u16", "u32", "u64", "u128", "u256", "i8",
                   "i16", "i32", "i64", "bigint"]
    sys.modules["genlayer"] = mod
    sys.modules["genlayer.gl"] = mod.gl


def load_full(path: Path, name: str) -> types.ModuleType:
    module = types.ModuleType(name)
    module.__file__ = str(path)
    exec(compile(path.read_text(encoding="utf8"), str(path), "exec"), module.__dict__)
    return module


# ---------------------------------------------------------------------------
# undefined-name scan (a NameError on chain is a dead contract)
# ---------------------------------------------------------------------------

def _own_nodes(scope):
    out = []

    def rec(node):
        for sub in ast.iter_child_nodes(node):
            if isinstance(sub, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
                continue
            out.append(sub)
            rec(sub)
    rec(scope)
    return out


def _child_scopes(scope):
    out = []

    def rec(node):
        for sub in ast.iter_child_nodes(node):
            if isinstance(sub, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
                out.append(sub)
            else:
                rec(sub)
    rec(scope)
    return out


def _bound_names(scope) -> set:
    out = set()
    args = getattr(scope, "args", None)
    if args is not None:
        for group in (args.posonlyargs, args.args, args.kwonlyargs):
            for a in group:
                out.add(a.arg)
        if args.vararg:
            out.add(args.vararg.arg)
        if args.kwarg:
            out.add(args.kwarg.arg)
    for sub in _own_nodes(scope):
        if isinstance(sub, ast.Name) and isinstance(sub.ctx, ast.Store):
            out.add(sub.id)
        elif isinstance(sub, ast.ExceptHandler) and sub.name:
            out.add(sub.name)
        elif isinstance(sub, (ast.Import, ast.ImportFrom)):
            for al in sub.names:
                out.add((al.asname or al.name).split(".")[0])
        elif isinstance(sub, ast.comprehension):
            for nm in ast.walk(sub.target):
                if isinstance(nm, ast.Name):
                    out.add(nm.id)
    for sub in _child_scopes(scope):
        if isinstance(sub, (ast.FunctionDef, ast.AsyncFunctionDef)):
            out.add(sub.name)
    for sub in _own_nodes(scope):
        if isinstance(sub, ast.ClassDef):
            out.add(sub.name)
    return out


def undefined_names(path: Path) -> list:
    """Names loaded that nothing binds. `from genlayer import *` supplies ONLY
    what the runner exports (measured): gl, Address and the integer types."""
    tree = ast.parse(path.read_text(encoding="utf8"))
    module_names = _bound_names(tree) | {
        "gl", "u8", "u16", "u32", "u64", "u128", "u256", "i8", "i16", "i32", "i64",
        "Address", "bigint"}
    builtin_names = set(dir(builtins))
    problems = []

    def visit(scope, enclosing, label):
        names = enclosing | _bound_names(scope)
        for sub in _own_nodes(scope):
            if isinstance(sub, ast.Name) and isinstance(sub.ctx, ast.Load):
                if sub.id not in names and sub.id not in builtin_names:
                    problems.append((label, sub.id, sub.lineno))
        for child in _child_scopes(scope):
            visit(child, names, label + "." + getattr(child, "name", "<lambda>"))

    for child in _child_scopes(tree):
        visit(child, module_names, getattr(child, "name", "<lambda>"))
    for node in _own_nodes(tree):
        if isinstance(node, ast.ClassDef):
            for child in _child_scopes(node):
                visit(child, module_names | _bound_names(node),
                      node.name + "." + getattr(child, "name", "<lambda>"))
    return problems
