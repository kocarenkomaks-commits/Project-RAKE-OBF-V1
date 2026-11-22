"""Obfuscation passes.

Order matters:

1. collect every identifier that appears in the chunk (fresh names must not
   collide with any of them);
2. rename locals/parameters (scope aware, never touches globals or fields);
3. replace string literals with calls to a generated decoder;
4. rewrite integer constants as small arithmetic expressions;
5. prepend the decoder helper (added last so it is not itself obfuscated);
6. optionally wrap the whole result in an encrypted loader.
"""

from __future__ import annotations

import random
import string
from dataclasses import dataclass, fields, replace

from . import ast as A
from .emitter import Emitter, quote_bytes
from .lexer import KEYWORDS
from .parser import parse

RESERVED = set(KEYWORDS) | {"self", "_ENV", "_G", "..."}

# Identifiers that appear literally inside the helper code we generate
# (string decoder / packed loader).  Fresh names must never collide with
# them, or the helper would shadow its own parameter or loop variable.
HELPER_NAMES = frozenset("""
v t n k i e s m acc out bits mult buf plain b64 map tbl load loadstring
error string table math char sub byte concat floor type select
""".split())


# --------------------------------------------------------------------------
# generic tree helpers
# --------------------------------------------------------------------------

def walk(node):
    """Yield every AST node in the tree (pre-order)."""
    if isinstance(node, list):
        for item in node:
            yield from walk(item)
        return
    if isinstance(node, tuple):
        for item in node:
            yield from walk(item)
        return
    if not isinstance(node, A.Node):
        return
    yield node
    for f in fields(node):
        yield from walk(getattr(node, f.name))


def transform(node, fn):
    """Bottom-up rebuild of the tree, applying `fn` to every node."""
    if isinstance(node, list):
        return [transform(x, fn) for x in node]
    if isinstance(node, tuple):
        return tuple(transform(x, fn) for x in node)
    if not isinstance(node, A.Node):
        return node
    changes = {}
    for f in fields(node):
        value = getattr(node, f.name)
        if isinstance(value, (A.Node, list, tuple)):
            new = transform(value, fn)
            if new is not value:
                changes[f.name] = new
    if changes:
        node = replace(node, **changes)
    return fn(node)


def collect_identifiers(block: A.Block) -> set[str]:
    """Every name that exists anywhere in the source, including declarations."""
    names: set[str] = set()
    for node in walk(block):
        if isinstance(node, A.Name):
            names.add(node.name)
        elif isinstance(node, A.LocalAssign):
            names.update(n for n, _ in node.names)
        elif isinstance(node, A.LocalFunction):
            names.add(node.name)
        elif isinstance(node, A.Function):
            names.update(node.params)
        elif isinstance(node, A.NumFor):
            names.add(node.var)
        elif isinstance(node, A.GenFor):
            names.update(node.names)
        elif isinstance(node, (A.Goto, A.Label)):
            names.add(node.label)
        elif isinstance(node, A.FieldNode) and node.name_key:
            names.add(node.name_key)
    return names


class NameGenerator:
    """Hands out fresh, globally unique, short identifiers."""

    _ALPHA = string.ascii_lowercase + string.ascii_uppercase
    _ALNUM = _ALPHA + string.digits + "_"

    def __init__(self, taken: set[str], seed: int | None = None):
        self.taken = set(taken) | RESERVED | HELPER_NAMES
        self.rng = random.Random(seed)
        self.count = 0

    def fresh(self) -> str:
        rng = self.rng
        while True:
            n = 1 if self.count < 26 else rng.choice((1, 1, 2, 2, 2, 3))
            first = rng.choice(self._ALPHA)
            rest = "".join(rng.choice(self._ALNUM) for _ in range(n - 1))
            name = first + rest
            if name not in self.taken:
                self.taken.add(name)
                self.count += 1
                return name


# --------------------------------------------------------------------------
# 1. scope-aware renaming
# --------------------------------------------------------------------------

class Scope:
    __slots__ = ("parent", "names")

    def __init__(self, parent: "Scope | None" = None):
        self.parent = parent
        self.names: dict[str, str] = {}

    def lookup(self, name: str) -> str | None:
        scope: Scope | None = self
        while scope is not None:
            if name in scope.names:
                return scope.names[name]
            scope = scope.parent
        return None

    def declare(self, original: str, mangled: str) -> None:
        self.names[original] = mangled


class Renamer:
    """Rename locals, parameters and loop variables.

    Purely sequential/lexical: a binding becomes visible only after its
    declaration, which matches Lua's own scoping rules (important for
    `local x = x` and for closures created before a later `local`).
    """

    def __init__(self, gen: NameGenerator):
        self.gen = gen
        self.renamed = 0
        self.skipped = 0

    def apply(self, block: A.Block) -> None:
        self.visit_block(block, Scope(), new_scope=False)

    # -- scope handling ---------------------------------------------------
    def visit_block(self, block: A.Block, scope: Scope, new_scope: bool = True) -> None:
        if new_scope:
            scope = Scope(scope)
        for stmt in block.stmts:
            self.visit_stmt(stmt, scope)

    def visit_function(self, fn: A.Function, scope: Scope) -> None:
        inner = Scope(scope)
        for i, param in enumerate(fn.params):
            mangled = self.gen.fresh()
            inner.declare(param, mangled)
            fn.params[i] = mangled
        self.visit_block(fn.body, inner)

    # -- statements -------------------------------------------------------
    def visit_stmt(self, node: A.Node, scope: Scope) -> None:
        if isinstance(node, A.LocalAssign):
            # Initialisers are evaluated in the *outer* scope.
            node.exprs = [self.visit_expr(e, scope) for e in node.exprs]
            for i, (name, attrib) in enumerate(node.names):
                if name == "_ENV":
                    scope.declare(name, name)
                    continue
                mangled = self.gen.fresh()
                scope.declare(name, mangled)
                node.names[i] = (mangled, attrib)
                self.renamed += 1

        elif isinstance(node, A.LocalFunction):
            mangled = self.gen.fresh()
            scope.declare(node.name, mangled)
            node.name = mangled
            self.renamed += 1
            self.visit_function(node.func, scope)

        elif isinstance(node, A.Assign):
            node.targets = [self.visit_expr(t, scope) for t in node.targets]
            node.exprs = [self.visit_expr(e, scope) for e in node.exprs]

        elif isinstance(node, A.CallStmt):
            node.call = self.visit_expr(node.call, scope)

        elif isinstance(node, A.Do):
            self.visit_block(node.body, scope)

        elif isinstance(node, A.While):
            node.cond = self.visit_expr(node.cond, scope)
            self.visit_block(node.body, scope)

        elif isinstance(node, A.Repeat):
            inner = Scope(scope)
            self.visit_block(node.body, inner, new_scope=False)
            # `until` sees the locals declared inside the loop body.
            node.cond = self.visit_expr(node.cond, inner)

        elif isinstance(node, A.If):
            node.clauses = [
                (self.visit_expr(cond, scope), self._visit_body(body, scope))
                for cond, body in node.clauses
            ]
            if node.orelse is not None:
                node.orelse = self._visit_body(node.orelse, scope)

        elif isinstance(node, A.NumFor):
            node.start = self.visit_expr(node.start, scope)
            node.stop = self.visit_expr(node.stop, scope)
            if node.step is not None:
                node.step = self.visit_expr(node.step, scope)
            inner = Scope(scope)
            mangled = self.gen.fresh()
            inner.declare(node.var, mangled)
            node.var = mangled
            self.renamed += 1
            self.visit_block(node.body, inner)

        elif isinstance(node, A.GenFor):
            node.exprs = [self.visit_expr(e, scope) for e in node.exprs]
            inner = Scope(scope)
            for i, name in enumerate(node.names):
                mangled = self.gen.fresh()
                inner.declare(name, mangled)
                node.names[i] = mangled
                self.renamed += 1
            self.visit_block(node.body, inner)

        elif isinstance(node, A.FuncDecl):
            node.target = self.visit_expr(node.target, scope)
            self.visit_function(node.func, scope)

        elif isinstance(node, A.Return):
            node.exprs = [self.visit_expr(e, scope) for e in node.exprs]

        # Break / Goto / Label carry no bindings.

    def _visit_body(self, block: A.Block, scope: Scope) -> A.Block:
        self.visit_block(block, scope)
        return block

    # -- expressions ------------------------------------------------------
    def visit_expr(self, node: A.Node, scope: Scope) -> A.Node:
        if isinstance(node, A.Name):
            mangled = scope.lookup(node.name)
            if mangled is not None and mangled != node.name:
                return A.Name(mangled)
            return node

        if isinstance(node, A.Index):
            node.obj = self.visit_expr(node.obj, scope)
            node.key = self.visit_expr(node.key, scope)
            return node

        if isinstance(node, A.Call):
            node.func = self.visit_expr(node.func, scope)
            node.args = [self.visit_expr(a, scope) for a in node.args]
            return node

        if isinstance(node, A.MethodCall):
            node.obj = self.visit_expr(node.obj, scope)
            node.args = [self.visit_expr(a, scope) for a in node.args]
            return node

        if isinstance(node, A.Function):
            self.visit_function(node, scope)
            return node

        if isinstance(node, A.Table):
            for f in node.fields:
                if f.key is not None:
                    f.key = self.visit_expr(f.key, scope)
                f.value = self.visit_expr(f.value, scope)
            return node

        if isinstance(node, A.BinOp):
            node.left = self.visit_expr(node.left, scope)
            node.right = self.visit_expr(node.right, scope)
            return node

        if isinstance(node, A.UnOp):
            node.operand = self.visit_expr(node.operand, scope)
            return node

        if isinstance(node, A.Paren):
            node.expr = self.visit_expr(node.expr, scope)
            return node

        return node


# --------------------------------------------------------------------------
# 2. string encryption
# --------------------------------------------------------------------------

class StringEncryptor:
    def __init__(self, gen: NameGenerator, rng: random.Random):
        self.key = bytes(rng.randrange(256) for _ in range(rng.randint(8, 14)))
        self.decoder = gen.fresh()
        self.cache = gen.fresh()
        self.param = gen.fresh()
        self.count = 0

    def encode(self, data: bytes) -> bytes:
        key = self.key
        return bytes((b - key[i % len(key)]) % 256 for i, b in enumerate(data))

    def make_decoder(self) -> list[A.Node]:
        template = """
local __C__ = {}
local function __D__(__S__)
  local v = __C__[__S__]
  if v then return v end
  local t, n, k = {}, #__S__, __K__
  for i = 1, n do
    t[i] = string.char((__S__:byte(i) + k:byte((i - 1) % #k + 1)) % 256)
  end
  v = table.concat(t)
  __C__[__S__] = v
  return v
end
""".replace("__C__", self.cache) \
   .replace("__D__", self.decoder) \
   .replace("__S__", self.param) \
   .replace("__K__", quote_bytes(self.key))
        return parse(template, "<decoder>").stmts

    def apply(self, block: A.Block) -> int:
        def visit(node: A.Node) -> A.Node:
            if isinstance(node, A.String):
                self.count += 1
                return A.Call(
                    A.Name(self.decoder),
                    [A.String(self.encode(node.value), "")],
                )
            return node

        new_block = transform(block, visit)
        block.stmts = new_block.stmts
        return self.count


# --------------------------------------------------------------------------
# 3. number obfuscation
# --------------------------------------------------------------------------

class NumberObfuscator:
    """Turn `n` into `(a + b)` with random small operands."""

    def __init__(self, rng: random.Random):
        self.rng = rng
        self.count = 0

    def apply(self, block: A.Block) -> int:
        def visit(node: A.Node) -> A.Node:
            if not isinstance(node, A.Number):
                return node
            raw = node.raw
            if not raw.isdigit():          # skip hex / floats / exponents
                return node
            value = int(raw)
            if value > 0x7FFFFFFF:
                return node
            self.count += 1
            if value >= 2:
                a = self.rng.randrange(1, value)
                b = value - a
                return A.BinOp("+", A.Number(str(a)), A.Number(str(b)))
            a = self.rng.randrange(2, 100)
            return A.BinOp("-", A.Number(str(value + a)), A.Number(str(a)))

        new_block = transform(block, visit)
        block.stmts = new_block.stmts
        return self.count


# --------------------------------------------------------------------------
# 4. packing (whole-chunk encryption + loader)
# --------------------------------------------------------------------------

B64_ALPHABET = ("ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                "abcdefghijklmnopqrstuvwxyz"
                "0123456789+/")


def b64encode(data: bytes) -> str:
    """Standard base64 with '+' and '/' - safe inside a Lua string literal."""
    out: list[str] = []
    for i in range(0, len(data), 3):
        chunk = data[i:i + 3]
        n = int.from_bytes(chunk.ljust(3, b"\0"), "big")
        out.append(B64_ALPHABET[(n >> 18) & 63])
        out.append(B64_ALPHABET[(n >> 12) & 63])
        out.append(B64_ALPHABET[(n >> 6) & 63] if len(chunk) > 1 else "=")
        out.append(B64_ALPHABET[n & 63] if len(chunk) > 2 else "=")
    return "".join(out)


def pack_source(source: str, gen: NameGenerator, rng: random.Random,
                chunkname: str = "chunk") -> str:
    key = bytes(rng.randrange(256) for _ in range(rng.randint(16, 24)))
    data = source.encode("utf-8", "surrogateescape")
    cipher = bytes((b - key[i % len(key)]) % 256 for i, b in enumerate(data))
    payload = b64encode(cipher)

    dec = gen.fresh()
    b64 = gen.fresh()
    table_ = gen.fresh()
    out = gen.fresh()
    acc = gen.fresh()
    bits = gen.fresh()
    val = gen.fresh()
    mult = gen.fresh()
    plain = gen.fresh()
    buf = gen.fresh()
    loader = gen.fresh()
    func = gen.fresh()
    err = gen.fresh()
    name = chunkname.encode("utf-8", "surrogateescape")
    name_lit = quote_bytes(b"=" + name)

    return f"""local {dec} = function(e)
  local {b64} = "{B64_ALPHABET}"
  local {table_} = {{}}
  for i = 1, #{b64} do {table_}[{b64}:sub(i, i)] = i - 1 end
  local {out}, {acc}, {bits} = {{}}, 0, 0
  for i = 1, #e do
    local {val} = {table_}[e:sub(i, i)]
    if {val} then
      {acc} = {acc} * 64 + {val}
      {bits} = {bits} + 6
      if {bits} >= 8 then
        {bits} = {bits} - 8
        local {mult} = 2 ^ {bits}
        {out}[#{out} + 1] = string.char(math.floor({acc} / {mult}) % 256)
        {acc} = {acc} % {mult}
      end
    end
  end
  local {plain} = table.concat({out})
  local {buf}, k = {{}}, {quote_bytes(key)}
  for i = 1, #{plain} do
    {buf}[i] = string.char(({plain}:byte(i) + k:byte((i - 1) % #k + 1)) % 256)
  end
  return table.concat({buf})
end
local {loader} = loadstring or load
local {func}, {err} = {loader}({dec}({quote_bytes(payload.encode("ascii"))}), {name_lit}, "t", _ENV)
if not {func} then error({err}) end
return {func}(...)
"""


# --------------------------------------------------------------------------
# public entry point
# --------------------------------------------------------------------------

@dataclass
class Options:
    rename: bool = True
    strings: bool = True
    numbers: bool = True
    pack: bool = False
    pretty: bool = False
    seed: int | None = None


@dataclass
class Result:
    code: str
    renamed: int = 0
    strings: int = 0
    numbers: int = 0


def obfuscate(source: str, filename: str = "<input>",
              options: Options | None = None) -> Result:
    opts = options or Options()
    block = parse(source, filename)

    seed = opts.seed if opts.seed is not None else random.randrange(1 << 30)
    rng = random.Random(seed)
    gen = NameGenerator(collect_identifiers(block), seed=seed)

    result = Result(code="")

    if opts.rename:
        renamer = Renamer(gen)
        renamer.apply(block)
        result.renamed = renamer.renamed

    if opts.strings:
        enc = StringEncryptor(gen, rng)
        result.strings = enc.apply(block)
        if result.strings:
            block.stmts[:0] = enc.make_decoder()

    if opts.numbers:
        result.numbers = NumberObfuscator(rng).apply(block)

    shebang = ""
    if source.startswith("#!"):
        end = source.find("\n")
        shebang = source[:end + 1] if end >= 0 else source + "\n"

    body = Emitter(compact=not opts.pretty).emit(block)

    if opts.pack:
        # The shebang goes outside the payload: `load` does not skip `#!`
        # lines (only the standalone interpreter does).
        code = pack_source(body, gen, rng, filename)
        if shebang:
            code = shebang + code
    else:
        code = shebang + body

    result.code = code
    return result
