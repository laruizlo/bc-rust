#!/usr/bin/env python3
"""A small reader of Rust source for the audit's listed searches (listed_searches.py).

It lexes a file into tokens that keep their line numbers, with comments removed and string and
character literals as one token each, and walks the token stream by brace matching to find
`impl`, `trait`, `mod` and `struct` items and the `fn`s inside them. Nothing here interprets
Rust beyond that: it can say where a token sequence stands and what encloses it, which is all
a listed search needs, and it cannot say what code means. The sources it reads are formatted
by rustfmt, which is what makes item headers regular enough for this.
"""
import re

_TOKEN = re.compile(r"""
    (?P<ws>\s+)
  | (?P<id>[A-Za-z_][A-Za-z0-9_]*)
  | (?P<num>[0-9][A-Za-z0-9_.]*)
  | (?P<punct>::|->|=>|==|!=|<=|>=|&&|\|\||\.\.=|\.\.|.)
""", re.X | re.S)


class Tok(str):
    """A token: its text, and the line it starts on."""
    __slots__ = ("line",)

    def __new__(cls, text, line):
        t = super().__new__(cls, text)
        t.line = line
        return t


def lex(src):
    out = []
    i, n, line = 0, len(src), 1

    def emit(j):
        nonlocal i, line
        out.append(Tok(src[i:j], line))
        line += src.count("\n", i, j)
        i = j

    def skip(j):
        nonlocal i, line
        line += src.count("\n", i, j)
        i = j

    while i < n:
        c = src[i]
        if src.startswith("/*", i):
            depth, j = 1, i + 2
            while j < n and depth:
                if src.startswith("/*", j):
                    depth, j = depth + 1, j + 2
                elif src.startswith("*/", j):
                    depth, j = depth - 1, j + 2
                else:
                    j += 1
            skip(j)
            continue
        if src.startswith("//", i):
            j = src.find("\n", i)
            skip(n if j < 0 else j)
            continue
        m = re.match(r'b?r(#*)"', src[i:i + 12])
        if m:
            end = src.find('"' + m.group(1), i + m.end())
            emit(n if end < 0 else end + 1 + len(m.group(1)))
            continue
        if c == '"' or src.startswith('b"', i):
            j = i + (2 if c == "b" else 1)
            while j < n and src[j] != '"':
                j += 2 if src[j] == "\\" else 1
            emit(j + 1)
            continue
        if c == "'" or src.startswith("b'", i):
            k = i + (1 if c == "b" else 0)
            m = re.match(r"'(\\(x[0-9a-fA-F]{2}|u\{[0-9a-fA-F_]+\}|.)|[^\\'])'", src[k:k + 16])
            if not m:
                m = re.match(r"'[A-Za-z_][A-Za-z0-9_]*", src[k:k + 80])      # a lifetime
            if m:
                emit(k + m.end())
                continue
        m = _TOKEN.match(src, i)
        if m.lastgroup == "ws":
            skip(m.end())
        else:
            emit(m.end())
    return out


def close_of(toks, i):
    """Index of the token that closes the bracket opened at toks[i]."""
    pairs = {"{": "}", "(": ")", "[": "]"}
    open_, close = toks[i], pairs[toks[i]]
    depth = 0
    for j in range(i, len(toks)):
        if toks[j] == open_:
            depth += 1
        elif toks[j] == close:
            depth -= 1
            if depth == 0:
                return j
    return len(toks) - 1


def angle_close(toks, i):
    """Index of the `>` that closes the `<` at toks[i] (generics; `->` and `=>` are single
    tokens, so they do not count)."""
    depth = 0
    for j in range(i, len(toks)):
        if toks[j] == "<":
            depth += 1
        elif toks[j] == ">":
            depth -= 1
            if depth == 0:
                return j
        elif toks[j] in ("{", ";") and depth == 0:
            break
    return i


class Item:
    def __init__(self, kind, name, toks, start, header_end, end, parent, vis, test, attrs):
        self.kind, self.name = kind, name                 # impl | trait | mod | struct | fn
        self.start, self.header_end, self.end = start, header_end, end   # token indices
        self.line = toks[start].line
        self.header = toks[start:header_end]              # up to, not including, `{` `;` or `(`-body
        self.parent, self.vis, self.test, self.attrs = parent, vis, test, attrs
        self.children = []

    def text(self, limit=None):
        s = join(self.header)
        return s if limit is None or len(s) <= limit else s[:limit - 3] + "..."

    def chain(self):
        """This item and what encloses it, outermost first."""
        out, it = [], self
        while it is not None:
            out.append(it)
            it = it.parent
        return out[::-1]


def join(toks):
    """Token text put back together readably."""
    out = ""
    for t in toks:
        if out and (re.match(r"[A-Za-z0-9_]", t[0]) or t in ("=", "+", "->", "{", "&", "&&", "==")) \
                and re.match(r"[A-Za-z0-9_>=+,:)\]]", out[-1]) and not (out[-1] == ":" and out.endswith("::")):
            out += " "
        elif out and out[-1] == "," or (out and out[-1] in "=+" and not out.endswith("=>")):
            out += " "
        out += t
    return out.replace(" ::", "::").replace(":: ", "::").replace("& mut", "&mut").replace("& '", "&'") \
              .replace("& self", "&self").replace("&mut  ", "&mut ")


_KINDS = ("impl", "trait", "mod", "struct", "fn")


def scan(src):
    """(tokens, items): every impl, trait, mod, struct and fn of a source text, nested."""
    toks = lex(src)
    items, stack = [], []          # stack of open items (those with a brace body)
    i, n = 0, len(toks)
    pending_attrs, attr_start = [], None
    while i < n:
        while stack and i > stack[-1].end:
            stack.pop()
        t = toks[i]
        if t == "#" and i + 1 < n and toks[i + 1] == "[":
            j = close_of(toks, i + 1)
            pending_attrs.append(join(toks[i:j + 1]))
            i = j + 1
            continue
        if t == "#" and i + 2 < n and toks[i + 1] == "!" and toks[i + 2] == "[":
            i = close_of(toks, i + 2) + 1
            continue
        prev = toks[i - 1] if i else ""
        is_item = (t in _KINDS and prev not in (".", "::") and i + 1 < n
                   and (t == "impl" or re.match(r"[A-Za-z_]", toks[i + 1]))
                   and not (t == "impl" and prev in (":", "->", "(", ",", "&", "<", "=", "+", "dyn")))
        if not is_item:
            if t not in ("pub", "const", "unsafe", "async", "extern", "crate", "(", ")", "in", "super", "default") \
                    and not t.startswith('"'):
                pending_attrs = []
            i += 1
            continue
        # visibility and qualifiers stand just before the keyword
        k = i - 1
        while k >= 0 and toks[k] in ("const", "unsafe", "async", "extern", "default") or (k >= 0 and toks[k].startswith('"')):
            k -= 1
        vis = "private"
        if k >= 0 and toks[k] == ")":
            o = k
            while o >= 0 and toks[o] != "(":
                o -= 1
            if o >= 1 and toks[o - 1] == "pub":
                vis = "pub(" + join(toks[o + 1:k]) + ")"
        elif k >= 0 and toks[k] == "pub":
            vis = "pub"
        name = toks[i + 1] if t != "impl" else ""
        # the header runs to the body's `{`, or to `;` (a declaration, a unit or tuple struct)
        j, depth = i + 1, 0
        while j < n:
            if toks[j] in ("(", "["):
                j = close_of(toks, j)
            elif toks[j] == "<":
                depth += 1
            elif toks[j] == ">":
                depth = max(0, depth - 1)
            elif toks[j] in ("{", ";") and depth == 0:
                break
            j += 1
        end = close_of(toks, j) if j < n and toks[j] == "{" else j
        parent = stack[-1] if stack else None
        test = (parent.test if parent else False) or any("cfg(test)" in a.replace(" ", "") for a in pending_attrs)
        item = Item(t, name, toks, i, j, end, parent, vis, test, pending_attrs)
        pending_attrs = []
        items.append(item)
        if parent:
            parent.children.append(item)
        if j < n and toks[j] == "{" and t != "struct":
            stack.append(item)
            i = j + 1
        elif t == "struct":
            i = end + 1
        else:
            i = j + 1
    return toks, items


def enclosing(items, idx, kinds=_KINDS):
    """The innermost item of one of `kinds` whose span holds token index idx."""
    best = None
    for it in items:
        if it.kind in kinds and it.start <= idx <= it.end and (best is None or it.start >= best.start):
            best = it
    return best


def impl_parts(item):
    """(trait name or None, self type name) of an impl header: the identifier before `for`,
    and the first identifier after it (or after the generics, for an inherent impl)."""
    h = item.header
    i = 1
    if i < len(h) and h[i] == "<":
        i = angle_close(h, i) + 1
    for_at, depth = None, 0
    for j in range(i, len(h)):
        if h[j] == "<":
            depth += 1
        elif h[j] == ">":
            depth -= 1
        elif h[j] == "for" and depth == 0:
            for_at = j
            break
        elif h[j] == "where" and depth == 0:
            break
    def first_name(seq):
        # the last identifier of a leading path: `crate::size::RsaSize` -> RsaSize
        name = None
        for j, t in enumerate(seq):
            if re.match(r"[A-Za-z_]", t) and t not in ("dyn", "mut", "const"):
                name = t
                if j + 1 < len(seq) and seq[j + 1] == "::":
                    continue
                return name
            if t in ("<", "where", "{"):
                return name
        return name
    if for_at is None:
        return None, first_name(h[i:])
    return first_name(h[i:for_at]), first_name(h[for_at + 1:])
