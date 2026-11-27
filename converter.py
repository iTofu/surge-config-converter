#!/usr/bin/env python3
"""Surge v5+ -> v4 configuration converter.

Usage:
    python3 converter.py [--snell-legacy PATH] [-o DIR] <input_file_path>

Output layout:
    All generated -v4 files are written 1-to-1 into the output directory
    (default: a v4/ subdirectory next to the source files):

        Documents/
        ├── profile.conf              <- source (v5+)
        ├── work-vps.dconf
        └── v4/
            ├── profile-v4.conf       <- converted (v4)
            └── work-vps-v4.dconf

    Files inside the output directory reference each other using bare
    filenames (e.g. #!include work-vps-v4.dconf) with no directory prefix.
    The output directory is self-contained for a single root profile:
    whenever anything in the loaded profile needs conversion, every file it
    loads gets a -v4 copy (verbatim if it needed no conversion). If you
    convert multiple root profiles in the same source folder that share
    sub-files with diverging conversions, pass -o / --output-dir to isolate
    each profile into its own output directory.
"""

import argparse
import configparser
import ctypes
import errno
import hashlib
import os
import re
import stat
import sys
import unicodedata
from dataclasses import dataclass, field
from pathlib import Path

from send2trash import send2trash


# ---------------------------------------------------------------------------
# Constants: Surge v5+/v6 -> v4 compatibility tables
# ---------------------------------------------------------------------------

# Proxy types not supported in Surge v4
V5PLUS_ONLY_PROXY_TYPES = {
    "hysteria2", "hy2", "anytls", "tuic", "tuic-v5",
    "trust-tunnel", "tailscale", "vless", "masque", "h2-connect",
}

# Snell versions above this have no v4 equivalent: v4 speaks up to version=4,
# version=5 is down-converted to 4, version=6+ nodes are disabled like the
# v5+ only types above.
SNELL_MAX_V4_VERSION = 5

# Optional per-file override for servers that run an extra v4-compatible snell
# instance next to the version=6+ one (own port / PSK, maybe own host).
_SNELL_LEGACY_KEYS = frozenset({"server", "port", "psk"})
SNELL_LEGACY_FILENAME = "snell-legacy.ini"

# Sections entirely unsupported in v4
V5PLUS_ONLY_SECTIONS = {"Port Forwarding", "Body Rewrite"}
# Section prefixes unsupported in v4 ([Tailscale <name>], [Tailscale *],
# inline [Ruleset <name>], [Ruleset *])
V5PLUS_ONLY_SECTION_PREFIXES = ("Tailscale ", "Ruleset ")
# Wildcard named-section includes ([<Base> *], iOS 5.22.0+ / Mac 6.9.0+);
# concrete [WireGuard <name>] remains valid in v4.
V5PLUS_WILDCARD_SECTION_BASES = {"WireGuard", "Tailscale", "Ruleset"}


def is_v5plus_only_section(section_name):
    """Return True if [section_name] is unsupported as a whole in Surge v4."""
    if section_name in V5PLUS_ONLY_SECTIONS:
        return True
    if any(section_name.startswith(p) for p in V5PLUS_ONLY_SECTION_PREFIXES):
        return True
    if section_name.endswith(" *"):
        return section_name[:-2] in V5PLUS_WILDCARD_SECTION_BASES
    return False


# General parameters not supported in v4
V5PLUS_ONLY_GENERAL_PARAMS = {"udp-priority", "block-quic"}

# Rule types not supported in v4
V5PLUS_ONLY_RULE_TYPES = {"HOSTNAME-TYPE", "DOMAIN-WILDCARD"}

# Rule options not supported in v4 (extended-matching: iOS 5.8.0+,
# pre-matching: iOS 5.14.0+).
V5PLUS_ONLY_RULE_OPTIONS = {"extended-matching", "pre-matching"}

# Known trailing options that can follow a rule's policy (or leaf sub-rule args)
RULE_TRAILING_OPTIONS = {
    "no-resolve",
    "force-remote-dns",
    "extended-matching",
    "dns-failed",
    "pre-matching",
}

# Surge built-in rule sets always take precedence over inline [Ruleset <name>]
BUILTIN_RULESETS = {"SYSTEM", "LAN"}

# Characters that Surge v4 cannot represent inside an include-other-group value
# (quoted \" / \\ escapes require iOS 5.21.0+ / Mac 6.8.0+; commas delimit items).
_V4_UNREPRESENTABLE_IOG_CHARS = ('"', ',')

# Proxy parameters not supported in v4
V5PLUS_ONLY_PROXY_PARAMS = {"port-hopping", "port-hopping-interval", "ecn", "block-quic"}

# Cascade-cleanup tag prefix: distinguishes follow-on deletions from direct hits.
CASCADE_TAG = "# [V5+ cascade] "

# Comment prefixes Surge accepts ("#", ";", "//"), possibly repeated with spaces.
# "#!" is a directive (#!include, #!MANAGED-CONFIG), never a comment.
_COMMENT_PREFIX_RE = re.compile(r'^\s*(?:(?:#(?!!)|//|;)\s*)+')

# Proxy types whose definition is "name = type, host, port, key=value...".
HOST_PORT_PROXY_TYPES = (
    {"http", "https", "socks5", "socks5-tls", "ss", "snell", "vmess", "trojan", "ssh"}
    | (V5PLUS_ONLY_PROXY_TYPES - {"tailscale"})
)

V4_SUBDIR = "v4"


# ---------------------------------------------------------------------------
# Layer 1: Surge Lexer & Line Primitives
# ---------------------------------------------------------------------------

def is_comment_line(line):
    """Return True if line is a Surge comment (#, ;, //), excluding #! directives."""
    stripped = line.lstrip()
    if not stripped:
        return False
    if stripped.startswith("#!"):
        return False
    return stripped.startswith("#") or _COMMENT_PREFIX_RE.match(stripped) is not None


def split_inline_comment(s):
    """Split a Surge line/RHS into (body, trailing_comment).

    Surge recognizes '#', ';', and '//' as inline comment starters when
    preceded by whitespace outside double quotes (respecting \\ and \" escapes).
    Leading whitespace before the comment marker stays attached to
    trailing_comment for lossless round-tripping.
    """
    in_quote = False
    i = 0
    n = len(s)
    while i < n:
        ch = s[i]
        if in_quote:
            if ch == "\\" and i + 1 < n:
                i += 2
                continue
            if ch == '"':
                in_quote = False
            i += 1
            continue
        if ch == '"':
            in_quote = True
            i += 1
            continue
        if i > 0 and s[i - 1].isspace():
            if ch in ("#", ";") or (ch == "/" and i + 1 < n and s[i + 1] == "/"):
                j = i
                while j > 0 and s[j - 1].isspace():
                    j -= 1
                return s[:j], s[j:]
        i += 1
    return s, ""


def _split_top_level_comma_spans(s, track_parens=True):
    """Return (start, end) index spans for comma-separated segments outside
    double quotes (respecting \\ and \" escapes) and optionally outside
    balanced parentheses.
    """
    spans = []
    depth = 0
    in_quote = False
    start = 0
    i = 0
    n = len(s)
    while i < n:
        ch = s[i]
        if in_quote:
            if ch == "\\" and i + 1 < n:
                i += 2
                continue
            if ch == '"':
                in_quote = False
            i += 1
            continue
        if ch == '"':
            in_quote = True
        elif track_parens and ch == "(":
            depth += 1
        elif track_parens and ch == ")":
            if depth > 0:
                depth -= 1
        elif ch == "," and (not track_parens or depth == 0):
            spans.append((start, i))
            start = i + 1
        i += 1
    spans.append((start, n))
    return spans


def _split_top_level_commas(s, track_parens=True):
    """Split a string by commas outside double quotes (with \\/\" escapes)
    and optionally outside balanced parentheses."""
    return [s[a:b].strip() for a, b in _split_top_level_comma_spans(s, track_parens=track_parens)]


def _escape_quoted(s):
    """Escape backslash and double-quote for Surge double-quoted values."""
    return s.replace("\\", "\\\\").replace('"', '\\"')


def unquote(name):
    """Strip surrounding double quotes and decode Surge \" and \\ escapes."""
    if len(name) >= 2 and name[0] == '"' and name[-1] == '"':
        return re.sub(r'\\(["\\])', r'\1', name[1:-1])
    return name


def _has_v5_quote_escape(raw_value):
    """Return True if a double-quoted value contains v5.21+/6.8+ \\ or \" escapes."""
    sv = raw_value.strip()
    if len(sv) >= 2 and sv[0] == '"' and sv[-1] == '"':
        inner = sv[1:-1]
        return '\\\\' in inner or '\\"' in inner
    return False


def parse_section_header(line, include_v5_commented=False):
    """Return the section name if line is a Surge [Section] header, else None.

    Strips legal Surge trailing inline comments before matching [Section].
    When include_v5_commented is True, also recognizes headers commented out
    by this converter ("# [V5+] [...]" / CASCADE_TAG).
    """
    stripped = line.strip()
    if include_v5_commented:
        for prefix in ("# [V5+] ", CASCADE_TAG):
            if stripped.startswith(prefix):
                stripped = stripped[len(prefix):].lstrip()
                break
    body, _ = split_inline_comment(stripped)
    body = body.strip()
    if len(body) >= 3 and body[0] == "[" and body[-1] == "]":
        inner = body[1:-1]
        if inner and "[" not in inner and "]" not in inner:
            return inner
    return None


def compute_sections(lines, default_section=None):
    """Return a list parallel to lines where each entry is the section name
    the line belongs to (including headers commented out by this converter).
    """
    result = []
    current = default_section
    for line in lines:
        sec = parse_section_header(line, include_v5_commented=True)
        if sec is not None:
            current = sec
        result.append(current)
    return result


def compute_live_sections(lines, default_section=None):
    """Return a list parallel to lines using ONLY live (uncommented) section
    headers, so pre-existing `# [V5+] [Section]` comments never hijack section
    ownership of subsequent lines.
    """
    result = []
    current = default_section
    for line in lines:
        sec = parse_section_header(line, include_v5_commented=False)
        if sec is not None:
            current = sec
        result.append(current)
    return result


def parse_include_list(line):
    """Parse a Surge #!include directive into decoded path/url entries, or None.

    Surge treats '#' as a literal filename character on #!include lines (no
    inline comments) and supports double-quoted entries containing commas.
    """
    m = re.match(r'^\s*#!include\s+(.+?)\s*$', line)
    if not m:
        return None
    tokens = _split_top_level_commas(m.group(1), track_parens=False)
    return [unquote(tok) for tok in tokens if tok]


def _format_include_entry(entry):
    """Quote an #!include entry when needed for Surge directive syntax."""
    if "," in entry or '"' in entry or entry != entry.strip():
        return f'"{_escape_quoted(entry)}"'
    return entry


def format_include_list(entries):
    """Format entries back into a Surge #!include line, or None if empty."""
    if not entries:
        return None
    return "#!include " + ", ".join(_format_include_entry(e) for e in entries)


def _serialize_lines(lines, original):
    """Join lines back into file content, restoring the trailing newline iff
    original had one."""
    joined = "\n".join(lines)
    if original.endswith("\n"):
        joined += "\n"
    return joined


def _preserve_indent(original_line, new_content):
    """Prepend original_line's leading whitespace to new_content."""
    stripped = original_line.lstrip()
    indent = original_line[:len(original_line) - len(stripped)]
    return indent + new_content


def comment_line(line):
    """Add # [V5+] prefix to a line."""
    return f"# [V5+] {line}"


def is_managed_config(content):
    """Return True if content's first non-blank line is #!MANAGED-CONFIG."""
    for raw in content.splitlines():
        line = raw.strip()
        if not line:
            continue
        return line.startswith("#!MANAGED-CONFIG")
    return False


# ---------------------------------------------------------------------------
# Layer 2: Proxy Group Structured IR (parse once, mutate in memory, render once)
# ---------------------------------------------------------------------------

def parse_include_other_groups(value):
    """Decode an include-other-group option value into a list of group names."""
    body, _ = split_inline_comment(value)
    raw = unquote(body.strip())
    return [g.strip() for g in raw.split(",") if g.strip()]


def is_v4_representable_group_name(name):
    """Return True if name can be encoded in a Surge v4 include-other-group value."""
    return not any(c in name for c in _V4_UNREPRESENTABLE_IOG_CHARS)


def format_include_other_groups(groups, was_quoted=False):
    """Format surviving group names into a Surge v4-readable include-other-group value.

    Surge v4 does not decode \\ / \" inside double quotes (added in iOS 5.21.0 /
    Mac 6.8.0): single backslash-bearing names without spaces are emitted
    unquoted so both v4 and v5+/v6 read the literal name, multi-group lists emit
    literal backslashes without v5.21+ doubling, and names containing '"' or ','
    raise ValueError because v4 cannot represent them unambiguously.
    """
    bad = [g for g in groups if not is_v4_representable_group_name(g)]
    if bad:
        raise ValueError(
            f"v4 include-other-group 无法表示含引号或逗号的组名: {', '.join(bad)}"
        )
    if len(groups) == 1:
        g = groups[0]
        if "\\" in g and " " not in g:
            return g
        if was_quoted or " " in g:
            return f'"{g}"'
        return g
    return '"' + ", ".join(groups) + '"'


@dataclass
class ProxyGroupLine:
    """Public structured representation of a Surge [Proxy Group] definition line."""
    name: str
    group_type: str
    members: list      # raw tokens, quotes preserved
    options: list      # ordered list of (key, value) tuples
    trailing_comment: str = ""


class _ICURegex:
    """Thin wrapper around macOS libicucore (the exact ICU regex engine used by
    Surge / NSRegularExpression) so patterns like \\p{Han} match identically."""

    _lib = None
    _init_attempted = False

    @classmethod
    def _load_lib(cls):
        if cls._init_attempted:
            return cls._lib
        cls._init_attempted = True
        if sys.platform != "darwin":
            return None
        try:
            lib = ctypes.CDLL("/usr/lib/libicucore.A.dylib")
            lib.uregex_open.argtypes = [
                ctypes.c_void_p, ctypes.c_int32, ctypes.c_uint32,
                ctypes.c_void_p, ctypes.POINTER(ctypes.c_int32),
            ]
            lib.uregex_open.restype = ctypes.c_void_p
            lib.uregex_setText.argtypes = [
                ctypes.c_void_p, ctypes.c_void_p, ctypes.c_int32,
                ctypes.POINTER(ctypes.c_int32),
            ]
            lib.uregex_find.argtypes = [
                ctypes.c_void_p, ctypes.c_int32, ctypes.POINTER(ctypes.c_int32),
            ]
            lib.uregex_find.restype = ctypes.c_int8
            lib.uregex_close.argtypes = [ctypes.c_void_p]
            cls._lib = lib
        except OSError:
            cls._lib = None
        return cls._lib

    def __init__(self, pattern):
        self._ptr = None
        lib = self._load_lib()
        if lib is None:
            raise RuntimeError("libicucore unavailable")
        p_u16 = pattern.encode("utf-16-le")
        buf = ctypes.create_string_buffer(p_u16, len(p_u16))
        err = ctypes.c_int32(0)
        ptr = lib.uregex_open(ctypes.addressof(buf), len(p_u16) // 2, 0, None, ctypes.byref(err))
        if err.value > 0 or not ptr:
            if ptr:
                lib.uregex_close(ptr)
            raise ValueError(f"invalid ICU regex: {pattern}")
        self._ptr = ptr

    def search(self, text):
        if not self._ptr:
            return False
        lib = self._lib
        t_u16 = text.encode("utf-16-le")
        buf = ctypes.create_string_buffer(t_u16, len(t_u16))
        err = ctypes.c_int32(0)
        lib.uregex_setText(self._ptr, ctypes.addressof(buf), len(t_u16) // 2, ctypes.byref(err))
        if err.value > 0:
            return False
        found = lib.uregex_find(self._ptr, 0, ctypes.byref(err))
        # Detach text pointer before buf is freed
        err_reset = ctypes.c_int32(0)
        lib.uregex_setText(self._ptr, None, 0, ctypes.byref(err_reset))
        return bool(found) and err.value <= 0

    def __del__(self):
        ptr = getattr(self, "_ptr", None)
        lib = getattr(self, "_lib", None)
        if ptr and lib is not None:
            self._ptr = None
            try:
                lib.uregex_close(ptr)
            except Exception:
                pass


class _UnverifiableRegex:
    """Sentinel for a policy-regex-filter pattern that cannot be verified with
    guaranteed Surge/ICU semantics in the current environment."""

    def __init__(self, pattern):
        self.pattern = pattern

    def match_set(self, names):
        """Return (definite_matched, uncertain_candidates)."""
        return set(), set(names)


# Positive-grammar validator for the non-macOS stdlib `re` fallback.
# Instead of blacklisting ICU features (which inevitably misses syntax such as
# `[a-z&&m-o]` set intersection, `--` subtraction, `{,n}`, `\337`, or `(?x)`),
# we tokenize the pattern and ONLY accept constructs proven identical between
# Apple libicucore ICU and Python stdlib `re`:
#   - Mode A (ascii_safe): printable ASCII + `\t` pattern evaluated against
#     printable ASCII + `\t` candidate names. Allows literals, punctuation
#     escapes, `\d/\D/\w/\W/\s/\S/\b/\B/\t`, simple non-nested character classes
#     (no `[`, `&`, `~`, `|`, `--`), `(`, `(?:`, `(?i)`/`(?-i)` at start,
#     `(?i:...)`/`(?-i:...)`, `^`, `$`, `|`, `.`, and non-possessive quantifiers
#     `*`, `+`, `?`, `{m}`, `{m,}`, `{m,n}` (optional lazy `?`).
#   - Mode B (unicode_literal_safe): exact codepoint literal/anchor/alternation/
#     group/quantifier subset (no flags, no `.`, no `[...]`, no shorthand
#     escapes — only punctuation literal escapes).
_FALLBACK_PUNCT_ESCAPES = frozenset(r"\.+*?^$()[]{}|/-")
_FALLBACK_CLASS_PUNCT_ESCAPES = frozenset(r"\.+*?^$()[]{}|/-&~")
_FALLBACK_ASCII_SHORTHANDS = frozenset("dDwWsSbBt")
_FALLBACK_CLASS_SHORTHANDS = frozenset("dDwWsS")
_FALLBACK_LINE_BREAKS = frozenset("\r\n\x0b\x0c\x85\u2028\u2029")


def _is_printable_ascii(text):
    return all(ch == "\t" or 0x20 <= ord(ch) <= 0x7E for ch in text)


def _is_safe_unicode_text(text):
    return all(
        (ch == "\t" or (ord(ch) >= 0x20 and ord(ch) != 0x7F))
        and ch not in _FALLBACK_LINE_BREAKS
        for ch in text
    )


def _parse_positive_char_class(pattern, start):
    """Parse a simple printable-ASCII `[...]` class with zero ICU set operators
    (`&&`, `--`, `~~`, `||`, nested `[...]`, POSIX `[:...:]`). Returns the index
    after the closing `]` or -1 if rejected."""
    n = len(pattern)
    j = start + 1
    if j < n and pattern[j] == "^":
        j += 1
    if j >= n or pattern[j] == "]":
        return -1

    items = []
    while j < n and pattern[j] != "]":
        c = pattern[j]
        if c in "[&~|":
            return -1
        if c == "\\":
            if j + 1 >= n:
                return -1
            nxt = pattern[j + 1]
            if nxt in _FALLBACK_CLASS_PUNCT_ESCAPES:
                items.append(("char", nxt))
            elif nxt == "t":
                items.append(("char", "\t"))
            elif nxt in _FALLBACK_CLASS_SHORTHANDS:
                items.append(("class", nxt))
            else:
                return -1
            j += 2
        elif c == "-":
            items.append(("dash",))
            j += 1
        else:
            items.append(("char", c))
            j += 1

    if j >= n or pattern[j] != "]" or not items:
        return -1

    # Validate unescaped dashes: only single valid ASCII `lo-hi` ranges or
    # solitary leading/trailing `-` (never `--`, `a-b-c`, `z-a`, or `\d-a`).
    k = 0
    m = len(items)
    while k < m:
        kind = items[k][0]
        if kind == "dash":
            if k == 0 and (m == 1 or items[1][0] != "dash"):
                k += 1
                continue
            if k == m - 1:
                k += 1
                continue
            return -1
        if kind == "char" and k + 2 < m and items[k + 1][0] == "dash":
            if items[k + 2][0] != "char":
                return -1
            if ord(items[k][1]) > ord(items[k + 2][1]):
                return -1
            if k + 3 < m and items[k + 3][0] == "dash":
                return -1
            k += 3
            continue
        if kind == "class":
            if k + 1 < m and items[k + 1][0] == "dash":
                return -1
            k += 1
            continue
        k += 1

    return j + 1


def _parse_positive_brace_quantifier(pattern, start):
    """Parse strict `{m}`, `{m,}`, `{m,n}` (`m` required, `m <= n`), optional
    single lazy `?` (never possessive `+`). Returns next index or -1."""
    n = len(pattern)
    j = start + 1
    m_start = j
    while j < n and pattern[j].isascii() and pattern[j].isdigit():
        j += 1
    if j == m_start or j >= n:
        return -1
    m_val = int(pattern[m_start:j])
    if pattern[j] == ",":
        j += 1
        n_start = j
        while j < n and pattern[j].isascii() and pattern[j].isdigit():
            j += 1
        if j >= n or pattern[j] != "}":
            return -1
        if j > n_start and int(pattern[n_start:j]) < m_val:
            return -1
    elif pattern[j] != "}":
        return -1
    j += 1
    if j < n and pattern[j] == "?":
        j += 1
    if j < n and pattern[j] in "*+?{":
        return -1
    return j


def _is_positive_fallback_regex(pattern, allow_ascii_ext):
    """Return True iff every token in `pattern` belongs to the proven
    ICU-equivalent stdlib `re` subset."""
    if allow_ascii_ext:
        if not _is_printable_ascii(pattern):
            return False
    elif not _is_safe_unicode_text(pattern):
        return False

    n = len(pattern)
    i = 0
    paren_depth = 0
    while i < n:
        ch = pattern[i]
        if ch == "\\":
            if i + 1 >= n:
                return False
            nxt = pattern[i + 1]
            if nxt in _FALLBACK_PUNCT_ESCAPES:
                i += 2
            elif allow_ascii_ext and nxt in _FALLBACK_ASCII_SHORTHANDS:
                i += 2
            else:
                return False
        elif ch == "[":
            if not allow_ascii_ext:
                return False
            nxt_i = _parse_positive_char_class(pattern, i)
            if nxt_i < 0:
                return False
            i = nxt_i
        elif ch in "]}":
            return False
        elif ch == "(":
            if i + 1 < n and pattern[i + 1] == "?":
                if pattern.startswith("(?:", i):
                    paren_depth += 1
                    i += 3
                elif allow_ascii_ext and i == 0 and pattern.startswith("(?i)", i):
                    i += 4
                elif allow_ascii_ext and i == 0 and pattern.startswith("(?-i)", i):
                    i += 5
                elif allow_ascii_ext and pattern.startswith("(?i:", i):
                    paren_depth += 1
                    i += 4
                elif allow_ascii_ext and pattern.startswith("(?-i:", i):
                    paren_depth += 1
                    i += 5
                else:
                    return False
            else:
                paren_depth += 1
                i += 1
        elif ch == ")":
            if paren_depth == 0:
                return False
            paren_depth -= 1
            i += 1
        elif ch in "*+?":
            i += 1
            if i < n and pattern[i] == "?":
                i += 1
            if i < n and pattern[i] in "*+?{":
                return False
        elif ch == "{":
            nxt_i = _parse_positive_brace_quantifier(pattern, i)
            if nxt_i < 0:
                return False
            i = nxt_i
        elif ch == ".":
            if not allow_ascii_ext:
                return False
            i += 1
        else:
            # Literal character or `^`, `$`, `|`
            i += 1

    return paren_depth == 0


class _ExactRegexMatcher:
    """Authoritative Surge/ICU regex matcher (macOS libicucore)."""

    def __init__(self, pattern, engine):
        self.pattern = pattern
        self._engine = engine

    def match_set(self, names):
        return {n for n in names if self._engine.search(n)}, set()


class _FallbackRegexMatcher:
    """Positive-grammar stdlib `re` matcher used only when native ICU is unavailable.

    Evaluates each candidate name independently and returns
    `(definite_matched, uncertain_candidates)`:
      - A candidate is verified exactly iff either the pattern is in the
        Unicode-literal-safe grammar (and the candidate has no line-break
        control chars), OR the pattern is in the printable-ASCII-safe grammar
        and the candidate is printable ASCII + `\\t`.
      - Any other candidate is placed in `uncertain_candidates` so downstream
        cascade/validation preserves certainty and fails closed when needed.
    """

    def __init__(self, pattern, compiled, ascii_safe, unicode_literal_safe):
        self.pattern = pattern
        self._compiled = compiled
        self._ascii_safe = ascii_safe
        self._unicode_literal_safe = unicode_literal_safe

    def match_set(self, names):
        definite = set()
        uncertain = set()
        for n in names:
            if (self._unicode_literal_safe and _is_safe_unicode_text(n)) or (
                self._ascii_safe and _is_printable_ascii(n)
            ):
                if self._compiled.search(n):
                    definite.add(n)
            else:
                uncertain.add(n)
        return definite, uncertain


def _compile_surge_regex(pattern):
    """Compile a Surge policy-regex-filter using Surge's native ICU engine on
    macOS, or a positive-grammar-validated stdlib fallback elsewhere.

    Returns a matcher with `.match_set(names) -> (definite_set, uncertain_set)`.
    """
    if sys.platform == "darwin" and _ICURegex._load_lib() is not None:
        try:
            return _ExactRegexMatcher(pattern, _ICURegex(pattern))
        except (ValueError, RuntimeError):
            return _UnverifiableRegex(pattern)
    ascii_safe = _is_positive_fallback_regex(pattern, allow_ascii_ext=True)
    unicode_literal_safe = _is_positive_fallback_regex(pattern, allow_ascii_ext=False)
    if not ascii_safe and not unicode_literal_safe:
        return _UnverifiableRegex(pattern)
    try:
        compiled = re.compile(pattern)
    except re.error:
        return _UnverifiableRegex(pattern)
    return _FallbackRegexMatcher(pattern, compiled, ascii_safe, unicode_literal_safe)


@dataclass
class _GroupOptionIR:
    """In-memory structured option inside a [Proxy Group] record."""
    key: str
    raw_value: str
    # Populated when key.lower() == "include-other-group"
    iog_groups: list = None
    initial_iog_groups: list = None
    iog_was_quoted: bool = False
    iog_had_v5_escape: bool = False
    iog_dirty: bool = False
    # Populated when key.lower() == "policy-path"
    policy_path: str = None
    policy_path_was_quoted: bool = False
    policy_path_dirty: bool = False


@dataclass
class _GroupRecordIR:
    """Single-parse IR for a live [Proxy Group] line during Pipeline analysis.

    Mutations happen strictly on structured fields in memory. Final v4
    rendering happens ONCE after all cascade and reference-rewriting passes
    complete, so v4-serialized quotes are never re-parsed by a v5+ parser.
    """
    name: str
    group_type: str
    members: list
    options: list           # list[_GroupOptionIR]
    trailing_comment: str
    indent: str
    initial_members: list = field(default_factory=list)
    initial_options: list = field(default_factory=list)
    dirty: bool = False
    commented_out: bool = False
    _regex_cached: bool = False
    _regex_matcher: object = None

    def needs_v4_writeback(self):
        return self.dirty or any(opt.iog_had_v5_escape for opt in self.options)

    def compiled_regex_filter(self):
        """Return matcher with .match_set(names), or None (no filter)."""
        if self._regex_cached:
            return self._regex_matcher
        self._regex_cached = True
        for opt in self.initial_options or self.options:
            if opt.key.lower() == "policy-regex-filter":
                pattern = unquote(opt.raw_value.strip())
                if not pattern:
                    self._regex_matcher = None
                    return None
                self._regex_matcher = _compile_surge_regex(pattern)
                return self._regex_matcher
        self._regex_matcher = None
        return None

    def external_policy_name_prefix(self):
        """Return decoded external-policy-name-prefix (applied to policy-path
        nodes AFTER this group's policy-regex-filter per Surge docs), or ''."""
        for opt in self.initial_options or self.options:
            if opt.key.lower() == "external-policy-name-prefix":
                return unquote(opt.raw_value.strip())
        return ""

    def has_effective_members(self, deleted_names, abandoned_paths=None, base_dir=None,
                              emptied_policy_paths=None, global_proxies_emptied=False,
                              resolve_path_fn=None):
        abandoned_paths = abandoned_paths or set()
        emptied_policy_paths = emptied_policy_paths or set()
        for m in self.members:
            if unquote(m) not in deleted_names:
                return True
        for opt in self.options:
            kl = opt.key.lower()
            if kl == "include-all-proxies" and opt.raw_value.strip() in {"1", "true"}:
                if not global_proxies_emptied:
                    return True
            if kl == "include-other-group" and opt.iog_groups is not None:
                if any(g not in deleted_names for g in opt.iog_groups):
                    return True
            if kl == "policy-path" and opt.policy_path is not None:
                if opt.policy_path.startswith(("http://", "https://")):
                    return True
                if resolve_path_fn is not None:
                    ref_abs = resolve_path_fn(opt.policy_path)
                    if ref_abs not in abandoned_paths and ref_abs not in emptied_policy_paths:
                        return True
                elif base_dir is not None:
                    ref_abs = os.path.normpath(os.path.join(base_dir, opt.policy_path))
                    if ref_abs not in abandoned_paths and ref_abs not in emptied_policy_paths:
                        return True
                elif os.path.basename(opt.policy_path) not in abandoned_paths:
                    return True
        return False

    def render_v4(self, allow_raw_iog=False):
        """Render this record to its final v4 text line.

        Raises ValueError if an active (non-commented) include-other-group
        option has surviving names unrepresentable in Surge v4.
        """
        rendered_opts = []
        for opt in self.options:
            kl = opt.key.lower()
            if kl == "include-other-group" and opt.iog_groups is not None:
                if not allow_raw_iog and (opt.iog_dirty or opt.iog_had_v5_escape):
                    val = format_include_other_groups(opt.iog_groups, was_quoted=opt.iog_was_quoted)
                elif allow_raw_iog and opt.iog_dirty:
                    val = '"' + ", ".join(opt.iog_groups) + '"' if len(opt.iog_groups) > 1 else opt.iog_groups[0]
                else:
                    val = opt.raw_value
                rendered_opts.append((opt.key, val))
            elif kl == "policy-path" and opt.policy_path is not None and opt.policy_path_dirty:
                val = f'"{_escape_quoted(opt.policy_path)}"' if opt.policy_path_was_quoted else opt.policy_path
                rendered_opts.append((opt.key, val))
            else:
                rendered_opts.append((opt.key, opt.raw_value))
        parts = [self.group_type]
        parts.extend(self.members)
        parts.extend(f"{k}={v}" for k, v in rendered_opts)
        body = f"{self.name} = " + ", ".join(parts) + self.trailing_comment
        if self.commented_out:
            return CASCADE_TAG + body.lstrip()
        return self.indent + body


def parse_proxy_group_line(line):
    """Parse a Surge [Proxy Group] definition line into ProxyGroupLine, or None."""
    stripped = line.lstrip()
    if (not stripped or is_comment_line(stripped)
            or stripped.startswith("[") or stripped.startswith("#!")):
        return None
    if "=" not in line:
        return None

    name_part, rest = line.split("=", 1)
    name = name_part.strip()
    if not name:
        return None

    body, trailing_comment = split_inline_comment(rest)
    tokens = _split_top_level_commas(body, track_parens=False)
    if not tokens or not tokens[0]:
        return None

    group_type = tokens[0]
    members = []
    options = []
    for token in tokens[1:]:
        if not token:
            continue
        if "=" in token and not token.startswith('"'):
            key, value = token.split("=", 1)
            options.append((key.strip(), value.strip()))
        else:
            members.append(token)

    return ProxyGroupLine(
        name=name, group_type=group_type, members=members,
        options=options, trailing_comment=trailing_comment,
    )


def _build_group_record(line):
    """Parse a live [Proxy Group] line ONCE into _GroupRecordIR, or None."""
    pgl = parse_proxy_group_line(line)
    if pgl is None:
        return None
    stripped = line.lstrip()
    indent = line[:len(line) - len(stripped)]
    opts = []
    for key, value in pgl.options:
        kl = key.lower()
        sv = value.strip()
        is_quoted = len(sv) >= 2 and sv[0] == '"' and sv[-1] == '"'
        if kl == "include-other-group":
            groups = parse_include_other_groups(sv)
            opts.append(_GroupOptionIR(
                key=key,
                raw_value=value,
                iog_groups=list(groups),
                initial_iog_groups=list(groups),
                iog_was_quoted=is_quoted,
                iog_had_v5_escape=_has_v5_quote_escape(sv),
            ))
        elif kl == "policy-path":
            opts.append(_GroupOptionIR(
                key=key,
                raw_value=value,
                policy_path=unquote(sv),
                policy_path_was_quoted=is_quoted,
            ))
        else:
            opts.append(_GroupOptionIR(key=key, raw_value=value))
    return _GroupRecordIR(
        name=pgl.name,
        group_type=pgl.group_type,
        members=list(pgl.members),
        options=opts,
        trailing_comment=pgl.trailing_comment,
        indent=indent,
        initial_members=list(pgl.members),
        initial_options=list(opts),
    )


def format_proxy_group_line(pgl):
    """Format a ProxyGroupLine back into a config line (stable round-trip)."""
    parts = [pgl.group_type]
    parts.extend(pgl.members)
    parts.extend(f"{k}={v}" for k, v in pgl.options)
    return f"{pgl.name} = " + ", ".join(parts) + pgl.trailing_comment


def has_effective_members(pgl, deleted_names, abandoned_basenames):
    """Return True if a ProxyGroupLine still has at least one valid member source."""
    for m in pgl.members:
        if unquote(m) not in deleted_names:
            return True
    for key, value in pgl.options:
        kl = key.lower()
        if kl == "include-all-proxies" and value.strip() in {"1", "true"}:
            return True
        if kl == "include-other-group":
            if any(g not in deleted_names for g in parse_include_other_groups(value)):
                return True
        if kl == "policy-path":
            path_val = unquote(value.strip())
            if path_val.startswith(("http://", "https://")):
                return True
            if os.path.basename(path_val) not in abandoned_basenames:
                return True
    return False


# ---------------------------------------------------------------------------
# Layer 3: Unified Recursive Rule AST (handles top-level & nested AND/OR/NOT)
# ---------------------------------------------------------------------------

@dataclass
class RuleNode:
    """Recursive AST node for a Surge [Rule] line or nested logical criterion."""
    kind: str                       # uppercase rule type ("AND", "OR", "NOT", "RULE-SET", "FINAL", ...)
    raw_kind: str                   # original spelling
    args: list                      # list[RuleNode] for AND/OR/NOT; list[str] for leaf rules
    policy: str = None              # present on top-level [Rule], None on sub-rules
    options: list = field(default_factory=list)
    trailing_comment: str = ""


def _strip_outer_parens(s):
    """If s (trimmed) is wrapped in a single matched (...) pair, return interior."""
    t = s.strip()
    if len(t) < 2 or t[0] != "(" or t[-1] != ")":
        return None
    depth = 0
    in_quote = False
    i = 0
    n = len(t)
    while i < n:
        ch = t[i]
        if in_quote:
            if ch == "\\" and i + 1 < n:
                i += 2
                continue
            if ch == '"':
                in_quote = False
            i += 1
            continue
        if ch == '"':
            in_quote = True
        elif ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
            if depth == 0 and i != n - 1:
                return None
        i += 1
    return t[1:-1] if depth == 0 else None


def _is_rule_option_token(token):
    return token in RULE_TRAILING_OPTIONS or ("=" in token and not token.startswith('"'))


def _rule_policy_index(tokens):
    """Return index of the policy token in a top-level [Rule] line, or 0.

    Surge's FINAL rule has zero match criteria (FINAL,<policy>[,options...]),
    while all other rules have at least one criterion before <policy>. Knowing
    that floor prevents policy names matching trailing options (e.g.
    `FINAL,no-resolve`) from being swallowed as options.
    """
    kind = tokens[0].upper()
    if kind == "FINAL":
        return 1 if len(tokens) >= 2 else 0
    if len(tokens) < 3:
        return 0
    i = len(tokens) - 1
    while i > 2 and _is_rule_option_token(tokens[i]):
        i -= 1
    return i


def _parse_logical_criteria(raw_group):
    """Parse `((SUB1),(SUB2),...)` into list[RuleNode], or None if malformed."""
    inner = _strip_outer_parens(raw_group)
    if inner is None:
        return None
    children = []
    for item in _split_top_level_commas(inner, track_parens=True):
        if not item:
            continue
        crit_inner = _strip_outer_parens(item)
        if crit_inner is None:
            return None
        sub_tokens = _split_top_level_commas(crit_inner, track_parens=True)
        if len(sub_tokens) < 2:
            return None
        raw_kind = sub_tokens[0]
        kind = raw_kind.upper()
        if kind in ("AND", "OR", "NOT"):
            sub_children = _parse_logical_criteria(sub_tokens[1])
            if sub_children is None:
                return None
            # Trailing options attached directly to the nested compound node
            extra = sub_tokens[2:]
            opt_idx = len(extra)
            while opt_idx > 0 and _is_rule_option_token(extra[opt_idx - 1]):
                opt_idx -= 1
            if opt_idx != 0:
                return None
            children.append(RuleNode(
                kind=kind, raw_kind=raw_kind, args=sub_children,
                policy=None, options=extra,
            ))
        else:
            opt_idx = len(sub_tokens)
            while opt_idx > 2 and _is_rule_option_token(sub_tokens[opt_idx - 1]):
                opt_idx -= 1
            children.append(RuleNode(
                kind=kind, raw_kind=raw_kind, args=sub_tokens[1:opt_idx],
                policy=None, options=sub_tokens[opt_idx:],
            ))
    return children


def parse_rule_line(line):
    """Parse a live [Rule] line into a RuleNode AST, or None if not a rule.

    Only logical rules (AND / OR / NOT) track balanced parentheses when
    splitting commas; non-logical rules (e.g. RULE-SET with a filename
    containing an unmatched '(') split with track_parens=False.
    """
    stripped = line.lstrip()
    if (not stripped or is_comment_line(stripped)
            or stripped.startswith("[") or stripped.startswith("#!")):
        return None
    body, trailing = split_inline_comment(stripped)
    first_comma = body.find(",")
    if first_comma == -1:
        return None
    leading_kind = body[:first_comma].strip().upper()
    is_logical = leading_kind in ("AND", "OR", "NOT")
    tokens = _split_top_level_commas(body, track_parens=is_logical)
    if len(tokens) < 2:
        return None
    pi = _rule_policy_index(tokens)
    if pi == 0:
        return None
    raw_kind = tokens[0]
    kind = raw_kind.upper()
    policy = tokens[pi]
    options = tokens[pi + 1:]
    if is_logical and pi == 2:
        children = _parse_logical_criteria(tokens[1])
        if children is not None:
            return RuleNode(
                kind=kind, raw_kind=raw_kind, args=children,
                policy=policy, options=options, trailing_comment=trailing,
            )
    return RuleNode(
        kind=kind, raw_kind=raw_kind, args=tokens[1:pi],
        policy=policy, options=options, trailing_comment=trailing,
    )


def render_rule_node(node):
    """Render a RuleNode AST back into a Surge rule string."""
    if node.kind in ("AND", "OR", "NOT") and node.args and isinstance(node.args[0], RuleNode):
        inner = "(" + ",".join(f"({render_rule_node(child)})" for child in node.args) + ")"
        parts = [node.raw_kind, inner]
    else:
        parts = [node.raw_kind, *node.args]
    if node.policy is not None:
        parts.append(node.policy)
    parts.extend(node.options)
    return ",".join(parts) + node.trailing_comment


def _transform_rule_ast(node, negated=False):
    """Recursively downgrade v5+ rule types and options in-place on a RuleNode.

    Returns (changed, must_comment, removed_opts, has_negated_leaf):
      - Any v5+-only rule type at any depth sets must_comment=True.
      - Any `extended-matching` attached to a leaf or compound node whose scope
        reaches an odd-NOT negated leaf sets must_comment=True (stripping it
        would narrow the inner matcher and expand the enclosing negation).
      - Positive-polarity `extended-matching` and any `pre-matching` are
        stripped cleanly while preserving the rule.
    """
    if node.kind in V5PLUS_ONLY_RULE_TYPES:
        return True, True, [], negated

    if node.kind in ("AND", "OR", "NOT") and node.args and isinstance(node.args[0], RuleNode):
        child_neg = (not negated) if node.kind == "NOT" else negated
        any_changed = False
        removed_all = []
        sub_has_neg = False
        for child in node.args:
            c_changed, c_comment, c_rem, c_neg = _transform_rule_ast(child, negated=child_neg)
            if c_comment:
                return True, True, [], True
            any_changed = any_changed or c_changed
            removed_all.extend(c_rem)
            sub_has_neg = sub_has_neg or c_neg
        removed_self = [opt for opt in node.options if opt in V5PLUS_ONLY_RULE_OPTIONS]
        if removed_self:
            if "extended-matching" in removed_self and sub_has_neg:
                return True, True, [], True
            node.options = [opt for opt in node.options if opt not in V5PLUS_ONLY_RULE_OPTIONS]
            any_changed = True
            removed_all.extend(removed_self)
        return any_changed, False, removed_all, sub_has_neg

    # Leaf rule (or unparsed logical syntax fallback)
    removed = [opt for opt in node.options if opt in V5PLUS_ONLY_RULE_OPTIONS]
    if not removed:
        return False, False, [], negated
    if (negated or node.kind == "NOT") and "extended-matching" in removed:
        return True, True, [], True
    node.options = [opt for opt in node.options if opt not in V5PLUS_ONLY_RULE_OPTIONS]
    return True, False, removed, negated


def _collect_rule_ruleset_targets(node):
    """Collect decoded RULE-SET targets referenced at any depth of a RuleNode."""
    if node.kind == "RULE-SET" and node.args:
        return [unquote(node.args[0])]
    if node.kind in ("AND", "OR", "NOT") and node.args and isinstance(node.args[0], RuleNode):
        out = []
        for child in node.args:
            out.extend(_collect_rule_ruleset_targets(child))
        return out
    return []


def _rewrite_rule_local_file_targets(node, resolve_fn):
    """Recursively rewrite local RULE-SET / DOMAIN-SET file args in-place.

    resolve_fn(raw_arg, kind) returns (new_arg, note) or None when untouched.
    Returns list of human-readable rewrite notes.
    """
    notes = []
    if node.kind in ("RULE-SET", "DOMAIN-SET") and node.args:
        res = resolve_fn(node.args[0], node.kind)
        if res is not None:
            new_arg, note = res
            node.args[0] = new_arg
            notes.append(note)
        return notes
    if node.kind in ("AND", "OR", "NOT") and node.args and isinstance(node.args[0], RuleNode):
        for child in node.args:
            notes.extend(_rewrite_rule_local_file_targets(child, resolve_fn))
    return notes


def extract_rule_policy(line):
    """Return the policy target from a live [Rule] line, or None."""
    node = parse_rule_line(line)
    return node.policy if node is not None else None


def _is_live_final_rule(line):
    """Return True if line is an active FINAL,... rule."""
    node = parse_rule_line(line)
    return node is not None and node.kind == "FINAL"


# ---------------------------------------------------------------------------
# Stats & File / Path Utilities
# ---------------------------------------------------------------------------

class ConversionStats:
    """Edit bookkeeping, tracked per file so edits for discarded files can be purged."""

    def __init__(self):
        self.files_processed = []
        self.changes = []
        self.deprecated_files = []
        self.abandoned_files = []    # managed configs we refused to convert
        self.stale_v4_files = []     # pre-existing -v4 files for abandoned managed configs
        self.errors = []             # fatal v4 conversion errors that block emission
        self._commented_by_file = {}
        self._params_by_file = {}

    @property
    def lines_commented(self):
        return sum(self._commented_by_file.values())

    @property
    def params_modified(self):
        return sum(self._params_by_file.values())

    def count_commented(self, filename, n=1):
        self._commented_by_file[filename] = self._commented_by_file.get(filename, 0) + n

    def count_params(self, filename, n=1):
        self._params_by_file[filename] = self._params_by_file.get(filename, 0) + n

    def discard_file(self, filename):
        """Drop every recorded edit for a file whose conversion was discarded."""
        self._commented_by_file.pop(filename, None)
        self._params_by_file.pop(filename, None)
        self.changes = [c for c in self.changes if c[0] != filename]

    def add_change(self, filename, line_num, section, action, detail):
        self.changes.append((filename, line_num, section, action, detail))

    def print_summary(self):
        by_file = {}
        for filename, line_num, section, action, detail in self.changes:
            by_file.setdefault(filename, []).append((line_num, section, action, detail))
        for filename, changes in by_file.items():
            print(f"{filename}:")
            for line_num, section, action, detail in changes:
                print(f"  [{line_num}] [{section}] {action}: {detail}")
        print("\n=== 转换摘要 ===")
        print(f"处理文件数: {len(self.files_processed)}")
        for f in self.files_processed:
            print(f"  - {f}")
        print(f"注释行数（含直接命中与级联清理）: {self.lines_commented}")
        print(f"修改参数数: {self.params_modified}")
        if self.abandoned_files:
            print(f"放弃的托管配置数: {len(self.abandoned_files)}")


def make_v4_filename(filepath, output_dir=None):
    """Generate the 1-to-1 -v4 output filename inside output_dir (default: v4/).

    Example: /path/to/profile.conf -> /path/to/v4/profile-v4.conf
    """
    p = Path(filepath)
    out_base = Path(output_dir) if output_dir is not None else (p.parent / V4_SUBDIR)
    return str(out_base / (p.stem + "-v4" + p.suffix))


def make_v4_relname(filename):
    """Generate the bare -v4 basename for config-internal references."""
    p = Path(filename)
    return p.stem + "-v4" + p.suffix


def _nearest_existing_dir(directory):
    """Walk up from directory to the nearest existing directory path."""
    probe_dir = os.path.abspath(directory)
    while probe_dir and not os.path.isdir(probe_dir):
        parent = os.path.dirname(probe_dir)
        if parent == probe_dir:
            return "."
        probe_dir = parent
    return probe_dir or "."


def _probe_volume_semantics(directory):
    """Return (case_sensitive, unicode_normalizing) for directory's filesystem."""
    probe_dir = _nearest_existing_dir(directory)
    if sys.platform == "darwin":
        case_sensitive = False
        try:
            # macOS _PC_CASE_SENSITIVE == 11 (0 = insensitive, 1 = sensitive)
            res = ctypes.CDLL(None).pathconf(os.fsencode(probe_dir), 11)
            if res == 1:
                case_sensitive = True
            elif res == 0:
                case_sensitive = False
        except OSError:
            pass
        # APFS and HFS+ are Unicode normalization-insensitive (NFD == NFC)
        return case_sensitive, True
    if os.name == "nt":
        return False, False
    return True, False


def _volume_path_key(filepath, follow_symlinks=False):
    """Normalize filepath according to the target volume's real equivalence
    rules (symlinks, case sensitivity, and Unicode normalization).

    When follow_symlinks=True, resolves the final path via os.path.realpath()
    first (including dangling symlink targets) so alias collisions are caught
    before opening any output file.
    """
    abs_path = os.path.realpath(os.path.abspath(filepath)) if follow_symlinks else os.path.abspath(filepath)
    existing_ancestor = _nearest_existing_dir(os.path.dirname(abs_path))
    case_sensitive, unicode_norm = _probe_volume_semantics(existing_ancestor)
    rel_tail = os.path.relpath(abs_path, existing_ancestor)
    parts = [p for p in Path(rel_tail).parts if p not in ("", ".")]
    norm_parts = []
    for part in parts:
        p = unicodedata.normalize("NFC", part) if unicode_norm else part
        if not case_sensitive:
            p = p.casefold()
        norm_parts.append(p)
    ancestor_real = os.path.realpath(existing_ancestor)
    if unicode_norm:
        ancestor_real = unicodedata.normalize("NFC", ancestor_real)
    if not case_sensitive:
        ancestor_real = ancestor_real.casefold()
    return (ancestor_real, *norm_parts)


def _file_identity(filepath):
    """Return (st_dev, st_ino) if filepath exists on disk, else None."""
    try:
        st = os.stat(filepath)
        return (st.st_dev, st.st_ino)
    except OSError:
        return None


def _output_unchanged(output_path, planned_content, is_binary=False):
    """Single source of truth for whether an existing output path already holds
    planned_content (shared by preflight backup checks and emit()).

    Symlinks (both live and dangling) ALWAYS return False so output directories
    never retain symlinks to external files and always materialize self-contained
    regular copies via the normal backup flow.
    """
    if os.path.islink(output_path) or not os.path.exists(output_path):
        return False
    try:
        if is_binary:
            with open(output_path, "rb") as f:
                return f.read() == planned_content
        with open(output_path, "r", encoding="utf-8") as f:
            return f.read() == planned_content
    except (OSError, UnicodeDecodeError):
        return False


def _filename_too_long(directory, filename):
    """Return True if filename cannot be created on directory's actual filesystem.

    Probes the nearest existing ancestor directory via zero-write os.lstat()
    (respecting APFS Unicode name units on macOS as well as 255-byte limits on
    ext4/Linux) and guards against PC_PATH_MAX on the full target path.
    """
    probe_dir = _nearest_existing_dir(directory)
    try:
        os.lstat(os.path.join(probe_dir, filename))
    except OSError as exc:
        if exc.errno == errno.ENAMETOOLONG:
            return True
    full_path = os.path.join(directory, filename)
    try:
        path_max = os.pathconf(probe_dir, "PC_PATH_MAX")
        if path_max > 0 and len(os.fsencode(full_path)) >= path_max:
            return True
    except (OSError, ValueError, AttributeError):
        pass
    return False


def _is_non_regular_target(path):
    """Return True if path exists (via lstat/stat) as a directory or non-regular
    filesystem entry (never safe to overwrite, rename as backup, or trash)."""
    if not os.path.lexists(path):
        return False
    if os.path.isdir(path):
        return True
    try:
        st = os.lstat(path)
    except OSError:
        return False
    return not (stat.S_ISREG(st.st_mode) or stat.S_ISLNK(st.st_mode))


def backup_if_exists(filepath):
    """If filepath exists (regular file or symlink — never a directory), rename
    it with a -deprecated suffix (trashing any pre-existing regular backup first)."""
    if os.path.lexists(filepath):
        if _is_non_regular_target(filepath):
            raise IsADirectoryError(f"拒绝移动目录或非普通文件: {filepath}")
        p = Path(filepath)
        backup = str(p.with_stem(p.stem + "-deprecated"))
        if os.path.lexists(backup):
            if _is_non_regular_target(backup):
                raise IsADirectoryError(f"拒绝删除目录或非普通文件备份: {backup}")
            send2trash(backup)
            print(f"已将旧备份移至垃圾桶: {backup}")
        os.rename(filepath, backup)
        return backup
    return None


# ---------------------------------------------------------------------------
# Single-Line Direct-Hit Transforms
# ---------------------------------------------------------------------------

def extract_proxy_type(line):
    """Extract lowercase proxy type from a live proxy definition line, or None."""
    if is_comment_line(line):
        return None
    m = re.match(r'^[^=]+=\s*(\w[\w-]*)', line)
    return m.group(1).strip().lower() if m else None


def extract_proxy_option(line, option_name):
    """Return decoded value of option_name on a live [Proxy] line, or None."""
    if is_comment_line(line) or "=" not in line:
        return None
    _, rhs = line.split("=", 1)
    rhs_body, _ = split_inline_comment(rhs)
    target = option_name.lower()
    for token in _split_top_level_commas(rhs_body, track_parens=False)[1:]:
        if "=" not in token or token.startswith('"'):
            continue
        k, v = token.split("=", 1)
        if k.strip().lower() == target:
            return unquote(v.strip())
    return None


def remove_proxy_params(line, params_to_remove):
    """Remove specific key=value parameters from a proxy line.

    Quote- and inline-comment-aware (with track_parens=False so unquoted
    passwords containing '(' stay intact). Preserves untouched spacing verbatim.
    Returns (modified_line, list_of_removed_param_names).
    """
    if "=" not in line:
        return line, []
    lhs, rhs = line.split("=", 1)
    rhs_body, trailing = split_inline_comment(rhs)
    targets = {p.lower() for p in params_to_remove}
    spans = _split_top_level_comma_spans(rhs_body, track_parens=False)
    if len(spans) <= 1:
        return line, []

    drop_ranges = []
    removed = []
    for idx in range(1, len(spans)):
        start, end = spans[idx]
        token = rhs_body[start:end].strip()
        if "=" not in token or token.startswith('"'):
            continue
        key, _ = token.split("=", 1)
        norm_key = key.strip().lower()
        if norm_key in targets:
            drop_ranges.append((start - 1, end))
            if norm_key not in removed:
                removed.append(norm_key)

    if not drop_ranges:
        return line, []

    out = []
    cursor = 0
    for d_start, d_end in drop_ranges:
        out.append(rhs_body[cursor:d_start])
        cursor = d_end
    out.append(rhs_body[cursor:])
    return lhs + "=" + "".join(out) + trailing, removed


def _replace_proxy_option_value(line, option_name, old_value, new_value):
    """Replace exact key=old_value with key=new_value in a proxy line's RHS,
    ignoring LHS, quoted values, and inline comments. Returns (line, count)."""
    if "=" not in line:
        return line, 0
    lhs, rhs = line.split("=", 1)
    rhs_body, trailing = split_inline_comment(rhs)
    target = option_name.lower()
    spans = _split_top_level_comma_spans(rhs_body, track_parens=False)
    if len(spans) <= 1:
        return line, 0
    replacements = []
    for idx in range(1, len(spans)):
        start, end = spans[idx]
        seg = rhs_body[start:end]
        stripped = seg.strip()
        if "=" not in stripped or stripped.startswith('"'):
            continue
        eq_rel = seg.find("=")
        key = seg[:eq_rel].strip().lower()
        val_part = seg[eq_rel + 1:]
        val_stripped = val_part.strip()
        if key == target and unquote(val_stripped) == old_value:
            val_lead = len(val_part) - len(val_part.lstrip())
            v_start = start + eq_rel + 1 + val_lead
            v_end = v_start + len(val_stripped)
            replacements.append((v_start, v_end))
    if not replacements:
        return line, 0
    out = []
    cursor = 0
    for v_start, v_end in replacements:
        out.append(rhs_body[cursor:v_start])
        out.append(new_value)
        cursor = v_end
    out.append(rhs_body[cursor:])
    return lhs + "=" + "".join(out) + trailing, len(replacements)


def v5plus_only_proxy_reason(line):
    """Why an uncommented proxy line cannot exist in v4 at all, or None."""
    proxy_type = extract_proxy_type(line)
    if proxy_type in V5PLUS_ONLY_PROXY_TYPES:
        return proxy_type
    if proxy_type == "snell":
        ver = extract_proxy_option(line, "version")
        if ver is not None and ver.isdigit() and int(ver) > SNELL_MAX_V4_VERSION:
            return f"snell version={ver}"
    return None


def snell_legacy_line(line, legacy):
    """Point a snell version=6+ node at the server's v4-compatible instance.

    Reuses the Layer-1 comma-span lexer so quoted values (e.g. a PSK containing
    `version=3`) and inline comments are never corrupted while untouched spacing
    remains byte-for-byte identical.
    """
    if "=" not in line:
        return line
    lhs, rhs = line.split("=", 1)
    rhs_body, trailing = split_inline_comment(rhs)
    spans = _split_top_level_comma_spans(rhs_body, track_parens=False)
    replacements = []

    def _replace_positional(span_idx, new_val):
        if span_idx >= len(spans):
            return
        start, end = spans[span_idx]
        seg = rhs_body[start:end]
        stripped = seg.strip()
        if not stripped:
            return
        lead = len(seg) - len(seg.lstrip())
        replacements.append((start + lead, start + lead + len(stripped), new_val))

    if "server" in legacy:
        _replace_positional(1, legacy["server"])
    if "port" in legacy:
        _replace_positional(2, legacy["port"])

    for idx in range(3, len(spans)):
        start, end = spans[idx]
        seg = rhs_body[start:end]
        stripped = seg.strip()
        if "=" not in stripped or stripped.startswith('"'):
            continue
        eq_rel = seg.find("=")
        key = seg[:eq_rel].strip().lower()
        val_part = seg[eq_rel + 1:]
        val_stripped = val_part.strip()
        if key == "version":
            new_val = "4"
        elif key == "psk" and "psk" in legacy:
            new_val = legacy["psk"]
        else:
            continue
        val_lead = len(val_part) - len(val_part.lstrip())
        v_start = start + eq_rel + 1 + val_lead
        replacements.append((v_start, v_start + len(val_stripped), new_val))

    if not replacements:
        return line
    replacements.sort(key=lambda r: r[0])
    out = []
    cursor = 0
    for r_start, r_end, new_val in replacements:
        out.append(rhs_body[cursor:r_start])
        out.append(new_val)
        cursor = r_end
    out.append(rhs_body[cursor:])
    return lhs + "=" + "".join(out) + trailing


def transform_proxy_line(line, stats, filename, line_num, section, legacy=None):
    """Transform a single live line in [Proxy] section."""
    proxy_type = extract_proxy_type(line)
    if not proxy_type:
        return line

    name = line.split("=", 1)[0].strip()

    reason = v5plus_only_proxy_reason(line)
    if reason and legacy and proxy_type == "snell":
        line = snell_legacy_line(line, legacy)
        stats.count_params(filename, 1 + len(legacy))
        stats.add_change(
            filename, line_num, section, f"{reason} → version=4",
            f"{name} (旧版实例: {', '.join(legacy)})",
        )
        reason = None
    if reason:
        stats.count_commented(filename)
        stats.add_change(filename, line_num, section, "注释", f"{name} ({reason})")
        return comment_line(line)

    modified = line

    if proxy_type == "snell":
        new, n = _replace_proxy_option_value(modified, "version", "5", "4")
        if n:
            modified = new
            stats.count_params(filename, n)
            stats.add_change(filename, line_num, section, "version=5 → version=4", name)

    new, n = _replace_proxy_option_value(modified, "shadow-tls-version", "3", "2")
    if n:
        modified = new
        stats.count_params(filename, n)
        stats.add_change(filename, line_num, section, "shadow-tls-version=3 → 2", name)

    modified, removed = remove_proxy_params(modified, V5PLUS_ONLY_PROXY_PARAMS)
    stats.count_params(filename, len(removed))
    for param in removed:
        stats.add_change(filename, line_num, section, "移除参数", f"{param} ({name})")

    return modified


def is_proxy_definition(body):
    """Strictly check that body is `name = type, host, port[, key=value...]`."""
    if "=" not in body:
        return False
    name, rest = body.split("=", 1)
    if not name.strip():
        return False
    rhs_body, _ = split_inline_comment(rest)
    tokens = _split_top_level_commas(rhs_body, track_parens=False)
    if len(tokens) < 3 or tokens[0].lower() not in HOST_PORT_PROXY_TYPES:
        return False
    host, port = tokens[1], tokens[2]
    if not host or "=" in host or " " in host or not port.isdigit():
        return False
    return all(re.match(r'^[\w-]+\s*=', t) for t in tokens[3:])


def transform_commented_proxy_line(line, stats, filename, line_num, section):
    """Apply proxy-line transforms to a commented-out node, preserving prefix."""
    if line.startswith(("# [V5+] ", CASCADE_TAG)):
        return line
    m = _COMMENT_PREFIX_RE.match(line)
    if not m:
        return line
    prefix, body = line[:m.end()], line[m.end():]
    if not is_proxy_definition(body) or v5plus_only_proxy_reason(body):
        return line
    return prefix + transform_proxy_line(body, stats, filename, line_num, section)


def transform_proxy_group_line(line, stats, filename, line_num, section):
    """Transform direct hits in [Proxy Group] section (smart -> url-test)."""
    if is_comment_line(line):
        return line
    m = re.match(r'^([^=]+=\s*)smart\b(.*)', line)
    if m:
        name = line.split("=", 1)[0].strip()
        stats.count_params(filename)
        stats.add_change(filename, line_num, section, "smart → url-test", name)
        return m.group(1) + "url-test" + m.group(2)
    return line


def transform_rule_line(line, stats, filename, line_num, section):
    """Transform a single line in [Rule] section via unified RuleNode AST."""
    stripped = line.lstrip()
    if not stripped or is_comment_line(stripped):
        return line

    node = parse_rule_line(line)
    if node is None:
        return line

    changed, must_comment, removed, _ = _transform_rule_ast(node, negated=False)
    if must_comment:
        stats.count_commented(filename)
        stats.add_change(filename, line_num, section, "注释", stripped)
        return comment_line(line)
    if not changed:
        return line

    indent = line[:len(line) - len(stripped)]
    rendered = render_rule_node(node)
    stats.count_params(filename, len(removed))
    for opt in removed:
        stats.add_change(filename, line_num, section, "移除参数", f"{opt} ({rendered})")
    return indent + rendered


def transform_general_line(line, stats, filename, line_num, section):
    """Transform a single line in [General] section."""
    stripped = line.lstrip()
    if is_comment_line(stripped):
        return line
    for param in V5PLUS_ONLY_GENERAL_PARAMS:
        if re.match(rf'^{re.escape(param)}\s*=', stripped):
            stats.count_commented(filename)
            stats.add_change(filename, line_num, section, "注释", param)
            return comment_line(line)
    return line


def convert_content(content, base_dir, stats, processed_files, default_section=None, filename="",
                    legacy=None):
    """Convert configuration content from v5+ to v4 format (direct hits only)."""
    lines = content.splitlines()
    result = []
    current_section = default_section
    in_v5plus_only_section = False

    for line_num, line in enumerate(lines, 1):
        stripped = line.strip()

        section_name = parse_section_header(line, include_v5_commented=False)
        if section_name is not None:
            if is_v5plus_only_section(section_name):
                in_v5plus_only_section = True
                current_section = section_name
                stats.count_commented(filename)
                stats.add_change(filename, line_num, current_section, "注释段", f"[{section_name}]")
                result.append(comment_line(line))
                continue
            in_v5plus_only_section = False
            current_section = section_name
            result.append(line)
            continue

        if in_v5plus_only_section:
            if stripped:
                stats.count_commented(filename)
                result.append(comment_line(line))
            else:
                result.append(line)
            continue

        if stripped.startswith("#!") or is_comment_line(line):
            result.append(line)
            continue

        if current_section == "General":
            result.append(transform_general_line(line, stats, filename, line_num, current_section))
        elif current_section == "Proxy":
            result.append(transform_proxy_line(
                line, stats, filename, line_num, current_section, legacy))
        elif current_section == "Proxy Group":
            result.append(transform_proxy_group_line(line, stats, filename, line_num, current_section))
        elif current_section == "Rule":
            result.append(transform_rule_line(line, stats, filename, line_num, current_section))
        else:
            result.append(line)

    return _serialize_lines(result, content)


# ---------------------------------------------------------------------------
# Layer 4 & 5: Pipeline (discover -> analyze -> emit)
# ---------------------------------------------------------------------------

def _section_is_loaded(loaded_set, section):
    """Return True if section is loaded (None means all sections, i.e. root)."""
    return loaded_set is None or section in loaded_set


def _wireguard_keys_complete(keys):
    """Return True if keys satisfy Surge's required [WireGuard <name>] fields."""
    return (
        "private-key" in keys
        and ("self-ip" in keys or "self-ip-v6" in keys)
        and "peer" in keys
    )


@dataclass
class FileState:
    """Intermediate state for one file during the three-phase conversion pipeline."""
    abs_path: str
    original: str
    converted: str
    is_managed: bool
    default_section: str = None
    is_abandoned: bool = False
    output_written: bool = False
    output_path: str = None
    policy_paths_discovered: bool = False
    had_initial_live_proxies: bool = False
    initial_proxies: set = field(default_factory=set)
    lines: list = field(default_factory=list)
    sections: list = field(default_factory=list)
    group_records: dict = field(default_factory=dict)  # line_idx -> _GroupRecordIR
    owned_proxies: set = field(default_factory=set)
    owned_groups: set = field(default_factory=set)
    owned_wireguard_sections: list = field(default_factory=list)
    owned_rulesets: set = field(default_factory=set)
    has_unexpanded_wg_wildcard: bool = False
    has_unexpanded_ruleset_wildcard: bool = False
    managed_wildcard_targets: set = field(default_factory=set)
    wg_lost_supply: set = field(default_factory=set)
    self_deleted_proxies: set = field(default_factory=set)
    self_deleted_groups: set = field(default_factory=set)


class Pipeline:
    """Three-phase converter: discover -> analyze -> emit."""

    def __init__(self, stats, processed_files=None, snell_legacy=None, output_dir=None):
        self.stats = stats
        self.snell_legacy = snell_legacy or {}
        self.output_dir = os.path.abspath(output_dir) if output_dir is not None else None
        self.root_output_dir = self.output_dir
        self.files = {}                  # canonical abs_path -> FileState (insertion order = root first)
        self.ruleset_files = {}          # canonical abs_path -> raw bytes for copied local RULE-SET / DOMAIN-SET
        self._source_id_to_path = {}     # (st_dev, st_ino) -> canonical abs_path for physical source dedup
        self._source_key_to_path = {}    # volume key -> canonical abs_path fallback
        self.processed_files = processed_files if processed_files is not None else {}
        self.abandoned_files = set()
        self.global_deleted = set()
        self.dead_wg_sections = set()
        self.ruleset_wildcard_sources = {}  # root abs_path -> [target abs_path]
        self.reachable = set()
        self.emitting = set()

    def _root_abs(self):
        return next(iter(self.files))

    def _canonical_source_path(self, path, register=False):
        """Deduplicate alternate path spellings of the same physical source file
        (e.g. Provider.dconf vs provider.dconf on case-insensitive APFS)."""
        abs_path = os.path.abspath(path)
        ident = _file_identity(abs_path)
        if ident is not None and ident in self._source_id_to_path:
            return self._source_id_to_path[ident]
        vol_key = _volume_path_key(abs_path, follow_symlinks=True)
        if vol_key in self._source_key_to_path:
            return self._source_key_to_path[vol_key]
        if register:
            if ident is not None:
                self._source_id_to_path[ident] = abs_path
            self._source_key_to_path[vol_key] = abs_path
        return abs_path

    def _resolve_local_path(self, ref, base_dir, prefer_root=False):
        """Resolve a local reference path relative to base_dir (or root dir first
        when prefer_root=True, matching Surge's Detached Profile Section lookup)
        and canonicalize existing source files by physical identity."""
        if prefer_root and self.files:
            root_dir = os.path.dirname(self._root_abs())
            root_cand = os.path.normpath(os.path.join(root_dir, ref))
            if os.path.isfile(root_cand) or root_dir == base_dir:
                return self._canonical_source_path(root_cand)
            local_cand = os.path.normpath(os.path.join(base_dir, ref))
            if os.path.isfile(local_cand):
                return self._canonical_source_path(local_cand)
            return self._canonical_source_path(root_cand)
        return self._canonical_source_path(os.path.normpath(os.path.join(base_dir, ref)))

    def discover(self, input_path, default_section=None, is_root=None):
        """Read a file, apply direct v5+ hits, build structured ProxyGroup IR,
        and recurse into Surge-loaded local dependencies.

        Surge executes #!include strictly one hop from the root profile (never
        recursively inside detached sub-files), while policy-path is loaded from
        any loaded [Proxy Group] (root or 1-hop included [Proxy Group] file).
        """
        if is_root is None:
            is_root = (len(self.files) == 0)
        abs_path = self._canonical_source_path(input_path, register=False)
        if is_root and self.root_output_dir is None:
            self.root_output_dir = os.path.join(os.path.dirname(abs_path), V4_SUBDIR)

        if abs_path in self.files:
            existing = self.files[abs_path]
            if (is_root or default_section == "Proxy Group") and not existing.policy_paths_discovered:
                self._discover_policy_paths(existing)
            return existing
        if not os.path.isfile(abs_path):
            return None
        abs_path = self._canonical_source_path(abs_path, register=True)

        try:
            with open(abs_path, "r", encoding="utf-8-sig") as f:
                original = f.read()
        except (OSError, UnicodeDecodeError) as e:
            print(f"错误: 无法读取文件: {abs_path} ({e})", file=sys.stderr)
            return None

        state = FileState(
            abs_path=abs_path,
            original=original,
            converted=original,
            is_managed=is_managed_config(original),
            default_section=default_section,
        )
        self.files[abs_path] = state

        base_dir = os.path.dirname(abs_path)
        basename = os.path.basename(abs_path)
        state.converted = convert_content(
            original, base_dir, self.stats, self.processed_files,
            default_section=default_section,
            filename=basename,
            legacy=self.snell_legacy.get(basename),
        )

        orig_lines = original.splitlines()
        state.lines = state.converted.splitlines()
        # Derive section ownership strictly from LIVE headers in the original input
        # so pre-existing `# [V5+] [Section]` comments never hijack later lines.
        state.sections = compute_live_sections(orig_lines, default_section)

        # Catalog definitions and build structured [Proxy Group] IR ONCE.
        for i, line in enumerate(state.lines):
            section = state.sections[i]
            live_header = parse_section_header(line, include_v5_commented=False)
            if live_header and live_header.startswith("WireGuard ") and live_header != "WireGuard *":
                wg_name = live_header[len("WireGuard "):].strip()
                if wg_name and wg_name not in state.owned_wireguard_sections:
                    state.owned_wireguard_sections.append(wg_name)
                continue
            if i < len(orig_lines):
                orig_hdr = parse_section_header(orig_lines[i], include_v5_commented=False)
                if orig_hdr and orig_hdr.startswith("Ruleset ") and orig_hdr != "Ruleset *":
                    rs_name = orig_hdr[len("Ruleset "):].strip()
                    if rs_name:
                        state.owned_rulesets.add(rs_name)
                    continue
            if section == "Proxy":
                if line.startswith("# [V5+] ") and (i >= len(orig_lines) or line != orig_lines[i]):
                    raw = line[len("# [V5+] "):]
                    if "=" in raw:
                        name = raw.split("=", 1)[0].strip()
                        if name:
                            state.self_deleted_proxies.add(unquote(name))
                elif not is_comment_line(line) and "=" in line:
                    name = line.split("=", 1)[0].strip()
                    if name:
                        state.owned_proxies.add(unquote(name))
            elif section == "Proxy Group":
                rec = _build_group_record(line)
                if rec is not None:
                    state.group_records[i] = rec
                    state.owned_groups.add(unquote(rec.name))

        state.initial_proxies = set(state.owned_proxies) | set(state.self_deleted_proxies)
        state.had_initial_live_proxies = bool(state.initial_proxies)

        # Surge executes #!include (and wildcard section includes) only from root.
        if is_root:
            for i, line in enumerate(state.lines):
                stripped = line.lstrip()
                section = state.sections[i]
                if stripped.startswith("#!include"):
                    for entry in parse_include_list(line) or []:
                        self._discover_ref(base_dir, entry, section)
                elif (section in ("WireGuard *", "Ruleset *")
                        and line.startswith("# [V5+] ")
                        and i < len(orig_lines)
                        and line != orig_lines[i]):
                    inner = line[len("# [V5+] "):]
                    if inner.lstrip().startswith("#!include"):
                        for entry in parse_include_list(inner) or []:
                            self._discover_ref(base_dir, entry, None)

        if is_root or default_section == "Proxy Group":
            self._discover_policy_paths(state)

        return state

    def _discover_policy_paths(self, state):
        state.policy_paths_discovered = True
        base_dir = os.path.dirname(state.abs_path)
        for rec in state.group_records.values():
            for opt in rec.options:
                if opt.key.lower() == "policy-path" and opt.policy_path is not None:
                    if opt.policy_path.startswith(("http://", "https://")):
                        continue
                    abs_path = self._resolve_local_path(opt.policy_path, base_dir, prefer_root=True)
                    if os.path.isfile(abs_path):
                        self.discover(abs_path, default_section="Proxy", is_root=False)

    def _discover_ref(self, base_dir, ref, default_section):
        if ref.startswith(("http://", "https://")):
            return
        abs_path = self._resolve_local_path(ref, base_dir, prefer_root=False)
        if os.path.isfile(abs_path):
            self.discover(abs_path, default_section=default_section, is_root=False)

    def _output_path(self, abs_path):
        return make_v4_filename(abs_path, output_dir=self.root_output_dir)

    def _pending_change(self, state, loaded_set=None):
        """True if any loaded section of state differs from original (including
        dirty or v5-escape-bearing [Proxy Group] IR records)."""
        for idx, rec in state.group_records.items():
            if _section_is_loaded(loaded_set, state.sections[idx]) and rec.needs_v4_writeback():
                return True
        if loaded_set is None:
            return _serialize_lines(state.lines, state.original) != state.original
        orig_lines = state.original.splitlines()
        orig_sections = compute_live_sections(orig_lines, state.default_section)
        orig_loaded = [l for l, s in zip(orig_lines, orig_sections) if s in loaded_set]
        cur_loaded = [l for l, s in zip(state.lines, state.sections) if s in loaded_set]
        return orig_loaded != cur_loaded

    def _live_local_refs(self, state, include_directives=True):
        """(abs_path, kind, section) for live #!include (root only) and policy-path refs."""
        refs = []
        base_dir = os.path.dirname(state.abs_path)
        for i, line in enumerate(state.lines):
            stripped = line.lstrip()
            if include_directives and stripped.startswith("#!include"):
                for entry in parse_include_list(line) or []:
                    if not entry.startswith(("http://", "https://")):
                        refs.append((
                            self._resolve_local_path(entry, base_dir, prefer_root=False),
                            "include", state.sections[i],
                        ))
            elif i in state.group_records:
                rec = state.group_records[i]
                if rec.commented_out:
                    continue
                for opt in rec.options:
                    if (opt.key.lower() == "policy-path"
                            and opt.policy_path is not None
                            and not opt.policy_path.startswith(("http://", "https://"))):
                        refs.append((
                            self._resolve_local_path(opt.policy_path, base_dir, prefer_root=True),
                            "policy-path", state.sections[i],
                        ))
        return refs

    def _loaded_state(self):
        """Return (loaded_sections, global_proxy_files) following exact Surge
        Detached Profile Section semantics:
          - #!include is executed ONLY in the root profile (1-hop) and loads
            ONLY section [S] of each target file.
          - policy-path inside any loaded [Proxy Group] (root or 1-hop included
            [Proxy Group] file) loads ONLY [Proxy] privately for the owning
            group (never enters global_proxy_files).
        """
        loaded = {}
        global_proxy_files = set()
        root_abs = self._root_abs()
        if self.files[root_abs].is_abandoned:
            return loaded, global_proxy_files
        loaded[root_abs] = None
        global_proxy_files.add(root_abs)
        stack = [root_abs]
        while stack:
            cur = stack.pop()
            cur_loaded = loaded[cur]
            for ref, kind, section in self._live_local_refs(
                self.files[cur], include_directives=(cur == root_abs)
            ):
                if not _section_is_loaded(cur_loaded, section):
                    continue
                sub = self.files.get(ref)
                if sub is None or sub.is_abandoned:
                    continue
                target_sec = "Proxy" if kind == "policy-path" else section
                changed = False
                if (kind == "include" and target_sec == "Proxy"
                        and cur == root_abs and ref not in global_proxy_files):
                    global_proxy_files.add(ref)
                    changed = True
                prev = loaded.get(ref)
                if prev is None and ref in loaded:
                    pass
                elif prev is None:
                    loaded[ref] = {target_sec}
                    changed = True
                elif target_sec not in prev:
                    prev.add(target_sec)
                    changed = True
                if changed:
                    stack.append(ref)
        return loaded, global_proxy_files

    def _loaded_sections(self):
        return self._loaded_state()[0]

    def _live_names(self):
        """Global policy names (proxies from global_proxy_files + loaded groups)
        that still have a surviving definition in the output."""
        live = set()
        loaded_map, global_proxy_files = self._loaded_state()
        for abs_path, loaded_set in loaded_map.items():
            state = self.files[abs_path]
            if state.is_abandoned:
                continue
            if abs_path in global_proxy_files:
                live |= state.owned_proxies - state.self_deleted_proxies
            if _section_is_loaded(loaded_set, "Proxy Group"):
                live |= state.owned_groups - state.self_deleted_groups
        return live

    def _file_has_live_proxies(self, abs_path):
        state = self.files.get(abs_path)
        if state is None or state.is_abandoned:
            return False
        return bool(state.owned_proxies - state.self_deleted_proxies)

    def _root_has_remote_proxy_include(self):
        root_state = self.files[self._root_abs()]
        if root_state.is_abandoned:
            return False
        for i, line in enumerate(root_state.lines):
            if root_state.sections[i] == "Proxy" and line.lstrip().startswith("#!include"):
                if any(e.startswith(("http://", "https://")) for e in parse_include_list(line) or []):
                    return True
        return False

    def _build_group_index(self, loaded_map, include_abandoned=False):
        """Map unquoted group name -> [(FileState, line_idx, _GroupRecordIR)]
        for all [Proxy Group] definitions in loaded_map."""
        index = {}
        for abs_path, loaded_set in loaded_map.items():
            if not _section_is_loaded(loaded_set, "Proxy Group"):
                continue
            st = self.files.get(abs_path)
            if st is None or (st.is_abandoned and not include_abandoned):
                continue
            for idx, rec in st.group_records.items():
                if not include_abandoned and rec.commented_out:
                    continue
                index.setdefault(unquote(rec.name), []).append((st, idx, rec))
        return index

    def _group_member_supply(self, state, rec, group_index, global_deleted,
                             global_proxies, use_initial, visited=None, memo=None):
        """Recursively compute:
          (definite_names, uncertain_names, has_unknown_supply,
           unverifiable_patterns, supply_sig, hit_cycle)
        for a [Proxy Group] either BEFORE conversion (use_initial=True) or
        AFTER current deletions (use_initial=False).

        - `definite_names` / `uncertain_names` are pure `frozenset[str]` using
          Kleene 3-valued propagation across nested `policy-regex-filter`s.
        - `supply_sig` is a 16-byte BLAKE2b Merkle DAG digest over every
          post-filter contributing source feeding this group (explicit members,
          contributing `include-all-proxies` / `policy-path` proxies, and each
          contributing `include-other-group` child's key, kept names, and own
          `supply_sig`). Any removal or mutation of a contributing path at any
          nesting depth changes `supply_sig` while keeping diamond DAGs O(V+E).

        Per Surge semantics:
          - Explicit static members are unfiltered.
          - policy-path proxies are filtered by this group's policy-regex-filter
            FIRST, then prefixed with external-policy-name-prefix before being
            exposed to parent include-other-group consumers.
          - include-all-proxies and include-other-group members are filtered by
            this group's policy-regex-filter.
        """
        if visited is None:
            visited = set()
        visit_key = (state.abs_path, id(rec))
        if memo is not None and visit_key in memo:
            m_def, m_unc, m_unk, m_unv, m_sig = memo[visit_key]
            return m_def, m_unc, m_unk, m_unv, m_sig, False
        if visit_key in visited:
            cyc_sig = hashlib.blake2b(
                f"CYCLE:{state.abs_path}:{id(rec)}".encode("utf-8"), digest_size=16
            ).digest()
            return frozenset(), frozenset(), False, (), cyc_sig, True
        visited = visited | {visit_key}

        base_dir = os.path.dirname(state.abs_path)
        matcher = rec.compiled_regex_filter()
        prefix = rec.external_policy_name_prefix()

        def _eval_names(names):
            if not names:
                return set(), set()
            if matcher is None:
                return set(names), set()
            return matcher.match_set(names)

        definite = set()
        uncertain = set()
        has_unknown = False
        hit_cycle = False
        unverifiable = []
        self_unv = False
        sig_parts = []

        # 1. Explicit static members (definite, unfiltered by policy-regex-filter)
        if use_initial:
            explicit_names = {unquote(m) for m in (rec.initial_members or rec.members)}
        else:
            explicit_names = {
                unquote(m) for m in rec.members if unquote(m) not in global_deleted
            }
        definite |= explicit_names
        for nm in sorted(explicit_names):
            sig_parts.append(("E", nm))

        # 2. Dynamic imported sources
        opts = (rec.initial_options or rec.options) if use_initial else rec.options
        has_include_all = False
        pp_remote_urls = set()
        pp_missing_paths = set()
        pp_local_pools = {}
        iog_missing_groups = set()
        iog_targets = {}

        for opt in opts:
            kl = opt.key.lower()
            if kl == "include-all-proxies" and opt.raw_value.strip() in {"1", "true"}:
                has_include_all = True
            elif kl == "policy-path" and opt.policy_path is not None:
                if opt.policy_path.startswith(("http://", "https://")):
                    has_unknown = True
                    pp_remote_urls.add(opt.policy_path)
                else:
                    ref_abs = self._resolve_local_path(opt.policy_path, base_dir, prefer_root=True)
                    st = self.files.get(ref_abs)
                    if st is None:
                        if ref_abs not in self.abandoned_files:
                            has_unknown = True
                            pp_missing_paths.add(ref_abs)
                    elif use_initial:
                        pp_local_pools.setdefault(ref_abs, set()).update(st.initial_proxies)
                    elif not st.is_abandoned:
                        pp_local_pools.setdefault(ref_abs, set()).update(
                            st.owned_proxies - st.self_deleted_proxies
                        )
            elif kl == "include-other-group" and opt.iog_groups is not None:
                groups = (
                    (opt.initial_iog_groups if opt.initial_iog_groups is not None else opt.iog_groups)
                    if use_initial else opt.iog_groups
                )
                for g in groups:
                    if not use_initial and g in global_deleted:
                        continue
                    targets = group_index.get(g)
                    if not targets:
                        has_unknown = True
                        iog_missing_groups.add(g)
                        continue
                    for sub_state, _, sub_rec in targets:
                        if not use_initial and sub_rec.commented_out:
                            continue
                        sub_key = (g, sub_state.abs_path, id(sub_rec))
                        if sub_key not in iog_targets:
                            iog_targets[sub_key] = (sub_state, sub_rec)

        # 2a. include-all-proxies
        if has_include_all:
            if self._root_has_remote_proxy_include():
                has_unknown = True
                sig_parts.append(("AR",))
            else:
                all_def, all_unc = _eval_names(global_proxies)
                if all_unc:
                    self_unv = True
                definite |= all_def
                uncertain |= all_unc
                if all_def or all_unc:
                    sig_parts.append(("A", tuple(sorted(all_def)), tuple(sorted(all_unc))))

        # 2b. policy-path (filter first, then apply external-policy-name-prefix)
        for url in sorted(pp_remote_urls):
            sig_parts.append(("PR", url))
        for ref_abs in sorted(pp_missing_paths):
            sig_parts.append(("PM", ref_abs))
        for ref_abs in sorted(pp_local_pools):
            pp_def, pp_unc = _eval_names(pp_local_pools[ref_abs])
            if pp_unc:
                self_unv = True
            if prefix:
                definite |= {prefix + n for n in pp_def}
                uncertain |= {prefix + n for n in pp_unc}
            else:
                definite |= pp_def
                uncertain |= pp_unc
            if pp_def or pp_unc:
                sig_parts.append(("P", ref_abs, tuple(sorted(pp_def)), tuple(sorted(pp_unc))))

        # 2c. include-other-group (preserve every contributing child's Merkle digest)
        for g in sorted(iog_missing_groups):
            sig_parts.append(("GM", g))
        for sub_key in sorted(iog_targets):
            g, sub_path, sub_id = sub_key
            sub_state, sub_rec = iog_targets[sub_key]
            sub_def, sub_unc, sub_unk, sub_unv, sub_sig, sub_cycle = self._group_member_supply(
                sub_state, sub_rec, group_index, global_deleted,
                global_proxies, use_initial, visited=visited, memo=memo,
            )
            has_unknown = has_unknown or sub_unk
            hit_cycle = hit_cycle or sub_cycle

            kept_def, unc_from_def = _eval_names(sub_def)
            unc_def_match, unc_from_unc = _eval_names(sub_unc)
            kept_unc_from_unc = unc_def_match | unc_from_unc
            if unc_from_def or unc_from_unc:
                self_unv = True
            definite |= kept_def
            uncertain |= unc_from_def | kept_unc_from_unc
            if kept_unc_from_unc and sub_unv:
                unverifiable.extend(sub_unv)
            if sub_unk or kept_def or unc_from_def or kept_unc_from_unc:
                sig_parts.append((
                    "G", g, sub_path, sub_id, sub_unk,
                    tuple(sorted(kept_def)),
                    tuple(sorted(unc_from_def)),
                    tuple(sorted(kept_unc_from_unc)),
                    sub_sig,
                ))

        if self_unv and matcher is not None:
            unverifiable.append((os.path.basename(state.abs_path), rec.name, matcher.pattern))

        h = hashlib.blake2b(digest_size=16)
        for part in sig_parts:
            h.update(repr(part).encode("utf-8"))
            h.update(b"\0")
        supply_sig = h.digest()

        res = (
            frozenset(definite),
            frozenset(uncertain),
            has_unknown,
            tuple(dict.fromkeys(unverifiable)),
            supply_sig,
        )
        if memo is not None and not hit_cycle:
            memo[visit_key] = res
        return res[0], res[1], res[2], res[3], res[4], hit_cycle

    def _group_lost_all_members(self, state, rec, initial_group_index, current_group_index,
                                global_deleted, initial_global_proxies, current_global_proxies,
                                initial_memo=None, current_memo=None):
        """Return (had_initial, has_current, unverifiable_error_list) using
        3-valued member certainty (definite vs uncertain) + Merkle DAG supply digest:

          - Cascade (`had_initial and not has_current`) ONLY when the group is
            PROVEN non-empty before conversion (`init_def` or `init_unk`) AND
            PROVEN empty after conversion (empty `cur_def`, `cur_unc`, `not cur_unk`).
          - Fail closed (report `unv_errors`) when the group has NO definite
            surviving member (`not cur_def and not cur_unk`) AND either:
              1. `cur_unc` is non-empty and the group's post-filter Merkle
                 dependency DAG changed during conversion (`init_sig != cur_sig`), OR
              2. `cur_unc` is empty, `init_def` was empty (`not init_unk`), and
                 `init_unc` was non-empty (all uncertain initial candidates were
                 removed, so we cannot prove whether the group was originally
                 non-empty and must cascade or originally empty and must stay).
        """
        init_def, init_unc, init_unk, init_unv, init_sig, _ = self._group_member_supply(
            state, rec, initial_group_index, set(), initial_global_proxies,
            use_initial=True, memo=initial_memo,
        )
        cur_def, cur_unc, cur_unk, cur_unv, cur_sig, _ = self._group_member_supply(
            state, rec, current_group_index, global_deleted, current_global_proxies,
            use_initial=False, memo=current_memo,
        )
        init_definitely_nonempty = init_unk or bool(init_def)
        cur_definitely_nonempty = cur_unk or bool(cur_def)
        cur_might_be_nonempty = cur_definitely_nonempty or bool(cur_unc)

        had_initial = init_definitely_nonempty
        has_current = cur_might_be_nonempty

        unv_errors = []
        if not cur_definitely_nonempty:
            supply_changed = (init_sig != cur_sig)
            if cur_unc and supply_changed:
                for fname, gname, pat in cur_unv:
                    unv_errors.append(
                        f"{fname} [{gname}] 无法按 Surge ICU 正则语义验证 policy-regex-filter={pat!r}，"
                        "动态代理池已删减且无法确认剩余匹配成员；已停止导出。"
                    )
            elif not cur_unc and not init_definitely_nonempty and init_unc:
                for fname, gname, pat in init_unv:
                    unv_errors.append(
                        f"{fname} [{gname}] 无法按 Surge ICU 正则语义验证 policy-regex-filter={pat!r}，"
                        "动态代理池已删减且无法确认原策略组是否非空；已停止导出。"
                    )
        return had_initial, has_current, unv_errors

    def _current_global_proxies(self, global_proxy_files):
        live = set()
        for p in global_proxy_files:
            st = self.files.get(p)
            if st is not None and not st.is_abandoned:
                live |= st.owned_proxies - st.self_deleted_proxies
        return live

    def _emitting(self):
        """All-or-nothing over the loaded profile: emit every loaded file iff
        at least one loaded section has a pending change."""
        loaded = self._loaded_sections()
        if not any(self._pending_change(self.files[p], secs) for p, secs in loaded.items()):
            return set()
        return set(loaded)

    def _abandon_state(self, state, loaded_set=None, is_global_proxy=False, wildcard_wg=False):
        if state.is_abandoned:
            return
        state.is_abandoned = True
        self.abandoned_files.add(state.abs_path)
        if is_global_proxy:
            self.global_deleted |= state.owned_proxies
            self.global_deleted |= state.self_deleted_proxies
        if _section_is_loaded(loaded_set, "Proxy Group"):
            self.global_deleted |= state.owned_groups
            self.global_deleted |= state.self_deleted_groups
        for wg_name in state.owned_wireguard_sections:
            if wildcard_wg or _section_is_loaded(loaded_set, f"WireGuard {wg_name}"):
                self.dead_wg_sections.add(wg_name)

    def _expand_wildcard_sections(self):
        """Expand active root [WireGuard *] includes into v4-valid concrete
        [WireGuard <name>] blocks, and catalog active root [Ruleset *] sources
        so references to commented inline rulesets cascade cleanly."""
        root_abs = self._root_abs()
        state = self.files[root_abs]
        if state.is_managed:
            return
        orig_lines = state.original.splitlines()
        base_dir = os.path.dirname(root_abs)
        basename = os.path.basename(root_abs)

        # 1. Catalog active root [Ruleset *] sources (always dead in v4, managed or unmanaged)
        for i, line in enumerate(state.lines):
            if (state.sections[i] != "Ruleset *"
                    or not line.startswith("# [V5+] ")
                    or i >= len(orig_lines)
                    or line == orig_lines[i]):
                continue
            inner = line[len("# [V5+] "):]
            if not inner.lstrip().startswith("#!include"):
                continue
            sources = self.ruleset_wildcard_sources.setdefault(root_abs, [])
            for entry in parse_include_list(inner) or []:
                if entry.startswith(("http://", "https://")):
                    state.has_unexpanded_ruleset_wildcard = True
                    continue
                target_abs = self._resolve_local_path(entry, base_dir, prefer_root=False)
                target = self.files.get(target_abs)
                if target is None:
                    state.has_unexpanded_ruleset_wildcard = True
                elif target_abs not in sources:
                    sources.append(target_abs)

        # 2. Expand active root [WireGuard *] blocks (single pass; Surge is 1-hop)
        existing_wg = set(state.owned_wireguard_sections)
        insertions = []  # (after_idx, [(wg_name, [entries...]), ...])
        i = 0
        n = len(state.lines)
        while i < n:
            if state.sections[i] != "WireGuard *":
                i += 1
                continue
            if i >= len(orig_lines) or parse_section_header(orig_lines[i], include_v5_commented=False) != "WireGuard *":
                i += 1
                continue
            last_nonempty = i
            entries = []
            while i < n and state.sections[i] == "WireGuard *":
                line = state.lines[i]
                if line.strip():
                    last_nonempty = i
                if line.startswith("# [V5+] ") and i < len(orig_lines) and line != orig_lines[i]:
                    inner = line[len("# [V5+] "):]
                    if inner.lstrip().startswith("#!include"):
                        entries.extend(parse_include_list(inner) or [])
                i += 1
            expanded_by_wg = {}
            for entry in entries:
                if entry.startswith(("http://", "https://")):
                    state.has_unexpanded_wg_wildcard = True
                    continue
                target_abs = self._resolve_local_path(entry, base_dir, prefer_root=False)
                target = self.files.get(target_abs)
                if target is None:
                    state.has_unexpanded_wg_wildcard = True
                elif target.is_managed:
                    state.has_unexpanded_wg_wildcard = True
                    if target.owned_wireguard_sections:
                        state.managed_wildcard_targets.add(target_abs)
                else:
                    for wg_name in target.owned_wireguard_sections:
                        if wg_name in existing_wg:
                            continue
                        bucket = expanded_by_wg.setdefault(wg_name, [])
                        if entry not in bucket:
                            bucket.append(entry)
            to_expand = []
            for wg_name, wg_entries in expanded_by_wg.items():
                existing_wg.add(wg_name)
                state.owned_wireguard_sections.append(wg_name)
                to_expand.append((wg_name, wg_entries))
            if to_expand:
                insertions.append((last_nonempty, to_expand))

        if insertions:
            for after_idx, items in reversed(insertions):
                new_lines = []
                new_sections = []
                for wg_name, wg_entries in items:
                    sec_label = f"WireGuard {wg_name}"
                    new_lines.append(f"[{sec_label}]")
                    new_lines.append(format_include_list(wg_entries))
                    new_sections.extend((sec_label, sec_label))
                    self.stats.add_change(
                        basename, after_idx + 2, sec_label,
                        "展开通配段", f"[{sec_label}] ← {', '.join(wg_entries)}",
                    )
                shift = len(new_lines)
                state.lines[after_idx + 1:after_idx + 1] = new_lines
                state.sections[after_idx + 1:after_idx + 1] = new_sections
                state.group_records = {
                    (idx + shift if idx > after_idx else idx): rec
                    for idx, rec in state.group_records.items()
                }

    def _strip_remote_wireguard_includes(self):
        """Strip v5+/v6 remote URL #!include entries inside root's concrete
        [WireGuard <name>] sections without echoing URLs or credentials."""
        root_abs = self._root_abs()
        state = self.files[root_abs]
        if state.is_abandoned:
            return
        basename = os.path.basename(root_abs)
        for i, line in enumerate(state.lines):
            sec = state.sections[i]
            if not (sec and sec.startswith("WireGuard ") and sec != "WireGuard *"):
                continue
            if not line.lstrip().startswith("#!include"):
                continue
            entries = parse_include_list(line) or []
            local_entries = [e for e in entries if not e.startswith(("http://", "https://"))]
            remote_entries = [e for e in entries if e.startswith(("http://", "https://"))]
            if not remote_entries:
                continue
            wg_name = sec[len("WireGuard "):].strip()
            state.wg_lost_supply.add(wg_name)
            count = len(remote_entries)
            if local_entries:
                new_line = format_include_list(local_entries)
                state.lines[i] = _preserve_indent(line, new_line)
                self.stats.add_change(
                    basename, i + 1, sec, "移除远端 include", f"{count} 条远端 include"
                )
            else:
                state.lines[i] = comment_line(line)
                self.stats.count_commented(basename)
                self.stats.add_change(
                    basename, i + 1, sec, "注释", f"{count} 条远端 include"
                )

    def _inspect_wireguard_section(self, abs_path, section_name, follow_includes=True):
        """Inspect a concrete [WireGuard <name>] section (root + 1-hop local
        non-abandoned #!include targets), returning (defined_keys, lost_supply)."""
        state = self.files.get(abs_path)
        if state is None or state.is_abandoned:
            return set(), True
        base_dir = os.path.dirname(abs_path)
        keys = set()
        wg_name = section_name[len("WireGuard "):].strip() if section_name.startswith("WireGuard ") else ""
        lost_supply = wg_name in state.wg_lost_supply
        for i, line in enumerate(state.lines):
            if state.sections[i] != section_name:
                continue
            stripped = line.lstrip()
            if not stripped or parse_section_header(line, include_v5_commented=True) is not None:
                continue
            if stripped.startswith(CASCADE_TAG + "#!include"):
                if follow_includes:
                    lost_supply = True
                continue
            if stripped.startswith("#!include"):
                if not follow_includes:
                    continue
                for entry in parse_include_list(line) or []:
                    if entry.startswith(("http://", "https://")):
                        lost_supply = True
                        continue
                    target = self._resolve_local_path(entry, base_dir, prefer_root=False)
                    sub_keys, sub_lost = self._inspect_wireguard_section(
                        target, section_name, follow_includes=False
                    )
                    keys |= sub_keys
                    lost_supply = lost_supply or sub_lost
                continue
            if is_comment_line(stripped):
                continue
            if "=" in stripped:
                k = stripped.split("=", 1)[0].strip().lower()
                if k:
                    keys.add(k)
        return keys, lost_supply

    def _cleanup_dead_wireguard_sections(self, root_state):
        """Cascade-comment concrete [WireGuard <name>] sections in root that lost
        a supply and no longer satisfy Surge's required fields."""
        root_abs = root_state.abs_path
        basename = os.path.basename(root_abs)
        i = 0
        n = len(root_state.lines)
        changed_any = False
        while i < n:
            hdr = parse_section_header(root_state.lines[i], include_v5_commented=False)
            if not (hdr and hdr.startswith("WireGuard ") and hdr != "WireGuard *"):
                i += 1
                continue
            wg_name = hdr[len("WireGuard "):].strip()
            sec_start = i
            i += 1
            while i < n and root_state.sections[i] == hdr:
                i += 1
            sec_end = i
            keys, lost_supply = self._inspect_wireguard_section(root_abs, hdr, follow_includes=True)
            if lost_supply and not _wireguard_keys_complete(keys):
                self.dead_wg_sections.add(wg_name)
                for idx in range(sec_start, sec_end):
                    stripped = root_state.lines[idx].lstrip()
                    if not stripped:
                        continue
                    if idx == sec_start or not is_comment_line(stripped) or stripped.startswith("#!include"):
                        root_state.lines[idx] = CASCADE_TAG + stripped
                        self.stats.count_commented(basename)
                        changed_any = True
                self.stats.add_change(
                    basename, sec_start + 1, hdr, "级联注释",
                    f"[{hdr}] 缺少必需 WireGuard 字段",
                )
        # Note: in-place line commenting does not change section boundaries or indices.

    def _root_live_wireguard_sections(self):
        """Concrete [WireGuard <name>] sections actually live and usable in root."""
        root_abs = self._root_abs()
        root_state = self.files[root_abs]
        if root_state.is_abandoned:
            return set()
        live_headers = set()
        for line in root_state.lines:
            hdr = parse_section_header(line, include_v5_commented=False)
            if hdr and hdr.startswith("WireGuard ") and hdr != "WireGuard *":
                live_headers.add(hdr[len("WireGuard "):].strip())
        live = set()
        for wg_name in root_state.owned_wireguard_sections:
            if wg_name not in live_headers:
                continue
            keys, lost_supply = self._inspect_wireguard_section(
                root_abs, f"WireGuard {wg_name}", follow_includes=True
            )
            if lost_supply:
                if _wireguard_keys_complete(keys):
                    live.add(wg_name)
            elif keys:
                live.add(wg_name)
        return live

    def _root_dead_rulesets(self):
        """Return (dead_ruleset_names, has_unexpanded_ruleset_wildcard) for
        active inline [Ruleset <name>] / [Ruleset *] sections disabled in root.

        Built-in rule sets (SYSTEM / LAN) always take precedence in Surge and
        are never added to dead_ruleset_names.
        """
        root_abs = self._root_abs()
        root_state = self.files[root_abs]
        if root_state.is_abandoned:
            return set(), False
        dead = set(root_state.owned_rulesets)
        has_unexpanded = root_state.has_unexpanded_ruleset_wildcard
        for src_abs in self.ruleset_wildcard_sources.get(root_abs, []):
            src = self.files.get(src_abs)
            if src is not None:
                dead |= src.owned_rulesets
        dead = {r for r in dead if r.upper() not in BUILTIN_RULESETS}
        return dead, has_unexpanded

    def _has_live_final(self, loaded_map, use_original=False):
        """Return True if any loaded [Rule] section contains an active FINAL rule."""
        for abs_path, loaded_set in loaded_map.items():
            if not _section_is_loaded(loaded_set, "Rule"):
                continue
            state = self.files.get(abs_path)
            if state is None or state.is_abandoned:
                continue
            if use_original:
                lines = state.original.splitlines()
                sections = compute_live_sections(lines, state.default_section)
            else:
                lines = state.lines
                sections = state.sections
            for line, sec in zip(lines, sections):
                if sec == "Rule" and _is_live_final_rule(line):
                    return True
        return False

    def analyze(self):
        """Cross-file cascade fixpoint, structured IR reference rewrite,
        single-pass v4 render, and pre-emit path validation."""
        root_abs = self._root_abs()
        initial_loaded, initial_global = self._loaded_state()
        ever_loaded_sections = {
            p: (None if s is None else set(s)) for p, s in initial_loaded.items()
        }
        ever_global_proxy = set(initial_global)
        initial_global_proxies = set()
        for p in initial_global:
            st = self.files.get(p)
            if st is not None:
                initial_global_proxies |= st.initial_proxies
        initial_group_index = self._build_group_index(initial_loaded, include_abandoned=True)
        initial_group_memo = {}

        def _record_loaded(loaded_map, global_proxy_files):
            ever_global_proxy.update(global_proxy_files)
            for p, secs in loaded_map.items():
                if secs is None:
                    ever_loaded_sections[p] = None
                elif p not in ever_loaded_sections:
                    ever_loaded_sections[p] = set(secs)
                elif ever_loaded_sections[p] is not None:
                    ever_loaded_sections[p].update(secs)

        had_initial_final = self._has_live_final(initial_loaded, use_original=True)
        self._expand_wildcard_sections()
        _record_loaded(*self._loaded_state())

        while True:
            # 1. Abandon any managed file that would need a -v4 copy
            cur_loaded, cur_global = self._loaded_state()
            emitting_now = self._emitting()
            for state in self.files.values():
                if state.is_managed and not state.is_abandoned and state.abs_path in emitting_now:
                    self._abandon_state(
                        state,
                        loaded_set=cur_loaded.get(state.abs_path, set()),
                        is_global_proxy=state.abs_path in cur_global,
                    )
            emitting_now = self._emitting()
            cur_loaded, cur_global = self._loaded_state()
            root_state = self.files[root_abs]
            if not root_state.is_abandoned and root_abs in emitting_now:
                for target_abs in root_state.managed_wildcard_targets:
                    target = self.files.get(target_abs)
                    if target is not None and not target.is_abandoned:
                        self._abandon_state(
                            target,
                            loaded_set=cur_loaded.get(target_abs, set()),
                            is_global_proxy=target_abs in cur_global,
                            wildcard_wg=True,
                        )

            # 2. Seed global deletions ONLY from global_proxy_files (never policy-path-only)
            loaded_map, global_proxy_files = self._loaded_state()
            _record_loaded(loaded_map, global_proxy_files)
            for abs_path in global_proxy_files:
                state = self.files[abs_path]
                if not state.is_abandoned:
                    self.global_deleted |= state.self_deleted_proxies

            # 2a. Strip abandoned policy-path options & abandoned/remote root #!include entries
            global_del_now = self.global_deleted - self._live_names()
            cur_global_proxies = self._current_global_proxies(global_proxy_files)
            cur_group_index = self._build_group_index(loaded_map, include_abandoned=False)
            cur_group_memo = {}
            for abs_path, loaded_set in loaded_map.items():
                state = self.files[abs_path]
                if state.is_abandoned:
                    continue
                if _section_is_loaded(loaded_set, "Proxy Group"):
                    self._strip_abandoned_policy_paths(
                        state, global_del_now, initial_group_index, cur_group_index,
                        initial_global_proxies, cur_global_proxies,
                        initial_memo=initial_group_memo, current_memo=cur_group_memo,
                    )
            if not root_state.is_abandoned:
                self._strip_abandoned_includes(root_state)
                self._strip_remote_wireguard_includes()
                self._cleanup_dead_wireguard_sections(root_state)

            live_wg_sections = self._root_live_wireguard_sections()
            has_unexpanded_wg = root_state.has_unexpanded_wg_wildcard
            dead_rulesets, has_unexpanded_rs = self._root_dead_rulesets()

            # 3. Fixpoint across loaded non-abandoned files (loaded sections only,
            #    strictly separating global vs private proxy namespaces)
            changed = True
            while changed:
                changed = False
                loaded_map, global_proxy_files = self._loaded_state()
                _record_loaded(loaded_map, global_proxy_files)
                cur_group_memo = {}
                for abs_path, loaded_set in loaded_map.items():
                    state = self.files[abs_path]
                    if state.is_abandoned:
                        continue
                    eff_global = self.global_deleted - self._live_names()
                    is_global_proxy = abs_path in global_proxy_files
                    cur_global_proxies = self._current_global_proxies(global_proxy_files)
                    cur_group_index = self._build_group_index(loaded_map, include_abandoned=False)
                    mutated = self._cascade_single_file(
                        state,
                        loaded_set=loaded_set,
                        is_global_proxy_file=is_global_proxy,
                        global_deleted_names=eff_global,
                        initial_group_index=initial_group_index,
                        current_group_index=cur_group_index,
                        initial_global_proxies=initial_global_proxies,
                        current_global_proxies=cur_global_proxies,
                        live_wg_sections=live_wg_sections,
                        has_unexpanded_wg=has_unexpanded_wg,
                        dead_rulesets=dead_rulesets,
                        has_unexpanded_rs=has_unexpanded_rs,
                        initial_memo=initial_group_memo,
                        current_memo=cur_group_memo,
                    )
                    if mutated:
                        changed = True
                        cur_group_memo.clear()

            # 3b. Withdraw names defined only in previously-loaded unreachable subtrees
            self.reachable = set(self._loaded_sections())
            new_withdrawn = set()
            for state in self.files.values():
                if (state.is_abandoned
                        or state.abs_path in self.reachable
                        or state.abs_path not in ever_loaded_sections):
                    continue
                names = set()
                if state.abs_path in ever_global_proxy:
                    names |= state.owned_proxies | state.self_deleted_proxies
                if _section_is_loaded(ever_loaded_sections[state.abs_path], "Proxy Group"):
                    names |= state.owned_groups | state.self_deleted_groups
                new_withdrawn |= names - self.global_deleted
            if new_withdrawn:
                self.global_deleted |= new_withdrawn
                continue

            # 4. Stop when no remaining non-abandoned managed file entered emitting set
            emitting = self._emitting()
            if not any(
                s.is_managed and not s.is_abandoned and s.abs_path in emitting
                for s in self.files.values()
            ):
                break

        # 5. Global fixpoint converged: check FINAL invariant and post-convergence
        #    unverifiable-regex diagnostics on surviving groups only, rewrite
        #    references, then render modified [Proxy Group] IR ONCE to v4.
        final_loaded, final_global_proxy_files = self._loaded_state()
        self.emitting = self._emitting()
        if self.emitting:
            if had_initial_final and not self._has_live_final(final_loaded, use_original=False):
                self.stats.errors.append(
                    "级联清理后 [Rule] 缺少可用的 FINAL 规则（原 FINAL 指向已删除的策略或已放弃的文件），"
                    "请为 v4 指定替代兜底策略；已停止导出。"
                )
            self._check_converged_unverifiable_regexes(
                final_loaded, final_global_proxy_files,
                initial_group_index, initial_global_proxies, initial_group_memo,
            )
            self._rewrite_references(final_loaded)
            self._render_group_records(final_loaded)

        if self.stats.errors:
            self.emitting = set()
            self.ruleset_files.clear()
            return

        # 6. Convert commented-out nodes in emitted files (loaded [Proxy] only),
        #    serialize final text, and validate ALL planned output/backup paths.
        for state in self.files.values():
            if state.is_abandoned:
                continue
            if state.abs_path in self.emitting:
                if _section_is_loaded(final_loaded.get(state.abs_path), "Proxy"):
                    self._convert_commented_proxies(state)
            state.converted = _serialize_lines(state.lines, state.original)

        if self.emitting:
            self._validate_planned_output_paths()
            if self.stats.errors:
                self.emitting = set()
                self.ruleset_files.clear()

    def _check_converged_unverifiable_regexes(self, final_loaded, final_global_proxy_files,
                                              initial_group_index, initial_global_proxies,
                                              initial_group_memo):
        """After the cascade fixpoint has converged, report unverifiable
        policy-regex-filter diagnostics ONLY for surviving, emitted groups whose
        final state still depends on an unverifiable filter."""
        final_global_deleted = self.global_deleted - self._live_names()
        final_global_proxies = self._current_global_proxies(final_global_proxy_files)
        final_group_index = self._build_group_index(final_loaded, include_abandoned=False)
        final_group_memo = {}
        for abs_path, loaded_set in final_loaded.items():
            if not _section_is_loaded(loaded_set, "Proxy Group"):
                continue
            state = self.files[abs_path]
            if state.is_abandoned:
                continue
            for idx in sorted(state.group_records):
                rec = state.group_records[idx]
                if rec.commented_out:
                    continue
                _, _, unv_errors = self._group_lost_all_members(
                    state, rec, initial_group_index, final_group_index,
                    final_global_deleted, initial_global_proxies, final_global_proxies,
                    initial_memo=initial_group_memo, current_memo=final_group_memo,
                )
                for err in unv_errors:
                    if err not in self.stats.errors:
                        self.stats.errors.append(err)

    def _render_group_records(self, loaded_map):
        """Render dirty or v5-escape-bearing [Proxy Group] IR records ONCE into
        final Surge v4 syntax. No parser ever re-parses the line afterwards."""
        for abs_path, loaded_set in loaded_map.items():
            if not _section_is_loaded(loaded_set, "Proxy Group"):
                continue
            state = self.files[abs_path]
            if state.is_abandoned:
                continue
            basename = os.path.basename(abs_path)
            for idx, rec in sorted(state.group_records.items()):
                if not rec.needs_v4_writeback():
                    continue
                if rec.commented_out:
                    state.lines[idx] = rec.render_v4(allow_raw_iog=True)
                    continue
                try:
                    new_line = rec.render_v4(allow_raw_iog=False)
                except ValueError as exc:
                    err_msg = f"{basename}:{idx + 1} [{rec.name}] {exc}"
                    if err_msg not in self.stats.errors:
                        self.stats.errors.append(err_msg)
                    continue
                if new_line != state.lines[idx]:
                    if not rec.dirty and any(opt.iog_had_v5_escape for opt in rec.options):
                        self.stats.count_params(basename)
                        self.stats.add_change(
                            basename, idx + 1, "Proxy Group", "v4 语法改写", rec.name
                        )
                    state.lines[idx] = new_line

    def _convert_commented_proxies(self, state):
        basename = os.path.basename(state.abs_path)
        for i, line in enumerate(state.lines):
            if state.sections[i] == "Proxy":
                state.lines[i] = transform_commented_proxy_line(
                    line, self.stats, basename, i + 1, "Proxy"
                )

    def _rewrite_references(self, loaded_map):
        """Rewrite root #!include lines, [Proxy Group] policy-path IR options,
        and live local RULE-SET / DOMAIN-SET file references to their -v4 names."""
        root_abs = self._root_abs()
        for abs_path, loaded_set in loaded_map.items():
            state = self.files[abs_path]
            if state.is_abandoned:
                continue
            base_dir = os.path.dirname(abs_path)
            basename = os.path.basename(abs_path)
            is_root = (abs_path == root_abs)
            for i, line in enumerate(state.lines):
                sec = state.sections[i]
                if not _section_is_loaded(loaded_set, sec):
                    continue
                if is_root and line.lstrip().startswith("#!include"):
                    entries = parse_include_list(line)
                    if not entries:
                        continue
                    new_entries = []
                    notes = []
                    for entry in entries:
                        if not entry.startswith(("http://", "https://")):
                            ref_abs = self._resolve_local_path(entry, base_dir, prefer_root=False)
                            if ref_abs in self.emitting:
                                rel_v4 = make_v4_relname(os.path.basename(ref_abs))
                                new_entries.append(rel_v4)
                                notes.append(f"{entry} → {rel_v4}")
                                continue
                        new_entries.append(entry)
                    if notes:
                        state.lines[i] = _preserve_indent(line, format_include_list(new_entries))
                        for note in notes:
                            self.stats.add_change(basename, i + 1, sec or "-", "引用改写", note)
                elif i in state.group_records:
                    rec = state.group_records[i]
                    if rec.commented_out:
                        continue
                    for opt in rec.options:
                        if (opt.key.lower() == "policy-path"
                                and opt.policy_path is not None
                                and not opt.policy_path.startswith(("http://", "https://"))):
                            ref_abs = self._resolve_local_path(
                                opt.policy_path, base_dir, prefer_root=True
                            )
                            if ref_abs in self.emitting:
                                old_val = opt.policy_path
                                rel_v4 = make_v4_relname(os.path.basename(ref_abs))
                                opt.policy_path = rel_v4
                                opt.policy_path_dirty = True
                                rec.dirty = True
                                self.stats.add_change(
                                    basename, i + 1, "Proxy Group", "引用改写",
                                    f"policy-path={old_val} → policy-path={rel_v4}",
                                )
                elif sec == "Rule":
                    node = parse_rule_line(line)
                    if node is None:
                        continue

                    def _resolve_rule_file(raw_arg, kind):
                        target = unquote(raw_arg.strip())
                        if not target or target.startswith(("http://", "https://")):
                            return None
                        if kind == "RULE-SET" and target.upper() in BUILTIN_RULESETS:
                            return None
                        ref_abs = self._resolve_local_path(target, base_dir, prefer_root=True)
                        if not os.path.isfile(ref_abs):
                            return None
                        ref_abs = self._canonical_source_path(ref_abs, register=True)
                        if ref_abs not in self.emitting and ref_abs not in self.ruleset_files:
                            try:
                                with open(ref_abs, "rb") as rf:
                                    self.ruleset_files[ref_abs] = rf.read()
                            except OSError as exc:
                                self.stats.errors.append(f"无法读取本地规则集文件: {ref_abs} ({exc})")
                                return None
                        rel_v4 = make_v4_relname(os.path.basename(ref_abs))
                        was_quoted = len(raw_arg.strip()) >= 2 and raw_arg.strip()[0] == '"' and raw_arg.strip()[-1] == '"'
                        new_arg = f'"{_escape_quoted(rel_v4)}"' if (was_quoted or "," in rel_v4 or '"' in rel_v4) else rel_v4
                        return new_arg, f"{target} → {rel_v4}"

                    notes = _rewrite_rule_local_file_targets(node, _resolve_rule_file)
                    if notes:
                        state.lines[i] = _preserve_indent(line, render_rule_node(node))
                        for note in notes:
                            self.stats.add_change(basename, i + 1, "Rule", "引用改写", note)

    def _cascade_single_file(self, state, loaded_set=None, is_global_proxy_file=True,
                             global_deleted_names=None, initial_group_index=None,
                             current_group_index=None, initial_global_proxies=None,
                             current_global_proxies=None, live_wg_sections=None,
                             has_unexpanded_wg=False, dead_rulesets=None,
                             has_unexpanded_rs=False, initial_memo=None,
                             current_memo=None):
        """Fixpoint over loaded sections: cascade deleted proxies/groups through
        underlying-proxy, dead WireGuard sections, unified effective-member
        ProxyGroup evaluation (including recursive include-other-group and
        Surge ICU regex filters), and Rule AST policies & dead RULE-SET refs.

        Returns True if any proxy/group state mutated during this call.
        """
        global_deleted = set(global_deleted_names or ())
        initial_group_index = initial_group_index if initial_group_index is not None else {}
        current_group_index = current_group_index if current_group_index is not None else {}
        initial_global_proxies = initial_global_proxies if initial_global_proxies is not None else set()
        current_global_proxies = current_global_proxies if current_global_proxies is not None else set()
        live_wg_sections = live_wg_sections if live_wg_sections is not None else set()
        dead_rulesets = dead_rulesets if dead_rulesets is not None else set()
        base_dir = os.path.dirname(state.abs_path)
        basename = os.path.basename(state.abs_path)
        mutated_any = False

        def _mark_deleted_proxy(deleted_name):
            state.self_deleted_proxies.add(deleted_name)
            if is_global_proxy_file:
                self.global_deleted.add(deleted_name)
                if deleted_name not in self._live_names():
                    global_deleted.add(deleted_name)

        def _mark_deleted_group(deleted_name):
            state.self_deleted_groups.add(deleted_name)
            self.global_deleted.add(deleted_name)
            if deleted_name not in self._live_names():
                global_deleted.add(deleted_name)

        changed = True
        while changed:
            changed = False
            proxy_deleted = (
                global_deleted if is_global_proxy_file
                else (global_deleted | state.self_deleted_proxies)
            )
            for i, line in enumerate(state.lines):
                section = state.sections[i]
                if not _section_is_loaded(loaded_set, section):
                    continue

                if section == "Proxy":
                    stripped = line.lstrip()
                    if not stripped or is_comment_line(stripped) or "=" not in line:
                        continue
                    name = line.split("=", 1)[0].strip()
                    if not name:
                        continue
                    underlying = extract_proxy_option(line, "underlying-proxy")
                    if underlying and underlying in proxy_deleted:
                        state.lines[i] = CASCADE_TAG + stripped
                        _mark_deleted_proxy(unquote(name))
                        self.stats.count_commented(basename)
                        self.stats.add_change(
                            basename, i + 1, "Proxy", "级联注释",
                            f"{name} (underlying-proxy={underlying})",
                        )
                        changed = True
                        mutated_any = True
                        if current_memo is not None:
                            current_memo.clear()
                        continue
                    if extract_proxy_type(line) == "wireguard":
                        wg_sec = extract_proxy_option(line, "section-name")
                        if (wg_sec and wg_sec not in live_wg_sections
                                and (wg_sec in self.dead_wg_sections or has_unexpanded_wg)):
                            state.lines[i] = CASCADE_TAG + stripped
                            _mark_deleted_proxy(unquote(name))
                            self.stats.count_commented(basename)
                            self.stats.add_change(
                                basename, i + 1, "Proxy", "级联注释",
                                f"{name} (WireGuard {wg_sec})",
                            )
                            changed = True
                            mutated_any = True
                            if current_memo is not None:
                                current_memo.clear()
                    continue

                if section != "Proxy Group" or i not in state.group_records:
                    continue
                rec = state.group_records[i]
                if rec.commented_out:
                    continue

                # Group-level underlying-proxy relay deleted -> cascade whole group
                dead_relay = None
                for opt in rec.options:
                    if opt.key.lower() == "underlying-proxy":
                        relay = unquote(opt.raw_value.strip())
                        if relay in global_deleted:
                            dead_relay = relay
                            break
                if dead_relay is not None:
                    rec.commented_out = True
                    rec.dirty = True
                    _mark_deleted_group(unquote(rec.name))
                    self.stats.count_commented(basename)
                    self.stats.add_change(
                        basename, i + 1, "Proxy Group", "级联注释",
                        f"{rec.name} (underlying-proxy={dead_relay})",
                    )
                    changed = True
                    mutated_any = True
                    if current_memo is not None:
                        current_memo.clear()
                    continue

                orig_members = list(rec.members)
                rec.members = [m for m in orig_members if unquote(m) not in global_deleted]
                removed_tokens = [m for m in orig_members if m not in rec.members]

                new_opts = []
                for opt in rec.options:
                    kl = opt.key.lower()
                    if kl == "include-other-group" and opt.iog_groups is not None:
                        kept = [g for g in opt.iog_groups if g not in global_deleted]
                        dropped = [g for g in opt.iog_groups if g in global_deleted]
                        if not dropped:
                            new_opts.append(opt)
                        elif kept:
                            opt.iog_groups = kept
                            opt.iog_dirty = True
                            new_opts.append(opt)
                            removed_tokens.append(f"{opt.key}:{', '.join(dropped)}")
                        else:
                            removed_tokens.append(f"{opt.key}={opt.raw_value}")
                    else:
                        new_opts.append(opt)
                rec.options = new_opts

                had_initial, has_current, _ = self._group_lost_all_members(
                    state, rec, initial_group_index, current_group_index,
                    global_deleted, initial_global_proxies, current_global_proxies,
                    initial_memo=initial_memo, current_memo=current_memo,
                )

                if had_initial and not has_current:
                    rec.dirty = True
                    rec.commented_out = True
                    _mark_deleted_group(unquote(rec.name))
                    self.stats.count_commented(basename)
                    self.stats.add_change(basename, i + 1, "Proxy Group", "级联注释", rec.name)
                    changed = True
                    mutated_any = True
                    if current_memo is not None:
                        current_memo.clear()
                elif removed_tokens:
                    rec.dirty = True
                    self.stats.add_change(
                        basename, i + 1, "Proxy Group", "级联移除成员",
                        f"{rec.name}: {', '.join(removed_tokens)}",
                    )
                    changed = True
                    mutated_any = True
                    if current_memo is not None:
                        current_memo.clear()

        # Post-fixpoint: comment out loaded [Rule] lines whose policy or RULE-SET is dead
        if not _section_is_loaded(loaded_set, "Rule"):
            return mutated_any
        for i, line in enumerate(state.lines):
            if state.sections[i] != "Rule":
                continue
            node = parse_rule_line(line)
            if node is None:
                continue
            stripped = line.lstrip()
            if node.policy is not None and unquote(node.policy) in global_deleted:
                state.lines[i] = CASCADE_TAG + stripped
                self.stats.count_commented(basename)
                self.stats.add_change(basename, i + 1, "Rule", "级联注释", line.strip())
                continue
            dead_rs = None
            for target in _collect_rule_ruleset_targets(node):
                if target.upper() in BUILTIN_RULESETS:
                    continue
                if target in dead_rulesets:
                    dead_rs = f"内联规则集 {target} 在 v4 不可用"
                    break
                if (has_unexpanded_rs
                        and not target.startswith(("http://", "https://"))
                        and not os.path.isfile(self._resolve_local_path(target, base_dir, prefer_root=True))):
                    dead_rs = f"规则集 {target} 来源在 v4 不可用"
                    break
            if dead_rs is not None:
                state.lines[i] = CASCADE_TAG + stripped
                self.stats.count_commented(basename)
                self.stats.add_change(
                    basename, i + 1, "Rule", "级联注释", f"{line.strip()} ({dead_rs})"
                )
        return mutated_any

    def _strip_abandoned_policy_paths(self, state, global_deleted, initial_group_index,
                                      current_group_index, initial_global_proxies,
                                      current_global_proxies, initial_memo=None,
                                      current_memo=None):
        if not self.abandoned_files:
            return
        base_dir = os.path.dirname(state.abs_path)
        basename = os.path.basename(state.abs_path)
        for i, rec in state.group_records.items():
            if rec.commented_out or state.sections[i] != "Proxy Group":
                continue
            new_opts = []
            removed_values = []
            for opt in rec.options:
                if (opt.key.lower() == "policy-path"
                        and opt.policy_path is not None
                        and not opt.policy_path.startswith(("http://", "https://"))
                        and self._resolve_local_path(opt.policy_path, base_dir, prefer_root=True) in self.abandoned_files):
                    removed_values.append(opt.policy_path)
                    continue
                new_opts.append(opt)
            if not removed_values:
                continue
            rec.options = new_opts
            rec.dirty = True
            if current_memo is not None:
                current_memo.clear()
            had_initial, has_current, _ = self._group_lost_all_members(
                state, rec, initial_group_index, current_group_index,
                global_deleted, initial_global_proxies, current_global_proxies,
                initial_memo=initial_memo, current_memo=current_memo,
            )
            if not (had_initial and not has_current):
                self.stats.add_change(
                    basename, i + 1, "Proxy Group",
                    "移除 policy-path", f"{rec.name}: {', '.join(removed_values)}",
                )
            else:
                rec.commented_out = True
                deleted_name = unquote(rec.name)
                state.self_deleted_groups.add(deleted_name)
                self.global_deleted.add(deleted_name)
                if current_memo is not None:
                    current_memo.clear()
                self.stats.count_commented(basename)
                self.stats.add_change(basename, i + 1, "Proxy Group", "级联注释", rec.name)

    def _strip_abandoned_includes(self, state):
        if not self.abandoned_files:
            return
        base_dir = os.path.dirname(state.abs_path)
        basename = os.path.basename(state.abs_path)
        for i, line in enumerate(state.lines):
            if not line.lstrip().startswith("#!include"):
                continue
            entries = parse_include_list(line)
            if entries is None:
                continue
            kept = [
                e for e in entries
                if e.startswith(("http://", "https://"))
                or self._resolve_local_path(e, base_dir, prefer_root=False) not in self.abandoned_files
            ]
            if len(kept) == len(entries):
                continue
            sec = state.sections[i]
            if sec and sec.startswith("WireGuard ") and sec != "WireGuard *":
                state.wg_lost_supply.add(sec[len("WireGuard "):].strip())
            if not kept:
                state.lines[i] = CASCADE_TAG + line.lstrip()
                self.stats.count_commented(basename)
                self.stats.add_change(basename, i + 1, "#!include", "级联注释", line.strip())
            else:
                new_line = format_include_list(kept)
                state.lines[i] = _preserve_indent(line, new_line)
                removed_entries = [e for e in entries if e not in kept]
                self.stats.add_change(
                    basename, i + 1, "#!include",
                    "移除 include 条目", ", ".join(removed_entries),
                )

    def _validate_planned_output_paths(self):
        """Verify every planned output and -deprecated backup path is free of:
          1. overlap with any source file in this run (by literal key,
             symlink-resolved target key, or inode — including dangling symlinks),
          2. collisions across emitted configs/rulesets/backups on the target
             volume (case-insensitivity, Unicode normalization, symlink aliases),
          3. filesystem filename/path length limits (via zero-write os.lstat).
        Uses the exact same _output_unchanged() predicate as emit() so backup
        decisions never diverge between preflight and writeback.
        """
        planned_writes = []  # (src_abs, planned_content, is_binary)
        for abs_path in sorted(self.emitting):
            state = self.files[abs_path]
            if state.is_abandoned or abs_path not in self.reachable:
                continue
            planned_writes.append((abs_path, state.converted, False))
        for abs_path in sorted(self.ruleset_files):
            planned_writes.append((abs_path, self.ruleset_files[abs_path], True))

        source_paths = set(self.files) | set(self.ruleset_files)
        source_keys = {}
        source_inodes = {}
        for p in source_paths:
            for k in (
                _volume_path_key(p, follow_symlinks=False),
                _volume_path_key(p, follow_symlinks=True),
            ):
                source_keys.setdefault(k, p)
            ident = _file_identity(p)
            if ident is not None:
                source_inodes[ident] = p

        seen_outputs_by_key = {}
        seen_outputs_by_inode = {}
        planned_backups = []  # (src_abs, backup_path, backup_keys, backup_inode)

        for abs_path, planned_content, is_binary in planned_writes:
            out_path = self._output_path(abs_path)
            out_dir = os.path.dirname(out_path)
            out_name = os.path.basename(out_path)

            if os.path.lexists(out_dir) and not os.path.isdir(out_dir):
                self.stats.errors.append(
                    f"输出目录路径被非目录条目占用，已中止导出: {out_dir}"
                )
                continue

            if _is_non_regular_target(out_path):
                self.stats.errors.append(
                    f"输出路径是已存在的目录或非普通文件，已中止以防移动或覆盖: {out_path}"
                )
                continue

            out_lit_key = _volume_path_key(out_path, follow_symlinks=False)
            out_res_key = _volume_path_key(out_path, follow_symlinks=True)
            out_keys = tuple(dict.fromkeys((out_lit_key, out_res_key)))
            out_inode = _file_identity(out_path)

            src_hit = next((source_keys[k] for k in out_keys if k in source_keys), None)
            if src_hit is None and out_inode is not None:
                src_hit = source_inodes.get(out_inode)
            if src_hit is not None:
                self.stats.errors.append(
                    f"输出路径与源配置重合，已中止以防覆盖源文件: {abs_path} → {out_path} (重合源文件: {src_hit})"
                )
                continue

            dup_hit = next((seen_outputs_by_key[k] for k in out_keys if k in seen_outputs_by_key), None)
            if dup_hit is None and out_inode is not None:
                dup_hit = seen_outputs_by_inode.get(out_inode)
            if dup_hit is not None:
                self.stats.errors.append(
                    f"多个源文件映射到同一输出路径: {dup_hit} 与 {abs_path} → {out_path}"
                )
                continue
            for k in out_keys:
                seen_outputs_by_key[k] = abs_path
            if out_inode is not None:
                seen_outputs_by_inode[out_inode] = abs_path

            if _filename_too_long(out_dir, out_name):
                self.stats.errors.append(f"输出文件名超出文件系统长度上限: {out_name}")
                continue

            if os.path.lexists(out_path) and not _output_unchanged(out_path, planned_content, is_binary=is_binary):
                p = Path(out_path)
                backup_path = str(p.with_stem(p.stem + "-deprecated"))
                backup_name = os.path.basename(backup_path)
                if _is_non_regular_target(backup_path):
                    self.stats.errors.append(
                        f"备份路径是已存在的目录或非普通文件，已中止以防误删: {backup_path}"
                    )
                    continue
                if _filename_too_long(out_dir, backup_name):
                    self.stats.errors.append(
                        f"备份文件名超出文件系统长度上限: {backup_name}"
                    )
                    continue
                backup_keys = tuple(dict.fromkeys((
                    _volume_path_key(backup_path, follow_symlinks=False),
                    _volume_path_key(backup_path, follow_symlinks=True),
                )))
                backup_inode = _file_identity(backup_path)
                b_src_hit = next((source_keys[k] for k in backup_keys if k in source_keys), None)
                if b_src_hit is None and backup_inode is not None:
                    b_src_hit = source_inodes.get(backup_inode)
                if b_src_hit is not None:
                    self.stats.errors.append(
                        f"备份路径与源配置重合，已中止以防覆盖源文件: {backup_path} (重合源文件: {b_src_hit})"
                    )
                    continue
                planned_backups.append((abs_path, backup_path, backup_keys, backup_inode))

        seen_backups_by_key = {}
        seen_backups_by_inode = {}
        for src_abs, backup_path, backup_keys, backup_inode in planned_backups:
            if any(k in seen_outputs_by_key for k in backup_keys) or (
                backup_inode is not None and backup_inode in seen_outputs_by_inode
            ):
                self.stats.errors.append(
                    f"备份路径与本轮输出路径冲突: {backup_path} (来自 {src_abs})"
                )
                continue
            if any(k in seen_backups_by_key for k in backup_keys) or (
                backup_inode is not None and backup_inode in seen_backups_by_inode
            ):
                self.stats.errors.append(
                    f"多个文件的备份路径冲突: {backup_path}"
                )
                continue
            for k in backup_keys:
                seen_backups_by_key[k] = src_abs
            if backup_inode is not None:
                seen_backups_by_inode[backup_inode] = src_abs

    def emit(self):
        """Write -v4 files based on FileState decisions. Returns root output path."""
        if self.stats.errors:
            for err in self.stats.errors:
                print(f"错误: {err}", file=sys.stderr)
            return None

        root_output = None
        root_abs = self._root_abs()
        reachable = self.reachable

        for abs_path, state in self.files.items():
            output_path = self._output_path(abs_path)

            if state.is_abandoned:
                self.stats.abandoned_files.append(abs_path)
                self.processed_files[abs_path] = None
                self.stats.discard_file(os.path.basename(abs_path))
                print(f"已放弃托管配置（含 v5+ 内容）: {abs_path}")
                src = Path(abs_path)
                old_layout = str(src.with_stem(src.stem + "-v4"))
                for stale in dict.fromkeys((output_path, old_layout)):
                    if os.path.exists(stale):
                        self.stats.stale_v4_files.append(stale)
                        print(f"  ⚠️  检测到旧的 v4 文件（未自动删除）: {stale}")
                if abs_path == root_abs:
                    root_output = None
                continue

            if abs_path not in reachable:
                self.processed_files[abs_path] = None
                self.stats.discard_file(os.path.basename(abs_path))
                continue

            if abs_path not in self.emitting:
                self.processed_files[abs_path] = None
                self.stats.discard_file(os.path.basename(abs_path))
                if abs_path == root_abs:
                    root_output = None
                continue

            if _output_unchanged(output_path, state.converted, is_binary=False):
                state.output_written = True
                state.output_path = output_path
                self.processed_files[abs_path] = output_path
                print(f"已跳过（内容未变化）: {output_path}")
                if abs_path == root_abs:
                    root_output = output_path
                continue

            os.makedirs(os.path.dirname(output_path), exist_ok=True)

            backup = backup_if_exists(output_path)
            if backup:
                self.stats.deprecated_files.append(backup)
                print(f"已备份: {output_path} → {backup}")

            with open(output_path, "w", encoding="utf-8") as f:
                f.write(state.converted)

            state.output_written = True
            state.output_path = output_path
            self.stats.files_processed.append(output_path)
            self.processed_files[abs_path] = output_path
            verb = "已复制（无需转换）" if state.converted == state.original else "已转换"
            print(f"{verb}: {abs_path} → {output_path}")
            if abs_path == root_abs:
                root_output = output_path

        # Copy surviving local RULE-SET / DOMAIN-SET data files verbatim into output_dir
        for abs_path, raw_bytes in self.ruleset_files.items():
            output_path = self._output_path(abs_path)
            if _output_unchanged(output_path, raw_bytes, is_binary=True):
                self.processed_files[abs_path] = output_path
                print(f"已跳过（内容未变化）: {output_path}")
                continue
            os.makedirs(os.path.dirname(output_path), exist_ok=True)
            backup = backup_if_exists(output_path)
            if backup:
                self.stats.deprecated_files.append(backup)
                print(f"已备份: {output_path} → {backup}")
            with open(output_path, "wb") as f:
                f.write(raw_bytes)
            self.stats.files_processed.append(output_path)
            self.processed_files[abs_path] = output_path
            print(f"已复制（规则集）: {abs_path} → {output_path}")

        return root_output

    def run(self, root_path, default_section=None):
        state = self.discover(root_path, default_section, is_root=True)
        if state is None:
            sys.exit(1)
        self.analyze()
        return self.emit()


# ---------------------------------------------------------------------------
# Public Entry Points & CLI
# ---------------------------------------------------------------------------

def convert_file(input_path, stats=None, processed_files=None, default_section=None,
                 snell_legacy=None, output_dir=None):
    """Convert a Surge config file from v5+ to v4 (top-level entry point)."""
    if stats is None:
        stats = ConversionStats()

    input_path = os.path.abspath(input_path)
    if not os.path.isfile(input_path):
        if os.path.isdir(input_path):
            print(f"错误: 路径是目录而非文件: {input_path}", file=sys.stderr)
        else:
            print(f"错误: 文件不存在: {input_path}", file=sys.stderr)
        sys.exit(1)

    pipeline = Pipeline(stats, processed_files, snell_legacy, output_dir=output_dir)
    return pipeline.run(input_path, default_section=default_section)


def default_snell_legacy_path():
    """${XDG_CONFIG_HOME:-~/.config}/surge-config-converter/snell-legacy.ini"""
    base = os.environ.get("XDG_CONFIG_HOME") or os.path.expanduser("~/.config")
    return os.path.join(base, "surge-config-converter", SNELL_LEGACY_FILENAME)


def _check_legacy_section(path, name, fields):
    """Exit on a malformed section. Messages name keys, never values."""
    unknown = sorted(set(fields) - _SNELL_LEGACY_KEYS)
    if unknown or not fields:
        sys.exit(f"错误: {path} [{name}] 只允许 server / port / psk 且至少一个"
                 f"（未知键: {', '.join(unknown) or '无'}）")
    for key, value in fields.items():
        if not value or "," in value or "\n" in value or (key == "port" and not value.isdigit()):
            sys.exit(f"错误: {path} [{name}] 的 {key} 取值无效（不能为空、含逗号或换行，port 须为数字）")


def load_snell_legacy(path):
    """Parse a snell legacy override file into {source basename: {field: value}}."""
    parser = configparser.RawConfigParser()
    parser.optionxform = str
    try:
        mode = os.stat(path).st_mode
        with open(path, encoding="utf-8") as f:
            parser.read_file(f)
    except (OSError, UnicodeDecodeError, configparser.Error) as e:
        sys.exit(f"错误: 无法读取 snell 旧版覆盖文件: {path} ({type(e).__name__})")
    if mode & 0o177:
        print(f"警告: {path} 权限宽于 0600，建议 chmod 600", file=sys.stderr)
    table = {name: dict(parser.items(name)) for name in parser.sections()}
    for name, fields in table.items():
        _check_legacy_section(path, name, fields)
    print(f"已加载 snell 旧版覆盖: {path}（{len(table)} 个文件）")
    return table


def resolve_snell_legacy(arg_path):
    """Explicit --snell-legacy path, else default path if it exists, else None."""
    if arg_path:
        return load_snell_legacy(arg_path)
    default = default_snell_legacy_path()
    return load_snell_legacy(default) if os.path.isfile(default) else None


def main():
    parser = argparse.ArgumentParser(description="Surge v5+ → v4 配置转换")
    parser.add_argument("input_path")
    parser.add_argument("--snell-legacy", metavar="PATH",
                        help=f"snell 旧版覆盖文件（默认 {default_snell_legacy_path()}，存在才加载）")
    parser.add_argument("-o", "--output-dir", metavar="DIR",
                        help="输出目录（默认写入源文件旁的 v4/ 子目录；多套主配置共用子文件需隔离时可指定独立目录）")
    args = parser.parse_args()

    input_path = args.input_path
    snell_legacy = resolve_snell_legacy(args.snell_legacy)
    stats = ConversionStats()
    processed_files = {os.path.abspath(input_path): None}
    result = convert_file(
        input_path, stats, processed_files,
        snell_legacy=snell_legacy,
        output_dir=args.output_dir,
    )
    if stats.errors:
        print("\n转换中止（未生成不完整的 v4 文件）:", file=sys.stderr)
        for err in stats.errors:
            print(f"  - {err}", file=sys.stderr)
        sys.exit(1)
    if result is None and not stats.abandoned_files:
        print("未发现 v5+ 内容，无需转换。")
    stats.print_summary()

    if stats.abandoned_files:
        print(f"\n发现 {len(stats.abandoned_files)} 个被放弃的托管配置:")
        for f in stats.abandoned_files:
            print(f"  - {f}")
        print("（这些文件含 v5+ 内容且是 Surge 托管配置，任何修改都会被刷新覆盖，故不生成 v4 版本。）")

    if stats.stale_v4_files:
        print(f"\n⚠️  发现 {len(stats.stale_v4_files)} 个过期的 v4 文件（未自动删除，请手动处理）:")
        for f in stats.stale_v4_files:
            print(f"  - {f}")
        print("（这些 v4 文件对应的源文件已被放弃。它们是之前脚本运行产生的遗留物，")
        print("  现在已与源文件脱节，可能含有 Surge v4 无法正确加载的悬空引用。建议你手动检查并删除。）")

    if stats.deprecated_files:
        print(f"\n发现 {len(stats.deprecated_files)} 个 deprecated 备份文件:")
        for f in stats.deprecated_files:
            print(f"  - {f}")
        if not sys.stdin.isatty():
            print("检测到非交互运行，已保留 deprecated 文件。")
            return
        try:
            answer = input("是否删除这些 deprecated 文件？（默认删除）[Y/n] ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            answer = "n"
            print()
        if answer in ("", "y", "yes"):
            for f in stats.deprecated_files:
                send2trash(f)
                print(f"已移至垃圾桶: {f}")
        else:
            print("已保留 deprecated 文件。")


if __name__ == "__main__":
    main()
