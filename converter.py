#!/usr/bin/env python3
"""Surge v5+ -> v4 configuration converter.

Usage:
    python3 converter.py [--snell-legacy PATH] <input_file_path>

Output layout:
    All generated -v4 files are written to a v4/ subdirectory next to
    the source files:

        Documents/
        ├── profile.conf              <- source (v5+)
        ├── work-vps.dconf
        └── v4/
            ├── profile-v4.conf       <- converted (v4)
            └── work-vps-v4.dconf

    Files inside v4/ reference each other using bare filenames (e.g.
    #!include work-vps-v4.dconf) with no directory prefix. v4/ is
    self-contained: whenever anything needs conversion, every file the
    profile loads gets a -v4 copy (verbatim if it needed no conversion),
    so copying v4/ alone to the Surge v4 device is enough.

Limitation:
    All referenced files (#!include, policy-path) must reside in the
    same directory as the root config. Sub-directory references produce
    output under <subdir>/v4/ while parents reference bare -v4 names,
    so those need manual merging; identically named files in different
    sub-directories would collide.
"""

import argparse
import configparser
import hashlib
import os
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path

from send2trash import send2trash


# Proxy types not supported in Surge v4
V5PLUS_ONLY_PROXY_TYPES = {
    "hysteria2", "hy2", "anytls", "tuic", "tuic-v5",
    "trust-tunnel", "tailscale", "vless", "masque", "h2-connect",
}

# Snell versions above this have no v4 equivalent: v4 speaks up to version=4,
# version=5 is down-converted to 4, version=6+ nodes are disabled like the
# v5+ only types above. The lookbehind keeps shadow-tls-version=N out.
SNELL_MAX_V4_VERSION = 5
_SNELL_VERSION_RE = re.compile(r'(?<![\w-])version\s*=\s*(\d+)')

# Optional per-file override for servers that run an extra v4-compatible snell
# instance next to the version=6+ one (own port / PSK, maybe own host). Live
# version=6+ nodes of a matching source file are rewritten to version=4 with
# these fields instead of being disabled. Group 1 of each regex spans the
# value; every other byte of the line is kept.
_SNELL_LEGACY_FIELD_RES = {
    "server": re.compile(r'^[^=]+=[^,]*,\s*([^,]*?)\s*(?=,)'),
    "port": re.compile(r'^[^=]+=[^,]*,[^,]*,\s*([^,]*?)\s*(?=,|$)'),
    "psk": re.compile(r'(?<![\w-])psk\s*=\s*([^,]*?)\s*(?=,|$)'),
}
SNELL_LEGACY_FILENAME = "snell-legacy.ini"

# Sections that should be entirely commented out in v4
V5PLUS_ONLY_SECTIONS = {"Port Forwarding", "Body Rewrite"}
# Section-name prefixes unsupported in v4 (e.g. [Tailscale my-net], [Tailscale *],
# inline [Ruleset my-list] Mac 5.3.1+, [Ruleset *] iOS 5.22.0+ / Mac 6.9.0+)
V5PLUS_ONLY_SECTION_PREFIXES = ("Tailscale ", "Ruleset ")
# Wildcard named-section includes ([<Base> *], iOS 5.22.0+ / Mac 6.9.0+);
# concrete [WireGuard <name>] remains supported in v4.
V5PLUS_WILDCARD_SECTION_BASES = {"WireGuard", "Tailscale", "Ruleset"}


def is_v5plus_only_section(section_name):
    """Return True if the entire [section_name] section is unsupported in v4."""
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
# pre-matching: iOS 5.14.0+). Stripped from the line; the rule itself stays.
V5PLUS_ONLY_RULE_OPTIONS = {"extended-matching", "pre-matching"}

# Surge built-in rule sets always take precedence over inline [Ruleset <name>]
# definitions (Surge manual, Rule Set resolution order).
BUILTIN_RULESETS = {"SYSTEM", "LAN"}

# Characters that Surge v4 cannot represent inside an include-other-group value
# (quoted \" / \\ escapes require iOS 5.21.0+ / Mac 6.8.0+; commas delimit items).
_V4_UNREPRESENTABLE_IOG_CHARS = ('"', ',')

# v5+ only rule types appearing as parenthesized criteria of AND/OR/NOT rules
_V5PLUS_NESTED_RULE_RE = re.compile(
    r'\(\s*(?:' + '|'.join(sorted(V5PLUS_ONLY_RULE_TYPES)) + r')\s*,'
)

# Proxy parameters to remove (v5+ only)
V5PLUS_ONLY_PROXY_PARAMS = {"port-hopping", "port-hopping-interval", "ecn", "block-quic"}

# Cascade-cleanup tag prefix: distinguishes follow-on deletions from direct hits.
CASCADE_TAG = "# [V5+ cascade] "

# Comment prefixes Surge accepts ("#", ";", "//", Surge manual, Profile
# Format), possibly repeated with spaces in between. "#!" is a directive
# (#!include, #!MANAGED-CONFIG), not a comment.
_COMMENT_PREFIX_RE = re.compile(r'^\s*(?:(?:#(?!!)|//|;)\s*)+')

# Proxy types whose definition is "name = type, host, port, key=value...".
# Only these are recognized inside comments; anything else stays verbatim.
HOST_PORT_PROXY_TYPES = (
    {"http", "https", "socks5", "socks5-tls", "ss", "snell", "vmess", "trojan", "ssh"}
    | (V5PLUS_ONLY_PROXY_TYPES - {"tailscale"})
)


def split_inline_comment(s):
    """Split a Surge value/RHS into (body, trailing_comment).

    Surge recognizes '#', ';', and '//' as inline comment starters when
    preceded by whitespace outside double quotes (respecting \\ and \" escapes).
    Leading whitespace before the comment marker stays attached to
    trailing_comment so callers can reattach it verbatim.
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


def _escape_quoted(s):
    """Escape backslash and double-quote for Surge double-quoted values."""
    return s.replace("\\", "\\\\").replace('"', '\\"')


def unquote(name):
    """Strip surrounding double quotes and decode Surge \" and \\ escapes."""
    if len(name) >= 2 and name[0] == '"' and name[-1] == '"':
        return re.sub(r'\\(["\\])', r'\1', name[1:-1])
    return name


def parse_include_other_groups(value):
    """Parse an include-other-group option value into decoded group names.

    Surge accepts a single name (GroupA or "GroupA") or a quoted
    comma-separated list ("GroupA, GroupB"), with optional trailing inline
    comments and Surge \\ / \" escapes inside quotes.
    """
    body, _ = split_inline_comment(value)
    raw = unquote(body.strip())
    return [g.strip() for g in raw.split(",") if g.strip()]


def is_v4_representable_group_name(name):
    """Return True if name can be encoded in a Surge v4 include-other-group value."""
    return not any(c in name for c in _V4_UNREPRESENTABLE_IOG_CHARS)


def _has_v5_quote_escape(raw_value):
    """Return True if a double-quoted value contains v5.21+/6.8+ \\ or \" escapes."""
    sv = raw_value.strip()
    if len(sv) >= 2 and sv[0] == '"' and sv[-1] == '"':
        inner = sv[1:-1]
        return '\\\\' in inner or '\\"' in inner
    return False


def format_include_other_groups(groups, was_quoted=False):
    """Format surviving group names into a Surge v4-readable include-other-group value.

    Surge v4 does not decode \\ / \" inside double quotes (added in iOS 5.21.0 /
    Mac 6.8.0): single backslash-bearing names are emitted unquoted so both v4
    and v5+/v6 read the literal name, multi-group lists emit literal backslashes
    without v5.21+ doubling, and names containing '"' or ',' raise ValueError
    because v4 cannot represent them unambiguously.
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


def parse_section_header(line, include_v5_commented=False):
    """Return the section name if line is a Surge [Section] header, else None.

    Skips legal Surge inline comments (whitespace + #, ;, or //) before
    matching [Section]. When include_v5_commented is True, also recognizes
    headers commented out by the converter ("# [V5+] [...]" / CASCADE_TAG).
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


def _serialize_lines(lines, original):
    """Join working lines back into file content, restoring the trailing
    newline iff the original had one.

    splitlines() drops the final newline, so a naive join + endswith check
    loses one newline for content ending in a blank line ("a\\n\\n" →
    ["a", ""] → "a\\n"): the join already ends with "\\n" and the naive
    compensation never fires. Appending unconditionally when the original
    ended with a newline is correct for every case.
    """
    joined = "\n".join(lines)
    if original.endswith("\n"):
        joined += "\n"
    return joined


def _preserve_indent(original_line, new_content):
    """Prepend original_line's leading whitespace to new_content."""
    stripped = original_line.lstrip()
    indent = original_line[: len(original_line) - len(stripped)]
    return indent + new_content


def compute_sections(lines, default_section=None):
    """Return a list parallel to lines where each entry is the section name
    the line belongs to (or default_section before any header appears).

    Also recognizes section headers that the direct-hit pass commented out
    (e.g. "# [V5+] [Port Forwarding]") so that the commented section body is
    not attributed to the preceding section.
    """
    result = []
    current = default_section
    for line in lines:
        sec = parse_section_header(line, include_v5_commented=True)
        if sec is not None:
            current = sec
        result.append(current)
    return result


def has_effective_members(pgl, deleted_names, abandoned_basenames):
    """Return True if the Proxy Group still has at least one valid member source.

    Valid sources:
      - an explicit member name not in deleted_names
      - include-all-proxies=1 option
      - include-other-group=<group> where <group> is not in deleted_names
      - policy-path=<file> where <file> is an HTTP URL, or a local file whose
        basename is NOT in abandoned_basenames
    """
    for m in pgl.members:
        if unquote(m) not in deleted_names:
            return True
    for key, value in pgl.options:
        k = key.lower()
        if k == "include-all-proxies" and value.strip() in {"1", "true"}:
            return True
        if k == "include-other-group":
            if any(g not in deleted_names for g in parse_include_other_groups(value)):
                return True
        if k == "policy-path":
            path_val = unquote(value.strip())
            if path_val.startswith("http://") or path_val.startswith("https://"):
                return True
            if os.path.basename(path_val) not in abandoned_basenames:
                return True
    return False


def is_managed_config(content):
    """Return True if content starts with a #!MANAGED-CONFIG directive.

    Skips leading blank lines. The directive must be the first non-blank line.
    """
    for raw in content.splitlines():
        line = raw.strip()
        if not line:
            continue
        return line.startswith("#!MANAGED-CONFIG")
    return False


class ConversionStats:
    """Edit bookkeeping, tracked per file so that edits recorded for a file
    whose conversion is later discarded (abandoned managed config, orphan)
    can be purged instead of misleading the final summary."""

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


V4_SUBDIR = "v4"


def make_v4_filename(filepath):
    """Generate the -v4 output filename inside the v4/ subdirectory.

    Example: /path/to/profile.conf -> /path/to/v4/profile-v4.conf
    """
    p = Path(filepath)
    return str(p.parent / V4_SUBDIR / (p.stem + "-v4" + p.suffix))


def make_v4_relname(filename):
    """Generate the -v4 basename for config-internal references.

    All v4 files share the same v4/ subdirectory, so cross-references
    between them use bare filenames without directory prefix.
    Example: work-vps.dconf -> work-vps-v4.dconf
    """
    p = Path(filename)
    return p.stem + "-v4" + p.suffix


def backup_if_exists(filepath):
    """If filepath exists, rename it with a -deprecated suffix.

    A pre-existing backup at the target name (kept by the user in an earlier
    run) is moved to the trash first — os.rename would silently overwrite it,
    destroying the only recoverable copy.
    """
    if os.path.exists(filepath):
        p = Path(filepath)
        backup = str(p.with_stem(p.stem + "-deprecated"))
        if os.path.exists(backup):
            send2trash(backup)
            print(f"已将旧备份移至垃圾桶: {backup}")
        os.rename(filepath, backup)
        return backup
    return None


def comment_line(line):
    """Add # [V5+] prefix to a line."""
    return f"# [V5+] {line}"


def extract_proxy_type(line):
    """Extract proxy type from a proxy definition line.

    Format: Name = type, host, port, params...
    Returns the type string (lowercase) or None.
    Proxy names may contain '#' (e.g. "Node #1"); commented lines are
    rejected by the explicit prefix check, not by the name character class.
    """
    if line.lstrip().startswith("#"):
        return None
    m = re.match(r'^[^=]+=\s*(\w[\w-]*)', line)
    if m:
        return m.group(1).strip().lower()
    return None


@dataclass
class ProxyGroupLine:
    """Structured representation of a Surge Proxy Group definition line."""
    name: str
    group_type: str
    members: list      # raw tokens, quotes preserved
    options: list      # ordered list of (key, value) tuples
    trailing_comment: str = ""


@dataclass
class FileState:
    """Intermediate state for one file during the three-phase conversion pipeline."""
    abs_path: str
    original: str                # raw file content
    converted: str               # content after direct-hit transforms (and later cascade)
    is_managed: bool
    default_section: str = None  # for files without explicit section headers
    is_abandoned: bool = False   # managed + changed → decided during analyze()
    output_written: bool = False # set during emit()
    output_path: str = None      # destination if written
    # Cascade fields (populated during Discover, consumed during Analyze)
    lines: list = field(default_factory=list)          # mutable working copy of converted
    sections: list = field(default_factory=list)       # per-line section name
    owned_proxies: set = field(default_factory=set)    # proxy names defined in this file
    owned_groups: set = field(default_factory=set)     # group names defined in this file
    owned_wireguard_sections: list = field(default_factory=list)  # concrete [WireGuard <name>]
    expanded_wg_sections: set = field(default_factory=set)        # expanded from [WireGuard *]
    owned_rulesets: dict = field(default_factory=dict)            # inline [Ruleset <name>] → raw lines
    has_unexpanded_wg_wildcard: bool = False
    has_unexpanded_ruleset_wildcard: bool = False
    managed_wildcard_targets: set = field(default_factory=set)    # managed files referenced via wildcard/ruleset include
    deleted_names: set = field(default_factory=set)    # names removed (propagates cascade)
    self_deleted: set = field(default_factory=set)     # subset killed by THIS file's own line


def parse_proxy_group_line(line):
    """Parse a Surge Proxy Group definition line.

    Returns a ProxyGroupLine or None if the line is not a group definition
    (comment, section header, empty line, etc.).
    """
    stripped = line.lstrip()
    if (not stripped or _COMMENT_PREFIX_RE.match(stripped)
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
        name=name,
        group_type=group_type,
        members=members,
        options=options,
        trailing_comment=trailing_comment,
    )


def format_proxy_group_line(pgl):
    """Format a ProxyGroupLine back into a config line (stable round-trip)."""
    parts = [pgl.group_type]
    parts.extend(pgl.members)
    parts.extend(f"{k}={v}" for k, v in pgl.options)
    return f"{pgl.name} = " + ", ".join(parts) + pgl.trailing_comment


# Known trailing options that can follow the policy in a rule line
RULE_TRAILING_OPTIONS = {
    "no-resolve",
    "force-remote-dns",
    "extended-matching",
    "dns-failed",
    "pre-matching",
}


def _split_top_level_comma_spans(s, track_parens=True):
    """Return (start, end) index spans split by commas outside double quotes
    (with \\/\" escapes), and optionally outside balanced parentheses.

    Only rule syntax (AND/OR/NOT compound criteria) uses parentheses for
    grouping; proxy and proxy-group option values treat literal '(' / ')' as
    ordinary characters (e.g. unquoted passwords containing '(').
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
        else:
            if ch == '"':
                in_quote = True
            elif track_parens and ch == "(":
                depth += 1
            elif track_parens and ch == ")":
                depth = max(0, depth - 1)
            elif ch == "," and depth == 0:
                spans.append((start, i))
                start = i + 1
        i += 1
    spans.append((start, n))
    return spans


def _split_top_level_commas(s, track_parens=True):
    """Split a string by commas outside double quotes (with \\/\" escapes)
    and optionally outside balanced parentheses."""
    return [s[a:b].strip() for a, b in _split_top_level_comma_spans(s, track_parens=track_parens)]


def parse_include_list(line):
    """Parse a #!include line into a list of path/url entries, or None.

    Returns None if the line is not an #!include directive.
    """
    m = re.match(r'^\s*#!include\s+(.+)$', line)
    if not m:
        return None
    body, _ = split_inline_comment(m.group(1))
    return [p.strip() for p in body.split(",") if p.strip()]


def _include_trailing_comment(line):
    """Return any trailing Surge inline comment on a #!include line."""
    m = re.match(r'^\s*#!include\s+(.+)$', line)
    if not m:
        return ""
    _, trailing = split_inline_comment(m.group(1))
    return trailing


def format_include_list(entries, trailing_comment=""):
    """Format a list of entries back into a #!include line.

    Returns None if the list is empty (caller should comment the whole line).
    """
    if not entries:
        return None
    return "#!include " + ", ".join(entries) + trailing_comment


def _rule_policy_index(tokens):
    """Return the index of the policy among a rule line's top-level tokens,
    or 0 if none is found.

    Walks from the end, skipping known trailing option keywords and
    key=value option pairs; the first remaining token is the policy.
    """
    i = len(tokens) - 1
    while i > 0 and (tokens[i] in RULE_TRAILING_OPTIONS
                     or ("=" in tokens[i] and not tokens[i].startswith('"'))):
        i -= 1
    return i


def extract_rule_policy(line):
    """Return the policy target from a rule line, or None if not a rule."""
    stripped = line.lstrip()
    if (not stripped or _COMMENT_PREFIX_RE.match(stripped)
            or stripped.startswith("[") or stripped.startswith("#!")):
        return None
    body, _ = split_inline_comment(stripped)
    tokens = _split_top_level_commas(body)
    i = _rule_policy_index(tokens)
    return tokens[i] if i > 0 else None


def _strip_outer_parens(s, start, end):
    """Trim whitespace around s[start:end] and strip one matching outer (...)
    pair, or return None if not wrapped in a single matching pair."""
    while start < end and s[start].isspace():
        start += 1
    while end > start and s[end - 1].isspace():
        end -= 1
    if end - start < 2 or s[start] != "(" or s[end - 1] != ")":
        return None
    depth = 0
    in_quote = False
    i = start
    while i < end:
        ch = s[i]
        if in_quote:
            if ch == "\\" and i + 1 < end:
                i += 2
                continue
            if ch == '"':
                in_quote = False
        else:
            if ch == '"':
                in_quote = True
            elif ch == "(":
                depth += 1
            elif ch == ")":
                depth -= 1
                if depth == 0 and i != end - 1:
                    return None
        i += 1
    return (start + 1, end - 1) if depth == 0 else None


def _collect_logical_ruleset_spans(body, start, end, refs):
    """Recursively collect (abs_start, abs_end, decoded_target) for every
    (RULE-SET,<target>) criterion inside a logical rule's criteria block."""
    inner = _strip_outer_parens(body, start, end)
    if inner is None:
        return
    inner_start, inner_end = inner
    for rel_s, rel_e in _split_top_level_comma_spans(body[inner_start:inner_end], track_parens=True):
        crit = _strip_outer_parens(body, inner_start + rel_s, inner_start + rel_e)
        if crit is None:
            continue
        c_start, c_end = crit
        sub_spans = _split_top_level_comma_spans(body[c_start:c_end], track_parens=True)
        if len(sub_spans) < 2:
            continue
        r0_s, r0_e = sub_spans[0]
        kind = body[c_start + r0_s:c_start + r0_e].strip().upper()
        if kind == "RULE-SET":
            r1_s, r1_e = sub_spans[1]
            abs_s, abs_e = c_start + r1_s, c_start + r1_e
            refs.append((abs_s, abs_e, unquote(body[abs_s:abs_e].strip())))
        elif kind in ("AND", "OR", "NOT"):
            r1_s, r1_e = sub_spans[1]
            _collect_logical_ruleset_spans(body, c_start + r1_s, c_start + r1_e, refs)


def _find_rule_ruleset_spans(body, require_policy=True):
    """Return [(start, end, decoded_target), ...] for every RULE-SET target
    in a rule body (top-level RULE-SET and nested inside AND/OR/NOT)."""
    refs = []
    min_tokens = 3 if require_policy else 2
    spans = _split_top_level_comma_spans(body, track_parens=True)
    if len(spans) < min_tokens:
        return refs
    first = body[spans[0][0]:spans[0][1]].strip().upper()
    if first == "RULE-SET":
        s1, e1 = spans[1]
        refs.append((s1, e1, unquote(body[s1:e1].strip())))
    elif first in ("AND", "OR", "NOT"):
        _collect_logical_ruleset_spans(body, spans[1][0], spans[1][1], refs)
    return refs


def extract_rule_ruleset_targets(line):
    """Return decoded RULE-SET targets referenced by a live [Rule] line
    (both top-level RULE-SET and nested inside AND/OR/NOT)."""
    stripped = line.lstrip()
    if (not stripped or _COMMENT_PREFIX_RE.match(stripped)
            or stripped.startswith("[") or stripped.startswith("#!")):
        return []
    body, _ = split_inline_comment(stripped)
    return [target for _, _, target in _find_rule_ruleset_spans(body, require_policy=True)]


def extract_ruleset_target(line):
    """If line is a live top-level RULE-SET,<target>,<policy>... rule, return decoded target."""
    stripped = line.lstrip()
    if (not stripped or _COMMENT_PREFIX_RE.match(stripped)
            or stripped.startswith("[") or stripped.startswith("#!")):
        return None
    body, _ = split_inline_comment(stripped)
    tokens = _split_top_level_commas(body, track_parens=True)
    if len(tokens) >= 3 and tokens[0].upper() == "RULE-SET":
        return unquote(tokens[1])
    return None


def _replace_rule_ruleset_targets(line, replacements):
    """Replace matching RULE-SET targets (top-level or inside AND/OR/NOT) in line."""
    stripped = line.lstrip()
    indent = line[:len(line) - len(stripped)]
    body, trailing = split_inline_comment(stripped)
    refs = _find_rule_ruleset_spans(body, require_policy=True)
    if not refs:
        return line
    new_body = body
    for s1, e1, decoded in reversed(refs):
        if decoded not in replacements:
            continue
        raw_seg = new_body[s1:e1]
        lws = raw_seg[:len(raw_seg) - len(raw_seg.lstrip())]
        rws = raw_seg[len(raw_seg.rstrip()):]
        new_body = new_body[:s1] + lws + replacements[decoded] + rws + new_body[e1:]
    return indent + new_body + trailing


def _is_live_final_rule(line):
    """Return True if line is an uncommented FINAL,... rule."""
    stripped = line.lstrip()
    if (not stripped or stripped.startswith("#")
            or _COMMENT_PREFIX_RE.match(stripped) or stripped.startswith("[")):
        return False
    body, _ = split_inline_comment(stripped)
    tokens = _split_top_level_commas(body, track_parens=True)
    return len(tokens) >= 2 and tokens[0].upper() == "FINAL"


def extract_proxy_option(line, option_name):
    """Return the decoded value of option_name on a live [Proxy] line, or None."""
    stripped = line.lstrip()
    if (not stripped or stripped.startswith("#")
            or _COMMENT_PREFIX_RE.match(stripped)):
        return None
    if "=" not in line:
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

    Parses top-level comma-separated options outside double quotes and
    trailing Surge inline comments (without parenthesis grouping, so unquoted
    passwords containing '(' stay intact), matching normalized option keys
    with arbitrary whitespace around '='. Untouched segments keep exact spacing.
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


def _expand_ruleset_for_v4(rs_name, available_rulesets, visited=None):
    """Expand an inline [Ruleset <rs_name>] tree into v4 external ruleset text.

    Recursively inlines nested `RULE-SET,<Inner>` referencing other local inline
    rulesets. Returns (converted_text, None) on success, or (None, reason) if
    the ruleset contains a v5+/v6 nested RULE-SET / DOMAIN-SET / cycle / logical
    RULE-SET condition that Surge v4 external .list files cannot express.
    """
    if visited is None:
        visited = set()
    if rs_name in visited:
        return None, f"规则集 {rs_name} 存在循环嵌套引用"
    next_visited = visited | {rs_name}
    out = []
    for line in available_rulesets[rs_name]:
        stripped = line.lstrip()
        if not stripped or _COMMENT_PREFIX_RE.match(stripped) or stripped.startswith("#!"):
            out.append(line)
            continue
        body, trailing = split_inline_comment(stripped)
        tokens = _split_top_level_commas(body, track_parens=True)
        rule_type = tokens[0].upper() if len(tokens) >= 2 else ""
        if rule_type in V5PLUS_ONLY_RULE_TYPES or _V5PLUS_NESTED_RULE_RE.search(body):
            out.append(comment_line(line))
            continue
        if rule_type == "RULE-SET":
            nested_target = unquote(tokens[1])
            extra_opts = [t for t in tokens[2:] if t not in V5PLUS_ONLY_RULE_OPTIONS]
            if extra_opts:
                return None, (
                    f"嵌套规则集 RULE-SET,{nested_target} 带附加选项"
                    f" ({', '.join(extra_opts)}) 无法等价展开到 v4 外部规则集"
                )
            if (nested_target.upper() not in BUILTIN_RULESETS
                    and nested_target in available_rulesets):
                sub_text, err = _expand_ruleset_for_v4(
                    nested_target, available_rulesets, next_visited
                )
                if err is not None:
                    return None, err
                if sub_text:
                    out.extend(sub_text.splitlines())
                continue
            return None, f"嵌套规则集 RULE-SET,{nested_target} 无法等价展开到 v4 外部规则集"
        if rule_type == "DOMAIN-SET":
            return None, f"嵌套 {tokens[0]} 无法等价展开到 v4 外部规则集"
        if rule_type in ("AND", "OR", "NOT") and _find_rule_ruleset_spans(body, require_policy=False):
            return None, "规则集内含逻辑规则嵌套 RULE-SET，无法等价展开到 v4 外部规则集"
        idx = len(tokens)
        while idx > 1 and (tokens[idx - 1] in RULE_TRAILING_OPTIONS
                           or ("=" in tokens[idx - 1] and not tokens[idx - 1].startswith('"'))):
            idx -= 1
        options = tokens[idx:]
        if any(t in V5PLUS_ONLY_RULE_OPTIONS for t in options):
            kept = tokens[:idx] + [t for t in options if t not in V5PLUS_ONLY_RULE_OPTIONS]
            indent = line[:len(line) - len(stripped)]
            out.append(indent + ",".join(kept) + trailing)
        else:
            out.append(line)
    return "\n".join(out) + ("\n" if out else ""), None


def convert_ruleset_lines(raw_lines):
    """Convert flat inline [Ruleset <name>] body lines into a v4 external ruleset."""
    text, err = _expand_ruleset_for_v4("_inline", {"_inline": raw_lines})
    if err is not None:
        raise ValueError(err)
    return text


def v5plus_only_proxy_reason(line):
    """Why an uncommented proxy line cannot exist in v4 at all, or None.

    Covers v5+ only proxy types and snell versions with no v4 equivalent.
    """
    proxy_type = extract_proxy_type(line)
    if proxy_type in V5PLUS_ONLY_PROXY_TYPES:
        return proxy_type
    if proxy_type == "snell":
        m = _SNELL_VERSION_RE.search(line)
        if m and int(m.group(1)) > SNELL_MAX_V4_VERSION:
            return f"snell version={m.group(1)}"
    return None


def _replace_group(regex, line, value):
    """Replace regex group 1 of its first match with value (no match: as is)."""
    m = regex.search(line)
    return line if m is None else line[:m.start(1)] + value + line[m.end(1):]


def snell_legacy_line(line, legacy):
    """Point a snell version=6+ node at the server's v4-compatible instance:
    version becomes 4 and each overridden field takes its value."""
    line = _replace_group(_SNELL_VERSION_RE, line, "4")
    for key, value in legacy.items():
        line = _replace_group(_SNELL_LEGACY_FIELD_RES[key], line, value)
    return line


def transform_proxy_line(line, stats, filename, line_num, section, legacy=None):
    """Transform a single proxy line in [Proxy] section.

    legacy: this file's snell override ({field: value}) or None. Only field
    names ever reach the change log, never values.
    """
    proxy_type = extract_proxy_type(line)
    if not proxy_type:
        return line

    name = line.split('=', 1)[0].strip()

    # Comment out proxies v4 cannot use (v5+ only types, snell version=6+),
    # unless the file's server keeps a v4-compatible snell instance.
    reason = v5plus_only_proxy_reason(line)
    if reason and legacy and proxy_type == "snell":
        line = snell_legacy_line(line, legacy)
        stats.count_params(filename, 1 + len(legacy))
        stats.add_change(filename, line_num, section, f"{reason} → version=4",
                         f"{name} (旧版实例: {', '.join(legacy)})")
        reason = None
    if reason:
        stats.count_commented(filename)
        stats.add_change(filename, line_num, section, "注释", f"{name} ({reason})")
        return comment_line(line)

    modified = line

    # Snell version=5 → version=4
    if proxy_type == "snell":
        new, n = re.subn(r'version\s*=\s*5\b', 'version=4', modified)
        if n:
            modified = new
            stats.count_params(filename, n)
            stats.add_change(filename, line_num, section, "version=5 → version=4", name)

    # shadow-tls-version=3 → shadow-tls-version=2
    new, n = re.subn(r'shadow-tls-version\s*=\s*3\b', 'shadow-tls-version=2', modified)
    if n:
        modified = new
        stats.count_params(filename, n)
        stats.add_change(filename, line_num, section, "shadow-tls-version=3 → 2", name)

    # Remove v5+ only parameters
    modified, removed = remove_proxy_params(modified, V5PLUS_ONLY_PROXY_PARAMS)
    stats.count_params(filename, len(removed))
    for param in removed:
        stats.add_change(filename, line_num, section, "移除参数", f"{param} ({name})")

    return modified


def is_proxy_definition(body):
    """Strictly check that body is a complete proxy definition:
    name = type, host, port[, key=value...] with a known host/port type.

    Used to tell commented-out nodes from free-form comment text, so it
    rejects anything it cannot fully account for.
    """
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
    """Apply the proxy-line transforms to a commented-out node, keeping the
    comment prefix verbatim, so uncommenting it in v4 yields a v4-valid node.

    Free-form comments, converter tags and nodes v4 cannot use (v5+ only
    types, snell version=6+: already disabled; a "# [V5+]" tag on top would
    add nothing) are returned unchanged.
    """
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
    """Transform a single line in [Proxy Group] section.

    Only direct hits (smart → url-test). policy-path reference rewriting
    happens later in Pipeline._rewrite_references, once every sub-file's
    final converted/abandoned status is known.
    """
    if line.startswith("#"):
        return line

    modified = line

    # smart → url-test
    m = re.match(r'^([^=]+=\s*)smart\b(.*)', modified)
    if m:
        name = line.split('=', 1)[0].strip()
        modified = m.group(1) + "url-test" + m.group(2)
        stats.count_params(filename)
        stats.add_change(filename, line_num, section, "smart → url-test", name)

    return modified


def transform_rule_line(line, stats, filename, line_num, section):
    """Transform a single line in [Rule] section."""
    stripped = line.lstrip()
    if stripped.startswith("#") or _COMMENT_PREFIX_RE.match(stripped):
        return line

    body, trailing = split_inline_comment(stripped)
    tokens = _split_top_level_commas(body, track_parens=True)
    rule_type = tokens[0].upper() if len(tokens) >= 2 else ""

    if rule_type in V5PLUS_ONLY_RULE_TYPES:
        stats.count_commented(filename)
        stats.add_change(filename, line_num, section, "注释", stripped)
        return comment_line(line)

    # v5+ only rule types nested inside AND/OR/NOT compound criteria,
    # e.g. AND,((DOMAIN-WILDCARD,*bar*),(DEST-PORT,443)),DIRECT
    if _V5PLUS_NESTED_RULE_RE.search(body):
        stats.count_commented(filename)
        stats.add_change(filename, line_num, section, "注释", stripped)
        return comment_line(line)

    # Strip v5+ only options after the policy, e.g.
    # RULE-SET,<url>,REJECT,extended-matching → RULE-SET,<url>,REJECT
    i = _rule_policy_index(tokens)
    if i == 0:
        return line
    options = tokens[i + 1:]
    removed = [t for t in options if t in V5PLUS_ONLY_RULE_OPTIONS]
    if not removed:
        return line
    kept = tokens[:i + 1] + [t for t in options if t not in V5PLUS_ONLY_RULE_OPTIONS]
    rule = ",".join(kept)
    stats.count_params(filename, len(removed))
    for opt in removed:
        stats.add_change(filename, line_num, section, "移除参数", f"{opt} ({rule})")
    return line[:len(line) - len(stripped)] + rule + trailing


def transform_general_line(line, stats, filename, line_num, section):
    """Transform a single line in [General] section."""
    stripped = line.lstrip()
    if stripped.startswith("#"):
        return line

    for param in V5PLUS_ONLY_GENERAL_PARAMS:
        if re.match(rf'^{re.escape(param)}\s*=', stripped):
            stats.count_commented(filename)
            stats.add_change(filename, line_num, section, "注释", param)
            return comment_line(line)

    return line


def convert_content(content, base_dir, stats, processed_files, default_section=None, filename="",
                    legacy=None):
    """Convert configuration content from v5+ to v4 format (direct hits only).

    Args:
        base_dir, processed_files: kept for signature compatibility; sub-file
                         discovery and reference rewriting now live in Pipeline.
        default_section: If set, treat lines before any [Section] header
                         as belonging to this section. Used for included files
                         that lack section headers.
        legacy: this file's snell override, see transform_proxy_line.

    Returns the converted content string.
    """
    lines = content.splitlines()
    result = []
    current_section = default_section
    in_v5plus_only_section = False

    for line_num, line in enumerate(lines, 1):
        stripped = line.strip()

        # Detect section headers (skipping legal Surge trailing inline comments)
        section_name = parse_section_header(line, include_v5_commented=False)
        if section_name is not None:
            if is_v5plus_only_section(section_name):
                in_v5plus_only_section = True
                current_section = section_name
                stats.count_commented(filename)
                stats.add_change(filename, line_num, current_section, "注释段", f"[{section_name}]")
                result.append(comment_line(line))
                continue
            else:
                in_v5plus_only_section = False
                current_section = section_name
                result.append(line)
                continue

        # If inside a v5+ only section, comment everything
        if in_v5plus_only_section:
            if stripped:  # Don't comment empty lines
                stats.count_commented(filename)
                result.append(comment_line(line))
            else:
                result.append(line)
            continue

        # Comments and #!include directives pass through untouched here.
        # Include reference rewriting happens later in the pipeline
        # (Pipeline._rewrite_references), once sub-file outcomes are known.
        # Commented-out nodes ("#", ";" or "//" in [Proxy]) never decide
        # whether a file needs conversion; they are rewritten only in files
        # that get emitted anyway (Pipeline._convert_commented_proxies).
        if stripped.startswith("#") or _COMMENT_PREFIX_RE.match(line):
            result.append(line)
            continue

        # Apply section-specific transformations
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

    joined = "\n".join(result)
    if content.endswith("\n"):
        joined += "\n"
    return joined


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


class Pipeline:
    """Three-phase converter: discover → analyze → emit.

    The pipeline owns the dict of FileState for the root file and all
    recursively-discovered dependencies. Analyze and emit iterate over this
    shared dict — this is what makes cross-file cascade cleanup possible.
    """

    def __init__(self, stats, processed_files=None, snell_legacy=None):
        self.stats = stats
        self.snell_legacy = snell_legacy or {}  # source basename → {field: value}
        self.files = {}  # abs_path → FileState (insertion order = discovery order)
        self.processed_files = processed_files if processed_files is not None else {}
        self.abandoned_files = set()    # absolute paths of managed files we refused
        self.global_deleted = set()     # union of all names deleted anywhere
        self.dead_wg_sections = set()   # WireGuard section names lost to abandonment/stripping
        self.dead_rulesets = set()      # inline ruleset names lost to abandonment/unresolvable
        self.ruleset_wildcard_sources = {}  # host abs_path → [target abs_path] from [Ruleset *]
        self.generated_rulesets = {}    # abs output path in v4/ → converted .list content
        self.reachable = set()          # final root-reachable set, settled by analyze()
        self.emitting = set()           # files that get a -v4 copy, settled by analyze()

    def discover(self, input_path, default_section=None):
        """Read a file, apply direct v5+ hits, and recurse into dependencies.

        No decisions are made here beyond the direct-hit transforms —
        abandonment and reference rewriting are analyze-phase concerns,
        because cascade mutations can change a file's status after discovery.

        Returns the FileState for this file, or None if not a valid /
        readable file. Idempotent: calling twice on the same path returns
        the cached state.
        """
        abs_path = os.path.abspath(input_path)
        if abs_path in self.files:
            return self.files[abs_path]
        if not os.path.isfile(abs_path):
            return None

        try:
            # utf-8-sig: strip a leading BOM, which would otherwise defeat
            # #!MANAGED-CONFIG detection and first-line section headers.
            with open(abs_path, "r", encoding="utf-8-sig") as f:
                original = f.read()
        except (OSError, UnicodeDecodeError) as e:
            print(f"错误: 无法读取文件: {abs_path} ({e})", file=sys.stderr)
            return None

        state = FileState(
            abs_path=abs_path,
            original=original,
            converted=original,  # placeholder; replaced after convert_content
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

        # Populate cascade fields: split into mutable lines, sectionize, and
        # catalog owned proxy / group / WireGuard / inline Ruleset definitions.
        # Seed deleted_names with any v5+ proxy whose definition just got
        # commented by direct-hit pass.
        state.lines = state.converted.splitlines()
        state.sections = compute_sections(state.lines, default_section)
        for i, line in enumerate(state.lines):
            section = state.sections[i]
            stripped = line.lstrip()
            live_header = parse_section_header(line, include_v5_commented=False)
            if live_header and live_header.startswith("WireGuard ") and live_header != "WireGuard *":
                wg_name = live_header[len("WireGuard "):].strip()
                if wg_name and wg_name not in state.owned_wireguard_sections:
                    state.owned_wireguard_sections.append(wg_name)
                continue
            if section == "Proxy":
                if line.startswith("# [V5+] "):
                    raw = line[len("# [V5+] "):]
                    if "=" in raw:
                        name = raw.split("=", 1)[0].strip()
                        if name:
                            deleted_name = unquote(name)
                            state.deleted_names.add(deleted_name)
                            state.self_deleted.add(deleted_name)
                elif (not stripped.startswith("#")
                      and not _COMMENT_PREFIX_RE.match(stripped)
                      and "=" in line):
                    name = line.split("=", 1)[0].strip()
                    if name:
                        state.owned_proxies.add(unquote(name))
            elif section == "Proxy Group":
                if (not stripped.startswith("#")
                        and not _COMMENT_PREFIX_RE.match(stripped)
                        and "=" in line):
                    name = line.split("=", 1)[0].strip()
                    if name:
                        state.owned_groups.add(unquote(name))

        # Capture inline [Ruleset <name>] bodies from original content before
        # direct-hit commenting so surviving RULE-SET references can be
        # materialized into v4 external .list files.
        orig_lines = original.splitlines()
        orig_sections = compute_sections(orig_lines, default_section)
        for i, orig_line in enumerate(orig_lines):
            sec = orig_sections[i]
            if sec and sec.startswith("Ruleset ") and sec != "Ruleset *":
                rs_name = sec[len("Ruleset "):].strip()
                if not rs_name:
                    continue
                if parse_section_header(orig_line, include_v5_commented=False) is not None:
                    state.owned_rulesets.setdefault(rs_name, [])
                else:
                    state.owned_rulesets.setdefault(rs_name, []).append(orig_line)
        for rs_lines in state.owned_rulesets.values():
            while rs_lines and not rs_lines[-1].strip():
                rs_lines.pop()

        # Recurse into local #!include and policy-path references so every
        # transitively referenced file lives in the shared FileState dict.
        # Also discover local #!include targets under commented [WireGuard *]
        # and [Ruleset *] / [Ruleset <name>] blocks so local definitions can
        # be expanded/extracted into v4-compatible form (or abandoned/cascaded).
        # policy-path detection is STRUCTURED (parse_proxy_group_line) — a
        # whole-line regex would also match inside quoted member names like
        # "policy-path=nodes.conf, Fast", which are identifiers, not refs.
        for i, line in enumerate(state.lines):
            stripped = line.lstrip()
            section = state.sections[i]
            if stripped.startswith("#!include"):
                for entry in parse_include_list(line) or []:
                    self._discover_ref(base_dir, entry, section)
            elif (section in ("WireGuard *", "Ruleset *")
                  or (section and section.startswith("Ruleset "))) and line.startswith("# [V5+] "):
                inner = line[len("# [V5+] "):]
                if inner.lstrip().startswith("#!include"):
                    for entry in parse_include_list(inner) or []:
                        self._discover_ref(base_dir, entry, None)
            elif section == "Proxy Group" and not stripped.startswith("#") and not _COMMENT_PREFIX_RE.match(stripped):
                pgl = parse_proxy_group_line(line)
                if pgl is None:
                    continue
                for key, value in pgl.options:
                    if key.lower() == "policy-path":
                        # policy-path always references proxy list files
                        self._discover_ref(base_dir, unquote(value.strip()), "Proxy")

        return state

    def _discover_ref(self, base_dir, ref, default_section):
        """Discover one local reference; URLs and missing files are ignored."""
        if ref.startswith("http://") or ref.startswith("https://"):
            return
        abs_path = os.path.normpath(os.path.join(base_dir, ref))
        if os.path.isfile(abs_path):
            self.discover(abs_path, default_section=default_section)

    def _pending_change(self, state, loaded_set=None):
        """True if the file's loaded sections differ from its original content."""
        if loaded_set is None:
            return _serialize_lines(state.lines, state.original) != state.original
        orig_lines = state.original.splitlines()
        orig_sections = compute_sections(orig_lines, state.default_section)
        orig_loaded = [l for l, s in zip(orig_lines, orig_sections) if s in loaded_set]
        cur_loaded = [l for l, s in zip(state.lines, state.sections) if s in loaded_set]
        return orig_loaded != cur_loaded

    def _live_local_refs(self, state):
        """(abs_path, kind, section) for local files referenced by live
        (non-commented) #!include / policy-path lines, resolved against the
        file's directory.

        `kind` is "include" or "policy-path"; `section` is the section the
        reference line sits in. In Surge, #!include inside `[S]` loads ONLY
        section `[S]` from the referenced file (Detached Profile Section), and
        policy-path loads ONLY `[Proxy]`.

        Recomputed from current lines each call, so entries already stripped
        by abandoned-reference cleanup no longer count.
        """
        refs = []
        base_dir = os.path.dirname(state.abs_path)
        for i, line in enumerate(state.lines):
            stripped = line.lstrip()
            if stripped.startswith("#!include"):
                for entry in parse_include_list(line) or []:
                    if not entry.startswith(("http://", "https://")):
                        refs.append((
                            os.path.normpath(os.path.join(base_dir, entry)),
                            "include", state.sections[i]))
            elif state.sections[i] == "Proxy Group" and not stripped.startswith("#") and not _COMMENT_PREFIX_RE.match(stripped):
                pgl = parse_proxy_group_line(line)
                if pgl is None:
                    continue
                for key, value in pgl.options:
                    if key.lower() == "policy-path":
                        path_val = unquote(value.strip())
                        if not path_val.startswith(("http://", "https://")):
                            refs.append((
                                os.path.normpath(os.path.join(base_dir, path_val)),
                                "policy-path", state.sections[i]))
        return refs

    def _loaded_sections(self):
        """abs_path → set[str] | None of sections the root profile actually loads.

        Surge's #!include is strictly section-scoped: an `#!include other.conf`
        under `[S]` loads ONLY section `[S]` from `other.conf`. `policy-path`
        under `[Proxy Group]` loads ONLY `[Proxy]`.

        The root file maps to None (every section loaded); any other reachable
        non-abandoned file maps to the non-empty set of section names loaded
        from it. Unloaded sections in sub-files never dirty the profile, never
        register live definitions, and never cascade.
        """
        loaded = {}
        root_abs = next(iter(self.files))
        if self.files[root_abs].is_abandoned:
            return loaded
        loaded[root_abs] = None
        stack = [root_abs]
        while stack:
            cur = stack.pop()
            cur_loaded = loaded[cur]
            for ref, kind, section in self._live_local_refs(self.files[cur]):
                if not _section_is_loaded(cur_loaded, section):
                    continue
                sub = self.files.get(ref)
                if sub is None or sub.is_abandoned:
                    continue
                target_sec = "Proxy" if kind == "policy-path" else section
                if target_sec is None:
                    continue
                if ref not in loaded:
                    loaded[ref] = {target_sec}
                    stack.append(ref)
                elif loaded[ref] is not None and target_sec not in loaded[ref]:
                    loaded[ref].add(target_sec)
                    stack.append(ref)
        return loaded

    def _compute_reachable(self):
        """Files reachable from the root through live references in loaded sections."""
        return set(self._loaded_sections())

    def _live_names(self):
        """Names that still have a surviving definition in actually-loaded sections.

        Surge flattens every loaded definition into ONE namespace, so a name is
        dead only if no loaded section defines it any more. Unloaded sections
        (e.g. [Proxy Group] in a file imported only via [Proxy] #!include or
        policy-path) never contribute live names.
        """
        live = set()
        for abs_path, loaded_set in self._loaded_sections().items():
            state = self.files[abs_path]
            if state.is_abandoned:
                continue
            names = set()
            if _section_is_loaded(loaded_set, "Proxy"):
                names |= state.owned_proxies
            if _section_is_loaded(loaded_set, "Proxy Group"):
                names |= state.owned_groups
            live |= names - state.self_deleted
        return live

    def _emitting(self):
        """Files that get a -v4 copy in v4/: all-or-nothing over the loaded profile.

        Only changes inside actually-loaded sections count as pending changes:
        v5+ syntax sitting in an unloaded section of a sub-file never dirties a
        pure-v4 profile or triggers abandonment of clean managed sub-files.
        """
        loaded = self._loaded_sections()
        if not any(self._pending_change(self.files[p], secs) for p, secs in loaded.items()):
            return set()
        return set(loaded)

    def _abandon_state(self, state):
        """Mark a managed file abandoned and withdraw its definitions globally."""
        if state.is_abandoned:
            return
        state.is_abandoned = True
        self.abandoned_files.add(state.abs_path)
        self.global_deleted |= state.owned_proxies
        self.global_deleted |= state.owned_groups
        self.global_deleted |= state.deleted_names
        self.dead_wg_sections |= set(state.owned_wireguard_sections)
        self.dead_rulesets |= set(state.owned_rulesets)

    def _expand_wildcard_sections(self):
        """Downgrade local [WireGuard *] and track local [Ruleset *] sources.

        - Local non-managed [WireGuard *] targets are expanded into concrete
          v4-valid [WireGuard <name>] / #!include blocks right below the
          commented wildcard block.
        - Local non-managed [Ruleset *] targets are recorded so surviving
          RULE-SET references can be exported into external v4 .list files.
        - Managed targets that supply WireGuard/Ruleset definitions are
          abandoned (never snapshotted); remote URLs and missing local files
          flag unexpandable wildcard state so dangling references cascade.
        """
        # 1. Inspect [Ruleset *] and inline [Ruleset <name>] includes once.
        for state in list(self.files.values()):
            if state.is_managed:
                continue
            base_dir = os.path.dirname(state.abs_path)
            for i, line in enumerate(state.lines):
                sec = state.sections[i]
                if not line.startswith("# [V5+] "):
                    continue
                inner = line[len("# [V5+] "):]
                if not inner.lstrip().startswith("#!include"):
                    continue
                entries = parse_include_list(inner) or []
                if sec == "Ruleset *":
                    sources = self.ruleset_wildcard_sources.setdefault(state.abs_path, [])
                    for entry in entries:
                        if entry.startswith(("http://", "https://")):
                            state.has_unexpanded_ruleset_wildcard = True
                            continue
                        target_abs = os.path.normpath(os.path.join(base_dir, entry))
                        target = self.files.get(target_abs)
                        if target is None:
                            state.has_unexpanded_ruleset_wildcard = True
                        elif target.is_managed:
                            if target.owned_rulesets:
                                state.managed_wildcard_targets.add(target_abs)
                        elif target_abs not in sources:
                            sources.append(target_abs)
                elif sec and sec.startswith("Ruleset "):
                    rs_name = sec[len("Ruleset "):].strip()
                    for entry in entries:
                        if entry.startswith(("http://", "https://")):
                            continue
                        target_abs = os.path.normpath(os.path.join(base_dir, entry))
                        target = self.files.get(target_abs)
                        if target is not None and target.is_managed and rs_name in target.owned_rulesets:
                            state.managed_wildcard_targets.add(target_abs)

        # 2. Expand [WireGuard *] blocks to fixpoint (handles chained includes).
        expanded_any = True
        while expanded_any:
            expanded_any = False
            for state in list(self.files.values()):
                if state.is_managed:
                    continue
                base_dir = os.path.dirname(state.abs_path)
                basename = os.path.basename(state.abs_path)
                existing_wg = set(state.owned_wireguard_sections)
                insertions = []  # list of (after_idx, [(wg_name, entry), ...])

                i = 0
                n = len(state.lines)
                while i < n:
                    if state.sections[i] != "WireGuard *":
                        i += 1
                        continue
                    block_start = i
                    last_nonempty = i
                    entries = []
                    while i < n and state.sections[i] == "WireGuard *":
                        line = state.lines[i]
                        if line.strip():
                            last_nonempty = i
                        if line.startswith("# [V5+] "):
                            inner = line[len("# [V5+] "):]
                            if inner.lstrip().startswith("#!include"):
                                entries.extend(parse_include_list(inner) or [])
                        i += 1
                    to_expand = []
                    for entry in entries:
                        if entry.startswith(("http://", "https://")):
                            state.has_unexpanded_wg_wildcard = True
                            continue
                        target_abs = os.path.normpath(os.path.join(base_dir, entry))
                        target = self.files.get(target_abs)
                        if target is None:
                            state.has_unexpanded_wg_wildcard = True
                        elif target.is_managed:
                            if target.owned_wireguard_sections:
                                state.managed_wildcard_targets.add(target_abs)
                        else:
                            for wg_name in target.owned_wireguard_sections:
                                if wg_name in existing_wg:
                                    continue
                                existing_wg.add(wg_name)
                                state.owned_wireguard_sections.append(wg_name)
                                state.expanded_wg_sections.add(wg_name)
                                to_expand.append((wg_name, entry))
                    if to_expand:
                        insertions.append((last_nonempty, to_expand))

                if insertions:
                    for after_idx, items in reversed(insertions):
                        new_lines = []
                        for wg_name, entry in items:
                            new_lines.append(f"[WireGuard {wg_name}]")
                            new_lines.append(f"#!include {entry}")
                            self.stats.add_change(
                                basename, after_idx + 2, f"WireGuard {wg_name}",
                                "展开通配段", f"[WireGuard {wg_name}] ← {entry}",
                            )
                        state.lines[after_idx + 1:after_idx + 1] = new_lines
                    state.sections = compute_sections(state.lines, state.default_section)
                    expanded_any = True

    def _inspect_wireguard_section(self, abs_path, section_name, visited=None):
        """Inspect a concrete [WireGuard <name>] section across local non-abandoned
        #!include links, returning (defined_keys, lost_supply).

        Remote URL #!include (Linked Profiles, Mac 6.0.0+) is unavailable in v4
        and marks lost_supply=True rather than counting as valid v4 content.
        """
        if visited is None:
            visited = set()
        if abs_path in visited:
            return set(), False
        visited.add(abs_path)
        state = self.files.get(abs_path)
        if state is None or state.is_abandoned:
            return set(), True
        base_dir = os.path.dirname(abs_path)
        keys = set()
        lost_supply = False
        for i, line in enumerate(state.lines):
            if state.sections[i] != section_name:
                continue
            stripped = line.lstrip()
            if not stripped:
                continue
            if parse_section_header(line, include_v5_commented=True) is not None:
                continue
            if stripped.startswith(CASCADE_TAG + "#!include"):
                lost_supply = True
                continue
            if stripped.startswith("#!include"):
                for entry in parse_include_list(line) or []:
                    if entry.startswith(("http://", "https://")):
                        lost_supply = True
                        continue
                    target = os.path.normpath(os.path.join(base_dir, entry))
                    sub_keys, sub_lost = self._inspect_wireguard_section(
                        target, section_name, visited
                    )
                    keys |= sub_keys
                    lost_supply = lost_supply or sub_lost
                continue
            if stripped.startswith("#") or _COMMENT_PREFIX_RE.match(stripped):
                continue
            if "=" in stripped:
                keys.add(stripped.split("=", 1)[0].strip().lower())
        return keys, lost_supply

    def _root_live_wireguard_sections(self):
        """Concrete [WireGuard <name>] sections actually loaded & usable by root in v4."""
        root_abs = next(iter(self.files))
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
                root_abs, f"WireGuard {wg_name}"
            )
            if lost_supply:
                if _wireguard_keys_complete(keys):
                    live.add(wg_name)
            elif keys:
                live.add(wg_name)
        return live

    def _resolve_ruleset_lines(self, abs_path, rs_name, visited=None):
        """Resolve an inline [Ruleset <rs_name>] body (following local #!include).

        Returns a list of raw lines, or None if an #!include target is a remote
        URL, missing, managed, or abandoned and therefore cannot be materialized.
        """
        if visited is None:
            visited = set()
        if abs_path in visited:
            return []
        visited.add(abs_path)
        state = self.files.get(abs_path)
        if state is None or state.is_abandoned or rs_name not in state.owned_rulesets:
            return None
        base_dir = os.path.dirname(abs_path)
        resolved = []
        for line in state.owned_rulesets[rs_name]:
            if line.lstrip().startswith("#!include"):
                for entry in parse_include_list(line) or []:
                    if entry.startswith(("http://", "https://")):
                        return None
                    target_abs = os.path.normpath(os.path.join(base_dir, entry))
                    sub = self._resolve_ruleset_lines(target_abs, rs_name, visited)
                    if sub is None:
                        return None
                    resolved.extend(sub)
            else:
                resolved.append(line)
        return resolved

    def _root_available_rulesets(self):
        """Return (exportable_dict, unresolved_reasons, has_unexpanded_wildcard)
        for inline rulesets reachable from the root profile.

        Built-in rule sets (SYSTEM / LAN) always take precedence in Surge and
        are never shadowed, exported, or treated as dead inline definitions.
        Nested inline `RULE-SET,<Inner>` definitions are recursively expanded;
        unconvertible rule trees (remote/builtin nested RULE-SET, DOMAIN-SET,
        cycles, logical RULE-SET inside a ruleset) move to unresolved_reasons.
        """
        root_abs = next(iter(self.files))
        root_state = self.files[root_abs]
        if root_state.is_abandoned:
            return {}, {}, False
        raw_available = {}
        unresolved_reasons = {}
        has_unexpanded = root_state.has_unexpanded_ruleset_wildcard

        for rs_name in root_state.owned_rulesets:
            if rs_name.upper() in BUILTIN_RULESETS:
                continue
            lines = self._resolve_ruleset_lines(root_abs, rs_name)
            if lines is None:
                unresolved_reasons[rs_name] = f"规则集 {rs_name} 含无法解析的 #!include"
            else:
                raw_available[rs_name] = lines

        seen_sources = {root_abs}
        queue = list(self.ruleset_wildcard_sources.get(root_abs, []))
        while queue:
            src_abs = queue.pop(0)
            if src_abs in seen_sources:
                continue
            seen_sources.add(src_abs)
            src = self.files.get(src_abs)
            if src is None or src.is_abandoned:
                continue
            if src.has_unexpanded_ruleset_wildcard:
                has_unexpanded = True
            for rs_name in src.owned_rulesets:
                if rs_name.upper() in BUILTIN_RULESETS or rs_name in raw_available:
                    continue
                lines = self._resolve_ruleset_lines(src_abs, rs_name)
                if lines is None:
                    unresolved_reasons[rs_name] = f"规则集 {rs_name} 含无法解析的 #!include"
                else:
                    raw_available[rs_name] = lines
            queue.extend(self.ruleset_wildcard_sources.get(src_abs, []))

        exportable = {}
        for rs_name in raw_available:
            text, err = _expand_ruleset_for_v4(rs_name, raw_available)
            if err is not None:
                unresolved_reasons[rs_name] = err
            else:
                exportable[rs_name] = text

        for rs_name in exportable:
            unresolved_reasons.pop(rs_name, None)

        return exportable, unresolved_reasons, has_unexpanded

    def _cleanup_dead_wireguard_sections(self, root_state):
        """Cascade-comment concrete [WireGuard <name>] sections in root that lost
        a required supply (abandoned/remote #!include) and no longer satisfy
        Surge's required fields (private-key, self-ip/self-ip-v6, peer)."""
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
            keys, lost_supply = self._inspect_wireguard_section(root_abs, hdr)
            if lost_supply and not _wireguard_keys_complete(keys):
                self.dead_wg_sections.add(wg_name)
                for idx in range(sec_start, sec_end):
                    stripped = root_state.lines[idx].lstrip()
                    if not stripped:
                        continue
                    if idx == sec_start or (
                        not stripped.startswith("#") and not _COMMENT_PREFIX_RE.match(stripped)
                    ) or stripped.startswith("#!include"):
                        root_state.lines[idx] = CASCADE_TAG + stripped
                        self.stats.count_commented(basename)
                        changed_any = True
                self.stats.add_change(
                    basename, sec_start + 1, hdr, "级联注释",
                    f"[{hdr}] 缺少必需 WireGuard 字段",
                )
        if changed_any:
            root_state.sections = compute_sections(root_state.lines, root_state.default_section)

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
                sections = compute_sections(lines, state.default_section)
            else:
                lines = state.lines
                sections = state.sections
            for line, sec in zip(lines, sections):
                if sec == "Rule" and _is_live_final_rule(line):
                    return True
        return False

    def analyze(self):
        """Cross-file cascade: abandonment, deleted-name propagation, and
        per-file cleanup, iterated to a global fixpoint.

        Abandonment (managed file + any change) can arise from direct hits
        OR from cascade mutations. Abandoning a file removes its names from
        the global namespace, which can cascade further and dirty additional
        managed files — so the whole sequence loops until no new file gets
        abandoned. Only then are include / policy-path references rewritten,
        when every file's final status is known.
        """
        initial_loaded = self._loaded_sections()
        ever_loaded = set(initial_loaded)
        had_initial_final = self._has_live_final(initial_loaded, use_original=True)
        self._expand_wildcard_sections()
        ever_loaded |= set(self._loaded_sections())
        exportable_rulesets = {}

        while True:
            # 1. Abandon any managed file that would need a -v4 copy (see
            # _emitting). A -v4 copy of a managed profile would be
            # overwritten by Surge's periodic refresh, so it must never be
            # written. Its discarded names vanish from the global namespace.
            # Re-evaluated per file: one abandonment can make another
            # managed file unreachable, and unreachable is not abandoned.
            for state in self.files.values():
                if state.is_managed and not state.is_abandoned and state.abs_path in self._emitting():
                    self._abandon_state(state)
            emitting_now = self._emitting()
            for state in self.files.values():
                if state.is_abandoned or state.abs_path not in emitting_now:
                    continue
                for target_abs in state.managed_wildcard_targets:
                    target = self.files.get(target_abs)
                    if target is not None and not target.is_abandoned:
                        self._abandon_state(target)

            # 2. Merge direct-hit deletions ONLY from files whose [Proxy]
            # section is actually loaded by the root profile, then seed every
            # loaded non-abandoned file with global_deleted - live_names.
            loaded_map = self._loaded_sections()
            ever_loaded |= set(loaded_map)
            for abs_path, loaded_set in loaded_map.items():
                state = self.files[abs_path]
                if not state.is_abandoned and _section_is_loaded(loaded_set, "Proxy"):
                    self.global_deleted |= state.deleted_names
            live = self._live_names()
            effective_deleted = self.global_deleted - live
            for abs_path in loaded_map:
                state = self.files[abs_path]
                if state.is_abandoned:
                    continue
                state.deleted_names = set(effective_deleted)

            # 2a. Strip policy-path options in loaded [Proxy Group] sections.
            for abs_path, loaded_set in loaded_map.items():
                state = self.files[abs_path]
                if state.is_abandoned:
                    continue
                if _section_is_loaded(loaded_set, "Proxy Group"):
                    self._strip_abandoned_policy_paths(state)

            # 2b. Strip #!include entries pointing at abandoned files (in loaded
            # sections only), then check root [WireGuard <name>] completeness.
            for abs_path, loaded_set in loaded_map.items():
                state = self.files[abs_path]
                if state.is_abandoned:
                    continue
                self._strip_abandoned_includes(state, loaded_set=loaded_set)
            root_state = self.files[next(iter(self.files))]
            if not root_state.is_abandoned:
                self._cleanup_dead_wireguard_sections(root_state)

            # 2c. Snapshot root-loaded WireGuard sections and inline Rulesets
            # so dangling wireguard / RULE-SET references cascade cleanly.
            live_wg_sections = self._root_live_wireguard_sections()
            has_unexpanded_wg = root_state.has_unexpanded_wg_wildcard
            exportable_rulesets, unresolved_rs_reasons, has_unexpanded_rs = (
                self._root_available_rulesets()
            )
            dead_rulesets = {
                r for r in (self.dead_rulesets | set(unresolved_rs_reasons))
                if r.upper() not in BUILTIN_RULESETS and r not in exportable_rulesets
            }

            # 3. Fixpoint across loaded non-abandoned files (loaded sections
            # ONLY): each file's cascade may produce new deletions that must
            # propagate to other loaded files, always subtracting _live_names().
            changed = True
            while changed:
                changed = False
                loaded_map = self._loaded_sections()
                ever_loaded |= set(loaded_map)
                for abs_path, loaded_set in loaded_map.items():
                    state = self.files[abs_path]
                    if state.is_abandoned:
                        continue
                    live_now = self._live_names()
                    state.deleted_names = self.global_deleted - live_now
                    before_self = set(state.self_deleted)
                    self._cascade_single_file(
                        state,
                        loaded_set=loaded_set,
                        live_wg_sections=live_wg_sections,
                        has_unexpanded_wg=has_unexpanded_wg,
                        exportable_rulesets=exportable_rulesets,
                        dead_rulesets=dead_rulesets,
                        unresolved_rs_reasons=unresolved_rs_reasons,
                        has_unexpanded_rs=has_unexpanded_rs,
                    )
                    new_self = state.self_deleted - before_self
                    if new_self:
                        self.global_deleted |= new_self
                        changed = True

            # 3b. Withdraw names defined only in unreachable subtrees. A
            # non-abandoned file whose every path from the root runs through
            # an abandoned file is never emitted — names it defines don't
            # exist in the output, so references to them must cascade too.
            # New withdrawals need another full round (seed + strip + cascade).
            self.reachable = self._compute_reachable()
            new_withdrawn = set()
            for state in self.files.values():
                if (state.is_abandoned
                        or state.abs_path in self.reachable
                        or state.abs_path not in ever_loaded):
                    continue
                names = state.owned_proxies | state.owned_groups | state.deleted_names
                new_withdrawn |= names - self.global_deleted
            if new_withdrawn:
                self.global_deleted |= new_withdrawn
                continue

            # 4. If the cascade just put a managed file into the emitting set
            # (the profile became dirty, or the file itself changed), its
            # abandonment must be processed by another round; otherwise
            # we're stable.
            emitting = self._emitting()
            if not any(
                s.is_managed and not s.is_abandoned and s.abs_path in emitting
                for s in self.files.values()
            ):
                break

        # 5. Settle the emitting set, validate v4 output invariants (no lost
        # FINAL, no v4-unrepresentable names), then rewrite include /
        # policy-path references to -v4 names and materialize referenced inline
        # rulesets to v4 .list files.
        final_loaded = self._loaded_sections()
        self.emitting = self._emitting()
        if self.emitting and had_initial_final and not self._has_live_final(final_loaded, use_original=False):
            self.stats.errors.append(
                "级联清理后 [Rule] 缺少可用的 FINAL 规则（原 FINAL 指向已删除的策略或已放弃的文件），"
                "请为 v4 指定替代兜底策略；已停止导出。"
            )
        if self.stats.errors:
            self.emitting = set()
            self.generated_rulesets = {}
            return

        self._rewrite_references(final_loaded)
        if self.emitting:
            self._materialize_rulesets(exportable_rulesets, final_loaded)

        # 6. Convert commented-out nodes in emitted files (loaded [Proxy] only),
        # then re-serialize converted content from mutated lines.
        for state in self.files.values():
            if state.is_abandoned:
                continue
            if state.abs_path in self.emitting:
                if _section_is_loaded(final_loaded.get(state.abs_path), "Proxy"):
                    self._convert_commented_proxies(state)
            state.converted = _serialize_lines(state.lines, state.original)

    def _convert_commented_proxies(self, state):
        """Give commented-out [Proxy] nodes the same transforms as live ones,
        so uncommenting a node in the v4 copy yields a v4-valid line."""
        basename = os.path.basename(state.abs_path)
        for i, line in enumerate(state.lines):
            if state.sections[i] == "Proxy":
                state.lines[i] = transform_commented_proxy_line(
                    line, self.stats, basename, i + 1, "Proxy")

    def _rewrite_references(self, loaded_map=None):
        """Point include / policy-path references (in loaded sections only) at
        the -v4 names of files that will actually be emitted."""
        for state in self.files.values():
            if state.is_abandoned:
                continue
            if loaded_map is not None and state.abs_path not in loaded_map:
                continue
            loaded_set = loaded_map.get(state.abs_path) if loaded_map is not None else None
            base_dir = os.path.dirname(state.abs_path)
            basename = os.path.basename(state.abs_path)
            for i, line in enumerate(state.lines):
                if not _section_is_loaded(loaded_set, state.sections[i]):
                    continue
                new_line, notes = self._rewrite_line_refs(line, state.sections[i], base_dir)
                if new_line != line:
                    state.lines[i] = new_line
                    for note in notes:
                        self.stats.add_change(
                            basename, i + 1, state.sections[i] or "-", "引用改写", note)

    def _rewrite_line_refs(self, line, section, base_dir):
        """Rewrite one line's local references to -v4 names.

        Returns (new_line, notes). policy-path handling is STRUCTURED
        (parse_proxy_group_line options only) — quoted member names that
        merely contain "policy-path=" are identifiers and must stay intact.
        """
        notes = []
        stripped = line.lstrip()
        if stripped.startswith("#!include"):
            entries = parse_include_list(line)
            if not entries:
                return line, notes
            new_entries = []
            for entry in entries:
                if not entry.startswith(("http://", "https://")):
                    abs_path = os.path.normpath(os.path.join(base_dir, entry))
                    if abs_path in self.emitting:
                        new_entries.append(make_v4_relname(entry))
                        notes.append(f"{entry} → {make_v4_relname(entry)}")
                        continue
                new_entries.append(entry)
            if not notes:
                return line, notes
            trailing = _include_trailing_comment(line)
            return _preserve_indent(line, format_include_list(new_entries, trailing)), notes

        if section == "Proxy Group" and not stripped.startswith("#") and not _COMMENT_PREFIX_RE.match(stripped):
            pgl = parse_proxy_group_line(line)
            if pgl is None:
                return line, notes
            new_options = []
            for key, value in pgl.options:
                if key.lower() == "policy-path":
                    path_val = unquote(value.strip())
                    if not path_val.startswith(("http://", "https://")):
                        abs_path = os.path.normpath(os.path.join(base_dir, path_val))
                        if abs_path in self.emitting:
                            rel_v4 = make_v4_relname(path_val)
                            is_q = len(value.strip()) >= 2 and value.strip()[0] == '"' and value.strip()[-1] == '"'
                            new_val = f'"{_escape_quoted(rel_v4)}"' if is_q else rel_v4
                            new_options.append((key, new_val))
                            notes.append(f"policy-path={path_val} → policy-path={rel_v4}")
                            continue
                new_options.append((key, value))
            if not notes:
                return line, notes
            pgl.options = new_options
            return _preserve_indent(line, format_proxy_group_line(pgl)), notes

        return line, notes

    def _materialize_rulesets(self, exportable_rulesets, loaded_map=None):
        """Export inline [Ruleset <name>] sections that still have live RULE-SET
        references (top-level or inside AND/OR/NOT) into root-scoped v4/*.list
        files and rewrite those RULE-SET targets."""
        if not exportable_rulesets:
            return
        root_abs = next(iter(self.files))
        root_path = Path(root_abs)
        root_stem = re.sub(r'[^A-Za-z0-9._-]+', '-', root_path.stem).strip('.-') or "profile"
        v4_dir = os.path.join(os.path.dirname(root_abs), V4_SUBDIR)
        used_names = {os.path.basename(make_v4_filename(p)) for p in self.emitting}
        assigned = {}  # rs_name → bare .list filename

        for abs_path in self.emitting:
            state = self.files[abs_path]
            if state.is_abandoned:
                continue
            loaded_set = loaded_map.get(abs_path) if loaded_map is not None else None
            if not _section_is_loaded(loaded_set, "Rule"):
                continue
            basename = os.path.basename(abs_path)
            for i, line in enumerate(state.lines):
                if state.sections[i] != "Rule":
                    continue
                targets = extract_rule_ruleset_targets(line)
                if not targets:
                    continue
                replacements = {}
                for target in targets:
                    if target.upper() in BUILTIN_RULESETS or target not in exportable_rulesets:
                        continue
                    if target not in assigned:
                        safe_rs = re.sub(r'[^A-Za-z0-9._-]+', '-', target).strip('.-') or "ruleset"
                        digest = hashlib.sha256(
                            f"{root_path.name}\0{target}".encode("utf-8")
                        ).hexdigest()[:8]
                        cand = f"{root_stem}-{safe_rs}-{digest}-ruleset-v4.list"
                        suffix = 2
                        while cand in used_names:
                            cand = f"{root_stem}-{safe_rs}-{digest}-{suffix}-ruleset-v4.list"
                            suffix += 1
                        used_names.add(cand)
                        assigned[target] = cand
                        self.generated_rulesets[os.path.join(v4_dir, cand)] = (
                            exportable_rulesets[target]
                        )
                    replacements[target] = assigned[target]
                if not replacements:
                    continue
                new_line = _replace_rule_ruleset_targets(line, replacements)
                if new_line != line:
                    state.lines[i] = new_line
                    for target, list_name in replacements.items():
                        self.stats.add_change(
                            basename, i + 1, "Rule", "规则集导出", f"{target} → {list_name}")

    def _cascade_single_file(self, state, loaded_set=None, live_wg_sections=None,
                             has_unexpanded_wg=False, exportable_rulesets=None,
                             dead_rulesets=None, unresolved_rs_reasons=None,
                             has_unexpanded_rs=False):
        """Fixpoint over loaded sections only: cascade deleted proxies/groups
        through underlying-proxy, dangling WireGuard section-names, Proxy Group
        members/options (using v4-readable formatting), and finally Rule
        policies and dead/unconvertible RULE-SET references (top-level and
        nested inside AND/OR/NOT)."""
        live_wg_sections = live_wg_sections if live_wg_sections is not None else set()
        exportable_rulesets = exportable_rulesets if exportable_rulesets is not None else {}
        dead_rulesets = dead_rulesets if dead_rulesets is not None else set()
        unresolved_rs_reasons = unresolved_rs_reasons if unresolved_rs_reasons is not None else {}
        basename = os.path.basename(state.abs_path)

        def _mark_deleted(deleted_name):
            state.self_deleted.add(deleted_name)
            self.global_deleted.add(deleted_name)
            if deleted_name not in self._live_names():
                state.deleted_names.add(deleted_name)

        changed = True
        while changed:
            changed = False
            for i, line in enumerate(state.lines):
                section = state.sections[i]
                if not _section_is_loaded(loaded_set, section):
                    continue
                stripped = line.lstrip()
                if not stripped or stripped.startswith("#") or _COMMENT_PREFIX_RE.match(stripped):
                    continue

                if section == "Proxy":
                    if "=" not in line:
                        continue
                    name = line.split("=", 1)[0].strip()
                    if not name:
                        continue
                    underlying = extract_proxy_option(line, "underlying-proxy")
                    if underlying and underlying in state.deleted_names:
                        state.lines[i] = CASCADE_TAG + stripped
                        _mark_deleted(unquote(name))
                        self.stats.count_commented(basename)
                        self.stats.add_change(
                            basename, i + 1, "Proxy", "级联注释",
                            f"{name} (underlying-proxy={underlying})",
                        )
                        changed = True
                        continue
                    if extract_proxy_type(line) == "wireguard":
                        wg_sec = extract_proxy_option(line, "section-name")
                        if (wg_sec and wg_sec not in live_wg_sections
                                and (wg_sec in self.dead_wg_sections or has_unexpanded_wg)):
                            state.lines[i] = CASCADE_TAG + stripped
                            _mark_deleted(unquote(name))
                            self.stats.count_commented(basename)
                            self.stats.add_change(
                                basename, i + 1, "Proxy", "级联注释",
                                f"{name} (WireGuard {wg_sec})",
                            )
                            changed = True
                    continue

                if section != "Proxy Group":
                    continue
                pgl = parse_proxy_group_line(line)
                if pgl is None:
                    continue

                # If the group's relay (underlying-proxy) was deleted, cascade
                # the entire group rather than silently dropping the relay.
                dead_relay = None
                for k, v in pgl.options:
                    if k.lower() == "underlying-proxy":
                        relay = unquote(v.strip())
                        if relay in state.deleted_names:
                            dead_relay = relay
                            break
                if dead_relay is not None:
                    state.lines[i] = CASCADE_TAG + stripped
                    _mark_deleted(unquote(pgl.name))
                    self.stats.count_commented(basename)
                    self.stats.add_change(
                        basename, i + 1, "Proxy Group", "级联注释",
                        f"{pgl.name} (underlying-proxy={dead_relay})",
                    )
                    changed = True
                    continue

                original_members = list(pgl.members)
                pgl.members = [
                    m for m in original_members
                    if unquote(m) not in state.deleted_names
                ]
                # include-other-group pointing at deleted group(s) is dead supply;
                # multi-group values ("G1, G2") strip only deleted entries and
                # re-encode surviving names into Surge v4-readable syntax.
                original_options = list(pgl.options)
                new_options = []
                removed_opt_tokens = []
                reencoded_iog = False
                for k, v in original_options:
                    if k.lower() == "include-other-group":
                        sv = v.strip()
                        was_quoted = len(sv) >= 2 and sv[0] == '"' and sv[-1] == '"'
                        groups = parse_include_other_groups(sv)
                        kept = [g for g in groups if g not in state.deleted_names]
                        dropped = [g for g in groups if g in state.deleted_names]
                        needs_v4_reencode = _has_v5_quote_escape(sv)
                        if not dropped and not needs_v4_reencode:
                            new_options.append((k, v))
                        elif kept:
                            try:
                                encoded = format_include_other_groups(kept, was_quoted=was_quoted)
                            except ValueError as exc:
                                err_msg = f"{basename}:{i + 1} [{pgl.name}] {exc}"
                                if err_msg not in self.stats.errors:
                                    self.stats.errors.append(err_msg)
                                new_options.append((k, v))
                                continue
                            new_options.append((k, encoded))
                            if dropped:
                                removed_opt_tokens.append(f"{k}:{', '.join(dropped)}")
                            elif encoded != v:
                                reencoded_iog = True
                        else:
                            removed_opt_tokens.append(f"{k}={v}")
                    else:
                        new_options.append((k, v))
                pgl.options = new_options
                removed_tokens = (
                    [m for m in original_members if m not in pgl.members]
                    + removed_opt_tokens
                )
                if not removed_tokens and not reencoded_iog:
                    continue  # D6: pre-existing empty groups left alone
                if not removed_tokens and reencoded_iog:
                    new_line = _preserve_indent(line, format_proxy_group_line(pgl))
                    if new_line != line:
                        state.lines[i] = new_line
                        self.stats.count_params(basename)
                        self.stats.add_change(
                            basename, i + 1, "Proxy Group", "v4 语法改写", pgl.name)
                        changed = True
                    continue
                if has_effective_members(pgl, state.deleted_names, abandoned_basenames=set()):
                    new_line = _preserve_indent(line, format_proxy_group_line(pgl))
                    if new_line != line:
                        state.lines[i] = new_line
                        self.stats.add_change(
                            basename, i + 1, "Proxy Group", "级联移除成员",
                            f"{pgl.name}: {', '.join(removed_tokens)}")
                        changed = True
                else:
                    # Tag the REFORMATTED (post-cleanup) line so the cascade
                    # comment shows the group in its cleaned state.
                    reformatted = _preserve_indent(line, format_proxy_group_line(pgl))
                    state.lines[i] = CASCADE_TAG + reformatted.lstrip()
                    _mark_deleted(unquote(pgl.name))
                    self.stats.count_commented(basename)
                    self.stats.add_change(basename, i + 1, "Proxy Group", "级联注释", pgl.name)
                    changed = True

        # Post-fixpoint: comment out loaded [Rule] lines whose policy or
        # RULE-SET target (top-level or nested inside AND/OR/NOT) is now dead.
        if not _section_is_loaded(loaded_set, "Rule"):
            return
        base_dir = os.path.dirname(state.abs_path)
        for i, line in enumerate(state.lines):
            if state.sections[i] != "Rule":
                continue
            stripped = line.lstrip()
            if not stripped or stripped.startswith("#") or _COMMENT_PREFIX_RE.match(stripped):
                continue
            policy = extract_rule_policy(line)
            if policy is not None and unquote(policy) in state.deleted_names:
                state.lines[i] = CASCADE_TAG + stripped
                self.stats.count_commented(basename)
                self.stats.add_change(basename, i + 1, "Rule", "级联注释", line.strip())
                continue
            rs_targets = extract_rule_ruleset_targets(line)
            dead_reason = None
            for rs_target in rs_targets:
                if rs_target.upper() in BUILTIN_RULESETS:
                    continue
                if rs_target in dead_rulesets:
                    dead_reason = unresolved_rs_reasons.get(rs_target) or f"规则集 {rs_target} 不可用"
                    break
                if (has_unexpanded_rs
                        and not rs_target.startswith(("http://", "https://"))
                        and rs_target not in exportable_rulesets
                        and not os.path.isfile(os.path.normpath(os.path.join(base_dir, rs_target)))):
                    dead_reason = f"规则集 {rs_target} 来源无法展开"
                    break
            if dead_reason is not None:
                state.lines[i] = CASCADE_TAG + stripped
                self.stats.count_commented(basename)
                self.stats.add_change(
                    basename, i + 1, "Rule", "级联注释",
                    f"{line.strip()} ({dead_reason})",
                )

    def _strip_abandoned_policy_paths(self, state):
        """Remove policy-path=<abandoned> options from Proxy Group lines.

        If a group becomes empty after the strip (no explicit members, no
        include-all-proxies, no other valid policy-path), tag it cascade
        and propagate the group name to global_deleted AND every other
        file's deleted_names so the downstream fixpoint sees it.
        """
        abandoned_basenames = {os.path.basename(p) for p in self.abandoned_files}
        if not abandoned_basenames:
            return
        for i, line in enumerate(state.lines):
            if state.sections[i] != "Proxy Group":
                continue
            if line.lstrip().startswith("#"):
                continue
            pgl = parse_proxy_group_line(line)
            if pgl is None:
                continue
            new_options = []
            removed_values = []
            for key, value in pgl.options:
                if key.lower() == "policy-path":
                    path_val = unquote(value.strip())
                    if path_val.startswith("http://") or path_val.startswith("https://"):
                        new_options.append((key, value))
                        continue
                    if os.path.basename(path_val) in abandoned_basenames:
                        removed_values.append(path_val)
                        continue
                new_options.append((key, value))
            if not removed_values:
                continue
            pgl.options = new_options
            if has_effective_members(pgl, state.deleted_names, abandoned_basenames):
                state.lines[i] = _preserve_indent(line, format_proxy_group_line(pgl))
                self.stats.add_change(
                    os.path.basename(state.abs_path), i + 1, "Proxy Group",
                    "移除 policy-path", f"{pgl.name}: {', '.join(removed_values)}")
            else:
                reformatted = _preserve_indent(line, format_proxy_group_line(pgl))
                state.lines[i] = CASCADE_TAG + reformatted.lstrip()
                deleted_name = unquote(pgl.name)
                state.deleted_names.add(deleted_name)
                state.self_deleted.add(deleted_name)
                self.global_deleted.add(deleted_name)
                # Propagate to all other non-abandoned files so the downstream
                # fixpoint catches references to this group — unless some other
                # emitted file still defines the same name.
                if deleted_name not in self._live_names():
                    for other in self.files.values():
                        if other is not state and not other.is_abandoned:
                            other.deleted_names.add(deleted_name)
                basename = os.path.basename(state.abs_path)
                self.stats.count_commented(basename)
                self.stats.add_change(basename, i + 1, "Proxy Group", "级联注释", pgl.name)

    def _strip_abandoned_includes(self, state, loaded_set=None):
        """Remove entries in #!include lines (in loaded sections only) that
        point at abandoned files.

        If the list becomes empty after stripping, tag the whole line cascade.
        """
        abandoned_basenames = {os.path.basename(p) for p in self.abandoned_files}
        if not abandoned_basenames:
            return
        for i, line in enumerate(state.lines):
            if not _section_is_loaded(loaded_set, state.sections[i]):
                continue
            if not line.lstrip().startswith("#!include"):
                continue
            entries = parse_include_list(line)
            if entries is None:
                continue
            kept = [
                e for e in entries
                # URLs are never abandoned local files — a remote entry whose
                # basename happens to collide with an abandoned local file
                # (e.g. a local mirror named after its source URL) must stay.
                if e.startswith(("http://", "https://"))
                or os.path.basename(e) not in abandoned_basenames
            ]
            if len(kept) == len(entries):
                continue
            if not kept:
                state.lines[i] = CASCADE_TAG + line.lstrip()
                basename = os.path.basename(state.abs_path)
                self.stats.count_commented(basename)
                self.stats.add_change(basename, i + 1, "#!include", "级联注释", line.strip())
            else:
                new_line = format_include_list(kept, _include_trailing_comment(line))
                state.lines[i] = _preserve_indent(line, new_line)
                removed_entries = [e for e in entries if e not in kept]
                self.stats.add_change(
                    os.path.basename(state.abs_path), i + 1, "#!include",
                    "移除 include 条目", ", ".join(removed_entries))

    def emit(self):
        """Write -v4 files based on FileState decisions. Returns root output path."""
        if self.stats.errors:
            for err in self.stats.errors:
                print(f"错误: {err}", file=sys.stderr)
            return None

        root_output = None
        root_abs = next(iter(self.files))  # first discovered = root

        # Reachability was settled by analyze() (it can't be recomputed here:
        # references are already rewritten to -v4 names). A sub-file only
        # reachable via an abandoned managed config is never emitted — and
        # analyze() has already withdrawn its names from the namespace.
        reachable = self.reachable

        for abs_path, state in self.files.items():
            output_path = make_v4_filename(abs_path)

            # Abandon decision was made in discover(). Just act on it here:
            # refuse to write, surface stale -v4 (don't delete).
            if state.is_abandoned:
                self.stats.abandoned_files.append(abs_path)
                self.processed_files[abs_path] = None
                # Its recorded edits were discarded along with the conversion.
                self.stats.discard_file(os.path.basename(abs_path))
                print(f"已放弃托管配置（含 v5+ 内容）: {abs_path}")
                # Check both layouts: the current v4/ subdirectory and the
                # pre-v4/-subdir layout (-v4 file next to the source), which
                # is where every file from older converter versions lives.
                src = Path(abs_path)
                old_layout = str(src.with_stem(src.stem + "-v4"))
                for stale in (output_path, old_layout):
                    if os.path.exists(stale):
                        self.stats.stale_v4_files.append(stale)
                        print(f"  ⚠️  检测到旧的 v4 文件（未自动删除）: {stale}")
                if abs_path == root_abs:
                    root_output = None
                continue

            # Discovered only through an abandoned file — nothing in the
            # emitted output references it; skip to avoid orphan files.
            if abs_path not in reachable:
                self.processed_files[abs_path] = None
                self.stats.discard_file(os.path.basename(abs_path))
                continue

            # Not part of the output: nothing in the profile needs conversion.
            if abs_path not in self.emitting:
                self.processed_files[abs_path] = None
                self.stats.discard_file(os.path.basename(abs_path))
                if abs_path == root_abs:
                    root_output = None
                continue

            # Skip if existing -v4 already has correct content
            if os.path.exists(output_path):
                with open(output_path, "r", encoding="utf-8") as f:
                    existing = f.read()
                if existing == state.converted:
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

        # Emit any externalized v4 ruleset files (.list) referenced by emitted configs.
        for output_path, content in self.generated_rulesets.items():
            if os.path.exists(output_path):
                with open(output_path, "r", encoding="utf-8") as f:
                    existing = f.read()
                if existing == content:
                    print(f"已跳过（内容未变化）: {output_path}")
                    continue
            os.makedirs(os.path.dirname(output_path), exist_ok=True)
            backup = backup_if_exists(output_path)
            if backup:
                self.stats.deprecated_files.append(backup)
                print(f"已备份: {output_path} → {backup}")
            with open(output_path, "w", encoding="utf-8") as f:
                f.write(content)
            self.stats.files_processed.append(output_path)
            print(f"已导出规则集: {output_path}")

        return root_output

    def run(self, root_path, default_section=None):
        state = self.discover(root_path, default_section)
        if state is None:
            # discover already printed the reason (unreadable / undecodable)
            sys.exit(1)
        self.analyze()
        return self.emit()


def convert_file(input_path, stats=None, processed_files=None, default_section=None,
                 snell_legacy=None):
    """Convert a Surge config file from v5+ to v4 (top-level entry point).

    Creates a Pipeline, runs discover → analyze → emit over this file and
    every transitively referenced local file, and returns the root file's
    output path (or None if abandoned / unchanged). snell_legacy is the
    table from load_snell_legacy (None: feature off).
    """
    if stats is None:
        stats = ConversionStats()

    input_path = os.path.abspath(input_path)
    if not os.path.isfile(input_path):
        if os.path.isdir(input_path):
            print(f"错误: 路径是目录而非文件: {input_path}", file=sys.stderr)
        else:
            print(f"错误: 文件不存在: {input_path}", file=sys.stderr)
        sys.exit(1)

    pipeline = Pipeline(stats, processed_files, snell_legacy)
    return pipeline.run(input_path, default_section=default_section)


def default_snell_legacy_path():
    """${XDG_CONFIG_HOME:-~/.config}/surge-config-converter/snell-legacy.ini"""
    base = os.environ.get("XDG_CONFIG_HOME") or os.path.expanduser("~/.config")
    return os.path.join(base, "surge-config-converter", SNELL_LEGACY_FILENAME)


def _check_legacy_section(path, name, fields):
    """Exit on a malformed section. Messages name keys, never values."""
    unknown = sorted(set(fields) - set(_SNELL_LEGACY_FIELD_RES))
    if unknown or not fields:
        sys.exit(f"错误: {path} [{name}] 只允许 server / port / psk 且至少一个"
                 f"（未知键: {', '.join(unknown) or '无'}）")
    for key, value in fields.items():
        if not value or "," in value or "\n" in value or (key == "port" and not value.isdigit()):
            sys.exit(f"错误: {path} [{name}] 的 {key} 取值无效（不能为空、含逗号或换行，port 须为数字）")


def load_snell_legacy(path):
    """Parse a snell legacy override file into {source basename: {field: value}}.

    INI sections are source basenames; keys are server / port / psk. Parse
    errors report only the exception type: configparser messages quote the
    offending line, which may hold a secret.
    """
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
    """Explicit --snell-legacy path, else the default path if it exists, else None."""
    if arg_path:
        return load_snell_legacy(arg_path)
    default = default_snell_legacy_path()
    return load_snell_legacy(default) if os.path.isfile(default) else None


def main():
    parser = argparse.ArgumentParser(description="Surge v5+ → v4 配置转换")
    parser.add_argument("input_path")
    parser.add_argument("--snell-legacy", metavar="PATH",
                        help=f"snell 旧版覆盖文件（默认 {default_snell_legacy_path()}，存在才加载）")
    args = parser.parse_args()

    input_path = args.input_path
    snell_legacy = resolve_snell_legacy(args.snell_legacy)
    stats = ConversionStats()
    processed_files = {os.path.abspath(input_path): None}
    result = convert_file(input_path, stats, processed_files, snell_legacy=snell_legacy)
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
            # Non-interactive run (cron / pipe): keep the backups. Deleting
            # files requires an explicit human answer — pipe content (even a
            # stray blank line) must never count as consent.
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
