#!/usr/bin/env python3
"""Surge v5+ -> v4 configuration converter.

Usage:
    python3 converter.py <input_file_path>

Output layout:
    All generated -v4 files are written to a v4/ subdirectory next to
    the source files:

        Documents/
        ├── home.conf              <- source (v5+)
        ├── mai-vps.dconf
        └── v4/
            ├── home-v4.conf       <- converted (v4)
            └── mai-vps-v4.dconf

    Files inside v4/ reference each other using bare filenames (e.g.
    #!include mai-vps-v4.dconf) with no directory prefix. To use them,
    copy everything in v4/ to the top-level config directory on the
    Surge v4 device. Referenced sub-files that needed no conversion get
    no -v4 copy and keep their original names in the parent — the
    destination directory must contain those originals too.

Limitation:
    All referenced files (#!include, policy-path) must reside in the
    same directory as the root config. Sub-directory references produce
    output under <subdir>/v4/ while parents reference bare -v4 names,
    so those need manual merging; identically named files in different
    sub-directories would collide.
"""

import os
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path

from send2trash import send2trash


# Proxy types not supported in Surge v4
V5PLUS_ONLY_PROXY_TYPES = {"hysteria2", "hy2", "anytls", "tuic", "trust-tunnel"}

# Sections that should be entirely commented out in v4
V5PLUS_ONLY_SECTIONS = {"Port Forwarding", "Body Rewrite"}

# General parameters not supported in v4
V5PLUS_ONLY_GENERAL_PARAMS = {"udp-priority", "block-quic"}

# Rule types not supported in v4
V5PLUS_ONLY_RULE_TYPES = {"HOSTNAME-TYPE", "DOMAIN-WILDCARD"}

# v5+ only rule types appearing as parenthesized criteria of AND/OR/NOT rules
_V5PLUS_NESTED_RULE_RE = re.compile(
    r'\(\s*(?:' + '|'.join(sorted(V5PLUS_ONLY_RULE_TYPES)) + r')\s*,'
)

# Proxy parameters to remove (v5+ only)
V5PLUS_ONLY_PROXY_PARAMS = {"port-hopping", "port-hopping-interval", "ecn"}

# Cascade-cleanup tag prefix: distinguishes follow-on deletions from direct hits.
CASCADE_TAG = "# [V5+ cascade] "

# policy-path option matcher. Tolerates whitespace around '=' and inside the
# path (a value runs until the next comma), matching the tolerant structured
# parser in parse_proxy_group_line.
POLICY_PATH_RE = re.compile(r'policy-path\s*=\s*([^,]+)')


def unquote(name):
    """Strip surrounding double quotes from a proxy / group name token."""
    if len(name) >= 2 and name[0] == '"' and name[-1] == '"':
        return name[1:-1]
    return name


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
        m = re.match(r'^(?:# \[V5\+\] )?\[(.+)\]$', line.strip())
        if m:
            current = m.group(1)
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
        if key == "include-all-proxies" and value.strip() in {"1", "true"}:
            return True
        if key == "include-other-group" and unquote(value.strip()) not in deleted_names:
            return True
        if key == "policy-path":
            if value.startswith("http://") or value.startswith("https://"):
                return True
            if os.path.basename(value) not in abandoned_basenames:
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

    Example: /path/to/home.conf -> /path/to/v4/home-v4.conf
    """
    p = Path(filepath)
    return str(p.parent / V4_SUBDIR / (p.stem + "-v4" + p.suffix))


def make_v4_relname(filename):
    """Generate the -v4 basename for config-internal references.

    All v4 files share the same v4/ subdirectory, so cross-references
    between them use bare filenames without directory prefix.
    Example: mai-vps.dconf -> mai-vps-v4.dconf
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
    deleted_names: set = field(default_factory=set)    # names removed (propagates cascade)
    child_refs: set = field(default_factory=set)       # abs paths of local #!include / policy-path refs


def parse_proxy_group_line(line):
    """Parse a Surge Proxy Group definition line.

    Returns a ProxyGroupLine or None if the line is not a group definition
    (comment, section header, empty line, etc.).
    """
    stripped = line.lstrip()
    if not stripped or stripped.startswith("#") or stripped.startswith("["):
        return None
    if "=" not in line:
        return None

    name_part, rest = line.split("=", 1)
    name = name_part.strip()
    if not name:
        return None

    tokens = _split_top_level_commas(rest)
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

    return ProxyGroupLine(name=name, group_type=group_type, members=members, options=options)


def format_proxy_group_line(pgl):
    """Format a ProxyGroupLine back into a config line (stable round-trip)."""
    parts = [pgl.group_type]
    parts.extend(pgl.members)
    parts.extend(f"{k}={v}" for k, v in pgl.options)
    return f"{pgl.name} = " + ", ".join(parts)


# Known trailing options that can follow the policy in a rule line
RULE_TRAILING_OPTIONS = {
    "no-resolve",
    "force-remote-dns",
    "extended-matching",
    "dns-failed",
    "pre-matching",
}


def _split_top_level_commas(s):
    """Split a string by commas at depth 0, outside of balanced parentheses
    AND outside of double quotes.

    Used for rule lines (AND/OR/NOT compound criteria wrapped in parens) and
    for proxy group member lists, where quoted names like "HK, Fast" must
    stay a single token.
    """
    parts = []
    depth = 0
    in_quote = False
    start = 0
    for i, ch in enumerate(s):
        if ch == '"':
            in_quote = not in_quote
        elif in_quote:
            continue
        elif ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
        elif ch == "," and depth == 0:
            parts.append(s[start:i])
            start = i + 1
    parts.append(s[start:])
    return [p.strip() for p in parts]


def parse_include_list(line):
    """Parse a #!include line into a list of path/url entries, or None.

    Returns None if the line is not an #!include directive.
    """
    m = re.match(r'^\s*#!include\s+(.+)$', line)
    if not m:
        return None
    return [p.strip() for p in m.group(1).split(",") if p.strip()]


def format_include_list(entries):
    """Format a list of entries back into a #!include line.

    Returns None if the list is empty (caller should comment the whole line).
    """
    if not entries:
        return None
    return "#!include " + ", ".join(entries)


def extract_rule_policy(line):
    """Return the policy target from a rule line, or None if not a rule.

    Walks top-level comma-separated tokens from the end, skipping known
    trailing option keywords and key=value option pairs; the first remaining
    token is the policy.
    """
    stripped = line.lstrip()
    if not stripped or stripped.startswith("#") or stripped.startswith("["):
        return None
    tokens = _split_top_level_commas(stripped)
    if len(tokens) < 2:
        return None
    i = len(tokens) - 1
    while i > 0:
        t = tokens[i]
        if t in RULE_TRAILING_OPTIONS:
            i -= 1
            continue
        if "=" in t and not t.startswith('"'):
            i -= 1
            continue
        return t
    return None


def remove_proxy_params(line, params_to_remove):
    """Remove specific key=value parameters from a proxy line.

    Returns (modified_line, list_of_removed_param_names).
    """
    removed = []
    for param in params_to_remove:
        # Match param=value where value can be quoted or unquoted
        # Handle: param=value, param="value", param='value'
        pattern = r',\s*' + re.escape(param) + r'=["\']?[^,]*["\']?'
        new_line, n = re.subn(pattern, '', line)
        if n > 0:
            line = new_line
            removed.append(param)
    return line, removed


def transform_proxy_line(line, stats, filename, line_num, section):
    """Transform a single proxy line in [Proxy] section."""
    proxy_type = extract_proxy_type(line)
    if not proxy_type:
        return line

    name = line.split('=', 1)[0].strip()

    # Comment out v5+ only proxy types
    if proxy_type in V5PLUS_ONLY_PROXY_TYPES:
        stats.count_commented(filename)
        stats.add_change(filename, line_num, section, "注释", f"{name} ({proxy_type})")
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
    if stripped.startswith("#"):
        return line

    for rule_type in V5PLUS_ONLY_RULE_TYPES:
        if stripped.startswith(rule_type + ","):
            stats.count_commented(filename)
            stats.add_change(filename, line_num, section, "注释", stripped)
            return comment_line(line)

    # v5+ only rule types nested inside AND/OR/NOT compound criteria,
    # e.g. AND,((DOMAIN-WILDCARD,*bar*),(DEST-PORT,443)),DIRECT
    if _V5PLUS_NESTED_RULE_RE.search(stripped):
        stats.count_commented(filename)
        stats.add_change(filename, line_num, section, "注释", stripped)
        return comment_line(line)

    return line


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


def convert_content(content, base_dir, stats, processed_files, default_section=None, filename=""):
    """Convert configuration content from v5+ to v4 format (direct hits only).

    Args:
        base_dir, processed_files: kept for signature compatibility; sub-file
                         discovery and reference rewriting now live in Pipeline.
        default_section: If set, treat lines before any [Section] header
                         as belonging to this section. Used for included files
                         that lack section headers.

    Returns the converted content string.
    """
    lines = content.splitlines()
    result = []
    current_section = default_section
    in_v5plus_only_section = False

    for line_num, line in enumerate(lines, 1):
        stripped = line.strip()

        # Detect section headers
        section_match = re.match(r'^\[(.+)\]$', stripped)
        if section_match:
            section_name = section_match.group(1)
            if section_name in V5PLUS_ONLY_SECTIONS:
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
        if stripped.startswith("#"):
            result.append(line)
            continue

        # Apply section-specific transformations
        if current_section == "General":
            result.append(transform_general_line(line, stats, filename, line_num, current_section))
        elif current_section == "Proxy":
            result.append(transform_proxy_line(line, stats, filename, line_num, current_section))
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


class Pipeline:
    """Three-phase converter: discover → analyze → emit.

    The pipeline owns the dict of FileState for the root file and all
    recursively-discovered dependencies. Analyze and emit iterate over this
    shared dict — this is what makes cross-file cascade cleanup possible.
    """

    def __init__(self, stats, processed_files=None):
        self.stats = stats
        self.files = {}  # abs_path → FileState (insertion order = discovery order)
        self.processed_files = processed_files if processed_files is not None else {}
        self.abandoned_files = set()    # absolute paths of managed files we refused
        self.global_deleted = set()     # union of all names deleted anywhere

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
        state.converted = convert_content(
            original, base_dir, self.stats, self.processed_files,
            default_section=default_section,
            filename=os.path.basename(abs_path),
        )

        # Populate cascade fields: split into mutable lines, sectionize, and
        # catalog owned proxy / group names. Seed deleted_names with any
        # v5+ proxy whose definition just got commented by direct-hit pass.
        state.lines = state.converted.splitlines()
        state.sections = compute_sections(state.lines, default_section)
        for i, line in enumerate(state.lines):
            section = state.sections[i]
            if section == "Proxy":
                if line.startswith("# [V5+] "):
                    raw = line[len("# [V5+] "):]
                    if "=" in raw:
                        name = raw.split("=", 1)[0].strip()
                        if name:
                            state.deleted_names.add(unquote(name))
                elif not line.lstrip().startswith("#") and "=" in line:
                    name = line.split("=", 1)[0].strip()
                    if name:
                        state.owned_proxies.add(unquote(name))
            elif section == "Proxy Group":
                if not line.lstrip().startswith("#") and "=" in line:
                    name = line.split("=", 1)[0].strip()
                    if name:
                        state.owned_groups.add(unquote(name))

        # Recurse into local #!include and policy-path references so every
        # transitively referenced file lives in the shared FileState dict.
        for i, line in enumerate(state.lines):
            stripped = line.lstrip()
            if stripped.startswith("#!include"):
                for entry in parse_include_list(line) or []:
                    self._discover_ref(state, base_dir, entry, state.sections[i])
            elif state.sections[i] == "Proxy Group" and not stripped.startswith("#"):
                # policy-path always references proxy list files
                for m in POLICY_PATH_RE.finditer(line):
                    self._discover_ref(state, base_dir, m.group(1).strip(), "Proxy")

        return state

    def _discover_ref(self, parent, base_dir, ref, default_section):
        """Discover one local reference; URLs and missing files are ignored."""
        if ref.startswith("http://") or ref.startswith("https://"):
            return
        abs_path = os.path.normpath(os.path.join(base_dir, ref))
        if not os.path.isfile(abs_path):
            return
        if self.discover(abs_path, default_section=default_section) is not None:
            parent.child_refs.add(abs_path)

    def _pending_change(self, state):
        """True if the file's working lines differ from its original content."""
        return _serialize_lines(state.lines, state.original) != state.original

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
        while True:
            # 1. Abandon any managed file whose working content has changed
            # (direct hits on the first iteration; cascade mutations later).
            # A -v4 copy of a managed profile would be overwritten by Surge's
            # periodic refresh, so it must never be written. Its discarded
            # names vanish from the global namespace.
            for state in self.files.values():
                if state.is_managed and not state.is_abandoned and self._pending_change(state):
                    state.is_abandoned = True
                    self.abandoned_files.add(state.abs_path)
                    self.global_deleted |= state.owned_proxies
                    self.global_deleted |= state.owned_groups
                    self.global_deleted |= state.deleted_names

            # 2. Merge direct-hit deletions from ALL files into global_deleted,
            # then seed every non-abandoned file. Without this, a proxy
            # commented in file A would not cascade into groups in file B.
            for state in self.files.values():
                if not state.is_abandoned:
                    self.global_deleted |= state.deleted_names
            for state in self.files.values():
                if state.is_abandoned:
                    continue
                state.deleted_names |= self.global_deleted

            # 2a. Strip policy-path options pointing at abandoned files.
            # May seed additional deletions (groups left without any member
            # source), which are propagated immediately.
            for state in self.files.values():
                if state.is_abandoned:
                    continue
                self._strip_abandoned_policy_paths(state)

            # 2b. Strip #!include entries pointing at abandoned files.
            for state in self.files.values():
                if state.is_abandoned:
                    continue
                self._strip_abandoned_includes(state)

            # 3. Fixpoint across all non-abandoned files: each file's cascade
            # may produce new deletions that must propagate to other files.
            changed = True
            while changed:
                changed = False
                for state in self.files.values():
                    if state.is_abandoned:
                        continue
                    before = set(state.deleted_names)
                    self._cascade_single_file(state)
                    new_deletions = state.deleted_names - before
                    if new_deletions:
                        self.global_deleted |= new_deletions
                        for other in self.files.values():
                            if other is not state and not other.is_abandoned:
                                other.deleted_names |= new_deletions
                        changed = True

            # 4. If the cascade just dirtied a managed file, its abandonment
            # must be processed by another round; otherwise we're stable.
            if not any(
                s.is_managed and not s.is_abandoned and self._pending_change(s)
                for s in self.files.values()
            ):
                break

        # 5. Rewrite include / policy-path references now that every file's
        # abandoned / changed status is settled.
        self._rewrite_references()

        # 6. Re-serialize converted content from mutated lines.
        for state in self.files.values():
            if state.is_abandoned:
                continue
            state.converted = _serialize_lines(state.lines, state.original)

    def _rewrite_references(self):
        """Point include / policy-path references at the -v4 names of
        sub-files that will actually be emitted.

        Runs to fixpoint: rewriting a reference makes the PARENT file itself
        changed, which may in turn require rewriting references to that
        parent elsewhere (mutual includes). The transition is monotone
        (unchanged → changed only), so this terminates.
        """
        def will_emit(abs_path):
            sub = self.files.get(abs_path)
            return sub is not None and not sub.is_abandoned and self._pending_change(sub)

        changed = True
        while changed:
            changed = False
            for state in self.files.values():
                if state.is_abandoned:
                    continue
                base_dir = os.path.dirname(state.abs_path)
                for i, line in enumerate(state.lines):
                    new_line = self._rewrite_line_refs(
                        line, state.sections[i], base_dir, will_emit)
                    if new_line != line:
                        state.lines[i] = new_line
                        changed = True

    def _rewrite_line_refs(self, line, section, base_dir, will_emit):
        """Rewrite one line's local references to -v4 names. Idempotent:
        an already-rewritten -v4 name resolves to no discovered file and is
        left alone."""
        stripped = line.lstrip()
        if stripped.startswith("#!include"):
            entries = parse_include_list(line)
            if not entries:
                return line
            new_entries = []
            any_changed = False
            for entry in entries:
                if not entry.startswith(("http://", "https://")):
                    abs_path = os.path.normpath(os.path.join(base_dir, entry))
                    if will_emit(abs_path):
                        new_entries.append(make_v4_relname(entry))
                        any_changed = True
                        continue
                new_entries.append(entry)
            if not any_changed:
                return line
            return _preserve_indent(line, format_include_list(new_entries))

        if section == "Proxy Group" and not stripped.startswith("#"):
            def repl(m):
                path = m.group(1).strip()
                if path.startswith(("http://", "https://")):
                    return m.group(0)
                abs_path = os.path.normpath(os.path.join(base_dir, path))
                if will_emit(abs_path):
                    return f"policy-path={make_v4_relname(path)}"
                return m.group(0)
            return POLICY_PATH_RE.sub(repl, line)

        return line

    def _cascade_single_file(self, state):
        """Fixpoint: remove deleted members from Proxy Group lines; if a group
        loses all effective members due to OUR removals, tag it cascade and
        add its name to deleted_names so it propagates in the next iteration."""
        changed = True
        while changed:
            changed = False
            for i, line in enumerate(state.lines):
                if state.sections[i] != "Proxy Group":
                    continue
                if line.lstrip().startswith("#"):
                    continue
                pgl = parse_proxy_group_line(line)
                if pgl is None:
                    continue
                original_members = list(pgl.members)
                pgl.members = [
                    m for m in original_members
                    if unquote(m) not in state.deleted_names
                ]
                # include-other-group pointing at a deleted group is dead supply
                original_options = list(pgl.options)
                pgl.options = [
                    (k, v) for k, v in original_options
                    if not (k == "include-other-group"
                            and unquote(v.strip()) in state.deleted_names)
                ]
                removed_something = (
                    len(pgl.members) < len(original_members)
                    or len(pgl.options) < len(original_options)
                )
                if not removed_something:
                    continue  # D6: pre-existing empty groups left alone
                if has_effective_members(pgl, state.deleted_names, abandoned_basenames=set()):
                    new_line = _preserve_indent(line, format_proxy_group_line(pgl))
                    if new_line != line:
                        state.lines[i] = new_line
                        changed = True
                else:
                    # Tag the REFORMATTED (post-cleanup) line so the cascade
                    # comment shows the group in its cleaned state.
                    reformatted = _preserve_indent(line, format_proxy_group_line(pgl))
                    state.lines[i] = CASCADE_TAG + reformatted.lstrip()
                    state.deleted_names.add(unquote(pgl.name))
                    basename = os.path.basename(state.abs_path)
                    self.stats.count_commented(basename)
                    self.stats.add_change(basename, i + 1, "Proxy Group", "级联注释", pgl.name)
                    changed = True

        # Post-fixpoint: comment out Rule lines whose policy is now deleted.
        # Rules are leaf nodes — no secondary cascade can come from here.
        for i, line in enumerate(state.lines):
            if state.sections[i] != "Rule":
                continue
            if line.lstrip().startswith("#"):
                continue
            policy = extract_rule_policy(line)
            if policy is None:
                continue
            if unquote(policy) in state.deleted_names:
                state.lines[i] = CASCADE_TAG + line.lstrip()
                basename = os.path.basename(state.abs_path)
                self.stats.count_commented(basename)
                self.stats.add_change(basename, i + 1, "Rule", "级联注释", line.strip())

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
            removed = False
            for key, value in pgl.options:
                if key == "policy-path":
                    if value.startswith("http://") or value.startswith("https://"):
                        new_options.append((key, value))
                        continue
                    if os.path.basename(value) in abandoned_basenames:
                        removed = True
                        continue
                new_options.append((key, value))
            if not removed:
                continue
            pgl.options = new_options
            if has_effective_members(pgl, state.deleted_names, abandoned_basenames):
                state.lines[i] = _preserve_indent(line, format_proxy_group_line(pgl))
            else:
                reformatted = _preserve_indent(line, format_proxy_group_line(pgl))
                state.lines[i] = CASCADE_TAG + reformatted.lstrip()
                deleted_name = unquote(pgl.name)
                state.deleted_names.add(deleted_name)
                self.global_deleted.add(deleted_name)
                # Propagate to all other non-abandoned files so the downstream
                # fixpoint catches references to this group.
                for other in self.files.values():
                    if other is not state and not other.is_abandoned:
                        other.deleted_names.add(deleted_name)
                basename = os.path.basename(state.abs_path)
                self.stats.count_commented(basename)
                self.stats.add_change(basename, i + 1, "Proxy Group", "级联注释", pgl.name)

    def _strip_abandoned_includes(self, state):
        """Remove entries in #!include lines that point at abandoned files.

        If the list becomes empty after stripping, tag the whole line cascade.
        """
        abandoned_basenames = {os.path.basename(p) for p in self.abandoned_files}
        if not abandoned_basenames:
            return
        for i, line in enumerate(state.lines):
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
                new_line = format_include_list(kept)
                state.lines[i] = _preserve_indent(line, new_line)

    def emit(self):
        """Write -v4 files based on FileState decisions. Returns root output path."""
        root_output = None
        root_abs = next(iter(self.files))  # first discovered = root

        # Reachability from the root through non-abandoned files: a sub-file
        # discovered only via an abandoned managed config has nothing left
        # referencing it — emitting it would drop an orphan into v4/.
        reachable = set()
        if not self.files[root_abs].is_abandoned:
            stack = [root_abs]
            while stack:
                cur = stack.pop()
                if cur in reachable:
                    continue
                reachable.add(cur)
                for ref in self.files[cur].child_refs:
                    sub = self.files.get(ref)
                    if sub is not None and not sub.is_abandoned:
                        stack.append(ref)

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

            # No changes needed
            if state.converted == state.original:
                self.processed_files[abs_path] = None
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
            print(f"已转换: {abs_path} → {output_path}")
            if abs_path == root_abs:
                root_output = output_path

        return root_output

    def run(self, root_path, default_section=None):
        state = self.discover(root_path, default_section)
        if state is None:
            # discover already printed the reason (unreadable / undecodable)
            sys.exit(1)
        self.analyze()
        return self.emit()


def convert_file(input_path, stats=None, processed_files=None, default_section=None):
    """Convert a Surge config file from v5+ to v4 (top-level entry point).

    Creates a Pipeline, runs discover → analyze → emit over this file and
    every transitively referenced local file, and returns the root file's
    output path (or None if abandoned / unchanged).
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

    pipeline = Pipeline(stats, processed_files)
    return pipeline.run(input_path, default_section=default_section)


def main():
    if len(sys.argv) != 2:
        print(f"用法: {sys.argv[0]} <input_file_path>", file=sys.stderr)
        sys.exit(1)

    input_path = sys.argv[1]
    stats = ConversionStats()
    processed_files = {os.path.abspath(input_path): None}
    result = convert_file(input_path, stats, processed_files)
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
        try:
            answer = input("是否删除这些 deprecated 文件？（默认删除）[Y/n] ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            # Non-interactive run (cron / pipe): keep the backups, never
            # destroy files without an explicit human answer.
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
