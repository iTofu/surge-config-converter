#!/usr/bin/env python3
"""Surge v5+ -> v4 configuration converter.

Usage:
    python3 converter.py <input_file_path>

Output layout:
    All generated -v4 files are written to a v4/ subdirectory next to
    the source files:

        Documents/
        ├── home.conf              <- source (v5)
        ├── mai-vps.dconf
        └── v4/
            ├── home-v4.conf       <- converted (v4)
            └── mai-vps-v4.dconf

    Files inside v4/ reference each other using bare filenames (e.g.
    #!include mai-vps-v4.dconf) with no directory prefix. To use them,
    copy everything in v4/ to the top-level config directory on the
    Surge v4 device.

Limitation:
    All referenced files (#!include, policy-path) must reside in the
    same directory as the root config. The v4/ output is a flat
    directory -- sub-directory paths are stripped, so identically named
    files in different sub-directories would collide.
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

# Proxy parameters to remove (v5+ only)
V5PLUS_ONLY_PROXY_PARAMS = {"port-hopping", "port-hopping-interval", "ecn"}

# Cascade-cleanup tag prefix: distinguishes follow-on deletions from direct hits.
CASCADE_TAG = "# [V5+ cascade] "


def unquote(name):
    """Strip surrounding double quotes from a proxy / group name token."""
    if len(name) >= 2 and name[0] == '"' and name[-1] == '"':
        return name[1:-1]
    return name


def _preserve_indent(original_line, new_content):
    """Prepend original_line's leading whitespace to new_content."""
    stripped = original_line.lstrip()
    indent = original_line[: len(original_line) - len(stripped)]
    return indent + new_content


def compute_sections(lines, default_section=None):
    """Return a list parallel to lines where each entry is the section name
    the line belongs to (or default_section before any header appears)."""
    result = []
    current = default_section
    for line in lines:
        m = re.match(r'^\[(.+)\]$', line.strip())
        if m:
            current = m.group(1)
        result.append(current)
    return result


def has_effective_members(pgl, deleted_names, abandoned_basenames):
    """Return True if the Proxy Group still has at least one valid member source.

    Valid sources:
      - an explicit member name not in deleted_names
      - include-all-proxies=1 option
      - policy-path=<file> where <file> is an HTTP URL, or a local file whose
        basename is NOT in abandoned_basenames
    """
    for m in pgl.members:
        if unquote(m) not in deleted_names:
            return True
    for key, value in pgl.options:
        if key == "include-all-proxies" and value.strip() in {"1", "true"}:
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
    def __init__(self):
        self.files_processed = []
        self.lines_commented = 0
        self.params_modified = 0
        self.changes = []
        self.deprecated_files = []
        self.abandoned_files = []    # managed configs we refused to convert
        self.stale_v4_files = []     # pre-existing -v4 files for abandoned managed configs

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
    """If filepath exists, rename it with a -deprecated suffix."""
    if os.path.exists(filepath):
        p = Path(filepath)
        backup = str(p.with_stem(p.stem + "-deprecated"))
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
    """
    m = re.match(r'^[^#=]+=\s*(\w[\w-]*)', line)
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
    is_abandoned: bool = False   # managed + changed → set eagerly during discover()
    output_written: bool = False # set during emit()
    output_path: str = None      # destination if written
    # Cascade fields (populated during Discover, consumed during Analyze)
    lines: list = field(default_factory=list)          # mutable working copy of converted
    sections: list = field(default_factory=list)       # per-line section name
    owned_proxies: set = field(default_factory=set)    # proxy names defined in this file
    owned_groups: set = field(default_factory=set)     # group names defined in this file
    deleted_names: set = field(default_factory=set)    # names removed (propagates cascade)


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

    tokens = [t.strip() for t in rest.split(",")]
    if not tokens or not tokens[0]:
        return None

    group_type = tokens[0]
    members = []
    options = []
    for token in tokens[1:]:
        if not token:
            continue
        if "=" in token:
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
    """Split a string by commas at depth 0 (outside of balanced parentheses).

    Used for rule lines which may contain AND/OR/NOT compound criteria
    wrapped in parens, where inner commas must not split the tokens.
    """
    parts = []
    depth = 0
    start = 0
    for i, ch in enumerate(s):
        if ch == "(":
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
        stats.lines_commented += 1
        stats.add_change(filename, line_num, section, "注释", f"{name} ({proxy_type})")
        return comment_line(line)

    modified = line

    # Snell version=5 → version=4
    if proxy_type == "snell":
        new, n = re.subn(r'version\s*=\s*5\b', 'version=4', modified)
        if n:
            modified = new
            stats.params_modified += n
            stats.add_change(filename, line_num, section, "version=5 → version=4", name)

    # shadow-tls-version=3 → shadow-tls-version=2
    new, n = re.subn(r'shadow-tls-version\s*=\s*3\b', 'shadow-tls-version=2', modified)
    if n:
        modified = new
        stats.params_modified += n
        stats.add_change(filename, line_num, section, "shadow-tls-version=3 → 2", name)

    # Remove v5+ only parameters
    modified, removed = remove_proxy_params(modified, V5PLUS_ONLY_PROXY_PARAMS)
    stats.params_modified += len(removed)
    for param in removed:
        stats.add_change(filename, line_num, section, "移除参数", f"{param} ({name})")

    return modified


def transform_proxy_group_line(line, stats, base_dir, processed_files, filename, line_num, section):
    """Transform a single line in [Proxy Group] section."""
    if line.startswith("#"):
        return line

    modified = line

    # smart → url-test
    m = re.match(r'^([^=]+=\s*)smart\b(.*)', modified)
    if m:
        name = line.split('=', 1)[0].strip()
        modified = m.group(1) + "url-test" + m.group(2)
        stats.params_modified += 1
        stats.add_change(filename, line_num, section, "smart → url-test", name)

    # Update local policy-path references
    modified = update_policy_path(modified, base_dir, processed_files, stats)

    return modified


def update_policy_path(line, base_dir, processed_files, stats):
    """Update policy-path=local_file references to -v4 versions.

    Only rewrites the path if the referenced file actually needed conversion.
    policy-path always references proxy list files, so converted with
    default_section="Proxy".
    """
    def replace_local_path(m):
        path = m.group(1).strip()
        if path.startswith("http://") or path.startswith("https://"):
            return m.group(0)

        abs_path = os.path.normpath(os.path.join(base_dir, path))

        if abs_path not in processed_files:
            if os.path.isfile(abs_path):
                processed_files[abs_path] = None
                result = convert_file(abs_path, stats, processed_files, default_section="Proxy")
            else:
                result = None
        else:
            result = processed_files[abs_path]

        if result:
            return f"policy-path={make_v4_relname(path)}"
        return m.group(0)

    return re.sub(r'policy-path=([^,\s]+)', replace_local_path, line)


def update_include_line(line, base_dir, processed_files, stats, current_section=None):
    """Update #!include references to -v4 versions and trigger conversion.

    Only rewrites a path if the referenced file actually needed conversion.
    current_section is passed to sub-file conversion so included content
    is treated as belonging to the parent section.
    """
    m = re.match(r'^\s*#!include\s+(.+)$', line)
    if not m:
        return line

    files_str = m.group(1)
    parts = [p.strip() for p in files_str.split(",")]
    new_parts = []
    any_changed = False

    for part in parts:
        if part.startswith("http://") or part.startswith("https://"):
            new_parts.append(part)
            continue

        abs_path = os.path.normpath(os.path.join(base_dir, part))

        if abs_path not in processed_files:
            if os.path.isfile(abs_path):
                processed_files[abs_path] = None
                result = convert_file(abs_path, stats, processed_files, default_section=current_section)
            else:
                result = None
        else:
            result = processed_files[abs_path]

        if result:
            new_parts.append(make_v4_relname(part))
            any_changed = True
        else:
            new_parts.append(part)

    if not any_changed:
        return line
    return _preserve_indent(line, "#!include " + ", ".join(new_parts))


def transform_rule_line(line, stats, filename, line_num, section):
    """Transform a single line in [Rule] section."""
    stripped = line.lstrip()
    if stripped.startswith("#"):
        return line

    for rule_type in V5PLUS_ONLY_RULE_TYPES:
        if stripped.startswith(rule_type + ","):
            stats.lines_commented += 1
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
            stats.lines_commented += 1
            stats.add_change(filename, line_num, section, "注释", param)
            return comment_line(line)

    return line


def convert_content(content, base_dir, stats, processed_files, default_section=None, filename=""):
    """Convert configuration content from v5+ to v4 format.

    Args:
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
                stats.lines_commented += 1
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
                stats.lines_commented += 1
                result.append(comment_line(line))
            else:
                result.append(line)
            continue

        # Skip already-commented lines (don't double-process)
        if stripped.startswith("#") and not stripped.startswith("#!include"):
            # But still handle #!include
            result.append(line)
            continue

        # Handle #!include directives (can appear in any section)
        if stripped.startswith("#!include"):
            result.append(update_include_line(line, base_dir, processed_files, stats, current_section))
            continue

        # Apply section-specific transformations
        if current_section == "General":
            result.append(transform_general_line(line, stats, filename, line_num, current_section))
        elif current_section == "Proxy":
            result.append(transform_proxy_line(line, stats, filename, line_num, current_section))
        elif current_section == "Proxy Group":
            result.append(transform_proxy_group_line(line, stats, base_dir, processed_files, filename, line_num, current_section))
        elif current_section == "Rule":
            result.append(transform_rule_line(line, stats, filename, line_num, current_section))
        else:
            result.append(line)

    joined = "\n".join(result)
    if content.endswith("\n"):
        joined += "\n"
    return joined


# Module-level global: the top-level convert_file creates a Pipeline and
# parks it here so that nested convert_file calls (triggered by
# update_include_line / update_policy_path during recursive discovery) can
# detect the active pipeline and reuse its shared FileState dict instead of
# spinning up a new, isolated one. Cleared in the top-level finally block.
_active_pipeline = None


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
        """Read a file, apply direct v5+ hits, recurse into dependencies,
        and decide abandonment eagerly.

        Returns the FileState for this file, or None if not a valid file.
        Idempotent: calling twice on the same path returns the cached state.
        """
        abs_path = os.path.abspath(input_path)
        if abs_path in self.files:
            return self.files[abs_path]
        if not os.path.isfile(abs_path):
            return None

        with open(abs_path, "r", encoding="utf-8") as f:
            original = f.read()

        state = FileState(
            abs_path=abs_path,
            original=original,
            converted=original,  # placeholder; replaced after convert_content
            is_managed=is_managed_config(original),
            default_section=default_section,
        )
        self.files[abs_path] = state

        # Pre-register so recursive calls from convert_content (via
        # update_include_line / update_policy_path) don't re-enter this file.
        self.processed_files[abs_path] = None

        base_dir = os.path.dirname(abs_path)
        converted = convert_content(
            original, base_dir, self.stats, self.processed_files,
            default_section=default_section,
            filename=os.path.basename(abs_path),
        )
        state.converted = converted

        # Update processed_files with the intended return value so that later
        # lookups by update_include_line / update_policy_path (which may be
        # triggered multiple times for the same sub-file) get the same answer
        # as the first recursive call would. Without this, the pre-registered
        # None sentinel persists and subsequent references to the same sub-file
        # are not rewritten to -v4. Abandoned / unchanged files stay as None.
        if state.is_managed and state.converted != state.original:
            self.processed_files[abs_path] = None  # will be abandoned
        elif state.converted == state.original:
            self.processed_files[abs_path] = None  # no output
        else:
            self.processed_files[abs_path] = make_v4_filename(abs_path)

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

        # Eager abandonment decision: allows the nested convert_file wrapper
        # to return None for abandoned files immediately, so the parent's
        # include / policy-path references stay pointing at the ORIGINAL
        # name (not rewritten to -v4). Later cascade passes match basenames
        # against abandoned_files to strip those references.
        if state.is_managed and state.converted != state.original:
            state.is_abandoned = True

        return state

    def analyze(self):
        """Cross-file cascade: propagate abandonment and deleted names across
        all discovered files, then fixpoint per-file cleanup."""
        # 1. Collect abandonment bookkeeping from decisions made in discover().
        # For an abandoned file, EVERY name it defined vanishes from the
        # global namespace — owned proxies, owned groups, AND names that were
        # already marked for direct-hit deletion inside the file.
        for state in self.files.values():
            if state.is_abandoned:
                self.abandoned_files.add(state.abs_path)
                self.global_deleted |= state.owned_proxies
                self.global_deleted |= state.owned_groups
                self.global_deleted |= state.deleted_names

        # 2. Merge direct-hit deletions from ALL files into global_deleted,
        # then seed every non-abandoned file. Without this, a proxy commented
        # in file A would not cascade into groups defined in file B.
        for state in self.files.values():
            if not state.is_abandoned:
                self.global_deleted |= state.deleted_names
        for state in self.files.values():
            if state.is_abandoned:
                continue
            state.deleted_names |= self.global_deleted

        # 2a. Pre-pass: strip policy-path options pointing at abandoned files.
        # This may seed additional deletions (groups that become empty after
        # losing their only member source), which are propagated immediately.
        for state in self.files.values():
            if state.is_abandoned:
                continue
            self._strip_abandoned_policy_paths(state)

        # 2b. Pre-pass: strip #!include entries pointing at abandoned files.
        # Independent of policy-path — no cascade interaction.
        for state in self.files.values():
            if state.is_abandoned:
                continue
            self._strip_abandoned_includes(state)

        # 3. Fixpoint across all non-abandoned files: each file's cascade may
        # produce new deletions that need to propagate to other files.
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

        # 4. Re-serialize converted content from mutated lines
        for state in self.files.values():
            if state.is_abandoned:
                continue
            joined = "\n".join(state.lines)
            if state.original.endswith("\n") and not joined.endswith("\n"):
                joined += "\n"
            state.converted = joined

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
                removed_something = len(pgl.members) < len(original_members)
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
                    self.stats.lines_commented += 1
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
                self.stats.lines_commented += 1

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
                self.stats.lines_commented += 1

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
                if os.path.basename(e) not in abandoned_basenames
            ]
            if len(kept) == len(entries):
                continue
            if not kept:
                state.lines[i] = CASCADE_TAG + line.lstrip()
                self.stats.lines_commented += 1
            else:
                new_line = format_include_list(kept)
                state.lines[i] = _preserve_indent(line, new_line)

    def emit(self):
        """Write -v4 files based on FileState decisions. Returns root output path."""
        root_output = None
        root_abs = next(iter(self.files))  # first discovered = root
        for abs_path, state in self.files.items():
            output_path = make_v4_filename(abs_path)

            # Abandon decision was made in discover(). Just act on it here:
            # refuse to write, surface stale -v4 (don't delete).
            if state.is_abandoned:
                self.stats.abandoned_files.append(abs_path)
                self.processed_files[abs_path] = None
                print(f"已放弃托管配置（含 v5+ 内容）: {abs_path}")
                if os.path.exists(output_path):
                    self.stats.stale_v4_files.append(output_path)
                    print(f"  ⚠️  检测到旧的 v4 文件（未自动删除）: {output_path}")
                if abs_path == root_abs:
                    root_output = None
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
        self.discover(root_path, default_section)
        self.analyze()
        return self.emit()


def convert_file(input_path, stats=None, processed_files=None, default_section=None):
    """Convert a Surge config file from v5+ to v4.

    Two modes:

    1. Top-level (no active Pipeline): create a Pipeline, run all three phases
       on this file and its dependencies, return the root file's output path
       (or None if abandoned / unchanged).

    2. Nested (called from update_include_line / update_policy_path while a
       Pipeline is already active): reuse the outer Pipeline via
       pipeline.discover(sub_path) to add this sub-file to the shared
       FileState dict. Returns a backward-compatible sentinel:
         - abandoned sub-file → None (parent keeps original reference)
         - unchanged sub-file → None (parent keeps original reference)
         - converted sub-file → make_v4_filename(input_path) (parent rewrites to -v4)

       The actual write happens later, when the top-level Pipeline.emit()
       iterates all discovered FileStates. Nested calls only discover.
    """
    global _active_pipeline

    if stats is None:
        stats = ConversionStats()

    input_path = os.path.abspath(input_path)
    if not os.path.isfile(input_path):
        print(f"错误: 文件不存在: {input_path}", file=sys.stderr)
        sys.exit(1)

    if _active_pipeline is not None:
        # Nested mode — reuse the outer Pipeline
        state = _active_pipeline.discover(input_path, default_section=default_section)
        if state is None:
            return None
        if state.is_abandoned:
            return None
        if state.converted == state.original:
            return None
        return make_v4_filename(input_path)

    # Top-level mode — create a new Pipeline
    pipeline = Pipeline(stats, processed_files)
    _active_pipeline = pipeline
    try:
        return pipeline.run(input_path, default_section=default_section)
    finally:
        _active_pipeline = None


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
        answer = input("是否删除这些 deprecated 文件？（默认删除）[Y/n] ").strip().lower()
        if answer != "n":
            for f in stats.deprecated_files:
                send2trash(f)
                print(f"已移至垃圾桶: {f}")
        else:
            print("已保留 deprecated 文件。")


if __name__ == "__main__":
    main()
