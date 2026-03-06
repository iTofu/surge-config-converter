#!/usr/bin/env python3
"""Surge v5+ → v4 configuration converter."""

import os
import re
import sys
from pathlib import Path


# Proxy types not supported in Surge v4
V5PLUS_ONLY_PROXY_TYPES = {"hysteria2", "hy2", "anytls", "tuic"}

# Sections that should be entirely commented out in v4
V5PLUS_ONLY_SECTIONS = {"Port Forwarding", "Body Rewrite"}

# General parameters not supported in v4
V5PLUS_ONLY_GENERAL_PARAMS = {"udp-priority", "block-quic"}

# Rule types not supported in v4
V5PLUS_ONLY_RULE_TYPES = {"HOSTNAME-TYPE", "DOMAIN-WILDCARD"}

# Proxy parameters to remove (v5+ only)
V5PLUS_ONLY_PROXY_PARAMS = {"port-hopping", "port-hopping-interval", "ecn"}


class ConversionStats:
    def __init__(self):
        self.files_processed = []
        self.lines_commented = 0
        self.params_modified = 0
        self.changes = []
        self.deprecated_files = []

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
        print(f"注释行数: {self.lines_commented}")
        print(f"修改参数数: {self.params_modified}")


def make_v4_filename(filepath):
    """Generate the -v4 output filename.

    Example: home.conf -> home-v4.conf
    """
    p = Path(filepath)
    return str(p.with_stem(p.stem + "-v4"))


def backup_if_exists(filepath):
    """If filepath exists, rename it with a -deprecated suffix."""
    if os.path.exists(filepath):
        p = Path(filepath)
        backup = str(p.with_stem(p.stem + "-deprecated"))
        os.rename(filepath, backup)
        return backup
    return None


def comment_line(line):
    """Add # [v5+] prefix to a line."""
    return f"# [v5+] {line}"


def extract_proxy_type(line):
    """Extract proxy type from a proxy definition line.

    Format: Name = type, host, port, params...
    Returns the type string (lowercase) or None.
    """
    m = re.match(r'^[^#=]+=\s*(\w[\w-]*)', line)
    if m:
        return m.group(1).strip().lower()
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

        abs_path = os.path.join(base_dir, path)

        if abs_path not in processed_files:
            if os.path.isfile(abs_path):
                processed_files[abs_path] = None
                result = convert_file(abs_path, stats, processed_files, default_section="Proxy")
            else:
                result = None
        else:
            result = processed_files[abs_path]

        if result:
            return f"policy-path={make_v4_filename(path)}"
        return m.group(0)

    return re.sub(r'policy-path=([^,\s]+)', replace_local_path, line)


def update_include_line(line, base_dir, processed_files, stats, current_section=None):
    """Update #!include references to -v4 versions and trigger conversion.

    Only rewrites a path if the referenced file actually needed conversion.
    current_section is passed to sub-file conversion so included content
    is treated as belonging to the parent section.
    """
    m = re.match(r'^#!include\s+(.+)$', line)
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

        abs_path = os.path.join(base_dir, part)

        if abs_path not in processed_files:
            if os.path.isfile(abs_path):
                processed_files[abs_path] = None
                result = convert_file(abs_path, stats, processed_files, default_section=current_section)
            else:
                result = None
        else:
            result = processed_files[abs_path]

        if result:
            new_parts.append(make_v4_filename(part))
            any_changed = True
        else:
            new_parts.append(part)

    if not any_changed:
        return line
    return "#!include " + ", ".join(new_parts)


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


def convert_file(input_path, stats=None, processed_files=None, default_section=None):
    """Convert a single Surge config file from v5+ to v4.

    Args:
        input_path: Path to the input file
        stats: ConversionStats instance (created if None)
        processed_files: Dict of already-processed absolute paths to output paths (or None if skipped)
        default_section: Default section context for files without headers

    Returns:
        The output file path, or None if no changes were needed.
    """
    if stats is None:
        stats = ConversionStats()
    if processed_files is None:
        processed_files = {}

    input_path = os.path.abspath(input_path)

    if not os.path.isfile(input_path):
        print(f"错误: 文件不存在: {input_path}", file=sys.stderr)
        sys.exit(1)

    base_dir = os.path.dirname(input_path)
    output_path = make_v4_filename(input_path)

    # Read and convert
    with open(input_path, "r", encoding="utf-8") as f:
        content = f.read()

    converted = convert_content(content, base_dir, stats, processed_files, default_section,
                                filename=os.path.basename(input_path))

    # No changes needed — skip writing
    if converted == content:
        processed_files[input_path] = None
        return None

    # Backup existing output file
    backup = backup_if_exists(output_path)
    if backup:
        stats.deprecated_files.append(backup)
        print(f"已备份: {output_path} → {backup}")

    # Write output
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(converted)

    stats.files_processed.append(output_path)
    processed_files[input_path] = output_path
    print(f"已转换: {input_path} → {output_path}")

    return output_path


def main():
    if len(sys.argv) != 2:
        print(f"用法: {sys.argv[0]} <input_file_path>", file=sys.stderr)
        sys.exit(1)

    input_path = sys.argv[1]
    stats = ConversionStats()
    processed_files = {os.path.abspath(input_path): None}
    result = convert_file(input_path, stats, processed_files)
    if result is None:
        print("未发现 v5+ 内容，无需转换。")
    stats.print_summary()

    if stats.deprecated_files:
        print(f"\n发现 {len(stats.deprecated_files)} 个 deprecated 备份文件:")
        for f in stats.deprecated_files:
            print(f"  - {f}")
        answer = input("是否删除这些 deprecated 文件？（默认保留）[y/N] ").strip().lower()
        if answer == "y":
            for f in stats.deprecated_files:
                os.remove(f)
                print(f"已删除: {f}")
        else:
            print("已保留 deprecated 文件。")


if __name__ == "__main__":
    main()
