# Managed Config Abandonment + Cascade Cleanup Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Safely handle Surge managed profiles (`#!MANAGED-CONFIG`) that contain v5+ features by abandoning them entirely, and clean up all cascade effects (dangling references in Proxy Groups, Rules, `#!include`, `policy-path`) in parent configurations.

**Architecture:** Refactor `converter.py` from single-pass streaming to three-phase pipeline — **Discover** (read all files, apply direct v5+ hits, catalog owned names), **Analyze** (fixpoint propagation of `deleted_names` and `abandoned_files` across all files), **Emit** (write outputs for converted files; for abandoned managed configs, refuse to write and warn about any stale pre-existing `-v4` without deleting it). Managed profiles containing any v5+ content are refused because Surge will overwrite any local modifications on refresh — a `-v4` file must never self-destruct. Cascade cleanup handles the follow-on question: when we remove X, who referenced X and what becomes of them?

**Tech Stack:** Python 3, pytest, `send2trash`, `pathlib`, `dataclasses` (stdlib).

---

## Background Context (read before starting)

### Why this exists

Surge v4 does not support proxy types `hysteria2`/`hy2`/`anytls`/`tuic`/`trust-tunnel`, rule types `HOSTNAME-TYPE`/`DOMAIN-WILDCARD`, or sections `[Port Forwarding]`/`[Body Rewrite]`. The current `converter.py` comments those out and writes a `-v4.conf` file.

**The broken case:** `xflash-leodxkr.conf` is a managed profile (`#!MANAGED-CONFIG <url> interval=43200 strict=true` on line 1). The current converter passes that header through into `xflash-leodxkr-v4.conf`. Surge then re-fetches the upstream URL every 12 hours and overwrites the `-v4` file with fresh v5+ content, undoing the conversion. Worse, `strict=true` means a failed fetch makes Surge reject the whole profile.

**The user's decision (recorded via brainstorming):** any managed profile that contains v5+ content is **abandoned** — the converter refuses to produce a `-v4` copy. Downstream references in parent files must be cleaned up.

### The cascade problem

When we remove or abandon something, other lines that referenced it become invalid:

1. **Commented-out v5+ proxy** → Proxy Group member lists, Rule policy fields reference a name that no longer exists
2. **Abandoned managed file via `#!include`** → parent's include list has a now-invalid entry
3. **Abandoned managed file via `policy-path=`** → parent's Proxy Group line is missing its member source; if that was the only source, the group itself becomes invalid
4. **Cascading deletions** → a Proxy Group becoming invalid means its NAME vanishes; other groups / rules referencing it also become invalid — iterate until stable

### User-confirmed decisions (don't re-litigate)

| ID | Decision |
|---|---|
| D1 | Managed profile + any v5+ change → abandon the entire file |
| D2 | On abandonment, DO NOT delete any stale `-v4` file. Instead, detect its existence, record it in `stats.stale_v4_files`, and surface a clear warning in the final summary so the user can decide what to do. |
| D3 | `select` group retained with 1 member after cleanup → keep (syntactically valid) |
| D4 | Group with only `include-all-proxies=1` and no explicit members → keep (valid) |
| D5 | Group that became empty due to our cleanup (zero members, no implicit supply) → comment with `# [V5+ cascade]` |
| D6 | Group that was empty BEFORE our cleanup (we removed nothing) → leave alone (not our bug to fix) |
| D7 | `smart → url-test` transform stays untouched; no `url=` injection (Surge falls back to `[General] proxy-test-url`, and `interval=` defaults to 600s) |
| D8 | User workflow unchanged: `python3 converter.py /path/to/home.conf` — single top-level file per invocation |
| D9 | Two distinct comment tags: `# [V5+]` for direct hits, `# [V5+ cascade]` for follow-on cleanups |
| D10 | Existing tag `# [v5+]` (lowercase) is renamed to `# [V5+]` (uppercase) to match the cascade tag's prefix |

### Minimum viable cascade example (user's real config)

Input files (abbreviated):

```
# xflash-leodxkr.conf
#!MANAGED-CONFIG https://www.xflash.org/api/v1/... interval=43200 strict=true
[Proxy]
🇯🇵 日本 = anytls, ..., password=...
🇭🇰 香港 = trojan, ..., password=...
```

```
# home.conf (NOT managed)
[Proxy Group]
✈️ Proxy = select, "💼 MAI", "♻️ Auto", "🧑‍💻 SelfVPS", "🏡 HomeProxy", policy-path=xflash-leodxkr.conf
♻️ Auto  = smart, policy-path=xflash-leodxkr.conf, interval=300

#!include xflash-leodxkr.conf, mai-vps.dconf, self-vps.dconf, self-home.dconf
```

Expected `home-v4.conf` after the new pipeline:

```
[Proxy Group]
✈️ Proxy = select, "💼 MAI", "🧑‍💻 SelfVPS", "🏡 HomeProxy"
# [V5+ cascade] ♻️ Auto  = url-test, interval=300

#!include mai-vps-v4.dconf, self-vps.dconf, self-home-v4.dconf
```

Expected: no `xflash-leodxkr-v4.conf` produced; if one pre-exists on disk, it is detected and surfaced in the final summary as a "stale v4 file" warning (not auto-deleted).

---

## File Structure

**All changes go into existing files.** No new modules — the codebase convention is one flat `converter.py`.

- **Modify** `converter.py` — add `FileState` dataclass, `Pipeline` class, `is_managed_config`, `parse_proxy_group_line`, `format_proxy_group_line`, `extract_rule_policy`, `parse_include_list`; refactor `convert_file` into a thin wrapper around `Pipeline`.
- **Modify** `test_converter.py` — rename tag literal; add test classes for each new helper and cascade scenario.
- **Create** `docs/superpowers/plans/2026-04-12-managed-config-cascade-cleanup.md` — this file.

The refactor keeps existing helpers (`transform_proxy_line`, `transform_general_line`, `transform_rule_line`, `comment_line`, `extract_proxy_type`, etc.) intact — they become single-file direct-hit utilities called by the Pipeline's Discover phase.

---

## Task 1: Rename tag `# [v5+]` → `# [V5+]`

**Rationale:** Prep step. Frees up naming room for `# [V5+ cascade]`. Pure rename, zero functional change.

**Files:**
- Modify: `converter.py:74-76` (function `comment_line`)
- Modify: `test_converter.py` (all literal `# [v5+]` assertions)

- [ ] **Step 1: Update `comment_line`**

In `converter.py`, replace:

```python
def comment_line(line):
    """Add # [v5+] prefix to a line."""
    return f"# [v5+] {line}"
```

with:

```python
def comment_line(line):
    """Add # [V5+] prefix to a line."""
    return f"# [V5+] {line}"
```

- [ ] **Step 2: Run tests to confirm failures**

Run: `pytest test_converter.py -x 2>&1 | tail -20`

Expected: Multiple failures, first one on a `# [v5+]` assertion.

- [ ] **Step 3: Bulk-rename literals in tests**

Run: `sed -i '' 's/# \[v5+\]/# [V5+]/g' test_converter.py`

- [ ] **Step 4: Run all tests**

Run: `pytest test_converter.py -v 2>&1 | tail -20`

Expected: All tests pass.

- [ ] **Step 5: Commit**

```bash
git add converter.py test_converter.py
git commit -m "refactor: rename comment tag v5+ to V5+ for consistency"
```

---

## Task 2: Add `is_managed_config` helper

**Rationale:** Detect whether a file is a Surge managed profile. Pure utility, no side effects.

**Files:**
- Modify: `converter.py` (add helper)
- Modify: `test_converter.py` (add test class)

- [ ] **Step 1: Write the failing test**

Append to `test_converter.py`:

```python
# --- T18: Managed config detection ---

class TestIsManagedConfig:
    def test_managed_on_first_line(self):
        from converter import is_managed_config
        assert is_managed_config("#!MANAGED-CONFIG https://x.com/a.conf interval=3600\n[General]\n")

    def test_managed_with_strict(self):
        from converter import is_managed_config
        assert is_managed_config("#!MANAGED-CONFIG https://x.com/a.conf interval=3600 strict=true\n")

    def test_not_managed_plain(self):
        from converter import is_managed_config
        assert not is_managed_config("[General]\nloglevel = notify\n")

    def test_not_managed_if_after_header(self):
        """Must be on the very first line. Anything before it disqualifies."""
        from converter import is_managed_config
        assert not is_managed_config("[General]\n#!MANAGED-CONFIG https://x.com/a.conf\n")

    def test_not_managed_if_commented(self):
        from converter import is_managed_config
        assert not is_managed_config("# #!MANAGED-CONFIG https://x.com/a.conf\n[General]\n")

    def test_leading_blank_lines_allowed(self):
        """Tolerate leading blank lines before the directive."""
        from converter import is_managed_config
        assert is_managed_config("\n\n#!MANAGED-CONFIG https://x.com/a.conf\n[General]\n")

    def test_empty_string(self):
        from converter import is_managed_config
        assert not is_managed_config("")
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest test_converter.py::TestIsManagedConfig -v`

Expected: `ImportError: cannot import name 'is_managed_config'`

- [ ] **Step 3: Implement `is_managed_config`**

Add to `converter.py` after the constants block (near the top, before `ConversionStats`):

```python
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
```

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest test_converter.py::TestIsManagedConfig -v`

Expected: 7 passed.

- [ ] **Step 5: Commit**

```bash
git add converter.py test_converter.py
git commit -m "feat: add is_managed_config helper for detecting Surge managed profiles"
```

---

## Task 3: Abandon top-level managed config with v5+ changes

**Rationale:** Simplest useful slice — if the input file is itself a managed profile AND the converter would make any change, refuse to write the `-v4` file, record the abandonment, and (if a stale `-v4` exists from a previous run) surface it as a warning without deleting it. No cascade yet.

**Files:**
- Modify: `converter.py` (extend `ConversionStats`, modify `convert_file`)
- Modify: `test_converter.py` (add test class)

- [ ] **Step 1: Write the failing tests**

Append to `test_converter.py`:

```python
# --- T19: Managed config abandonment ---

class TestManagedAbandon:
    def test_managed_with_v5plus_is_abandoned(self, tmp_path):
        main = tmp_path / "sub.conf"
        main.write_text(
            "#!MANAGED-CONFIG https://x.com/sub.conf interval=43200 strict=true\n"
            "[Proxy]\n"
            "JP = anytls, 1.2.3.4, 443, password=pwd\n"
            "HK = trojan, 5.6.7.8, 443, password=pwd\n"
        )
        stats = ConversionStats()
        result = convert_file(str(main), stats, {str(main): None})

        assert result is None
        assert not (tmp_path / "sub-v4.conf").exists()
        assert str(main) in stats.abandoned_files

    def test_managed_without_v5plus_passes_through(self, tmp_path):
        """Managed profile with no v5+ content → no change needed, no abandon."""
        main = tmp_path / "sub.conf"
        main.write_text(
            "#!MANAGED-CONFIG https://x.com/sub.conf interval=43200\n"
            "[Proxy]\n"
            "HK = trojan, 5.6.7.8, 443, password=pwd\n"
        )
        stats = ConversionStats()
        result = convert_file(str(main), stats, {str(main): None})

        assert result is None
        assert not (tmp_path / "sub-v4.conf").exists()
        assert str(main) not in stats.abandoned_files

    def test_non_managed_with_v5plus_still_converts(self, tmp_path):
        """Non-managed file: abandon rule does not apply."""
        main = tmp_path / "sub.conf"
        main.write_text(
            "[Proxy]\n"
            "JP = anytls, 1.2.3.4, 443, password=pwd\n"
            "HK = trojan, 5.6.7.8, 443, password=pwd\n"
        )
        stats = ConversionStats()
        result = convert_file(str(main), stats, {str(main): None})

        assert result == str(tmp_path / "sub-v4.conf")
        assert (tmp_path / "sub-v4.conf").exists()
        assert stats.abandoned_files == []

    def test_stale_v4_detected_but_not_deleted_on_abandon(self, tmp_path):
        """If a -v4 file exists from a previous run, abandoning records it in
        stats.stale_v4_files WITHOUT deleting it. The user is warned in the final
        summary and decides what to do."""
        main = tmp_path / "sub.conf"
        main.write_text(
            "#!MANAGED-CONFIG https://x.com/sub.conf interval=43200\n"
            "[Proxy]\n"
            "JP = anytls, 1.2.3.4, 443, password=pwd\n"
        )
        stale = tmp_path / "sub-v4.conf"
        stale.write_text("stale content from earlier converter run")

        stats = ConversionStats()
        with patch("converter.send2trash") as mock_trash:
            convert_file(str(main), stats, {str(main): None})
            # Must NOT be auto-deleted
            assert mock_trash.call_count == 0

        # Stale file still on disk, untouched
        assert stale.exists()
        assert stale.read_text() == "stale content from earlier converter run"

        # But the abandonment was recorded
        assert str(main) in stats.abandoned_files
        # And the stale -v4 was surfaced for user visibility
        assert str(stale) in stats.stale_v4_files
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `pytest test_converter.py::TestManagedAbandon -v`

Expected: 4 failures — `AttributeError: 'ConversionStats' object has no attribute 'abandoned_files'`.

- [ ] **Step 3: Extend `ConversionStats`**

In `converter.py`, modify `ConversionStats.__init__`:

```python
class ConversionStats:
    def __init__(self):
        self.files_processed = []
        self.lines_commented = 0
        self.params_modified = 0
        self.changes = []
        self.deprecated_files = []
        self.abandoned_files = []
        self.stale_v4_files = []  # -v4 files found on disk for abandoned managed configs
```

- [ ] **Step 4: Modify `convert_file` to handle abandonment**

Replace the current `convert_file` function (converter.py:345-406) with:

```python
def convert_file(input_path, stats=None, processed_files=None, default_section=None):
    """Convert a single Surge config file from v5+ to v4.

    Returns the output file path, or None if no output was produced.

    If the input is a managed profile (#!MANAGED-CONFIG on first line) AND the
    converter would make any change, the file is ABANDONED: no -v4 output is
    written, the abandonment is recorded in stats.abandoned_files, and if a
    stale -v4 file exists on disk from a previous run, its path is recorded in
    stats.stale_v4_files so the user can see it in the final summary (we do NOT
    auto-delete it — the user decides).

    Rationale: Surge re-fetches managed profiles on an interval and overwrites
    local modifications, so a mutated -v4 copy would self-destruct.
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

    with open(input_path, "r", encoding="utf-8") as f:
        content = f.read()

    converted = convert_content(content, base_dir, stats, processed_files, default_section,
                                filename=os.path.basename(input_path))

    # Abandon managed profile that would be mutated
    if is_managed_config(content) and converted != content:
        stats.abandoned_files.append(input_path)
        processed_files[input_path] = None
        print(f"已放弃托管配置（含 v5+ 内容）: {input_path}")
        if os.path.exists(output_path):
            stats.stale_v4_files.append(output_path)
            print(f"  ⚠️  检测到旧的 v4 文件（未自动删除）: {output_path}")
        return None

    # No changes needed — skip writing
    if converted == content:
        processed_files[input_path] = None
        return None

    # Skip if existing -v4 file already has correct content
    if os.path.exists(output_path):
        with open(output_path, "r", encoding="utf-8") as f:
            existing = f.read()
        if existing == converted:
            processed_files[input_path] = output_path
            print(f"已跳过（内容未变化）: {output_path}")
            return output_path

    backup = backup_if_exists(output_path)
    if backup:
        stats.deprecated_files.append(backup)
        print(f"已备份: {output_path} → {backup}")

    with open(output_path, "w", encoding="utf-8") as f:
        f.write(converted)

    stats.files_processed.append(output_path)
    processed_files[input_path] = output_path
    print(f"已转换: {input_path} → {output_path}")

    return output_path
```

- [ ] **Step 5: Run the new tests**

Run: `pytest test_converter.py::TestManagedAbandon -v`

Expected: 4 passed.

- [ ] **Step 6: Run full test suite for regression check**

Run: `pytest test_converter.py -v 2>&1 | tail -10`

Expected: All tests pass (including the ones from Task 1 and Task 2).

- [ ] **Step 7: Update `main()` to report abandoned files**

In `converter.py`, modify `main()`:

```python
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
```

- [ ] **Step 8: Commit**

```bash
git add converter.py test_converter.py
git commit -m "feat: abandon managed profiles containing v5+ content

Surge re-fetches managed profiles periodically and would overwrite any
-v4 mutations. The only safe action is to refuse conversion. Stale -v4
files from previous runs are detected and surfaced in the final summary
so the user can manually clean them up."
```

---

## Task 4: Add `parse_proxy_group_line` / `format_proxy_group_line` helpers

**Rationale:** Cascade cleanup of Proxy Group lines requires splitting the line into its structural parts (name, type, members, options). Pure parsing, no integration yet.

**Files:**
- Modify: `converter.py` (add helpers)
- Modify: `test_converter.py` (add test class)

### Structural notes

Proxy group line format:

```
<name> = <type>, <member1>, <member2>, ..., <key1>=<value1>, <key2>=<value2>, ...
```

- Members are **positional arguments** after the type, until the first `key=value` token.
- Member names may be quoted (`"💼 MAI"`) — quotes must be preserved for round-trip.
- `key=value` tokens may have values containing `=` or `/` (URLs, regexes), but commas must not appear inside values in practice (Surge uses comma as the outer delimiter).
- Whitespace around commas is free — normalize to `, ` on reformat.

### Data model

```python
@dataclass
class ProxyGroupLine:
    name: str                    # e.g., '✈️ Proxy'
    group_type: str              # e.g., 'select'
    members: list[str]           # raw tokens as they appeared, including any quotes
    options: list[tuple[str, str]]  # ordered list of (key, value) to preserve original order
```

Two entry points:

- `parse_proxy_group_line(line: str) -> ProxyGroupLine | None` — returns None if the line cannot be parsed as a proxy group definition (comment, section header, etc.)
- `format_proxy_group_line(pgl: ProxyGroupLine) -> str` — stable round-trip

- [ ] **Step 1: Write the failing tests**

Append to `test_converter.py`:

```python
# --- T20: Proxy Group line parsing ---

class TestParseProxyGroupLine:
    def test_select_with_members_only(self):
        from converter import parse_proxy_group_line
        pgl = parse_proxy_group_line("Proxy = select, DIRECT, HK, JP")
        assert pgl.name == "Proxy"
        assert pgl.group_type == "select"
        assert pgl.members == ["DIRECT", "HK", "JP"]
        assert pgl.options == []

    def test_select_with_quoted_members(self):
        from converter import parse_proxy_group_line
        pgl = parse_proxy_group_line('✈️ Proxy = select, "💼 MAI", "♻️ Auto", DIRECT')
        assert pgl.name == "✈️ Proxy"
        assert pgl.members == ['"💼 MAI"', '"♻️ Auto"', "DIRECT"]

    def test_url_test_with_options(self):
        from converter import parse_proxy_group_line
        pgl = parse_proxy_group_line("Auto = url-test, HK, JP, url=http://x.com/204, interval=300")
        assert pgl.group_type == "url-test"
        assert pgl.members == ["HK", "JP"]
        assert pgl.options == [("url", "http://x.com/204"), ("interval", "300")]

    def test_policy_path_is_an_option_not_a_member(self):
        from converter import parse_proxy_group_line
        pgl = parse_proxy_group_line("Auto = smart, policy-path=proxies.conf, interval=300")
        assert pgl.members == []
        assert pgl.options == [("policy-path", "proxies.conf"), ("interval", "300")]

    def test_mixed_members_and_policy_path(self):
        from converter import parse_proxy_group_line
        pgl = parse_proxy_group_line(
            'Proxy = select, "💼 MAI", "♻️ Auto", policy-path=xflash.conf'
        )
        assert pgl.members == ['"💼 MAI"', '"♻️ Auto"']
        assert pgl.options == [("policy-path", "xflash.conf")]

    def test_include_all_proxies_is_an_option(self):
        from converter import parse_proxy_group_line
        pgl = parse_proxy_group_line(
            "AI = select, REJECT, include-all-proxies=1, policy-regex-filter=(HK|JP)"
        )
        assert pgl.members == ["REJECT"]
        assert ("include-all-proxies", "1") in pgl.options

    def test_comment_line_returns_none(self):
        from converter import parse_proxy_group_line
        assert parse_proxy_group_line("# Proxy = select, HK") is None

    def test_section_header_returns_none(self):
        from converter import parse_proxy_group_line
        assert parse_proxy_group_line("[Proxy Group]") is None

    def test_extra_whitespace_tolerated(self):
        from converter import parse_proxy_group_line
        pgl = parse_proxy_group_line("  Proxy  =  select  ,  HK  ,  JP  ")
        assert pgl.name == "Proxy"
        assert pgl.group_type == "select"
        assert pgl.members == ["HK", "JP"]


class TestFormatProxyGroupLine:
    def test_roundtrip_simple(self):
        from converter import parse_proxy_group_line, format_proxy_group_line
        line = "Proxy = select, DIRECT, HK, JP"
        assert format_proxy_group_line(parse_proxy_group_line(line)) == line

    def test_roundtrip_with_options(self):
        from converter import parse_proxy_group_line, format_proxy_group_line
        line = "Auto = url-test, HK, JP, url=http://x.com/204, interval=300"
        assert format_proxy_group_line(parse_proxy_group_line(line)) == line

    def test_roundtrip_quoted_members(self):
        from converter import parse_proxy_group_line, format_proxy_group_line
        line = '✈️ Proxy = select, "💼 MAI", "♻️ Auto", DIRECT'
        assert format_proxy_group_line(parse_proxy_group_line(line)) == line

    def test_format_with_no_members(self):
        from converter import ProxyGroupLine, format_proxy_group_line
        pgl = ProxyGroupLine(
            name="Auto", group_type="url-test", members=[], options=[("interval", "300")]
        )
        assert format_proxy_group_line(pgl) == "Auto = url-test, interval=300"

    def test_format_with_empty_options(self):
        from converter import ProxyGroupLine, format_proxy_group_line
        pgl = ProxyGroupLine(
            name="Proxy", group_type="select", members=["HK", "JP"], options=[]
        )
        assert format_proxy_group_line(pgl) == "Proxy = select, HK, JP"
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `pytest test_converter.py::TestParseProxyGroupLine test_converter.py::TestFormatProxyGroupLine -v`

Expected: ImportError on `parse_proxy_group_line`.

- [ ] **Step 3: Implement the helpers**

Add to `converter.py` near the other helpers (after `extract_proxy_type`):

```python
from dataclasses import dataclass, field


@dataclass
class ProxyGroupLine:
    name: str
    group_type: str
    members: list               # raw tokens, quotes preserved
    options: list                # ordered list of (key, value) tuples


def parse_proxy_group_line(line):
    """Parse a Surge Proxy Group definition line.

    Returns a ProxyGroupLine or None if the line is not a group definition
    (e.g., a comment, section header, or empty line).
    """
    stripped = line.lstrip()
    if not stripped or stripped.startswith("#") or stripped.startswith("["):
        return None
    if "=" not in line:
        return None

    name_part, rest = line.split("=", 1)
    name = name_part.strip()
    tokens = [t.strip() for t in rest.split(",")]
    if not tokens:
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
```

- [ ] **Step 4: Run tests**

Run: `pytest test_converter.py::TestParseProxyGroupLine test_converter.py::TestFormatProxyGroupLine -v`

Expected: 13 passed.

- [ ] **Step 5: Run full suite for regression**

Run: `pytest test_converter.py -v 2>&1 | tail -10`

Expected: all pass.

- [ ] **Step 6: Commit**

```bash
git add converter.py test_converter.py
git commit -m "feat: add parse_proxy_group_line / format_proxy_group_line helpers"
```

---

## Task 5: Add `extract_rule_policy` helper

**Rationale:** Cascade cleanup for rules needs the policy field (3rd comma-separated token for simple rules; nested for `AND`/`OR`/`NOT`). Pure utility.

**Files:**
- Modify: `converter.py` (add helper)
- Modify: `test_converter.py` (add test class)

### Structural notes

Simple rule: `TYPE,CRITERIA,POLICY[,opt1,opt2]` where options are trailing bare tokens (e.g., `no-resolve`) or `key=value` pairs (rare in rules).

Compound rule: `AND,((TYPE,CRIT),(TYPE,CRIT)),POLICY` — policy is still the last top-level field. Criteria are wrapped in balanced parentheses.

Strategy: tokenize by top-level commas (ignoring commas inside parentheses), the policy is the last token unless it is a well-known rule option like `no-resolve`/`force-remote-dns`/`extended-matching`. For our cascade cleanup we only need to know whether the policy matches a deleted name — a simple heuristic is fine: **the policy is the last token that is NOT a known option keyword and NOT a `key=value` pair.**

- [ ] **Step 1: Write the failing tests**

Append to `test_converter.py`:

```python
# --- T21: Rule policy extraction ---

class TestExtractRulePolicy:
    def test_domain_suffix(self):
        from converter import extract_rule_policy
        assert extract_rule_policy("DOMAIN-SUFFIX,example.com,DIRECT") == "DIRECT"

    def test_quoted_policy(self):
        from converter import extract_rule_policy
        assert extract_rule_policy('DOMAIN,foo.com,"✈️ Proxy"') == '"✈️ Proxy"'

    def test_policy_with_emoji(self):
        from converter import extract_rule_policy
        assert extract_rule_policy("DOMAIN,foo.com,♻️ Auto") == "♻️ Auto"

    def test_ip_cidr_with_no_resolve(self):
        from converter import extract_rule_policy
        assert extract_rule_policy("IP-CIDR,1.2.3.4/32,DIRECT,no-resolve") == "DIRECT"

    def test_geoip_with_force_remote_dns(self):
        from converter import extract_rule_policy
        assert extract_rule_policy("GEOIP,CN,DIRECT,force-remote-dns") == "DIRECT"

    def test_rule_set(self):
        from converter import extract_rule_policy
        assert extract_rule_policy("RULE-SET,https://x.com/list.list,Proxy") == "Proxy"

    def test_and_rule(self):
        from converter import extract_rule_policy
        assert extract_rule_policy(
            "AND,((DOMAIN-SUFFIX,example.com),(DEST-PORT,443)),DIRECT"
        ) == "DIRECT"

    def test_or_rule_with_quoted_policy(self):
        from converter import extract_rule_policy
        assert extract_rule_policy(
            'OR,((DOMAIN,a.com),(DOMAIN,b.com)),"✈️ Proxy"'
        ) == '"✈️ Proxy"'

    def test_final_rule(self):
        from converter import extract_rule_policy
        assert extract_rule_policy("FINAL,Proxy,dns-failed") == "Proxy"

    def test_comment_returns_none(self):
        from converter import extract_rule_policy
        assert extract_rule_policy("# DOMAIN,foo.com,DIRECT") is None

    def test_section_header_returns_none(self):
        from converter import extract_rule_policy
        assert extract_rule_policy("[Rule]") is None

    def test_empty_returns_none(self):
        from converter import extract_rule_policy
        assert extract_rule_policy("") is None
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `pytest test_converter.py::TestExtractRulePolicy -v`

Expected: ImportError.

- [ ] **Step 3: Implement `extract_rule_policy`**

Add to `converter.py`:

```python
# Known trailing options that are never a policy target
RULE_TRAILING_OPTIONS = {
    "no-resolve",
    "force-remote-dns",
    "extended-matching",
    "dns-failed",
    "pre-matching",
}


def _split_top_level_commas(s):
    """Split a string by commas at depth 0 (outside of balanced parentheses)."""
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


def extract_rule_policy(line):
    """Return the policy target from a rule line, or None if not a rule.

    Strategy: split by top-level commas (respecting parens for AND/OR/NOT),
    walk from the end discarding known trailing option keywords and key=value
    pairs; the first remaining token is the policy.
    """
    stripped = line.lstrip()
    if not stripped or stripped.startswith("#") or stripped.startswith("["):
        return None
    tokens = _split_top_level_commas(stripped)
    if len(tokens) < 2:
        return None
    # Walk from end, skip trailing options
    i = len(tokens) - 1
    while i > 0:
        t = tokens[i]
        if t in RULE_TRAILING_OPTIONS:
            i -= 1
            continue
        if "=" in t and not t.startswith('"'):
            # key=value option (very rare in rules; be conservative)
            i -= 1
            continue
        return t
    return None
```

- [ ] **Step 4: Run tests**

Run: `pytest test_converter.py::TestExtractRulePolicy -v`

Expected: 12 passed.

- [ ] **Step 5: Run full suite**

Run: `pytest test_converter.py 2>&1 | tail -5`

Expected: all pass.

- [ ] **Step 6: Commit**

```bash
git add converter.py test_converter.py
git commit -m "feat: add extract_rule_policy helper with AND/OR/NOT paren awareness"
```

---

## Task 6: Add `parse_include_list` helper

**Rationale:** `#!include` directive accepts comma-separated file paths and/or URLs. Cascade cleanup needs to split, filter, and rejoin.

**Files:**
- Modify: `converter.py`
- Modify: `test_converter.py`

- [ ] **Step 1: Write the failing tests**

Append to `test_converter.py`:

```python
# --- T22: Include list parsing ---

class TestParseIncludeList:
    def test_single_file(self):
        from converter import parse_include_list
        assert parse_include_list("#!include proxies.conf") == ["proxies.conf"]

    def test_multiple_files(self):
        from converter import parse_include_list
        assert parse_include_list("#!include a.conf, b.conf, c.dconf") == [
            "a.conf", "b.conf", "c.dconf",
        ]

    def test_extra_whitespace(self):
        from converter import parse_include_list
        assert parse_include_list("#!include   a.conf  ,  b.conf  ") == ["a.conf", "b.conf"]

    def test_url_and_local_mixed(self):
        from converter import parse_include_list
        assert parse_include_list(
            "#!include https://x.com/a.conf, local.conf"
        ) == ["https://x.com/a.conf", "local.conf"]

    def test_not_an_include(self):
        from converter import parse_include_list
        assert parse_include_list("[General]") is None
        assert parse_include_list("# comment") is None
        assert parse_include_list("") is None


class TestFormatIncludeList:
    def test_single(self):
        from converter import format_include_list
        assert format_include_list(["a.conf"]) == "#!include a.conf"

    def test_multiple(self):
        from converter import format_include_list
        assert format_include_list(["a.conf", "b.conf"]) == "#!include a.conf, b.conf"

    def test_empty_returns_none(self):
        """Empty list → None so caller knows to comment the whole line."""
        from converter import format_include_list
        assert format_include_list([]) is None
```

- [ ] **Step 2: Run tests to verify failure**

Run: `pytest test_converter.py::TestParseIncludeList test_converter.py::TestFormatIncludeList -v`

Expected: ImportError.

- [ ] **Step 3: Implement the helpers**

Add to `converter.py`:

```python
def parse_include_list(line):
    """Parse a #!include line into a list of path/url entries, or None.

    Returns None if the line is not an #!include directive.
    """
    m = re.match(r'^#!include\s+(.+)$', line)
    if not m:
        return None
    return [p.strip() for p in m.group(1).split(",") if p.strip()]


def format_include_list(entries):
    """Format a list of entries back into a #!include line.

    Returns None if the list is empty.
    """
    if not entries:
        return None
    return "#!include " + ", ".join(entries)
```

- [ ] **Step 4: Run tests**

Run: `pytest test_converter.py::TestParseIncludeList test_converter.py::TestFormatIncludeList -v`

Expected: 8 passed.

- [ ] **Step 5: Commit**

```bash
git add converter.py test_converter.py
git commit -m "feat: add parse_include_list / format_include_list helpers"
```

---

## Task 7: Introduce `FileState` dataclass and `Pipeline` skeleton

**Rationale:** Restructure `convert_file` into a three-phase pipeline (Discover → Analyze → Emit). This task does the structural refactor only — behavior stays identical to today's `convert_file`. No cascade logic yet. Subsequent tasks add cascade rules on top of this skeleton.

**Files:**
- Modify: `converter.py` (add `FileState`, `Pipeline`, rewire `convert_file`)
- Existing tests in `test_converter.py` must continue to pass unchanged.

### Design

```
Pipeline.run()
├── discover(root, default_section)
│     ├── read file, detect is_managed
│     ├── run convert_content to produce a "direct-hit" converted string
│     │     (this catalogs v5+ proxies, commented sections, etc.)
│     ├── recursively discover includes and policy-paths (local only)
│     └── store FileState(abs_path, original, converted, is_managed, ...)
│
├── analyze()
│     └── [no-op in this task; cascade logic added in Tasks 8–12]
│
└── emit()
      ├── for each FileState:
      │     if is_managed and converted != original → abandon path:
      │         record in stats.abandoned_files
      │         if stale -v4 exists on disk → record in stats.stale_v4_files
      │           (do NOT delete; user decides from final summary)
      │         skip write
      │     elif converted == original → skip write
      │     else:
      │         write converted → -v4 path (with deprecated backup)
      └── return output_path for the root FileState
```

`FileState` is a minimal dataclass; we'll add fields in later tasks.

### Important: preserve existing recursion semantics

The current implementation recursively triggers sub-file conversion INSIDE `update_include_line` and `update_policy_path` via calls to `convert_file(sub_path, ...)`. Those callsites stay — we don't rewrite them. But we change what `convert_file` DOES when it detects that a Pipeline is already running.

**The integration strategy:** a module-level `_active_pipeline` variable is set by the top-level `convert_file` call and read by nested calls. Top-level calls create a new Pipeline and run all three phases; nested calls (from `update_include_line` / `update_policy_path`) detect the active Pipeline and reuse it via `pipeline.discover(sub_path)` rather than creating a new one. This way every `FileState` — root and all recursively-discovered sub-files — lives in the same `self.files` dict, which is what Tasks 8–12's cascade logic iterates over.

**Early abandonment decision:** `Pipeline.discover` decides `state.is_abandoned` immediately after computing `converted` (before returning to the caller). This is safe because both inputs to the decision (`is_managed` from line 1, `converted != original` from running direct-hit transforms) are known at that point. Making the decision eager lets the nested `convert_file` wrapper return `None` for abandoned sub-files, so `update_include_line` / `update_policy_path` KEEP the original file reference in the parent's string (not rewrite it to `-v4`). Task 12 can then match the original basename against `abandoned_files` and strip it.

- [ ] **Step 1: Write a smoke test for the refactor**

Append to `test_converter.py`:

```python
# --- T23: Pipeline skeleton regression ---

class TestPipelineSkeleton:
    def test_pipeline_runs_end_to_end(self, tmp_path):
        """Pipeline.run must produce the same output as the old convert_file for a simple case."""
        main = tmp_path / "main.conf"
        main.write_text("[Proxy]\nHY = hysteria2, 1.2.3.4, 443, password=pwd\n")

        stats = ConversionStats()
        result = convert_file(str(main), stats, {str(main): None})

        assert result == str(tmp_path / "main-v4.conf")
        out = (tmp_path / "main-v4.conf").read_text()
        assert "# [V5+]" in out

    def test_pipeline_skip_unchanged(self, tmp_path):
        main = tmp_path / "main.conf"
        main.write_text("[General]\nloglevel = notify\n")

        stats = ConversionStats()
        result = convert_file(str(main), stats, {str(main): None})
        assert result is None
        assert not (tmp_path / "main-v4.conf").exists()

    def test_pipeline_include_recursion(self, tmp_path):
        sub = tmp_path / "sub.conf"
        sub.write_text("HY = hysteria2, 1.2.3.4, 443, password=pwd\n")

        main = tmp_path / "main.conf"
        main.write_text("[Proxy]\n#!include sub.conf\n")

        stats = ConversionStats()
        convert_file(str(main), stats, {str(main): None})

        assert (tmp_path / "sub-v4.conf").exists()
        assert (tmp_path / "main-v4.conf").exists()
        main_out = (tmp_path / "main-v4.conf").read_text()
        assert "#!include sub-v4.conf" in main_out
```

- [ ] **Step 2: Run the new smoke tests to confirm they pass on current code**

Run: `pytest test_converter.py::TestPipelineSkeleton -v`

Expected: 3 passed (these tests describe current behavior — the refactor must preserve it).

- [ ] **Step 3: Add `FileState` dataclass**

In `converter.py`, add after the `ProxyGroupLine` definition:

```python
@dataclass
class FileState:
    """Intermediate state for one file during the conversion pipeline."""
    abs_path: str
    original: str                # raw file content
    converted: str               # content after direct-hit transforms
    is_managed: bool
    default_section: str = None  # for files without explicit section headers
    is_abandoned: bool = False   # decided in analyze()
    output_written: bool = False # decided in emit()
    output_path: str = None      # destination if written
```

- [ ] **Step 4: Add `Pipeline` class (skeleton, no cascade yet)**

In `converter.py`, add after `FileState`:

```python
# Module-level global: when a top-level convert_file creates a Pipeline, it
# sets this to the pipeline instance so that nested convert_file calls
# (triggered by update_include_line / update_policy_path during recursive
# discovery) can detect and reuse the same pipeline instead of creating a new
# one. Reset to None in the top-level finally block.
_active_pipeline = None


class Pipeline:
    """Three-phase converter: discover → analyze → emit."""

    def __init__(self, stats, processed_files=None):
        self.stats = stats
        self.files = {}  # abs_path → FileState (insertion order = discovery order)
        self.processed_files = processed_files if processed_files is not None else {}

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
            converted=original,  # placeholder; replaced below
            is_managed=is_managed_config(original),
            default_section=default_section,
        )
        self.files[abs_path] = state

        # Pre-register in processed_files so recursive calls from convert_content
        # (via update_include_line / update_policy_path) don't re-enter this file.
        self.processed_files[abs_path] = None

        base_dir = os.path.dirname(abs_path)
        converted = convert_content(
            original, base_dir, self.stats, self.processed_files,
            default_section=default_section,
            filename=os.path.basename(abs_path),
        )
        state.converted = converted

        # Eager abandonment decision: lets the nested convert_file wrapper
        # return None for abandoned files so the parent's include/policy-path
        # references stay pointing at the ORIGINAL name (not rewritten to -v4).
        # Task 12 will then match the original basename against abandoned_files
        # and strip it.
        if state.is_managed and state.converted != state.original:
            state.is_abandoned = True

        return state

    def analyze(self):
        """Cross-file cascade propagation. No-op in the skeleton; filled in later tasks."""
        pass

    def emit(self):
        """Write -v4 files based on FileState decisions. Returns the root output path."""
        root_output = None
        root_abs = next(iter(self.files))  # first discovered = root
        for abs_path, state in self.files.items():
            output_path = make_v4_filename(abs_path)

            # Abandon decision was made in discover(). Here we just act on it:
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
```

- [ ] **Step 5: Rewire `convert_file` as a dual-mode wrapper**

Replace the `convert_file` function body with:

```python
def convert_file(input_path, stats=None, processed_files=None, default_section=None):
    """Convert a Surge config file from v5+ to v4.

    Two modes:

    1. **Top-level (no active Pipeline)**: create a Pipeline, run discover →
       analyze → emit on this file and all its dependencies, return the root
       file's output path (or None if abandoned / unchanged).

    2. **Nested (called from update_include_line / update_policy_path while
       a Pipeline is already running)**: reuse the active Pipeline via
       `pipeline.discover(input_path)` to add this sub-file to the shared
       `self.files` dict, then return a backward-compatible sentinel:
       - abandoned sub-file → None (parent keeps original reference)
       - unchanged sub-file → None (parent keeps original reference)
       - converted sub-file → make_v4_filename(input_path) (parent rewrites to -v4)

       The actual write/emit of sub-files happens later, when the top-level
       `Pipeline.emit` iterates over all states. Nested calls only discover.
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
```

- [ ] **Step 6: Run full test suite**

Run: `pytest test_converter.py -v 2>&1 | tail -25`

Expected: All tests pass (including the new `TestPipelineSkeleton` from Step 1 and all pre-existing tests from earlier tasks).

If any test fails, the refactor has introduced a regression. The most likely culprit is that `update_include_line` / `update_policy_path` are still calling the old standalone `convert_file`, which now re-enters the Pipeline. Verify by inspecting the execution — it should still work because Pipeline correctly pre-registers files in `processed_files` before diving in.

- [ ] **Step 7: Commit**

```bash
git add converter.py test_converter.py
git commit -m "refactor: introduce FileState + Pipeline three-phase skeleton

Preserves existing behavior; lays groundwork for cascade cleanup.
convert_file is now a thin wrapper around Pipeline.run()."
```

---

## Task 8: Single-file cascade — clean deleted proxy names from Proxy Groups

**Rationale:** When a v5+ proxy is commented out in `[Proxy]`, any Proxy Group line in the SAME file that lists that proxy as a member has a dangling reference. Remove the reference. If removing it leaves the group with zero effective members, tag the whole line `# [V5+ cascade]` and add the group's name to the deleted set. Iterate until no further changes (fixpoint).

**Files:**
- Modify: `converter.py` (new cascade logic inside `FileState`/`Pipeline`)
- Modify: `test_converter.py`

### Semantics

A Proxy Group has "effective members" if ANY of these holds:
- At least one explicit member remains (after removing deleted names) AND that member is not itself in the deleted set
- `include-all-proxies=1` option is present
- `policy-path=<file>` option is present AND the file is not abandoned (this task assumes no abandonment yet; the abandonment integration is Task 11)

**Critical rule (backward compatibility):** only tag a group as cascade-empty if we actually REMOVED something from it. A group that was ALREADY empty before our cleanup (e.g., `Auto = smart, interval=300` with no members) is left alone. Rationale: it was already broken before we touched it; we don't fix pre-existing bugs.

### Design

Extend `FileState` with per-file bookkeeping:

```python
@dataclass
class FileState:
    abs_path: str
    original: str
    converted: str
    is_managed: bool
    default_section: str = None
    is_abandoned: bool = False
    output_written: bool = False
    output_path: str = None
    # New fields for cascade:
    lines: list = field(default_factory=list)  # working copy, mutable
    owned_proxies: set = field(default_factory=set)   # proxy names defined here (from direct-hit pass)
    owned_groups: set = field(default_factory=set)    # group names defined here
    deleted_names: set = field(default_factory=set)   # names to remove (proxies and groups)
```

After Discover populates `converted`, we split it into `lines`. `deleted_names` is seeded by scanning `[Proxy]` for commented-out `# [V5+] name = type, ...` lines.

The single-file cascade runs in Analyze (or at the end of Discover, before the cross-file phase). For this task, put it in Analyze since that's the semantic home.

Algorithm:

```python
def single_file_cascade(state):
    changed = True
    while changed:
        changed = False
        for i, line in enumerate(state.lines):
            # Only touch lines inside [Proxy Group]
            if not in_proxy_group_section(state, i):
                continue
            if line.lstrip().startswith("#"):
                continue
            pgl = parse_proxy_group_line(line)
            if pgl is None:
                continue
            original_member_count = len(pgl.members)
            # Drop deleted members
            pgl.members = [m for m in pgl.members if unquote(m) not in state.deleted_names]
            removed_something = len(pgl.members) < original_member_count
            if not removed_something:
                continue  # nothing changed, don't touch the line
            # Rebuild the line
            if has_effective_members(pgl, state.deleted_names, abandoned_files=set()):
                state.lines[i] = preserve_indent(line, format_proxy_group_line(pgl))
                changed = True
            else:
                state.lines[i] = CASCADE_TAG + line.lstrip()
                state.deleted_names.add(pgl.name)
                changed = True
    state.converted = "\n".join(state.lines) + ("\n" if state.original.endswith("\n") else "")
```

The helper `in_proxy_group_section(state, i)` walks backwards to find the most recent `[Section]` header.

- [ ] **Step 1: Write the failing tests**

Append to `test_converter.py`:

```python
# --- T24: Single-file cascade (proxy → proxy group) ---

class TestSingleFileProxyCascade:
    def test_group_member_removed_when_proxy_deleted(self, tmp_path):
        """A v5+ proxy is commented; a group that listed it should drop the reference."""
        main = tmp_path / "main.conf"
        main.write_text(
            "[Proxy]\n"
            "JP = anytls, 1.2.3.4, 443, password=pwd\n"
            "HK = trojan, 5.6.7.8, 443, password=pwd\n"
            "\n"
            "[Proxy Group]\n"
            "Proxy = select, JP, HK\n"
        )
        convert_file(str(main), ConversionStats(), {str(main): None})
        out = (tmp_path / "main-v4.conf").read_text()
        assert "# [V5+] JP = anytls" in out
        assert "Proxy = select, HK" in out

    def test_group_becomes_empty_after_cascade(self, tmp_path):
        """A group with only v5+ members becomes empty → tag as cascade."""
        main = tmp_path / "main.conf"
        main.write_text(
            "[Proxy]\n"
            "JP = anytls, 1.2.3.4, 443, password=pwd\n"
            "US = hysteria2, 5.6.7.8, 443, password=pwd\n"
            "\n"
            "[Proxy Group]\n"
            "Fast = url-test, JP, US\n"
        )
        convert_file(str(main), ConversionStats(), {str(main): None})
        out = (tmp_path / "main-v4.conf").read_text()
        assert "# [V5+ cascade] Fast = url-test" in out

    def test_group_with_builtin_survives(self, tmp_path):
        """Group retaining a built-in policy is still valid."""
        main = tmp_path / "main.conf"
        main.write_text(
            "[Proxy]\n"
            "JP = anytls, 1.2.3.4, 443, password=pwd\n"
            "\n"
            "[Proxy Group]\n"
            "Block = select, REJECT, JP, DIRECT\n"
        )
        convert_file(str(main), ConversionStats(), {str(main): None})
        out = (tmp_path / "main-v4.conf").read_text()
        assert "Block = select, REJECT, DIRECT" in out
        assert "# [V5+ cascade]" not in out

    def test_group_with_include_all_survives(self, tmp_path):
        """include-all-proxies=1 counts as implicit member supply."""
        main = tmp_path / "main.conf"
        main.write_text(
            "[Proxy]\n"
            "JP = anytls, 1.2.3.4, 443, password=pwd\n"
            "\n"
            "[Proxy Group]\n"
            "Auto = url-test, JP, include-all-proxies=1, interval=300\n"
        )
        convert_file(str(main), ConversionStats(), {str(main): None})
        out = (tmp_path / "main-v4.conf").read_text()
        assert "# [V5+ cascade]" not in out
        assert "Auto = url-test, include-all-proxies=1, interval=300" in out

    def test_cascade_propagates_to_referencing_group(self, tmp_path):
        """Group A loses all members → Group B that referenced A now has a dangling ref."""
        main = tmp_path / "main.conf"
        main.write_text(
            "[Proxy]\n"
            "JP = anytls, 1.2.3.4, 443, password=pwd\n"
            "HK = trojan, 5.6.7.8, 443, password=pwd\n"
            "\n"
            "[Proxy Group]\n"
            "OnlyV5 = select, JP\n"
            "Outer = select, OnlyV5, HK\n"
        )
        convert_file(str(main), ConversionStats(), {str(main): None})
        out = (tmp_path / "main-v4.conf").read_text()
        assert "# [V5+ cascade] OnlyV5 = select" in out
        assert "Outer = select, HK" in out

    def test_pre_existing_empty_group_left_alone(self, tmp_path):
        """A group that was already empty before our cleanup must not be touched."""
        main = tmp_path / "main.conf"
        main.write_text(
            "[Proxy]\n"
            "JP = anytls, 1.2.3.4, 443, password=pwd\n"
            "\n"
            "[Proxy Group]\n"
            "Auto = smart, interval=300\n"  # zero explicit members, pre-existing
        )
        convert_file(str(main), ConversionStats(), {str(main): None})
        out = (tmp_path / "main-v4.conf").read_text()
        # smart → url-test still happens (direct hit)
        assert "Auto = url-test, interval=300" in out
        # but NO cascade tag, because we removed nothing from Auto
        assert "# [V5+ cascade]" not in out

    def test_quoted_member_cascade(self, tmp_path):
        """Quoted member names must also be recognized for deletion."""
        main = tmp_path / "main.conf"
        main.write_text(
            "[Proxy]\n"
            '"🇯🇵 JP" = anytls, 1.2.3.4, 443, password=pwd\n'
            '"🇭🇰 HK" = trojan, 5.6.7.8, 443, password=pwd\n'
            "\n"
            "[Proxy Group]\n"
            'Proxy = select, "🇯🇵 JP", "🇭🇰 HK"\n'
        )
        convert_file(str(main), ConversionStats(), {str(main): None})
        out = (tmp_path / "main-v4.conf").read_text()
        assert 'Proxy = select, "🇭🇰 HK"' in out
```

- [ ] **Step 2: Run to confirm failures**

Run: `pytest test_converter.py::TestSingleFileProxyCascade -v`

Expected: Multiple failures; the cascade logic does not exist yet.

- [ ] **Step 3: Extend `FileState` with cascade fields**

Replace the existing `FileState` definition with:

```python
@dataclass
class FileState:
    abs_path: str
    original: str
    converted: str
    is_managed: bool
    default_section: str = None
    is_abandoned: bool = False
    output_written: bool = False
    output_path: str = None
    # Cascade fields (populated during Analyze):
    lines: list = field(default_factory=list)
    owned_proxies: set = field(default_factory=set)
    owned_groups: set = field(default_factory=set)
    deleted_names: set = field(default_factory=set)
    sections: list = field(default_factory=list)  # per-line section name
```

- [ ] **Step 4: Add the `CASCADE_TAG` constant and the `unquote` helper**

Near the other constants in `converter.py`:

```python
CASCADE_TAG = "# [V5+ cascade] "

BUILTIN_POLICIES = {
    "DIRECT", "REJECT", "REJECT-DROP", "REJECT-NO-DROP", "REJECT-TINYGIF",
}


def unquote(name):
    """Strip surrounding double quotes from a proxy/group name token."""
    if len(name) >= 2 and name[0] == '"' and name[-1] == '"':
        return name[1:-1]
    return name
```

- [ ] **Step 5: Add `compute_sections` helper and populate `FileState.sections` / `lines` in Discover**

Add to `converter.py`:

```python
def compute_sections(lines, default_section=None):
    """Return a list parallel to `lines` where each entry is the section name
    that line belongs to (or `default_section` before any header appears)."""
    result = []
    current = default_section
    for line in lines:
        m = re.match(r'^\[(.+)\]$', line.strip())
        if m:
            current = m.group(1)
        result.append(current)
    return result
```

In `Pipeline.discover`, after setting `state.converted`, add:

```python
        state.lines = state.converted.splitlines()
        state.sections = compute_sections(state.lines, default_section)

        # Catalog owned proxy and group names; seed deleted_names from commented v5+ proxies
        for i, line in enumerate(state.lines):
            section = state.sections[i]
            if section == "Proxy":
                # Commented-out v5+ proxy? → extract name, add to deleted_names
                if line.startswith("# [V5+] "):
                    raw = line[len("# [V5+] "):]
                    name = raw.split("=", 1)[0].strip() if "=" in raw else None
                    if name:
                        state.deleted_names.add(unquote(name))
                elif not line.lstrip().startswith("#") and "=" in line:
                    name = line.split("=", 1)[0].strip()
                    state.owned_proxies.add(unquote(name))
            elif section == "Proxy Group":
                if not line.lstrip().startswith("#") and "=" in line:
                    name = line.split("=", 1)[0].strip()
                    state.owned_groups.add(unquote(name))
```

- [ ] **Step 6: Add `has_effective_members` helper**

Add to `converter.py`:

```python
def has_effective_members(pgl, deleted_names, abandoned_files):
    """Return True if the group still has at least one valid member source.

    A group is valid if it has:
      - at least one explicit member not in deleted_names, OR
      - include-all-proxies=1 option, OR
      - policy-path=<file> where the file is not abandoned (HTTP URLs always count as valid)
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
            # Local path: abandoned_files contains absolute paths; we compare the basename
            # (caller must use the right form). For this task, abandoned_files is empty.
            if value not in abandoned_files:
                return True
    return False
```

- [ ] **Step 7: Add `_preserve_indent` helper**

Add to `converter.py`:

```python
def _preserve_indent(original_line, new_content):
    """Prepend original_line's leading whitespace to new_content."""
    stripped = original_line.lstrip()
    indent = original_line[:len(original_line) - len(stripped)]
    return indent + new_content
```

- [ ] **Step 8: Implement `Pipeline.analyze` single-file cascade**

Replace `Pipeline.analyze` with:

```python
    def analyze(self):
        """Apply cascade cleanup. Fixpoint iteration over all files."""
        for state in self.files.values():
            self._cascade_single_file(state)
        # Re-serialize converted content from mutated lines
        for state in self.files.values():
            joined = "\n".join(state.lines)
            if state.original.endswith("\n") and not joined.endswith("\n"):
                joined += "\n"
            state.converted = joined

    def _cascade_single_file(self, state):
        """Fixpoint: remove deleted members from Proxy Group lines; if a group
        loses all effective members, tag it cascade and propagate its name."""
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
                pgl.members = [m for m in original_members if unquote(m) not in state.deleted_names]
                removed_something = len(pgl.members) < len(original_members)
                if not removed_something:
                    continue  # nothing to do (D6: pre-existing empty groups left alone)
                if has_effective_members(pgl, state.deleted_names, abandoned_files=set()):
                    new_line = _preserve_indent(line, format_proxy_group_line(pgl))
                    if new_line != line:
                        state.lines[i] = new_line
                        changed = True
                else:
                    # Tag the REFORMATTED (post-cleanup) line so the cascade
                    # comment shows what the group would have been, not what
                    # it was before we touched it.
                    reformatted = _preserve_indent(line, format_proxy_group_line(pgl))
                    state.lines[i] = CASCADE_TAG + reformatted.lstrip()
                    state.deleted_names.add(unquote(pgl.name))
                    self.stats.lines_commented += 1
                    changed = True
```

- [ ] **Step 9: Run the cascade tests**

Run: `pytest test_converter.py::TestSingleFileProxyCascade -v`

Expected: 7 passed.

- [ ] **Step 10: Run the full suite**

Run: `pytest test_converter.py 2>&1 | tail -10`

Expected: all pass. If the `TestChangeOutput` or `TestSmartToUrlTest` tests fail with "line count changed", the "pre-existing empty group" rule is misfiring — double-check the `removed_something` guard.

- [ ] **Step 11: Commit**

```bash
git add converter.py test_converter.py
git commit -m "feat: cascade cleanup for deleted proxy names in same file

When a v5+ proxy is commented, any Proxy Group in the same file that
referenced it has the member removed; if the group becomes empty, it
is tagged with # [V5+ cascade] and its name propagates (fixpoint)."
```

---

## Task 9: Single-file cascade — clean Rules pointing at deleted names

**Rationale:** Rules like `DOMAIN,foo.com,♻️ Auto` become dangling when `♻️ Auto` is deleted (by Task 8 cascade or by upstream deletion). Comment the rule with `# [V5+ cascade]`.

**Files:**
- Modify: `converter.py`
- Modify: `test_converter.py`

- [ ] **Step 1: Write the failing tests**

Append:

```python
# --- T25: Single-file cascade — rules ---

class TestSingleFileRuleCascade:
    def test_rule_commented_when_policy_deleted(self, tmp_path):
        main = tmp_path / "main.conf"
        main.write_text(
            "[Proxy]\n"
            "JP = anytls, 1.2.3.4, 443, password=pwd\n"
            "HK = trojan, 5.6.7.8, 443, password=pwd\n"
            "\n"
            "[Rule]\n"
            "DOMAIN,foo.com,JP\n"
            "DOMAIN,bar.com,HK\n"
        )
        convert_file(str(main), ConversionStats(), {str(main): None})
        out = (tmp_path / "main-v4.conf").read_text()
        assert "# [V5+ cascade] DOMAIN,foo.com,JP" in out
        assert "DOMAIN,bar.com,HK" in out  # unchanged

    def test_rule_with_cascade_deleted_group(self, tmp_path):
        main = tmp_path / "main.conf"
        main.write_text(
            "[Proxy]\n"
            "JP = anytls, 1.2.3.4, 443, password=pwd\n"
            "HK = trojan, 5.6.7.8, 443, password=pwd\n"
            "\n"
            "[Proxy Group]\n"
            "OnlyV5 = select, JP\n"
            "\n"
            "[Rule]\n"
            "DOMAIN,foo.com,OnlyV5\n"
        )
        convert_file(str(main), ConversionStats(), {str(main): None})
        out = (tmp_path / "main-v4.conf").read_text()
        assert "# [V5+ cascade] OnlyV5 = select" in out
        assert "# [V5+ cascade] DOMAIN,foo.com,OnlyV5" in out

    def test_and_rule_cascade(self, tmp_path):
        main = tmp_path / "main.conf"
        main.write_text(
            "[Proxy]\n"
            "JP = anytls, 1.2.3.4, 443, password=pwd\n"
            "\n"
            "[Rule]\n"
            "AND,((DOMAIN-SUFFIX,example.com),(DEST-PORT,443)),JP\n"
        )
        convert_file(str(main), ConversionStats(), {str(main): None})
        out = (tmp_path / "main-v4.conf").read_text()
        assert "# [V5+ cascade] AND,((DOMAIN-SUFFIX,example.com),(DEST-PORT,443)),JP" in out
```

- [ ] **Step 2: Run tests to confirm failure**

Run: `pytest test_converter.py::TestSingleFileRuleCascade -v`

Expected: 3 failures.

- [ ] **Step 3: Extend `_cascade_single_file` with rule cleanup**

In `Pipeline._cascade_single_file`, after the `while changed` loop finishes (fixpoint stable), add:

```python
        # Post-fixpoint: scan [Rule] for dangling policy references
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
```

- [ ] **Step 4: Run the new tests**

Run: `pytest test_converter.py::TestSingleFileRuleCascade -v`

Expected: 3 passed.

- [ ] **Step 5: Run full suite**

Run: `pytest test_converter.py 2>&1 | tail -10`

Expected: all pass.

- [ ] **Step 6: Commit**

```bash
git add converter.py test_converter.py
git commit -m "feat: cascade cleanup for Rule lines referencing deleted names"
```

---

## Task 10: Cross-file cascade — abandoned file propagates `owned_names` into parent's `deleted_names`

**Rationale:** When the pipeline abandons `xflash-leodxkr.conf`, every proxy or group defined inside that file vanishes from the namespace of every file that `#!include`d it. Parent files need to know which names are gone so their cascade pass can clean up.

Note: this task changes WHERE the cascade picks up names. It's no longer just per-file — Analyze must union `owned_proxies ∪ owned_groups` from every abandoned file into a GLOBAL deleted set, then re-run cascade on every parent file.

**Files:**
- Modify: `converter.py`
- Modify: `test_converter.py`

### Design change

`Pipeline` gains instance-level state:

```python
self.abandoned_files: set[str] = set()  # abs paths
self.global_deleted: set[str] = set()   # all names deleted anywhere
```

`Pipeline.analyze` now:

```
1. For each FileState, run discover-time cascade seeding:
   - state.deleted_names already has v5+ proxy names from Discover
2. For each FileState, decide is_abandoned:
   - is_managed AND (any line in state.lines differs from state.original)
3. For each abandoned state:
   - self.abandoned_files.add(state.abs_path)
   - self.global_deleted |= state.owned_proxies | state.owned_groups
4. For each NON-abandoned state:
   - state.deleted_names |= self.global_deleted
5. Fixpoint loop across all non-abandoned states:
   - run _cascade_single_file on each
   - if any state's lines changed AND its owned_groups shrank (new cascade), add those shrunk names to self.global_deleted
   - any change → re-run the loop
6. Final pass: re-serialize state.converted from state.lines
```

- [ ] **Step 1: Write the failing tests**

Append (this test isolates Task 10's concern — cross-file name propagation
from an abandoned sub-file into the parent's Proxy Group members. Include-line
cleanup is Task 12's job; this test does NOT assert on the include line):

```python
# --- T26: Cross-file cascade — owned names propagate ---

class TestCrossFileOwnedNames:
    def test_abandoned_proxies_removed_from_parent_group(self, tmp_path):
        """When a sub-file is abandoned, proxy names defined inside it must
        propagate into the parent's deleted_names so the parent's Proxy Group
        members referencing those names (by name, not via policy-path) get
        removed."""
        sub = tmp_path / "sub.conf"
        sub.write_text(
            "#!MANAGED-CONFIG https://x.com/sub.conf interval=3600\n"
            "[Proxy]\n"
            "JP = anytls, 1.2.3.4, 443, password=pwd\n"
            "HK = trojan, 5.6.7.8, 443, password=pwd\n"
        )
        main = tmp_path / "main.conf"
        main.write_text(
            "[Proxy]\n"
            "LOCAL = ss, 9.9.9.9, 443, encrypt-method=aes-256-gcm, password=pwd\n"
            "#!include sub.conf\n"
            "\n"
            "[Proxy Group]\n"
            "Proxy = select, LOCAL, JP, HK\n"
        )

        stats = ConversionStats()
        convert_file(str(main), stats, {str(main): None})

        # 1. sub.conf abandoned (no -v4 produced)
        assert not (tmp_path / "sub-v4.conf").exists()
        assert str(sub) in stats.abandoned_files

        # 2. main-v4.conf exists (parent has changes from cascade)
        main_v4 = tmp_path / "main-v4.conf"
        assert main_v4.exists()
        out = main_v4.read_text()

        # 3. JP and HK are no longer in the Proxy group's member list
        #    (THIS is the Task 10 assertion — cross-file name propagation)
        for out_line in out.splitlines():
            if out_line.startswith("Proxy = select"):
                assert "LOCAL" in out_line
                assert "JP" not in out_line
                assert "HK" not in out_line
                break
        else:
            assert False, "Proxy group line not found in output"
```

- [ ] **Step 2: Run to confirm failure**

Run: `pytest test_converter.py::TestCrossFileOwnedNames -v`

Expected: failure — JP and HK still in the Proxy group because cross-file propagation doesn't exist yet.

- [ ] **Step 3: Extend `Pipeline` state and refactor `analyze`**

In `Pipeline.__init__`, add:

```python
        self.abandoned_files = set()
        self.global_deleted = set()
```

Replace `Pipeline.analyze` with:

```python
    def analyze(self):
        """Cross-file cascade: propagate abandonment and deleted names, then fixpoint.

        Note: state.is_abandoned is already set by Pipeline.discover (eager
        decision). Analyze just collects bookkeeping from those decisions.
        """
        # Collect abandonment bookkeeping from decisions made in discover().
        # For an abandoned file, EVERY name it defined vanishes from the
        # global namespace — this includes:
        #   - owned_proxies: non-v5+ proxies (would have been kept if the file
        #     weren't abandoned)
        #   - owned_groups: proxy groups (same)
        #   - deleted_names: v5+ proxies that were commented by direct hit
        #     (already gone from THIS file, but parents may reference by name)
        for state in self.files.values():
            if state.is_abandoned:
                self.abandoned_files.add(state.abs_path)
                self.global_deleted |= state.owned_proxies
                self.global_deleted |= state.owned_groups
                self.global_deleted |= state.deleted_names

        # Seed per-file deleted_names with the global set
        for state in self.files.values():
            if state.is_abandoned:
                continue
            state.deleted_names |= self.global_deleted

        # Fixpoint across all non-abandoned files
        changed = True
        while changed:
            changed = False
            for state in self.files.values():
                if state.is_abandoned:
                    continue
                before = set(state.deleted_names)
                self._cascade_single_file(state)
                after = state.deleted_names
                new_deletions = after - before - self.global_deleted
                if new_deletions:
                    self.global_deleted |= new_deletions
                    # Propagate to every other file
                    for other in self.files.values():
                        if other is not state and not other.is_abandoned:
                            other.deleted_names |= new_deletions
                    changed = True

        # Re-serialize converted from mutated lines
        for state in self.files.values():
            if state.is_abandoned:
                continue
            joined = "\n".join(state.lines)
            if state.original.endswith("\n") and not joined.endswith("\n"):
                joined += "\n"
            state.converted = joined
```

Also update `Pipeline.emit` to use `state.is_abandoned` instead of re-checking `is_managed and converted != original`:

```python
    def emit(self):
        root_output = None
        root_abs = next(iter(self.files))
        for abs_path, state in self.files.items():
            output_path = make_v4_filename(abs_path)

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

            if state.converted == state.original:
                self.processed_files[abs_path] = None
                if abs_path == root_abs:
                    root_output = None
                continue

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
```

- [ ] **Step 4: Run the new test**

Run: `pytest test_converter.py::TestCrossFileOwnedNames -v`

Expected: passed.

- [ ] **Step 5: Run full suite**

Run: `pytest test_converter.py 2>&1 | tail -10`

Expected: all pass.

- [ ] **Step 6: Commit**

```bash
git add converter.py test_converter.py
git commit -m "feat: propagate owned names from abandoned files into global deleted set"
```

---

## Task 11: Cross-file cascade — abandoned files propagate to parent `policy-path=`

**Rationale:** When `Pipeline.discover` processes a parent file, `update_policy_path` rewrites `policy-path=sub.conf` → `policy-path=sub-v4.conf` if the sub was converted, or leaves it alone if it was unchanged. Abandonment is a third outcome: the parent must REMOVE the option entirely.

**Files:**
- Modify: `converter.py` (`update_policy_path` + `Pipeline.analyze`)
- Modify: `test_converter.py`

### Design

Since Discover has already rewritten `policy-path=` values by the time Analyze runs, the abandoned file's basename will already appear as the ORIGINAL name (because the recursive conversion returned None, so `update_policy_path` kept the original reference). We need Analyze to go back over every Proxy Group line in every non-abandoned file and strip any `policy-path=` option whose resolved file is in `abandoned_files`.

After stripping, re-check `has_effective_members` — if the group is now empty, cascade it.

- [ ] **Step 1: Write the failing tests**

Append:

```python
# --- T27: Cross-file cascade — policy-path → abandoned ---

class TestCrossFilePolicyPath:
    def test_policy_path_option_stripped(self, tmp_path):
        sub = tmp_path / "sub.conf"
        sub.write_text(
            "#!MANAGED-CONFIG https://x.com/sub.conf interval=3600\n"
            "[Proxy]\n"
            "JP = anytls, 1.2.3.4, 443, password=pwd\n"
        )
        main = tmp_path / "main.conf"
        main.write_text(
            "[Proxy Group]\n"
            'Proxy = select, "💼 MAI", "🧑‍💻 SelfVPS", policy-path=sub.conf\n'
        )
        convert_file(str(main), ConversionStats(), {str(main): None})
        out = (tmp_path / "main-v4.conf").read_text()
        assert 'Proxy = select, "💼 MAI", "🧑‍💻 SelfVPS"' in out
        assert "policy-path=sub.conf" not in out

    def test_group_becomes_empty_after_policy_path_stripped(self, tmp_path):
        sub = tmp_path / "sub.conf"
        sub.write_text(
            "#!MANAGED-CONFIG https://x.com/sub.conf interval=3600\n"
            "[Proxy]\n"
            "JP = anytls, 1.2.3.4, 443, password=pwd\n"
        )
        main = tmp_path / "main.conf"
        main.write_text(
            "[Proxy Group]\n"
            "Auto = smart, policy-path=sub.conf, interval=300\n"
        )
        convert_file(str(main), ConversionStats(), {str(main): None})
        out = (tmp_path / "main-v4.conf").read_text()
        # smart→url-test direct hit applied, then cascade empties the group
        assert "# [V5+ cascade] Auto = url-test, interval=300" in out

    def test_http_policy_path_not_stripped(self, tmp_path):
        sub = tmp_path / "sub.conf"
        sub.write_text(
            "#!MANAGED-CONFIG https://x.com/sub.conf interval=3600\n"
            "[Proxy]\n"
            "JP = anytls, 1.2.3.4, 443, password=pwd\n"
        )
        main = tmp_path / "main.conf"
        main.write_text(
            "[Proxy Group]\n"
            "Mix = select, policy-path=https://example.com/a.conf, policy-path=sub.conf\n"
        )
        convert_file(str(main), ConversionStats(), {str(main): None})
        out = (tmp_path / "main-v4.conf").read_text()
        assert "policy-path=https://example.com/a.conf" in out
        assert "policy-path=sub.conf" not in out
```

- [ ] **Step 2: Run to confirm failures**

Run: `pytest test_converter.py::TestCrossFilePolicyPath -v`

Expected: 3 failures.

- [ ] **Step 3: Add an abandoned-files-aware cascade pass in `Pipeline.analyze`**

Add a helper method on Pipeline:

```python
    def _strip_abandoned_policy_paths(self, state):
        """Remove policy-path=<abandoned> options from Proxy Group lines in this file.

        If a group becomes empty (no explicit members, no include-all-proxies,
        no other valid policy-path), tag it cascade and propagate the group
        name to self.global_deleted AND to every other non-abandoned file's
        deleted_names so the downstream fixpoint loop sees it.
        """
        abandoned_basenames = {os.path.basename(p) for p in self.abandoned_files}
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
            if has_effective_members(pgl, state.deleted_names, self.abandoned_files):
                state.lines[i] = _preserve_indent(line, format_proxy_group_line(pgl))
            else:
                # Tag the reformatted (post-strip) line, not the original
                reformatted = _preserve_indent(line, format_proxy_group_line(pgl))
                state.lines[i] = CASCADE_TAG + reformatted.lstrip()
                deleted_name = unquote(pgl.name)
                state.deleted_names.add(deleted_name)
                self.global_deleted.add(deleted_name)
                # Propagate immediately so the downstream fixpoint loop sees it
                # when it processes other files — otherwise a group in file B
                # referencing this now-deleted group A would not be cleaned up.
                for other in self.files.values():
                    if other is not state and not other.is_abandoned:
                        other.deleted_names.add(deleted_name)
                self.stats.lines_commented += 1
```

In `Pipeline.analyze`, after the initial abandonment decision and BEFORE the main fixpoint loop, add a pre-pass:

```python
        # Pre-pass: strip abandoned policy-path options; this may seed additional
        # deletions which are propagated immediately inside the helper.
        for state in self.files.values():
            if state.is_abandoned:
                continue
            self._strip_abandoned_policy_paths(state)
```

- [ ] **Step 4: Run the new tests**

Run: `pytest test_converter.py::TestCrossFilePolicyPath -v`

Expected: 3 passed.

- [ ] **Step 5: Run full suite**

Run: `pytest test_converter.py 2>&1 | tail -10`

Expected: all pass.

- [ ] **Step 6: Commit**

```bash
git add converter.py test_converter.py
git commit -m "feat: strip policy-path options pointing at abandoned files

Propagates group emptiness through cascade when policy-path was the
only member source."
```

---

## Task 12: Cross-file cascade — abandoned files propagate to parent `#!include`

**Rationale:** The parent's `#!include a.conf, sub.conf, c.conf` must drop the abandoned entry. If the list becomes empty, comment out the whole line with `# [V5+ cascade]`.

**Files:**
- Modify: `converter.py`
- Modify: `test_converter.py`

### Design subtlety

During Discover, `update_include_line` already rewrote entries whose sub-file was CONVERTED (`a.conf` → `a-v4.conf`). For abandoned sub-files, the sub-file returned None, so the entry was kept as the original name. We now need to remove those entries post-hoc.

The abandonment check needs to compare basenames: the include line has `sub.conf`, and `self.abandoned_files` has the absolute path `/tmp/xyz/sub.conf`.

- [ ] **Step 1: Write the failing tests**

Append:

```python
# --- T28: Cross-file cascade — #!include → abandoned ---

class TestCrossFileInclude:
    def test_abandoned_include_entry_removed(self, tmp_path):
        sub = tmp_path / "sub.conf"
        sub.write_text(
            "#!MANAGED-CONFIG https://x.com/sub.conf interval=3600\n"
            "[Proxy]\n"
            "JP = anytls, 1.2.3.4, 443, password=pwd\n"
        )
        other = tmp_path / "other.conf"
        other.write_text(
            "[Proxy]\n"
            "HK = trojan, 5.6.7.8, 443, password=pwd\n"
        )
        main = tmp_path / "main.conf"
        main.write_text(
            "[Proxy]\n"
            "#!include sub.conf, other.conf\n"
        )
        convert_file(str(main), ConversionStats(), {str(main): None})
        out = (tmp_path / "main-v4.conf").read_text()
        assert "#!include other.conf" in out
        assert "sub.conf" not in out
        # sub.conf abandoned, other.conf pure v4 (no conversion, keeps original name)

    def test_sole_abandoned_include_commented(self, tmp_path):
        sub = tmp_path / "sub.conf"
        sub.write_text(
            "#!MANAGED-CONFIG https://x.com/sub.conf interval=3600\n"
            "[Proxy]\n"
            "JP = anytls, 1.2.3.4, 443, password=pwd\n"
        )
        main = tmp_path / "main.conf"
        main.write_text(
            "[General]\nloglevel = notify\n"
            "[Proxy]\n"
            "#!include sub.conf\n"
            "LOCAL = ss, 9.9.9.9, 443, encrypt-method=aes-256-gcm, password=pwd\n"
        )
        convert_file(str(main), ConversionStats(), {str(main): None})
        out = (tmp_path / "main-v4.conf").read_text()
        assert "# [V5+ cascade] #!include sub.conf" in out
        assert "LOCAL = ss" in out

    def test_mixed_include_partial_abandon(self, tmp_path):
        """sub1 abandoned (managed v5+), sub2 converted normally."""
        sub1 = tmp_path / "sub1.conf"
        sub1.write_text(
            "#!MANAGED-CONFIG https://x.com/sub1.conf interval=3600\n"
            "[Proxy]\n"
            "JP = anytls, 1.2.3.4, 443, password=pwd\n"
        )
        sub2 = tmp_path / "sub2.conf"
        sub2.write_text(
            "[Proxy]\n"
            "SNELL = snell, 5.6.7.8, 443, psk=pwd, version=5\n"
        )
        main = tmp_path / "main.conf"
        main.write_text(
            "[Proxy]\n"
            "#!include sub1.conf, sub2.conf\n"
        )
        convert_file(str(main), ConversionStats(), {str(main): None})
        out = (tmp_path / "main-v4.conf").read_text()
        assert "#!include sub2-v4.conf" in out
        assert "sub1.conf" not in out
        assert "sub1-v4.conf" not in out
```

- [ ] **Step 2: Run to confirm failures**

Run: `pytest test_converter.py::TestCrossFileInclude -v`

Expected: 3 failures.

- [ ] **Step 3: Add include cleanup to `Pipeline.analyze`**

Add a helper on Pipeline:

```python
    def _strip_abandoned_includes(self, state):
        """Remove entries in #!include lines that point at abandoned files."""
        abandoned_basenames = {os.path.basename(p) for p in self.abandoned_files}
        for i, line in enumerate(state.lines):
            if line.lstrip().startswith("#") and not line.lstrip().startswith("#!include"):
                continue
            entries = parse_include_list(line)
            if entries is None:
                continue
            kept = [e for e in entries if os.path.basename(e) not in abandoned_basenames]
            if len(kept) == len(entries):
                continue
            if not kept:
                state.lines[i] = CASCADE_TAG + line.lstrip()
                self.stats.lines_commented += 1
            else:
                new_line = format_include_list(kept)
                state.lines[i] = _preserve_indent(line, new_line)
```

In `Pipeline.analyze`, after `_strip_abandoned_policy_paths` pre-pass, add:

```python
        for state in self.files.values():
            if state.is_abandoned:
                continue
            self._strip_abandoned_includes(state)
```

- [ ] **Step 4: Run the new tests**

Run: `pytest test_converter.py::TestCrossFileInclude -v`

Expected: 3 passed.

- [ ] **Step 5: Run full suite**

Run: `pytest test_converter.py 2>&1 | tail -10`

Expected: all pass.

- [ ] **Step 6: Commit**

```bash
git add converter.py test_converter.py
git commit -m "feat: strip abandoned file entries from #!include lines"
```

---

## Task 13: End-to-end integration test with home.conf-like fixture

**Rationale:** The user's real config is `home.conf` + `xflash-leodxkr.conf` (managed, v5+) + `mai-vps.dconf` + `self-vps.dconf` + `self-home.dconf`. Build a minimal fixture that reproduces the structure and assert on the full expected output.

**Files:**
- Modify: `test_converter.py`

- [ ] **Step 1: Write the integration test**

Append:

```python
# --- T29: End-to-end real-world scenario ---

class TestRealWorldCascade:
    def test_home_conf_with_abandoned_xflash(self, tmp_path):
        """Faithful reproduction of home.conf structure with abandoned managed profile."""
        xflash = tmp_path / "xflash-leodxkr.conf"
        xflash.write_text(
            "#!MANAGED-CONFIG https://www.xflash.org/api/v1/... interval=43200 strict=true\n"
            "[Proxy]\n"
            "🇯🇵 日本 = anytls, 03.giant.jp.matchacocoa.com, 35000, password=pwd\n"
            "🇭🇰 香港 = trojan, 03.giant.hk.matchacocoa.com, 443, password=pwd\n"
            "🇺🇸 美国 = anytls, 03.giant.us.matchacocoa.com, 35000, password=pwd\n"
        )
        mai = tmp_path / "mai-vps.dconf"
        mai.write_text("[Proxy]\n🇺🇸 MA-DMIT-US-SNELL = snell, 01.study.us, 7443, psk=pwd, version=5\n")
        self_vps = tmp_path / "self-vps.dconf"
        self_vps.write_text("[Proxy]\n# commented out\n")
        self_home = tmp_path / "self-home.dconf"
        self_home.write_text("[Proxy]\n🏡 HomeSnell = snell, home.x, 6161, psk=pwd, version=5\n")

        home = tmp_path / "home.conf"
        home.write_text(
            "[General]\n"
            "loglevel = notify\n"
            "proxy-test-url = http://cp.cloudflare.com/generate_204\n"
            "\n"
            "[Proxy]\n"
            "#!include xflash-leodxkr.conf, mai-vps.dconf, self-vps.dconf, self-home.dconf\n"
            "\n"
            "[Proxy Group]\n"
            '✈️ Proxy = select, "💼 MAI", "♻️ Auto", "🧑‍💻 SelfVPS", "🏡 HomeProxy", policy-path=xflash-leodxkr.conf\n'
            "♻️ Auto  = smart, policy-path=xflash-leodxkr.conf, interval=300\n"
            '💼 MAI = select, include-all-proxies=1\n'
            '🧑‍💻 SelfVPS = select, include-all-proxies=1\n'
            '🏡 HomeProxy = select, include-all-proxies=1\n'
            "\n"
            "[Rule]\n"
            'DOMAIN-SUFFIX,example.com,"✈️ Proxy"\n'
            "FINAL,✈️ Proxy\n"
        )

        stats = ConversionStats()
        result = convert_file(str(home), stats, {str(home): None})

        # 1. xflash-leodxkr.conf abandoned
        assert not (tmp_path / "xflash-leodxkr-v4.conf").exists()
        assert str(xflash) in stats.abandoned_files

        # 2. home-v4.conf produced
        home_v4 = tmp_path / "home-v4.conf"
        assert home_v4.exists()
        out = home_v4.read_text()

        # 3. Include line has xflash removed, mai-vps/self-home rewritten, self-vps kept (no changes)
        assert "xflash-leodxkr.conf" not in out
        assert "xflash-leodxkr-v4.conf" not in out
        assert "mai-vps-v4.dconf" in out
        assert "self-home-v4.dconf" in out
        assert "self-vps.dconf" in out

        # 4. ✈️ Proxy lost policy-path but kept 3 explicit members (♻️ Auto pruned in round 2)
        assert '✈️ Proxy = select, "💼 MAI", "🧑‍💻 SelfVPS", "🏡 HomeProxy"' in out

        # 5. ♻️ Auto cascaded to empty → commented
        assert "# [V5+ cascade] ♻️ Auto = url-test, interval=300" in out

        # 6. Other Proxy Groups untouched
        assert '💼 MAI = select, include-all-proxies=1' in out

        # 7. Rules unchanged (✈️ Proxy still exists)
        assert 'DOMAIN-SUFFIX,example.com,"✈️ Proxy"' in out
        assert "FINAL,✈️ Proxy" in out

        # 8. Sub-file mai-vps-v4.dconf has Snell version downgraded
        assert (tmp_path / "mai-vps-v4.dconf").exists()
        mai_out = (tmp_path / "mai-vps-v4.dconf").read_text()
        assert "version=4" in mai_out
        assert "version=5" not in mai_out

    def test_stale_xflash_v4_detected_not_deleted(self, tmp_path):
        """If xflash-leodxkr-v4.conf existed from a previous run, it gets
        recorded in stats.stale_v4_files (NOT deleted). User sees it in the
        final summary and decides what to do."""
        xflash = tmp_path / "xflash.conf"
        xflash.write_text(
            "#!MANAGED-CONFIG https://x.com/sub.conf interval=3600\n"
            "[Proxy]\n"
            "JP = anytls, 1.2.3.4, 443, password=pwd\n"
        )
        stale = tmp_path / "xflash-v4.conf"
        stale.write_text("stale content")

        main = tmp_path / "main.conf"
        main.write_text("[Proxy]\n#!include xflash.conf\n")

        stats = ConversionStats()
        with patch("converter.send2trash") as mock_trash:
            convert_file(str(main), stats, {str(main): None})
            # send2trash is still called for deprecated_files path, but NOT for
            # abandonment's stale v4. Since there are no deprecated files in
            # this scenario, it should never be called.
            assert mock_trash.call_count == 0

        # Stale file still sits on disk, untouched
        assert stale.exists()
        assert stale.read_text() == "stale content"

        # But it was detected and recorded
        assert str(stale) in stats.stale_v4_files
        assert str(xflash) in stats.abandoned_files
```

- [ ] **Step 2: Run the integration test**

Run: `pytest test_converter.py::TestRealWorldCascade -v`

Expected: 2 passed. If a specific assertion fails, read the actual `home-v4.conf` content (print it in the test temporarily) and reconcile — it often reveals a missed cascade rule or formatting subtlety.

- [ ] **Step 3: Run full suite**

Run: `pytest test_converter.py 2>&1 | tail -10`

Expected: all pass.

- [ ] **Step 4: Commit**

```bash
git add test_converter.py
git commit -m "test: end-to-end cascade scenario matching real home.conf structure"
```

---

## Task 14: Stats and CLI output updates

**Rationale:** Users need to see what was abandoned, what was cascade-cleaned, and what was directly hit. Split the counts.

**Files:**
- Modify: `converter.py`
- Modify: `test_converter.py`

- [ ] **Step 1: Write the failing tests**

Append:

```python
# --- T30: Stats reporting ---

class TestStatsReporting:
    def test_cascade_count_tracked(self, tmp_path):
        main = tmp_path / "main.conf"
        main.write_text(
            "[Proxy]\n"
            "JP = anytls, 1.2.3.4, 443, password=pwd\n"
            "\n"
            "[Proxy Group]\n"
            "OnlyV5 = select, JP\n"
            "\n"
            "[Rule]\n"
            "DOMAIN,foo.com,OnlyV5\n"
        )
        stats = ConversionStats()
        convert_file(str(main), stats, {str(main): None})
        # Expect at least: JP proxy commented (direct), OnlyV5 commented (cascade), rule commented (cascade)
        assert stats.lines_commented >= 3

    def test_abandoned_files_tracked(self, tmp_path):
        sub = tmp_path / "sub.conf"
        sub.write_text(
            "#!MANAGED-CONFIG https://x.com/sub.conf interval=3600\n"
            "[Proxy]\n"
            "JP = anytls, 1.2.3.4, 443, password=pwd\n"
        )
        main = tmp_path / "main.conf"
        main.write_text("[Proxy]\n#!include sub.conf\n")

        stats = ConversionStats()
        convert_file(str(main), stats, {str(main): None})

        assert len(stats.abandoned_files) == 1
        assert str(sub) in stats.abandoned_files
```

- [ ] **Step 2: Run to confirm current state**

Run: `pytest test_converter.py::TestStatsReporting -v`

Expected: both pass (the counting already works from Tasks 8–12). If not, debug the counter increments.

- [ ] **Step 3: Update `ConversionStats.print_summary` to highlight cascade**

Replace `print_summary` with:

```python
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
        print(f"注释行数（含直接命中与级联）: {self.lines_commented}")
        print(f"修改参数数: {self.params_modified}")
        if self.abandoned_files:
            print(f"放弃的托管配置数: {len(self.abandoned_files)}")
```

- [ ] **Step 4: Run full suite**

Run: `pytest test_converter.py 2>&1 | tail -10`

Expected: all pass.

- [ ] **Step 5: Commit**

```bash
git add converter.py test_converter.py
git commit -m "feat: surface abandoned files and cascade counts in conversion summary"
```

---

## Task 15: Manual validation against real user config

**Rationale:** The plan's correctness is validated by tests, but the user's actual iCloud config is the ultimate truth. Dry-run the converter and visually compare before committing anyone to the output.

**Files:** (no code changes in this task)

- [ ] **Step 1: Back up the current v4 outputs before testing**

```bash
cp "/Users/leo/Library/Mobile Documents/iCloud~com~nssurge~inc/Documents/home-v4.conf" /tmp/home-v4-pre-refactor.conf 2>/dev/null || true
cp "/Users/leo/Library/Mobile Documents/iCloud~com~nssurge~inc/Documents/xflash-leodxkr-v4.conf" /tmp/xflash-v4-pre-refactor.conf 2>/dev/null || true
```

- [ ] **Step 2: Run the refactored converter against home.conf**

```bash
cd /Users/leo/Documents/ai-project/surge-config-converter
python3 converter.py "/Users/leo/Library/Mobile Documents/iCloud~com~nssurge~inc/Documents/home.conf"
```

Expected console output includes:
- `已放弃托管配置（含 v5+ 内容）: .../xflash-leodxkr.conf`
- `⚠️  检测到旧的 v4 文件（未自动删除）: .../xflash-leodxkr-v4.conf` (only if the stale file exists)
- `已转换: .../home.conf → .../home-v4.conf`
- `已转换: .../mai-vps.dconf → .../mai-vps-v4.dconf` (and similar for self-home)
- A final warning block listing all stale v4 files for manual handling

- [ ] **Step 3: Manually delete the stale xflash-leodxkr-v4.conf (one-time cleanup)**

The script will not auto-delete it. After confirming from the console output that it was detected, run:

```bash
mv "/Users/leo/Library/Mobile Documents/iCloud~com~nssurge~inc/Documents/xflash-leodxkr-v4.conf" ~/.Trash/
```

(Or use Finder. The point is: the user is in control, the script just warned.)

- [ ] **Step 4: Inspect the resulting `home-v4.conf`**

```bash
diff /tmp/home-v4-pre-refactor.conf "/Users/leo/Library/Mobile Documents/iCloud~com~nssurge~inc/Documents/home-v4.conf" | head -80
```

Manually verify:
- `#!include` line no longer mentions `xflash-leodxkr.conf` or `xflash-leodxkr-v4.conf`
- `✈️ Proxy = select, ...` no longer has `policy-path=xflash...`
- `♻️ Auto = ...` line is either commented with `# [V5+ cascade]` or has been cleaned up
- No existing valid configuration has been accidentally commented

- [ ] **Step 5: Run converter a second time to verify idempotency**

```bash
python3 converter.py "/Users/leo/Library/Mobile Documents/iCloud~com~nssurge~inc/Documents/home.conf"
```

Expected: `已跳过（内容未变化）: .../home-v4.conf` for every derived file. The abandonment line for xflash-leodxkr.conf still appears, but the "⚠️ 检测到旧的 v4 文件" line should NOT (because you manually cleaned it up in Step 3).

- [ ] **Step 6: Also run against `home-tv.conf`**

```bash
python3 converter.py "/Users/leo/Library/Mobile Documents/iCloud~com~nssurge~inc/Documents/home-tv.conf"
```

home-tv.conf's `#!include xflash-leodxkr.conf` must now become `# [V5+ cascade] #!include xflash-leodxkr.conf` (sole entry) or be removed from a multi-entry list, depending on the file.

- [ ] **Step 7: Open the resulting configs in Surge to verify parsing**

Manually load `home-v4.conf` in Surge (or simulator). Confirm no parse errors. If Surge complains about missing named proxies or undefined groups, the cascade missed a case — revisit the plan and add a fix.

- [ ] **Step 8: Final commit if everything is clean**

No code changes in this task — but if you discovered bugs in Steps 2–7, fix them in the relevant earlier task files, add regression tests, and commit. This task is a go/no-go gate.

---

## Self-Review

### Spec coverage

| Requirement | Task(s) |
|---|---|
| D1 Managed profile + v5+ change → abandon | Task 3 (top-level), Task 10–12 (cross-file) |
| D2 Detect (not delete) stale -v4 on abandonment; warn in final summary | Task 3 (stats field + convert_file logic + main summary), Task 13 (integration) |
| D3 1-member select kept | Task 8 (has_effective_members logic) |
| D4 include-all-proxies=1 kept | Task 8 (has_effective_members logic, T24 tests) |
| D5 Empty-after-cleanup group → cascade comment | Task 8, Task 11 |
| D6 Pre-existing empty group left alone | Task 8 (removed_something guard, T24 test) |
| D7 smart→url-test untouched | preserved from existing code; Task 13 integration asserts it |
| D8 CLI workflow unchanged | Task 3/7 (convert_file signature preserved), Task 15 (manual run) |
| D9 Dual tags `# [V5+]` vs `# [V5+ cascade]` | Task 1 (rename), Task 8 (cascade tag constant) |
| D10 Rename v5+ → V5+ | Task 1 |
| Parser helpers | Tasks 4, 5, 6 |
| Three-phase refactor | Task 7 |
| Rule cascade | Task 9 |
| policy-path cascade | Task 11 |
| #!include cascade | Task 12 |
| Stats reporting | Task 14 |

No gaps.

### Placeholder scan

- No "TBD", "implement later", or "add validation" markers.
- Every code step shows the complete code.
- Every test step shows the actual test body.
- Expected outputs are given for every `run:` command.

### Type consistency

- `parse_proxy_group_line` returns `ProxyGroupLine | None` — consistent throughout Tasks 4, 8, 11.
- `extract_rule_policy` returns `str | None` — consistent in Tasks 5, 9.
- `parse_include_list` returns `list[str] | None` — consistent in Tasks 6, 12.
- `FileState` fields introduced in Task 7, extended in Task 8 — later tasks use the extended form.
- `Pipeline` methods: `discover`, `analyze`, `emit`, `run` — stable signatures across tasks.
- `has_effective_members(pgl, deleted_names, abandoned_files)` — 3 args, stable signature in Tasks 8 and 11.
- `_preserve_indent(original_line, new_content)` — 2 args, stable in Tasks 8, 11.
- `CASCADE_TAG` constant — referenced consistently in Tasks 8, 9, 11, 12.
- `BUILTIN_POLICIES` set — referenced but not critical to the cascade logic after simplification.
- `unquote(name)` — 1 arg, stable in Tasks 8, 9, 11.
- `stats.abandoned_files` — added in Task 3, used in Tasks 10, 13, 14.

One potential footgun: in Task 8 Step 8, the code shows a first members filter that gets superseded by a second assignment. The step explicitly calls this out and instructs keeping only the second form. Engineers executing this plan via subagent must read that note.

### Risks and mitigations

| Risk | Mitigation |
|---|---|
| Task 7 refactor breaks existing tests | Task 7 Step 6 runs the full suite; Task 1 ensures tag literals match |
| Cascade accidentally comments pre-existing empty groups | Explicit test `test_pre_existing_empty_group_left_alone` in Task 8 |
| Abandoned file path comparison (basename vs absolute) | Tasks 11/12 use `os.path.basename` on both sides |
| Fixpoint infinite loop | Loop condition is `changed`, only set when `deleted_names` grew; bounded by group count |
| User's real config has a case the fixtures miss | Task 15 requires manual validation before considering the feature done |

---

## Execution Handoff

Plan complete and saved to `docs/superpowers/plans/2026-04-12-managed-config-cascade-cleanup.md`.

Two execution options:

**1. Subagent-Driven (recommended)** — I dispatch a fresh subagent per task, review between tasks, fast iteration.

**2. Inline Execution** — Execute tasks in this session using `superpowers:executing-plans`, batch execution with checkpoints.

Which approach?
