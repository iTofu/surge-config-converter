# v5 → v5+ 全局重命名 Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** 将项目中所有 "v5" 命名统一为 "v5+"，更准确地表达「v5 及以上版本引入的特性」语义。

**Architecture:** 纯文本重命名，涉及 3 个文件（converter.py、test_converter.py、README.md），零逻辑变更。采用 test-first 方式：先改测试期望值使其 fail，再改实现使其 pass。

**Tech Stack:** Python 3, pytest

---

### Task 1: 更新测试期望值（test_converter.py）

**Files:**
- Modify: `test_converter.py`

**Step 1: 更新 docstring 和注释中的 v5 → v5+**

将文件首行 docstring 和所有注释中的 "v5" 更新为 "v5+"：

```python
# Line 1: docstring
"""Tests for Surge v5+ → v4 configuration converter."""

# Line 142: docstring
"""For a v4-supported proxy type, v5+-only params should be stripped."""

# Line 160-161: method name comment + docstring
def test_v5plus_proxy_with_v5plus_params_just_commented(self):
    """v5+-only proxy types are fully commented, params don't matter."""

# Line 197: section comment
# --- T6: v5+-only rule types ---

# Line 241: section comment
# --- T7: [General] v5+-only parameters ---

# Line 309: method name
def test_empty_lines_in_v5plus_section_preserved(self):
```

**Step 2: 更新所有 assert 中的 `# [v5]` → `# [v5+]`**

全局替换测试文件中所有 `# [v5]` 字符串为 `# [v5+]`。涉及约 30 处 assert 语句。

**Step 3: 运行测试，确认全部 FAIL**

Run: `python3 -m pytest test_converter.py -v 2>&1 | tail -5`
Expected: 多个 FAIL（因为 converter 还在输出 `# [v5]`）

---

### Task 2: 更新转换器实现（converter.py）

**Files:**
- Modify: `converter.py`

**Step 1: 重命名 5 个常量**

```
V5_ONLY_PROXY_TYPES   → V5PLUS_ONLY_PROXY_TYPES
V5_ONLY_SECTIONS      → V5PLUS_ONLY_SECTIONS
V5_ONLY_GENERAL_PARAMS → V5PLUS_ONLY_GENERAL_PARAMS
V5_ONLY_RULE_TYPES    → V5PLUS_ONLY_RULE_TYPES
V5_ONLY_PROXY_PARAMS  → V5PLUS_ONLY_PROXY_PARAMS
```

每个常量在定义处 + 引用处都需要更新。

**Step 2: 重命名局部变量**

```
in_v5_only_section → in_v5plus_only_section
```

出现在 `convert_content` 函数中，共 4 处（L240, L250, L256, L262）。

**Step 3: 更新 comment_line 输出标记**

```python
# converter.py:62-64
def comment_line(line):
    """Add # [v5+] prefix to a line."""
    return f"# [v5+] {{line}}"
```

**Step 4: 更新代码注释和 docstring 中的 v5 → v5+**

```
Line 2:  """Surge v5+ → v4 configuration converter."""
Line 23: # Proxy parameters to remove (v5+-only)
Line 102: # Comment out v5+-only proxy types
Line 122: # Remove v5+-only parameters
Line 228: """Convert configuration content from v5+ to v4 format.
Line 261: # If inside a v5+-only section, comment everything
Line 297: """Convert a single Surge config file from v5+ to v4.
```

**Step 5: 运行测试，确认全部 PASS**

Run: `python3 -m pytest test_converter.py -v`
Expected: ALL PASS

**Step 6: Commit**

```bash
git add converter.py test_converter.py
git commit -m "refactor: 全局重命名 v5 → v5+，统一语义为「v5 及以上版本特性」"
```

---

### Task 3: 更新文档（README.md）

**Files:**
- Modify: `README.md`

**Step 1: 更新所有 v5 引用**

```
Line 1:  # Surge Config Converter (v5+ → v4)
Line 3:  将 Surge v5+ 配置文件转换为 v4 兼容格式。自动识别并处理 v5+ 独有的协议、参数和语法...
Line 67: 被转换工具注释的行以 `# [v5+]` 开头，便于与用户原始注释区分。
```

**Step 2: Commit**

```bash
git add README.md
git commit -m "docs: README 同步 v5 → v5+ 命名更新"
```

---

### Task 4: 最终验证

**Step 1: 运行完整测试套件**

Run: `python3 -m pytest test_converter.py -v`
Expected: ALL PASS, 0 failures

**Step 2: 检查是否有遗漏的 v5 引用**

Run: `grep -rn 'v5' converter.py test_converter.py README.md | grep -v 'v5+' | grep -v 'v5\.' | grep -v 'version=5' | grep -v 'version=4'`
Expected: 仅 Snell `version=5` 相关的业务逻辑行（这些是 Surge 配置中的实际值，不应修改）
