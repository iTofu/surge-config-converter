# Surge Config Converter (v5+ → v4)

将 Surge v5+ 配置文件转换为 v4 兼容格式。自动识别并处理 v5+ 独有的协议、参数和语法，递归处理 `#!include` 和 `policy-path` 引用的子文件，并跨文件级联清理因转换产生的悬空引用。

## 使用

```bash
python3 converter.py <config_file_path>
```

示例：

```bash
python3 converter.py ~/Library/Mobile\ Documents/iCloud~com~nssurge~inc/Documents/home.conf
```

### 输出布局

所有生成的 `-v4` 文件统一写入源文件旁的 `v4/` 子目录：

```
Documents/
├── home.conf              ← 源文件 (v5+)
├── mai-vps.dconf
└── v4/
    ├── home-v4.conf       ← 转换产物 (v4)
    └── mai-vps-v4.dconf
```

`v4/` 内的文件互相引用时使用 bare filename（如 `#!include mai-vps-v4.dconf`），无目录前缀。使用时将 `v4/` 内所有文件拷贝到 Surge v4 设备的配置根目录即可。

### 旧文件处理

若输出文件已存在且内容有变化，旧文件先重命名为 `-deprecated` 后缀备份。运行结束后脚本会提示是否删除这些备份，确认后通过回收站（send2trash）安全删除。

## 转换规则

### 代理协议（[Proxy]）

| 规则 | 动作 |
|------|------|
| `hysteria2` / `hy2` | 注释（iOS 5.8.0+） |
| `anytls` | 注释（iOS 5.17.0+） |
| `tuic` | 注释（iOS 5.2.0+） |
| `trust-tunnel` | 注释（Mac 6.4.4+） |
| Snell `version=5` | 替换为 `version=4` |
| `shadow-tls-version=3` | 替换为 `shadow-tls-version=2` |
| `port-hopping` / `port-hopping-interval` / `ecn` | 移除参数 |

### 策略组（[Proxy Group]）

| 规则 | 动作 |
|------|------|
| `smart` | 替换为 `url-test` |

### 规则（[Rule]）

| 规则 | 动作 |
|------|------|
| `HOSTNAME-TYPE` | 注释 |
| `DOMAIN-WILDCARD` | 注释 |

### 通用参数（[General]）

| 规则 | 动作 |
|------|------|
| `udp-priority` | 注释 |
| `block-quic` | 注释 |

### 整段

| 规则 | 动作 |
|------|------|
| `[Port Forwarding]` | 整段注释 |
| `[Body Rewrite]` | 整段注释 |

### 引用文件

- `#!include` 和 `policy-path` 引用的本地文件会被递归转换
- 若子文件内容无需转换，不生成 `-v4` 副本，父文件保留原引用路径
- 引用路径仅在子文件实际产生变化时更新为 `-v4` 版本
- HTTP/HTTPS URL 不处理

### 托管配置（Managed Config）

含 `#!MANAGED-CONFIG` 指令的文件是 Surge 托管配置，Surge 会定期从远端刷新覆盖本地内容。如果这类文件含有 v5+ 特性：

- **放弃转换**：不生成 `-v4` 副本（否则会被远端刷新自毁）
- **检测过期文件**：若之前运行曾生成过对应的 `-v4` 文件，会在最终摘要中警告（不自动删除，由用户决定）
- **级联清理**：父文件中引用该托管配置的 `#!include` 条目和 `policy-path` 选项会被自动移除

### 级联清理

当某个 proxy 或 proxy group 因 v5+ 转换被注释或因托管配置放弃而消失时，引用它的其他配置行也会被清理：

- **Proxy Group 成员**：从成员列表中移除已删除的名称；若 group 因此失去所有有效成员来源，整行注释
- **Rule 策略**：规则指向已删除的 group/proxy 时，整行注释
- **`#!include`**：移除指向被放弃文件的条目；若列表清空，整行注释
- **`policy-path`**：移除指向被放弃文件的选项；若 group 因此失去所有成员来源，整行注释

级联清理会跨文件传播并迭代至稳定（fixpoint），确保不留悬空引用。

## 注释标记

| 标记 | 含义 |
|------|------|
| `# [V5+]` | 直接命中：该行含有 v5+ 独有语法，被转换工具注释 |
| `# [V5+ cascade]` | 级联清理：该行本身合法，但引用了被删除的 proxy/group，因此被注释 |

两种标记均与用户原始注释（`#` 开头但无 `[V5+]` 前缀）区分。

## 测试

```bash
python3 -m pytest test_converter.py -v
```
