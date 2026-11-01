# Surge Config Converter (v5+ → v4)

将 Surge v5+ 配置文件转换为 v4 兼容格式。自动识别并处理 v5+ 独有的协议、参数和语法，递归处理 `#!include` 和 `policy-path` 引用的子文件，并跨文件级联清理因转换产生的悬空引用。

## 环境要求

- Python ≥ 3.9
- 依赖安装：

```bash
pip3 install -r requirements.txt   # 运行只需 send2trash，测试另需 pytest
```

## 使用

```bash
python3 converter.py [--snell-legacy PATH] <config_file_path>
```

`--snell-legacy` 可选，见下文「Snell 旧版实例覆盖」。

示例：

```bash
python3 converter.py ~/Library/Mobile\ Documents/iCloud~com~nssurge~inc/Documents/profile.conf
```

### 输出布局

所有生成的 `-v4` 文件统一写入源文件旁的 `v4/` 子目录：

```
Documents/
├── profile.conf              ← 源文件 (v5+)
├── work-vps.dconf
└── v4/
    ├── profile-v4.conf       ← 转换产物 (v4)
    └── work-vps-v4.dconf
```

`v4/` 内的文件互相引用时使用 bare filename（如 `#!include work-vps-v4.dconf`），无目录前缀。

**部署**：将 `v4/` 内所有文件拷贝到 Surge v4 设备的配置根目录即可。`v4/` 是自包含的：只要配置里有任何内容需要转换，它加载的每个文件都会产出 `-v4` 副本（无需转换的原样复制），引用一律改写为 `-v4` 名。整套配置都无需转换时不产出任何文件。托管配置不会被复制（Surge 刷新会覆盖副本），需要进 `v4/` 时一律放弃并摘除引用。

**限制**：所有被引用文件须与根配置同目录。子目录中的引用文件会在 `<子目录>/v4/` 下产出，而父文件以 bare filename 引用它，部署时需手动合并；不同子目录中的同名文件会互相覆盖。

### 旧文件处理

若输出文件已存在且内容有变化，旧文件先重命名为 `-deprecated` 后缀备份；若同名 `-deprecated` 备份已存在（上次运行选择保留的），会先将其移入回收站再改名，绝不静默覆盖。运行结束后脚本会提示是否删除这些备份（**直接回车默认删除**，仅 `y` / `yes` / 回车视为确认，其余输入一律保留；非交互运行不删除），删除通过回收站（send2trash）执行，可恢复。

## 转换规则

### 代理协议（[Proxy]）

| 规则 | 动作 |
|------|------|
| `hysteria2` / `hy2` | 注释（iOS 5.8.0+） |
| `anytls` | 注释（iOS 5.17.0+） |
| `tuic` | 注释（iOS 5.2.0+） |
| `trust-tunnel` | 注释（Mac 6.4.4+） |
| Snell `version=5` | 替换为 `version=4` |
| Snell `version=6` 及以上 | 注释（v4 无对应版本）；配了旧版实例覆盖的文件改写为 `version=4`，见下文 |
| `shadow-tls-version=3` | 替换为 `shadow-tls-version=2` |
| `port-hopping` / `port-hopping-interval` / `ecn` | 移除参数 |

被注释掉的节点行（`#` / `;` / `//` 开头，可重复、可带空格）在产出的 `-v4` 文件里按上表同样改参数，注释前缀原样保留，取消注释即可在 v4 使用；v5+ 独有协议与 Snell `version=6` 及以上的注释行本已停用，原样保留。去掉前缀后必须是完整的 `名称 = 类型, host, port, key=value...` 才转换，其余注释文字一律原样。注释行不参与「是否需要转换」的判定：只有注释行变化时不产出 `v4/`，也不会因此放弃托管配置。

### Snell 旧版实例覆盖（可选）

Snell v6 server 不兼容 v4 客户端，同一端口也不能同时跑两个版本，所以只改 `version` 得不到能用的 v4 节点。如果服务端另开了一个旧版 snell 实例（独立端口、独立 PSK，可能还有独立 host），可以用覆盖文件告诉转换器怎么连它：

```ini
# 每个 section 名是源配置文件的 basename
[my-vps.dconf]
port = 8444
psk = <legacy-psk>
# server = legacy.example.com
```

- 允许的键只有 `server`、`port`、`psk`，都可选、至少一个，键名区分大小写；`%` 不做插值。未知键、空值、含逗号或换行的值、非数字端口都会报错退出，报错信息不含取值
- 加载顺序：命令行 `--snell-legacy PATH`；未给时若存在 `${XDG_CONFIG_HOME:-~/.config}/surge-config-converter/snell-legacy.ini` 则自动加载；都没有则功能关闭，行为与不支持此功能时完全一致
- 文件含凭证，权限宽于 `0600` 时打印警告。运行日志只出现文件名、节点名、计数和被替换的键名，不出现 server / psk 的值
- 命中 section 的源文件里，未注释的 Snell `version=6` 及以上节点不注释：`version` 改为 `4`，并替换给出的 `server` / `port` / `psk` 字段，其余字段逐字节不变（含空格风格），所在策略组与规则不级联；改写后的行继续走上表的常规转换（如 `shadow-tls-version=3` 降为 `2`）
- 未命中的文件照旧注释并级联；已注释的 v6 节点原样保留；`version=5` 节点照旧只降为 `4`；其他 v5+ 独有协议照旧注释

### 策略组（[Proxy Group]）

| 规则 | 动作 |
|------|------|
| `smart` | 替换为 `url-test` |

### 规则（[Rule]）

| 规则 | 动作 |
|------|------|
| `HOSTNAME-TYPE` | 注释 |
| `DOMAIN-WILDCARD` | 注释 |
| `AND` / `OR` / `NOT` 复合规则内嵌上述类型 | 注释整行 |
| 策略后的 `extended-matching` / `pre-matching` 参数 | 移除参数，规则保留 |

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
- 只要配置里有任何内容需要转换，它实际加载的每个本地文件都产出 `-v4` 副本，无需转换的原样复制；引用一律改写为 `-v4` 名，保证 `v4/` 内没有悬空引用
- 仅被未加载段落提及的文件（如 `policy-path` 导入文件里 `[Proxy]` 以外的引用）不算加载，不产出
- HTTP/HTTPS URL 不处理

### 托管配置（Managed Config）

首个非空行为 `#!MANAGED-CONFIG` 指令的文件是 Surge 托管配置，Surge 会定期从远端刷新覆盖本地内容。如果这类文件需要进 `v4/`——它会因转换产生任何变化（含直接命中与级联清理），或者它被一份需要转换的配置加载（`v4/` 自包含，本应原样复制）：

- **放弃转换**：不生成 `-v4` 副本（否则会被远端刷新自毁）
- **检测过期文件**：若之前运行曾生成过对应的 `-v4` 文件，会在最终摘要中警告（不自动删除，由用户决定）
- **级联清理**：父文件中引用该托管配置的 `#!include` 条目和 `policy-path` 选项会被自动移除

### 级联清理

当某个 proxy 或 proxy group 因 v5+ 转换被注释或因托管配置放弃而消失时，引用它的其他配置行也会被清理：

- **Proxy Group 成员**：从成员列表中移除已删除的名称（含指向已删除 group 的 `include-other-group` 选项）；若 group 因此失去所有有效成员来源（显式成员 / `include-all-proxies` / `include-other-group` / 有效 `policy-path`），整行注释
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
