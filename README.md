# Surge Config Converter (v5+ → v4)

将 Surge v5+ / v6 配置文件转换为 v4 兼容格式。自动识别并处理 v5+ / v6 独有的协议、参数、段落和规则语法，按 Surge 的段落隔离语义递归处理 `#!include` 与 `policy-path` 引用的本地文件，并跨文件级联清理因转换产生的悬空引用。

## 环境要求

- Python ≥ 3.9
- 依赖安装：

```bash
pip3 install -r requirements.txt   # 运行只需 send2trash，测试另需 pytest
```

## 使用

```bash
python3 converter.py [--snell-legacy PATH] [-o DIR] <config_file_path>
```

- `--snell-legacy PATH`：可选，见下文「Snell 旧版实例覆盖」。
- `-o DIR` / `--output-dir DIR`：可选，指定输出目录（默认写入源文件旁的 `v4/` 子目录）。

示例：

```bash
python3 converter.py ~/Library/Mobile\ Documents/iCloud~com~nssurge~inc/Documents/profile.conf
```

### 输出布局

所有生成的 `-v4` 文件按严格的 1-to-1 映射写入输出目录（默认是源文件旁的 `v4/` 子目录）：

```
Documents/
├── profile.conf              ← 源文件 (v5+/v6)
├── work-vps.dconf
└── v4/
    ├── profile-v4.conf       ← 转换产物 (v4)
    └── work-vps-v4.dconf
```

输出目录内的文件互相引用时使用 bare filename（如 `#!include work-vps-v4.dconf`），无目录前缀。

**部署**：将输出目录内所有文件拷贝到 Surge v4 设备的配置根目录即可。输出目录面向单个根配置是自包含的：只要加载到的内容有任何变化，它实际加载的每个本地文件都会产出 `-v4` 副本（无需转换的原样复制），引用一律改写为 `-v4` 名；整套配置都无需转换时不产出任何文件。托管配置不会被复制（Surge 刷新会覆盖副本），需要进输出目录时一律放弃并摘除引用。

**多主配置隔离（单根配置约定）**：默认 `v4/` 面向单套根配置，采用 1-to-1 扁平命名。若同一源目录下有多套主配置共用同一个子文件，且在不同主配置下转换结果不同（例如不同的 `--snell-legacy` 或不同的级联上下文），请用 `-o / --output-dir` 为每套主配置指定独立输出目录：

```bash
python3 converter.py -o /tmp/v4-profile-a profile-a.conf
python3 converter.py -o /tmp/v4-profile-b profile-b.conf
```

**预写校验**：正式写盘前会先校验所有计划输出路径与 `-deprecated` 备份路径。若同一次转换中有多个源文件映射到同一输出文件名，或输出/备份文件名超出目标文件系统长度限制，会直接报错并中止，不写入不完整的部分结果。

### 旧文件处理

若输出文件已存在且内容有变化，旧文件先重命名为 `-deprecated` 后缀备份；若同名 `-deprecated` 备份已存在（上次运行选择保留的），会先将其移入回收站再改名，绝不静默覆盖。运行结束后脚本会提示是否删除这些备份（**直接回车默认删除**，仅 `y` / `yes` / 回车视为确认，其余输入一律保留；非交互运行不删除），删除通过回收站（send2trash）执行，可恢复。

## 转换规则

### 代理协议（`[Proxy]`）

| 规则 | 动作 |
|------|------|
| `hysteria2` / `hy2` | 注释（iOS 5.8.0+） |
| `anytls` | 注释（iOS 5.17.0+） |
| `tuic` / `tuic-v5` | 注释（iOS 5.2.0+ / Mac 6.x） |
| `trust-tunnel` | 注释（Mac 6.4.4+） |
| `tailscale` | 注释（v6+） |
| `vless` / `masque` / `h2-connect` | 注释（v5+ / v6+） |
| Snell `version=5` | 替换为 `version=4` |
| Snell `version=6` 及以上 | 注释（v4 无对应版本）；配了旧版实例覆盖的文件改写为 `version=4`，见下文 |
| `shadow-tls-version=3` | 替换为 `shadow-tls-version=2` |
| `port-hopping` / `port-hopping-interval` / `ecn` / `block-quic` | 移除参数（感知引号与行尾注释，不误伤密码或注释内容） |

被注释掉的节点行（`#` / `;` / `//` 开头，可重复、可带空格）在产出的 `-v4` 文件里按上表同样改参数，注释前缀原样保留，取消注释即可在 v4 使用；v5+ 独有协议与 Snell `version=6` 及以上的注释行本已停用，原样保留。去掉前缀后必须是完整的 `名称 = 类型, host, port, key=value...` 才转换，其余注释文字一律原样。注释行不参与「是否需要转换」的判定：只有注释行变化时不产出输出，也不会因此放弃托管配置。

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
- 命中 section 的源文件里，未注释的 Snell `version=6` 及以上节点不注释：`version` 改为 `4`，并替换给出的 `server` / `port` / `psk` 字段，其余字段逐字节不变（含空格风格与行尾注释），所在策略组与规则不级联；改写后的行继续走上表的常规转换（如 `shadow-tls-version=3` 降为 `2`）
- 未命中的文件照旧注释并级联；已注释的 v6 节点原样保留；`version=5` 节点照旧只降为 `4`；其他 v5+ 独有协议照旧注释

### 策略组（`[Proxy Group]`）

| 规则 | 动作 |
|------|------|
| `smart` | 替换为 `url-test` |
| `include-other-group` 多组列表与 v5.21+ 转义 | 解析多组列表并按需级联移除已删组；写回 v4 可读语法（无 `\\` 双重转义）；若存活组名含 v4 无法表示的 `"` 或 `,`，中止导出并报错 |

### 规则（`[Rule]`）

| 规则 | 动作 |
|------|------|
| `HOSTNAME-TYPE` / `DOMAIN-WILDCARD` | 注释（含任意深度 `AND` / `OR` / `NOT` 复合规则内嵌） |
| 正极性位置的 `extended-matching` 与任意位置的 `pre-matching` | 移除参数，规则保留（含复合规则子条件） |
| 位于奇数层 `NOT` 作用域内的 `extended-matching` | 注释整行（移除会缩小内层匹配并意外扩大否定规则的匹配面） |

### 通用参数（`[General]`）

| 规则 | 动作 |
|------|------|
| `udp-priority` | 注释 |
| `block-quic` | 注释 |

### 整段与通配段

| 规则 | 动作 |
|------|------|
| `[Port Forwarding]` / `[Body Rewrite]` | 整段注释 |
| `[Tailscale <name>]` / `[Tailscale *]` | 整段注释 |
| `[Ruleset <name>]` / `[Ruleset *]` | 整段注释，并级联注释引用了这些内联规则集的 `RULE-SET` 规则；Surge 内置规则集（`SYSTEM` / `LAN`）与磁盘上已存在的本地规则集文件不受影响 |
| `[WireGuard *]` | 注释通配段；对指向本地非托管文件的 `#!include`，自动展开为 v4 合法的具名 `[WireGuard <name>]` + `#!include`（支持跨多文件拆分与链式通配）；若具名 `[WireGuard <name>]` 含 v6 远端 URL `#!include`，自动剥离远端条目并在缺失必需字段（`private-key`、`self-ip`/`self-ip-v6`、`peer`）时级联注释该段及依赖它的 `wireguard` 节点 |

### 引用文件与段落隔离语义

遵循 Surge 真实的 Detached Profile Section 语义：

- `[S]` 段落下的 `#!include` **仅加载**目标文件中的 `[S]` 段落（不会把目标文件的其他段落隐式混入全局）
- `policy-path` 引用的本地文件仅将其 `[Proxy]` 段落私有导入所属策略组，不进入全局代理命名空间
- 只要实际加载到的段落中有任何内容需要转换，所有实际加载的本地文件都会产出 `-v4` 副本（无需转换的原样复制），引用一律改写为 `-v4` 名
- 仅被未加载段落提及的文件不算加载，不产出
- HTTP/HTTPS URL 不处理（具名 `[WireGuard <name>]` 内的远端 `#!include` 除外，因 v4 不支持而剥离）

### 托管配置（Managed Config）

首个非空行为 `#!MANAGED-CONFIG` 指令的文件是 Surge 托管配置，Surge 会定期从远端刷新覆盖本地内容。如果这类文件需要进输出目录——它会因转换产生任何变化（含直接命中与级联清理），或者它被一份需要转换的配置加载（输出目录自包含，本应原样复制）：

- **放弃转换**：不生成 `-v4` 副本（否则会被远端刷新自毁）
- **检测过期文件**：若之前运行曾生成过对应的 `-v4` 文件，会在最终摘要中警告（不自动删除，由用户决定）
- **级联清理**：父文件中引用该托管配置的 `#!include` 条目和 `policy-path` 选项会被按路径精确移除

### 级联清理与安全护栏

当某个 proxy、proxy group、WireGuard 段落或内联 Ruleset 因 v5+/v6 转换被注释或因托管配置放弃而消失时，引用它的其他配置行也会被清理：

- **Proxy 链路**：`underlying-proxy` 指向已删除的节点或策略组、或 `wireguard` 节点指向已失效的 `[WireGuard <name>]` 段落时，整行注释并继续向上级联
- **Proxy Group**：策略组自身的 `underlying-proxy` 失效时整行注释；普通成员或 `include-other-group` 中已删除的名称会被精确移除；若策略组因此失去所有有效成员来源（显式成员 / `include-all-proxies` / `include-other-group` / 有效 `policy-path`），整行注释
- **Rule 策略与内联规则集**：规则指向已删除的策略，或在顶层/嵌套复合规则中引用了失效的内联 `RULE-SET` 时，整行注释
- **`FINAL` 兜底护栏**：若源配置原本存在有效 `FINAL` 规则，但级联清理导致最终输出没有任何可用的 `FINAL` 规则，会报错并中止导出，避免生成 Surge 拒绝加载的残缺配置
- **`#!include` 与 `policy-path`**：移除指向被放弃文件的条目；若列表清空则整行注释

级联清理会跨文件传播并迭代至稳定（fixpoint），确保不留悬空引用。

## 注释标记

| 标记 | 含义 |
|------|------|
| `# [V5+]` | 直接命中：该行含有 v5+ / v6 独有语法，被转换工具注释 |
| `# [V5+ cascade]` | 级联清理：该行本身合法，但引用了被删除的代理、策略组、WireGuard 段落或内联规则集，因此被注释 |

两种标记均与用户原始注释（`#` 开头但无 `[V5+]` 前缀）区分。

## 测试

```bash
python3 -m pytest test_converter.py -v
```
