# Surge Config Converter (v5+ → v4)

将 Surge v5+ 配置文件转换为 v4 兼容格式。自动识别并处理 v5+ 独有的协议、参数和语法，递归处理 `#!include` 和 `policy-path` 引用的子文件。

## 使用

```bash
python3 converter.py <config_file_path>
```

示例：

```bash
python3 converter.py ~/Library/Mobile\ Documents/iCloud~com~nssurge~inc/Documents/home.conf
```

输出文件在同目录下，文件名加 `-v4` 后缀（如 `home.conf` → `home-v4.conf`）。若输出文件已存在，旧文件会被重命名为 `-deprecated` 后缀（如 `home-v4-deprecated.conf`），每次覆盖。

## 转换规则

### 代理协议（[Proxy]）

| 规则 | 动作 |
|------|------|
| `hysteria2` / `hy2` | 注释（iOS 5.8.0+） |
| `anytls` | 注释（iOS 5.17.0+） |
| `tuic` | 注释（Mac 5.1.1+） |
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

## 注释标记

被转换工具注释的行以 `# [v5+]` 开头，便于与用户原始注释区分。

## 测试

```bash
python3 -m pytest test_converter.py -v
```
