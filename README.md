# GrokSwitch

[![CI](https://github.com/JasonJarvan/GrokSwitch/actions/workflows/ci.yml/badge.svg)](https://github.com/JasonJarvan/GrokSwitch/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/JasonJarvan/GrokSwitch)](https://github.com/JasonJarvan/GrokSwitch/releases/latest)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

GrokSwitch 是一个用于管理和切换 [Grok Build](https://x.ai/cli) 登录账号的命令行工具。设计参考了 [Loongphy/codex-auth](https://github.com/Loongphy/codex-auth)，并针对 Grok Build 官方的 `~/.grok/auth.json`、`GROK_HOME` 与 `GROK_AUTH_PATH` 机制重新实现。

## 功能

- 保存当前 Grok 登录态，并为账号设置别名
- 在隔离认证文件中执行 `grok login`，不会覆盖尚未保存的当前账号
- 通过序号、别名、邮箱、账号 ID 或唯一关键词切换账号
- 列表直接显示每个账号的 Tier 订阅、剩余额度和本地时区重置时间，并在凭据过期或遇 HTTP 401 时自动静默刷新 OIDC token
- 支持 `grok-switch refresh`（别名 `refresh-tokens`）显式刷新单个或全部已保存账号的 OIDC token，便于定时保活或手动续期
- 一条命令切回上一个账号
- 导入已有 `auth.json`，或将 CLIProxyAPI（CPA）的 xAI OAuth JSON 转换为 Grok 格式
- 用指定账号单独启动 Grok，多个账号可并行运行
- JSON 输出，便于脚本集成

## 安装

需要 Go 1.23 或更高版本。

直接安装最新版：

```bash
go install github.com/JasonJarvan/GrokSwitch/cmd/grok-switch@latest
```

二进制会进入 `GOBIN`；未设置时通常是 `$(go env GOPATH)/bin`。也可以从 [GitHub Releases](https://github.com/JasonJarvan/GrokSwitch/releases/latest) 下载对应系统和架构的压缩包。

从源码构建：

```bash
git clone https://github.com/JasonJarvan/GrokSwitch.git
cd GrokSwitch
make install

# 或只构建当前平台
make build
./bin/grok-switch version
```

Grok Build 本身需要提前安装：

```bash
curl -fsSL https://x.ai/cli/install.sh | bash
grok --version
```

## 快速开始

如果现在已经登录了一个 Grok 账号，先保存它：

```bash
grok-switch save --alias personal
```

添加第二个账号。登录在隔离文件中进行，成功后新账号会自动成为当前账号：

```bash
grok-switch login --alias work
# 无浏览器的机器：
grok-switch login --alias server --device-auth
```

查看和切换：

```bash
grok-switch list
grok-switch switch personal
grok-switch switch 02
grok-switch previous
```

`grok-switch list` 默认并发查询 Grok 官方的账号订阅与 `/usage` 额度接口，显示 Tier、剩余额度百分比和本地时区重置时间；若某个已保存账号的 access token 已过期（或接近过期）或接口返回 HTTP 401，会自动使用该账号快照中的 `refresh_token` 向 `https://auth.x.ai/oauth2/token` 静默续期并回写快照。断网或只想查看本地账号时可执行 `grok-switch list --offline`。

也可以显式刷新 token（不会切换全局账号，且遵循 `auth.json.lock` 避免干扰正在运行的 Grok 会话）：

```bash
grok-switch refresh                 # 刷新全部过期或即将过期的账号
grok-switch refresh work            # 刷新指定账号
grok-switch refresh --all --force   # 强制刷新全部账号
grok-switch refresh --all --json    # JSON 输出（不含任何 token）
```

示例：

```text
   #   ALIAS     EMAIL                 TIER      QUOTA LEFT  RESETS AT
*  01  personal  owner@example.com     GrokPro   78%         08-15 16:23
   02  work      engineer@example.com  XPremium  31%         08-14 03:00
```

`*` 表示当前全局账号；重置时间按本机时区显示。接口不可用时，相应字段显示 `unknown`，不会影响本地列出或切换账号。

导入 CPA 的 xAI 账号文件（与参考项目一样使用显式 `--cpa`）：

```bash
grok-switch import --cpa /path/to/xai-account.json --alias backup
```

GrokSwitch 会把 CPA 文件转换成 Grok 使用的 `auth.json` 格式并加入账号列表。源文件带有 `disabled` 标记或登录态已经过期时，命令会给出提示。导入不会修改或删除 CPA 源文件。

全局切换会更新 Grok 当前使用的 `auth.json`。切换前请退出普通 Grok 会话；旧会话继续运行时可能再次写回原账号。切换完成后再启动新的 Grok 会话。

## 隔离运行

如果希望同时运行多个账号，不必反复改全局账号。假设 `personal` 已是全局当前账号，直接运行 `grok`；另一个非当前账号通过 GrokSwitch 启动：

```bash
grok                         # 当前 personal 账号
grok-switch run work -- --model grok-4.5
```

`run` 仅接受非全局当前账号，并会为子进程设置 `GROK_AUTH_PATH`，直接使用该账号自己的认证文件。运行中的账号变化会写回对应快照，不会覆盖全局 `~/.grok/auth.json`。子进程中的 `GROK_AUTH`、`XAI_API_KEY` 和旧版 `GROK_CODE_XAI_API_KEY` 会被移除；父 shell 不受影响。

同一个账号一次只能有一个 `grok-switch run` 进程，不同账号可以并行。进程运行期间不能切换、重新导入或删除正在使用的账号。

## 命令

| 命令 | 作用 |
| --- | --- |
| `grok-switch list [--json] [--offline]` | 列出账号、Tier、实时剩余额度和重置时间 |
| `grok-switch status [--json]` | 显示当前账号、上一个账号和存储路径 |
| `grok-switch save [--alias NAME]` | 保存或更新当前 Grok 登录态 |
| `grok-switch login [--alias NAME] [--device-auth]` | 隔离登录并激活账号 |
| `grok-switch import FILE [--alias NAME] [--switch]` | 导入 Grok `auth.json`；默认不切换 |
| `grok-switch import --cpa FILE [--alias NAME] [--switch]` | 导入 CPA xAI OAuth JSON，并在内存中转换 |
| `grok-switch switch [QUERY]` | 切换账号；省略查询时显示交互选择 |
| `grok-switch previous` | 切回上一个账号 |
| `grok-switch alias QUERY NAME` | 修改账号别名 |
| `grok-switch remove QUERY` | 删除账号；若为当前账号则自动选择回退账号 |
| `grok-switch refresh [QUERY\|--all] [--force] [--json]` | 刷新已保存账号的 xAI OIDC token（别名 `refresh-tokens`） |
| `grok-switch run QUERY [-- GROK_ARGS]` | 用指定账号启动隔离的 Grok 进程 |
| `grok-switch doctor [--json]` | 检查安装、路径、凭据格式和快照完整性 |

`QUERY` 支持：列表序号、完整别名、邮箱、账号 ID/前缀，以及能唯一匹配的名称片段。

## 文件位置

默认布局：

```text
~/.grok/
├── auth.json                     # Grok 全局当前账号
├── auth.json.lock                # Grok 官方锁文件
└── accounts/
    ├── registry.json             # 账号列表与别名
    ├── .grok-switch.lock
    ├── acc_<id>/
    │   ├── auth.json             # 该账号完整认证快照
    │   └── auth.json.lock
    └── acc_<id>/
        └── auth.json
```

可用环境变量：

- `GROK_HOME`：覆盖 Grok 主目录，默认 `~/.grok`
- `GROK_AUTH_PATH`：覆盖全局当前认证文件，GrokSwitch 与 Grok 都会遵循
- `GROK_SWITCH_HOME`：覆盖账号仓库，默认 `$GROK_HOME/accounts`
- `GROK_SWITCH_GROK_BIN`：覆盖 `grok` 可执行文件路径

如果设置了内联 `GROK_AUTH`，它的优先级高于文件认证，GrokSwitch 会拒绝全局切换并提示先取消该变量。

版本变化见 [CHANGELOG.md](CHANGELOG.md)。

## 开发

```bash
make check       # gofmt 检查、go vet、测试
make test-race   # 带 race detector 的核心测试
make build       # 构建当前平台二进制
```

测试全部使用临时 `GROK_HOME` 和测试账号数据，不读取或修改真实的 `~/.grok/auth.json`。

## 兼容性

目标平台为 macOS、Linux 和 Windows 的 amd64/arm64。当前实现依据 Grok Build 公开的 `auth.json` 结构，并接受未知字段。建议升级 Grok Build 后运行一次：

```bash
grok-switch doctor
```

本项目与 xAI 或 Grok 无隶属关系。
