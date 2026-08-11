# GrokSwitch

[![CI](https://github.com/bbbkawaii/GrokSwitch/actions/workflows/ci.yml/badge.svg)](https://github.com/bbbkawaii/GrokSwitch/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/bbbkawaii/GrokSwitch)](https://github.com/bbbkawaii/GrokSwitch/releases/latest)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

GrokSwitch 是一个用于管理和切换 [Grok Build](https://x.ai/cli) 登录账号的命令行工具。设计参考了 [Loongphy/codex-auth](https://github.com/Loongphy/codex-auth)，并针对 Grok Build 官方的 `~/.grok/auth.json`、`GROK_HOME` 与 `GROK_AUTH_PATH` 机制重新实现。

它不会请求第三方账号接口，也不会把令牌打印到终端。所有切换都在本机完成。

## 功能

- 保存当前 Grok 登录态，并为账号设置别名
- 在隔离认证文件中执行 `grok login`，不会覆盖尚未保存的当前账号
- 通过序号、别名、邮箱、账号 ID 或唯一关键词切换账号
- 列表直接显示每个账号的 Tier 订阅、剩余额度和本地时区重置时间
- 一条命令切回上一个账号
- 导入已有 `auth.json`，或将 CLIProxyAPI（CPA）的 xAI OAuth JSON 转换为 Grok 格式
- 用指定账号单独启动 Grok，多个账号可并行运行
- JSON 输出，便于脚本集成
- 原子写入、私有文件权限，以及与 Grok Build 兼容的 `auth.json.lock`

## 安装

需要 Go 1.23 或更高版本。

直接安装最新版：

```bash
go install github.com/bbbkawaii/GrokSwitch/cmd/grok-switch@latest
```

二进制会进入 `GOBIN`；未设置时通常是 `$(go env GOPATH)/bin`。也可以从 [GitHub Releases](https://github.com/bbbkawaii/GrokSwitch/releases/latest) 下载对应系统和架构的压缩包。

从源码构建：

```bash
git clone https://github.com/bbbkawaii/GrokSwitch.git
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

`grok-switch list` 默认并发查询 Grok 官方的账号订阅与 `/usage` 额度接口，显示 Tier、剩余额度百分比和本地时区重置时间。断网或只想查看本地账号时可执行 `grok-switch list --offline`。

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

转换全程在本机内存中完成：GrokSwitch 会交叉校验两个 JWT 的签发方、账号、客户端 ID 和时间，再只保存 Grok Build 所需的 `auth.json` 快照。CPA 的 `disabled` 标记不会直接判定令牌失效，但命令会显示警告；是否可用最终以 Grok 向 xAI 验证令牌或刷新令牌的结果为准。

导入不会修改或删除 CPA 源文件。账号仓库中的新快照会设为私有权限；源文件仍应由你自行限制访问，例如在 macOS/Linux 上执行 `chmod 600 /path/to/xai-account.json`。

全局切换会更新 Grok 当前使用的 `auth.json`。执行 `switch`、`previous`、会激活账号的 `login/import` 或删除当前账号前，请先退出所有普通 Grok 会话；旧进程仍可能持有旧账号的内存刷新令牌，继续运行会把文件切回旧凭据。切换完成后再启动新的 Grok 会话。

## 隔离运行

如果希望同时运行多个账号，不必反复改全局账号。假设 `personal` 已是全局当前账号，直接运行 `grok`；另一个非当前账号通过 GrokSwitch 启动：

```bash
grok                         # 当前 personal 账号
grok-switch run work -- --model grok-4.5
```

`run` 仅接受非全局当前账号，并会为子进程设置 `GROK_AUTH_PATH`，直接指向该账号自己的私有认证文件。Grok 刷新令牌时会更新这个账号快照，不会覆盖全局 `~/.grok/auth.json`。为了保证选择的账号生效，子进程中的 `GROK_AUTH`、`XAI_API_KEY` 和旧版 `GROK_CODE_XAI_API_KEY` 会被移除；父 shell 不受影响。

同一个账号一次只能有一个 `grok-switch run` 进程，不同账号可以并行。进程运行期间，GrokSwitch 会拒绝全局切换、重新导入或删除该账号，从而避免两个认证文件同时轮换同一刷新令牌。

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
    ├── registry.json             # 仅包含非令牌元数据
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

## 安全设计

- Unix 上账号目录为 `0700`，凭据与注册表为 `0600`
- 令牌文件使用同目录临时文件、`fsync` 和重命名进行原子发布
- 切换与删除会取得 Grok Build 使用的 `auth.json.lock` 排他锁，避免撞上令牌刷新
- 切换前会再次在锁内保存当前认证，减少刷新令牌轮换造成的丢失风险
- `run` 持有账号级会话租约，阻止运行中账号被复制、覆盖或删除
- 注册表只记录邮箱、显示名称、团队、认证方式和过期时间等元数据
- Tier 与实时额度只请求 Grok Build 官方使用的 `cli-chat-proxy.grok.com`，访问令牌仅放在请求头中，不写入输出或缓存
- 解析时保留完整原始 JSON，因此 Grok 后续新增字段不会被旧版 GrokSwitch 删掉

认证快照本质上仍是可登录凭据。不要把 `~/.grok/accounts` 上传到 Git、网盘、工单或聊天中；建议启用 FileVault、BitLocker 或 LUKS。

发现安全问题时请按 [SECURITY.md](SECURITY.md) 私下报告，切勿附带真实认证文件或令牌。

版本变化见 [CHANGELOG.md](CHANGELOG.md)。

`auth.json.lock` 只覆盖 Grok 实际刷新令牌的短暂窗口，并不代表整个 Grok 会话都已退出。因此全局账号切换仍要求先关闭普通 Grok 进程；由 `grok-switch run` 启动的隔离进程则由会话租约自动保护。

## 开发

```bash
make check       # gofmt 检查、go vet、测试
make test-race   # 带 race detector 的核心测试
make build       # 构建当前平台二进制
```

测试全部使用隔离的临时 `GROK_HOME` 和伪造令牌，不读取或修改真实的 `~/.grok/auth.json`。

## 兼容性

目标平台为 macOS、Linux 和 Windows 的 amd64/arm64。当前实现依据 Grok Build 公开的 `auth.json` 结构，并接受未知字段。建议升级 Grok Build 后运行一次：

```bash
grok-switch doctor
```

本项目与 xAI 或 Grok 无隶属关系。
