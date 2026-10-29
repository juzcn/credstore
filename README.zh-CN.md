# credstore

跨平台凭证存储 — 操作系统密钥链 + AES 加密文件备份。

一个独立的密钥管理器。最初从 [Slife](https://github.com/juzcn/slife) 中剥离而来（Slife 以它作为凭据存储），但 credstore **不依赖** Slife。声明四个运行时依赖：`keyring`、`keyrings-cryptfile`、`jaraco.classes` 和 `pywin32-ctypes`（仅 Windows）。

支持 **Windows**、**macOS**（桌面 + 无头）、**Linux**（桌面 + 无头）和 **WSL**（通过 PowerShell 桥接 Windows 凭据管理器）。

## 安装

需要 **Python ≥ 3.13**。

```bash
pip install credstore
# 或在隔离环境中：
uv tool install --force --python '>=3.13' credstore
```

> `--python '>=3.13'` 不是可选项。不加它，`uv` 会用自己偏好的解释器搭工具环境，然后装**该 Python 版本能装的最高版本**——在 3.12 上就是早已过时的 0.9.0，而不是当前版本。加上约束后，uv 会去取合适的解释器，取不到就明确报错。

一键安装脚本（必要时先装 `uv`，再 `uv tool install --force --python '>=3.13' credstore`）：

```bash
# macOS / Linux / WSL
curl -fsSL https://raw.githubusercontent.com/juzcn/credstore/main/install.sh | bash

# Windows PowerShell
powershell -ExecutionPolicy Bypass -Command "irm https://raw.githubusercontent.com/juzcn/credstore/main/install.ps1 | iex"
```

安装脚本和 `--force` 形式都是**幂等**的——首次运行安装，重跑即**更新**到
PyPI 最新版。不带 `--force` 的 `uv tool install credstore` 在工具已安装时
是空操作。卸载用 `uninstall.sh` / `uninstall.ps1`（`~/.credstore/` 下的用户
数据会保留）。

验证：`credstore status`

无需配置。运行 `credstore set-password` 以启用加密备份。

## CLI

所有密钥输入均使用脱敏输入——每次按键回显 `*`，支持粘贴，实际值从不显示、不落日志。

> **需要交互式终端。** 除 `status`、`remove` 和 `uninject` 外，所有命令都要求交互式 TTY（`@requires_tty`）；请在真实终端中运行，而不是管道或 CI 步骤。`remove` 可在无终端环境运行：主存储副本照样删除，只有备份清理需要终端（见注²）。

### 初始化

```bash
credstore set-password    # 创建 ~/.credstore/credentials.crypt（或修改主密码）
```

路径可通过 `CREDSTORE_FILE` 环境变量覆盖。

修改主密码会写入一个**新**文件，并把旧文件移为 `credentials.crypt.bak`（同目录，同样受
`CREDSTORE_FILE` 覆盖）。保留备份是刻意的：若用新密码重新加密中途失败，它是你唯一的凭据副本，
且仍可用旧密码打开。

### 备份中的 key 名称

key 在两个存储中都是**区分大小写**的。加密文件里则不然：`keyrings.cryptfile` 会把 key 转义成 INI
选项名，configparser 又把该名称折叠为小写（`gh/cli-token` → `gh_2fcli_2dtoken`），而原始大小写被
绑进该条目的 AEAD 关联数据。因此文件本身无法区分 `myapp/api_key` 与 `MYAPP/API_KEY`——用错误
的大小写读取会 MAC 校验失败，而不会返回错误的密钥。读取备份时会尝试所有可能产生该选项名的写法：

- `reset-keyring` 与 `set-password`（改密码）在平台支持枚举时（Windows、WSL——这也是唯一能还原
  `myApp/ApiKey` 这类混合大小写 key 的来源）向系统密钥链查询每个条目的原始写法；macOS 与 Linux
  上则依次尝试还原名的大写与小写形式。
- 任何写法都无法解密的条目会被**明确报告**，而不是静默丢弃。请用 `credstore set KEY` 按它当初
  存储时的大小写重新写入；若密钥链可枚举，`credstore reset-backup` 也会从密钥链把它重写回备份。
- 在列表中，密钥链里有、但备份无法用该名称读回的凭据会显示为 `MISMATCH ⚠`。

### 命令

| 命令 | 主密码 | 说明 |
|------|--------|------|
| `set-password` | 设置密码 | 创建或修改主密码（≥8 字符） |
| `status` | — | 查看后端状态 |
| `set KEY` | 必需¹ | 原子双写：cryptfile → 主存储（密钥链，或环境变量回退）。主存储失败时回滚 |
| `get KEY` | — | 仅主存储，脱敏输出（`sk-…b722`） |
| `get KEY -p` | 询问 | 双查询主存储 + cryptfile，明文输出。不一致时报错 |
| `remove KEY` | 询问² | 从两个存储中删除（尽力而为） |
| `copy SOURCE DEST` | 必需¹ | 幂等复制（主存储 + cryptfile，两者都已一致才算幂等）。若目标已注入环境变量则自动重新注入 |
| *（无命令）* | 询问³ | 三重读取：主存储 + cryptfile + 环境变量。显示每个 key 的同步状态 |
| `inject KEY… [--shell]` | — ³ | 持久化到系统环境：注册表（Win）或 shell 配置文件（Unix）。读主存储；仅当主存储没有该 key 时才回退读取备份（询问主密码） |
| `uninject KEY… [--shell]` | — | 从系统环境中移除（回退模式下同时从环境存储中移除） |
| `reset-keyring` | 询问 | 从 cryptfile 恢复全部 → 系统密钥链（灾难恢复） |
| `reset-env` | 询问 | 从 cryptfile 恢复全部 → 环境变量回退（无密钥链时） |
| `reset-backup` | 必需¹ | 同步主存储 → cryptfile |

¹ `set`、`copy` 和 `reset-backup` 前置门控——主密码未设置前（`credstore set-password`）拒绝运行。
² `remove` 会询问主密码以清理 cryptfile 副本；主存储副本无论如何都会删除——包括在非交互式 shell 中，此时备份副本会被跳过并给出提示。若尚无备份（未运行过 `set-password`），则不会询问任何密码——没有需要清理的备份。
³ 仅当主存储没有该 key、需要读取备份时才询问主密码。

`--shell` 可选 `auto`（默认）、`bash`、`powershell` 或 `cmd`。

### `get` 模式

| 模式 | 读取来源 | 输出 | 适用场景 |
|------|---------|------|---------|
| `get KEY` | 仅主存储 | 脱敏 | 快速检查，可安全投屏 |
| `get KEY -p` | 主存储 + cryptfile | 明文 | 验证一致性，管道传递给其他工具 |

`-p` 模式执行双查询一致性校验：

- 两个存储都有且一致 → 打印明文
- 一个存储缺失 → 报错并给出恢复指令（环境回退模式下，若环境副本缺失则打印备份中的值，旧的 cryptfile-only 工作流不受影响）
- 值不一致 → 报错，告知应执行哪个命令

**环境变量回退**（无可用系统密钥链——例如 Linux 上 keyctl 被安全策略屏蔽）：环境变量取代密钥链成为主存储。`set`/`copy` 双写环境与 AES cryptfile；`get KEY`、`inject` 和 Python API 直接读环境，**无需主密码**；`status` 显示 "environment fallback"。只有解锁加密备份（`get -p`、`reset-env`、`remove` 的备份清理）才需要主密码。

| 平台 | 环境持久化方式 |
|------|---------------|
| Windows | `HKCU\Environment`（即 `inject` 使用的注册表存储），外加当前进程环境 |
| Unix | `~/.credstore/env`（权限 0600，可用 `CREDSTORE_ENV_FILE` 覆盖），由 `~/.bashrc` source，外加当前进程环境 |

合法的环境变量名（如 `DEEPSEEK_API_KEY`）直接作为变量名存储，子进程可读取；其它 key（如 `myapp/provider/deepseek`）存储在 `CREDSTORE_KEY_` 前缀加可逆转义之下（`/` → `_2F`，`_` → `__`）。以 `CREDSTORE_` 开头的 key 一律转义，因此凭据永远不会覆盖 credstore 自己的 `CREDSTORE_FILE` / `CREDSTORE_KEYCHAIN` 配置。读取优先使用当前进程环境：容器运行时、CI 或父 shell 提供的值优先于持久化副本。

> ⚠️ **明文落盘。** 与密钥链不同，环境变量不加密。cryptfile 仍是加密副本；回退模式用静态机密性换取免密码读取。回退生效时 `credstore status` 会给出警告。

> **Python API 在回退模式下可用。** `get_credential`、`exists_credential` 和 `resolve_uri` 直接读取环境回退、不会弹窗，因此无密钥链时免密码启动解析依旧可用。只有加密备份对它们不可读：主存储没有副本时返回 `None` / 抛 `KeyError`；读取备份本身仍需要 CLI 和主密码。

### `inject` / `uninject`

`inject` 从主存储（密钥链，或环境变量回退）读取密钥并持久化到系统环境：

| 平台 | 持久化方式 | 激活 |
|------|----------|------|
| Windows | 注册表（`HKCU\Environment`）+ 广播 | 重启 shell，或 `Invoke-Expression (credstore inject KEY)` |
| Unix | Shell 配置文件（`~/.bashrc`） | 新 shell，或 `eval "$(credstore inject KEY)"` |

当 stdout 是终端时，`inject` 打印激活提示而非密钥本身。实际的导出命令仅通过管道输出。

```bash
eval "$(credstore inject DEEPSEEK_API_KEY)"           # Bash/Zsh — 立即激活
Invoke-Expression (credstore inject DEEPSEEK_API_KEY)  # PowerShell — 立即激活
```

`uninject` 执行反向操作——从注册表或配置文件中移除，并打印 unset 命令。环境回退模式下它同时从环境存储中删除该变量（主副本）；加密备份仍可由 `reset-env` 恢复。

### 默认（无命令）输出

```
  KEY                  SYSTEM KEYRING   CRYPTFILE        ENV    STATUS
  ────────             ──────────────   ──────────────   ────   ──────
  ANTHROPIC_API_KEY    ✔                ✔                —      synced
  DEEPSEEK_API_KEY     ✔                ✔                ✔      synced
  OPENAI_API_KEY       —                ✔                —      cryptfile only
  ────────             ──────────────   ──────────────   ────   ──────
  3 credential(s) — synced: 2, cryptfile only: 1, env: 1
```

| 列 | 含义 |
|----|------|
| `SYSTEM KEYRING` | ✔ = 已存入 OS 密钥链；`?` = 本平台无法枚举密钥链 |
| `CRYPTFILE` | ✔ = 已存入加密备份 |
| `ENV` | ✔ = 当前已设为环境变量 |
| `STATUS` | `synced`（已同步）、`keyring only`、`cryptfile only`、`MISMATCH ⚠`（不一致）或 `in backup`（密钥链为 `?`，无法比对） |

在**环境回退**模式下，第一列改标为 `ENV FALLBACK`，列出环境中的副本；状态与提示也改为针对环境存储。

> 在 **macOS** 和 **Linux** 上系统密钥链完全无法枚举（无列表 API），因此该列显示 `?`、每行状态为 `in backup`，并且不给出逐 key 的同步结论与提示——在这些平台上无法确认密钥链里是否有该凭据。key 名称显示为规范形式（大写），因为文件不保留原始大小写（见[备份中的 key 名称](#备份中的-key-名称)）。只有 **Windows** 和 **WSL** 会直接枚举凭据管理器。

## 内存安全

密钥是不可变的 Python `str` 对象——无法原地归零。缓解措施：

1. **绝不批量加载** — `list` 仅收集 key 名称。同步比对时逐个取值并立即 `del`。
2. **优先存在性检查** — `exists_credential()` / `list_credential_keys()` 从不返回密钥内容。
3. **显式清理** — 每个 CLI 处理器在所有退出路径（含错误分支）上 `del` 密钥引用。

| 操作 | 清理方式 |
|------|---------|
| `get` / `get_credential()` | 调用者必须 `del` 返回值 |
| `set` | 双写后 `del secret` + `del master_pw` |
| `copy` | 同 `set`。幂等：目标值相同时跳过。若目标已持久化到环境则自动重新注入 |
| `list` | 逐个取值、比对、立即 `del` |
| `inject` | 取值 → 持久化 → `del`。TTY 模式：stdout 无密钥内容 |
| `reset-keyring` | 写入系统密钥链后逐个 `del` |
| `reset-env` | 写入环境存储后逐个 `del` |
| `reset-backup` | 密钥链路径必须批量加载；环境路径逐个读取 |

`masked_input()` 每次按键回显 `*`——支持粘贴，实际值从不显示。

## Python API

```python
import credstore

# 读取 / 检查 / 删除（仅主存储，无需交互）
credstore.get_credential("myapp/api_key")      # → str | None
credstore.exists_credential("myapp/api_key")   # → bool  （绝不返回密钥值）
credstore.list_credential_keys()               # → list[str]  （绝不返回密钥值）
credstore.set_credential("myapp/api_key", "sk-…")
credstore.delete_credential("myapp/api_key")   # → bool

# keyring: URI 解析
credstore.is_keyring_uri("keyring:myapp/k")    # → True
credstore.resolve_uri("keyring:myapp/k")       # → 密钥值（找不到抛 KeyError）
credstore.parse_keyring_uri("keyring:srv/k")   # → ("srv", "k") | None

# Shell 格式化
credstore.format_export("KEY", "secret", "bash")   # → "export KEY='secret'"
credstore.format_unset("KEY", "bash")              # → "unset KEY"

# 环境持久化（`inject` / `uninject` 的编程形式）
credstore.persist_key("KEY", "secret", "bash")     # 注册表（Win）/ 配置文件（Unix）
credstore.unpersist_key("KEY", "bash")             # 从系统环境移除

# 诊断
credstore.init_store()              # → CredentialStore（显式懒初始化）
credstore.check_backend()           # → {"available": True, "backend": "…", …}
credstore.get_backend_name()        # → "system keyring + cryptfile (dual-write)"
```

**Python API 仅操作主存储**——无需主密码，无需交互。主存储即系统密钥链；无可用密钥链时是环境变量回退（此时读写都不需要主密码）。双写（主存储 + cryptfile）由 CLI 层处理。有两点值得注意：

- `set_credential()` 只写主存储，但仍**要求主密码已设置**（运行过一次 `credstore set-password`——cryptfile 必须存在），否则抛出 `RuntimeError`。这是刻意的：绝不让密钥只存在于主存储而没有加密备份（用于抵御 OS 密码变更）。它从不弹窗。
- `get_credential()` 和 `resolve_uri()` 在主存储没有副本时返回 `None` / 抛 `KeyError`——API 从不解锁 cryptfile。只有 CLI 能读加密备份，且需要主密码。

`get_credential()` 和 `resolve_uri()` 的调用者必须在用完后 `del` 返回值。仅需判断是否存在时，优先使用 `exists_credential()`。`reset_credentials()`（对应 `reset-keyring`）和 `reset_environment_credentials()`（对应 `reset-env`）仅供 CLI 内部使用，不属于公开包 API。

## 配置

加密凭据文件路径按以下优先级解析：

1. `CREDSTORE_FILE=<path>`（环境变量）
2. `~/.credstore/credentials.crypt`（默认值）

环境变量回退（仅在无系统密钥链时使用）的明文文件另行解析：

1. `CREDSTORE_ENV_FILE=<path>`（环境变量）
2. `~/.credstore/env`（默认值；权限 0600，由 `~/.bashrc` source）

解析与当前目录无关，credstore 自己的源码树也不例外：系统 keyring 在源码检出和生产安装之间是共享的，
放在检出目录里的 cryptfile 只是把备份分叉了，并没有隔离任何东西。

## 架构

### 后端矩阵

后端选择**按平台确定性分发**——不依赖 keyring 的自动发现。仅支持以下五种平台配置，其它平台直接报清晰错误。

| 平台 | 后端 | 机制 |
|------|------|------|
| **Windows** | `WinVaultKeyring` | Windows 凭据管理器（Vault API，由 keyring 提供） |
| **WSL** | `WslBackend` | PowerShell → advapi32.dll CredReadW/CredWriteW（C# P/Invoke）——与 Windows 共享同一 CredMan 存储 |
| **macOS**（GUI） | `macOS.Keyring` | macOS 登录钥匙串 |
| **macOS**（无头） | `macOS.Keyring` + 隔离钥匙串 | `CREDSTORE_KEYCHAIN`（或 `~/.credstore/credentials.keychain-db`）；首次使用时自动通过 `security create-keychain` 创建 |
| **Linux** | `KeyutilsBackend` | 内核持久化 keyring（`@p`），通过 `add_key`/`keyctl` 系统调用（ctypes，零额外依赖） |

`WslBackend`（优先级 9.5）和 `KeyutilsBackend`（优先级 1.5）也注册为标准 `keyring.backends` 入口点，因此对外部消费方会正确参与 keyring 自身的优先级链——但 credstore 自身的分发是直接选定它们，从不靠发现。

### 双写流程

```
┌──────────────────────────────────────────────────┐
│  CLI (__main__.py)                               │
│  交互式：masked_input()、主密码                   │
│  原子双写：cryptfile → 主存储                     │
│  主存储失败时回滚                                  │
├──────────────────────────────────────────────────┤
│  Python API (__init__.py)                        │
│  程序化调用：无需交互、仅主存储                   │
├────────────────────┬─────────────────────────────┤
│  主存储             │  加密文件备份                │
│  密钥链或环境变量    │  （加密）                    │
│  ────────────────  │  ───────────────────────    │
│  Win 凭据管理器     │  keyrings.cryptfile         │
│  WSL（PowerShell） │  AES 加密 INI 文件           │
│  macOS 钥匙串      │  OS 密码变更不受影响          │
│  Linux keyutils    │                             │
│  环境变量 *        │                             │
└────────────────────┴─────────────────────────────┘

* 环境变量回退：仅在无可用密钥链后端时使用。
```

### WSL 后端

在 WSL 上，没有可用的 Linux 桌面密钥链。`WslBackend` 通过调用 `powershell.exe` 并嵌入 C# 代码 P/Invoke `advapi32.dll`（`CredReadW`、`CredWriteW`、`CredDeleteW`）来桥接 Windows 凭据管理器。由于直接对接 CredMan，WSL 与原生 Windows 共享同一凭据存储——任一侧 `credstore set` 的数据另一侧都能读到。它还能读取原生 Windows 布局（`TargetName = service`，key 在 `UserName` 字段），使 `WinVaultKeyring` 写入的凭据在 WSL 上也能正确解析。与平台自动发现不同，`WslBackend` 被确定性地选中（无优先级竞争）。

### Keyutils 后端

在 Linux（无论桌面还是无头）上，`KeyutilsBackend` 将凭据存储在内核的持久化 keyring（`@p`）中。通过 `ctypes` 直接调用 `add_key` 和 `keyctl` 系统调用——标准库外零 Python 依赖。每个凭据是一个 `"user"` 键，描述为 `"credstore:<service>/<key>"`。系统调用号按架构硬编码——`x86_64`、`i686`、`aarch64`、`armv7l`、`ppc64le`、`s390x`、`riscv64`——均取自内核自身的系统调用表；不在该列表中的机器会被拒绝，而不是猜一个号。若内核 keyring 不可用（例如 HPC 登录节点上 seccomp 屏蔽了 keyctl），credstore 降级为**环境变量回退模式**：`set` 双写环境与 AES 备份，`get`/`inject`/Python API 免主密码读取环境，`get -p`/`set-password`/`status`/`remove` 照常工作，原因可通过 `credstore status` 查看。完全不支持的平台仍然报错，而不是错误选择后端。

### 环境变量回退

当受支持的平台没有可用的密钥链后端时（Linux 的 keyctl 被屏蔽、Windows 凭据管理器不可达）启用。`_envstore.py` 让环境变量承担密钥链的角色：

- `set` 双写：先写加密备份，再写环境；环境写入失败会像密钥链写入失败一样回滚备份条目。
- `get`、`inject`、`get_credential()`/`resolve_uri()` 读取环境，从不弹窗。`get -p` 仍会比较环境副本与备份并报告漂移。
- 无密钥链时 `reset-keyring` 会拒绝并提示 `reset-env`，由它从备份恢复到环境。
- `reset-backup` 把环境同步回加密备份：转义（`CREDSTORE_KEY_*`）条目，加上备份已知的每个 key（大小写不敏感匹配，保留原始写法）。备份未知的裸名变量无法枚举，会报告为跳过。
- Windows 持久化到 `HKCU\Environment`；Unix 持久化到 `~/.credstore/env`（0600，由 `~/.bashrc` source），并直接读取该文件，因此即使非交互进程没有加载 profile 也能工作。
- 读取优先使用当前进程环境，容器运行时或 CI 可以直接提供值，无需 `credstore set`。

环境变量是明文。这是回退模式的刻意取舍；cryptfile 仍是加密副本。

### macOS 后端

macOS 在 GUI 会话中使用 `keyring.backends.macOS.Keyring`（登录钥匙串）。对于无头 macOS（CI、服务器）——登录钥匙串交互失败（`errSecInteractionNotAllowed`）的环境——设置 `CREDSTORE_KEYCHAIN` 指向一个隔离钥匙串路径，或让 credstore 使用 `~/.credstore/credentials.keychain-db`；该文件首次使用时通过 `security create-keychain` 自动创建。

### 凭据枚举

`credstore`（默认、无命令视图）通过平台特定 API 从 OS 凭据存储读取 key：

| 平台 | API |
|------|-----|
| **Windows** | `win32cred.CredEnumerate` |
| **WSL** | `powershell.exe` + 嵌入式 C# `CredEnumerateW` 通过 `advapi32.dll` |
| **其他** | 不支持——列表使用环境变量回退及 cryptfile 中的 key 名称 |

枚举仅获取 key 名称——永远不会批量加载密钥值。在 WSL 上，除非确实需要取值，PowerShell 桥接层根本不会去读取凭据 blob，因此列取操作不会把密钥从凭据管理器里搬出来。同步比对时逐个取值并立即丢弃。

## 开发

需要 [uv](https://docs.astral.sh/uv/)。

```bash
uv sync --locked     # 创建 .venv，安装运行时 + 开发依赖
uv run pytest        # 运行测试
uv run ruff check    # 静态检查
uv run ruff format   # 格式化
uv run pyright       # 类型检查
```

CI 在 Windows、macOS、Linux 上跑测试（`.github/workflows/ci.yml`），另有独立的 lint 和类型检查任务。

### 发版

改 `pyproject.toml` 里的 `version`，提交，然后推一个同名 tag：

```bash
git tag -a v0.10.8 -m "credstore 0.10.8" && git push origin v0.10.8
```

`.github/workflows/publish.yml` 会校验 tag 与包版本完全一致，不一致直接失败；通过后经 trusted publishing 上传到 PyPI。

## 许可证

MIT
