# 放映机 (cinema)

把一段二进制程序的执行过程变成可回放、可定位、可讲述的叙事。

现有 trace 工具（`strace`、各类 viewer）擅长回答"发生了什么"，却很难回答"当时是
什么样子"——某一帧的寄存器、内存、调用栈，以及它与前后帧的关系。放映机的核心能力
只有一句话：**任意一帧都可以瞬间回去看**。

## 能力

- 指令级事件采集：每条指令、寄存器写入、内存写入、系统调用、程序输出、退出，全部记录
- 任意帧 seek：重建某一帧的完整机器状态（寄存器 + 内存 + 输出），不重新执行指令
- 快照索引：间隔几何增长，快照数对数级于事件数，反向单步代价有界
- `.ctrace` 轨迹格式：自包含、FNV-1a 校验、百万级事件量级
- 确定性内核：Stage 1 不含 UI、不含 LLM，所有事件来自真实 Unicorn 执行

## 安装

从 GitHub 下载源码后本地构建（不发布到 PyPI）：

```console
$ git clone https://github.com/TSVMV/cinema.git
$ cd cinema
$ cargo build --release            # 原生引擎（Rust）
$ pip install -e ".[dev]"          # Python 界面（Textual TUI）
```

需要 Python >= 3.11 与 Rust 工具链（stable）。Windows 与 Linux 均可用；原生引擎
通过 abi3 wheel 在 CI 上为用户构建，也可以在本机直接构建。

## 快速开始

```console
$ cinema record hello_static --out hello.ctrace
recorded hello.ctrace (144021 bytes)
```

`hello_static` 是一个静态链接的 x86_64 ELF，内容为输出 `hello, winVpwn`。

## 命令

### record — 采集

```console
$ cinema record <binary> [--out <file>] [--timeout <ms>] [--max-events <n>]
```

- `--out`：把轨迹写入 `.ctrace` 文件；缺省只打印摘要
- `--timeout`：执行预算（毫秒），0 表示不限制
- `--max-events`：最多记录多少事件后停止，0 表示不限制

### info — 轨迹摘要

```console
$ cinema info <trace>
```

输出条目：入口地址、事件数、最终帧号、快照数、初始页数、镜像 SHA-256，以及
退出方式与完整输出。

### trace — 事件列表

```console
$ cinema trace <trace> [--from <n>] [--to <n>] [--only <kinds>] [--limit <n>]
```

- `--from` / `--to`：帧区间（半开区间 `[from, to)`）
- `--only`：按类型过滤，逗号分隔：`insn,reg,mem,syscall,output,exit`
- `--limit`：最多显示多少行

### frame — 单帧状态

```console
$ cinema frame <trace> <frame> [--mem <addr[:len]>]...
```

重建指定帧的完整机器状态：

- 全部寄存器（`rip` 高亮）
- 到目前为止的输出
- dirty page 数
- 产生该帧的事件
- 用 `--mem` 读取任意内存窗口（可重复给出，`0x402000:32` 读 32 字节）

### tui — 交互式回放

```console
$ cinema tui <trace> [--frame <n>]
```

Textual 交互界面。上/下方双栏：事件列表（行号即帧号）与单帧状态面板。

- `方向键` / `PageUp` / `PageDown` / `Home` / `End`：移动
- `g`：跳到指定帧号

### export — HTML 静态导出

```console
$ cinema export <trace> <out.html> [--mem <addr[:len]>]...
```

导出自包含 HTML 报告：不需要任何外部资源，双击即可打开，包含事件列表、寄存器、
输出与可选的任意内存窗口，支持在浏览器内逐帧回放与跳转。

### 所有命令支持

- `--json`：输出机器可读 JSON
- `--no-color`：禁用 ANSI 颜色

## 示例输出

```console
$ cinema info hello.ctrace
                                  recording
entry        0x401000
events       28
final frame  28
snapshots    0
base pages   35
image hash   9ae9dc45854bfb3c1ab7926db1f3739621f60e978a1e2d4f106536267ccc9809
  exit(0)
  output: 'hello, winVpwn\n'

$ cinema trace hello.ctrace --only syscall
                         frames 0-27
#   kind           detail
13  syscall_enter  write (1) 0x1, 0x402000, 0xf, 0x0, 0x0, 0x0
15  syscall_exit   ret = 15
26  syscall_enter  exit (60) 0x0, 0x402000, 0xf, 0x0, 0x0, 0x0

$ cinema frame hello.ctrace 13 --mem 0x402000:32
       frame 13
reg     value
rip     0x40101e
rax     0x1
rsi     0x402000
rdx     0xf
...
output so far: ''
producing event: 0x40101c  2 bytes  0f 05
memory 0x402000: 68 65 6c 6c 6f 2c 20 77 69 6e 56 70 77 6e 0a 00 ...
```

## Python API

```python
from cinema import record, load_ctrace

# 采集
trace = record(open("hello_static", "rb").read())

# 任意帧重建
state = trace.state_at(42)
state.rip()          # 该帧的 rip
state.regs()         # 全部寄存器
state.output()       # 到该帧为止的输出
state.read_memory(0x402000, 16)

# 轨迹落盘与重载
open("hello.ctrace", "wb").write(trace.encode())
reloaded = load_ctrace(open("hello.ctrace", "rb").read())
```

## 状态与路线

- Stage 1：采集与回放内核，已完成
- Stage 2：TUI（Textual）交互界面，已完成
- Stage 3：HTML 静态导出，已完成
- Stage 4：Agent 对话层（受控工具驱动的取证问答），工具层完成

## 边界

内核面向静态 `ET_EXEC` x86_64 镜像与确定性 syscall 集合（`write`、`exit`、
`exit_group`）。文件、网络、信号与动态链接留给后续阶段。Agent 层目前提供受控
工具（无自由 shell）与脚本化决策器，真实 LLM 接入是 Stage 4 的最后一环。

放映机用于授权环境：CTF 题目、教学、以及你自己拥有的软件。被放映的二进制在
Unicorn 沙箱中运行，不触碰宿主文件系统与网络，运行权限不高于宿主进程。

## 开发

```console
$ cargo test --no-default-features
$ cargo clippy --all-targets --no-default-features -- -D warnings
$ cargo fmt --all -- --check
$ pip install -e .
$ pytest --cov=cinema --cov-fail-under=80
$ ruff check src tests
$ mypy src tests
```

## 设计文档

详细的数据结构与算法见 `docs/design.md`。
