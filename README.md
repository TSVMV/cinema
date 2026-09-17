# 放映机 (working name: winvpwn-cinema)

把一段二进制程序的执行过程变成可回放、可定位、可讲述的叙事。

现有 trace 工具（`strace`、各类 viewer）擅长回答"发生了什么"，却很难回答"当时是
什么样子"——某一帧的寄存器、内存、调用栈，以及它与前后帧的关系。放映机的核心能力
只有一句话：**任意一帧都可以瞬间回去看**。

## 状态

- Stage 1：采集与回放内核，已完成
- Stage 2：TUI（Textual）交互界面，已完成
- Stage 3：HTML 静态导出，已完成
- Stage 4：Agent 对话层（受控工具驱动），工具层完成

Stage 1 的能力：

- 指令级事件采集（基于 Unicorn Engine）
- 快照与 dirty page 追踪（间隔几何增长，快照数对数级于事件数）
- 任意帧 seek 与反向单步（事件回放不重新执行指令）
- `.ctrace` 轨迹格式读写（FNV-1a 校验，百万级事件量级）
- CLI：`record` / `info` / `trace` / `frame` / `tui` / `export`
- 复用 winVpwn 的 ELF 加载与 syscall 分发，依赖固定在 tag `v0.1.0`

不含 LLM。全部事件来自真实 Unicorn 执行，无任何假数据。

## 形态

TUI（Textual）为主界面，CLI 负责脚本化，HTML 静态导出负责分享。不做实时 Web
应用，不做原生 GUI。

## 使用

```console
$ cinema record hello_static --out hello.ctrace
recorded hello.ctrace (144021 bytes)

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

## 文档

- [设计文档](docs/design.md)

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

## 边界

内核面向静态 `ET_EXEC` x86_64 镜像与确定性 syscall 集合（`write`、`exit`、
`exit_group`）。文件、网络、信号与动态链接留给后续阶段，CI 目前只在 Linux 上
验证，Windows 支持在验证后再声明。

放映机用于授权环境：CTF 题目、教学、以及你自己拥有的软件。被放映的二进制在
Unicorn 沙箱中运行，不触碰宿主文件系统与网络，运行权限不高于宿主进程。
