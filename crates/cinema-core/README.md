# cinema-core

Core engine of the replay projector: an instruction-level event capture loop,
snapshot anchors, and arbitrary-frame replay, backed by Unicorn Engine and
winVpwn's ELF loader and syscall dispatcher.

Stage 1 scope: static `ET_EXEC` x86_64 images, deterministic syscall set
(`write`, `exit`, `exit_group`), no UI, no model.

```rust
use cinema_core::event::Frame;
use cinema_core::replay::Replay;
use cinema_core::session::{record_elf, RecordOptions};

let image = std::fs::read("hello_static")?;
let trace = record_elf(&image, &RecordOptions::default())?;

let replay = Replay::new(&trace);
let state = replay.state_at(trace.last_frame());
assert_eq!(state.output, b"hello, winVpwn\n");

let encoded = trace.encode();
let reloaded = cinema_core::trace::Trace::decode(&encoded)?;
```

Build without Python bindings:

```console
$ cargo test --no-default-features
```
