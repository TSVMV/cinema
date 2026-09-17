"""Static HTML export of a recording.

`export_trace` writes a self-contained HTML file: the event stream on the
left, the reconstructed machine state on the right, fully interactive with
no external assets. Every value embedded in the page comes from the trace.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from cinema._core import Trace
from cinema.ui.format import detail

_REG_ORDER: tuple[str, ...] = (
    "rax",
    "rbx",
    "rcx",
    "rdx",
    "rsi",
    "rdi",
    "rbp",
    "rsp",
    "r8",
    "r9",
    "r10",
    "r11",
    "r12",
    "r13",
    "r14",
    "r15",
    "rip",
    "rflags",
)

_TEMPLATE = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>cinema — replay report</title>
<style>
  :root { color-scheme: dark; }
  * { box-sizing: border-box; }
  body { margin:0; font:14px/1.5 ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
         background:#1a1c1e; color:#c9d1d9; }
  header { padding:12px 16px; border-bottom:1px solid #30363d; background:#161819; }
  header h1 { margin:0; font-size:16px; font-weight:600; color:#e6edf3; }
  header p { margin:4px 0 0; color:#8b949e; font-size:12px; }
  .layout { display:grid; grid-template-columns:minmax(360px, 5fr) 7fr; height:calc(100vh - 78px); }
  .pane { overflow:auto; padding:8px; }
  .pane.left { border-right:1px solid #30363d; }
  .evt { padding:3px 8px; cursor:pointer; white-space:nowrap; overflow:hidden; text-overflow:ellipsis; }
  .evt:hover { background:#1f2428; }
  .evt.sel { background:#14324d; }
  .evt .fr { color:#6e7681; display:inline-block; width:5ch; text-align:right; margin-right:8px; }
  .evt .kind { display:inline-block; width:11ch; }
  table { border-collapse:collapse; width:100%; }
  td, th { padding:1px 10px 1px 0; text-align:left; white-space:nowrap; }
  td.reg { color:#6e7681; }
  td.rip { color:#58a6ff; }
  .status { color:#8b949e; margin-bottom:8px; }
  pre.out { background:#161819; border:1px solid #30363d; padding:8px; white-space:pre-wrap; margin:0; }
  .win { margin-top:10px; }
  .win b { color:#8b949e; font-weight:600; }
  .controls { padding:8px 16px; border-top:1px solid #30363d; background:#161819;
              display:flex; gap:6px; align-items:center; }
  button { background:#21262d; color:#c9d1d9; border:1px solid #30363d; padding:3px 10px; cursor:pointer; }
  button:hover { background:#30363d; }
  input#goto { width:10ch; background:#0d1117; color:#c9d1d9; border:1px solid #30363d; padding:3px 6px; }
  .kind.insn { color:#6e7681; } .kind.reg_write { color:#79c0ff; } .kind.mem_write { color:#a5d6ff; }
  .kind.syscall_enter { color:#9ecbff; } .kind.syscall_exit { color:#6e7681; }
  .kind.output { color:#3fb950; } .kind.exit { color:#e3b341; }
</style>
</head>
<body>
<header>
  <h1>cinema — replay report</h1>
  <p id="meta"></p>
</header>
<div class="controls">
  <button id="start">start</button>
  <button id="prev">prev</button>
  <button id="next">next</button>
  <button id="end">end</button>
  <input id="goto" placeholder="frame" autocomplete="off">
  <button id="jump">go</button>
  <span class="status" id="pos"></span>
</div>
<div class="layout">
  <div class="pane left" id="events"></div>
  <div class="pane" id="state"></div>
</div>
<script id="trace-data" type="application/json">__TRACE_DATA__</script>
<script>
const DATA = JSON.parse(document.getElementById('trace-data').textContent);
let cur = 0;
const $ = (id) => document.getElementById(id);
const esc = (s) => String(s).replace(/[&<>"']/g, (c) =>
  ({ '&':'&amp;', '<':'&lt;', '>':'&gt;', '"':'&quot;', "'":'&#39;' })[c]);

function regTable(regs) {
  return '<table>' + DATA.reg_names.map((n, i) =>
    '<tr><td class="reg">' + n + '</td><td class="' + (n === 'rip' ? 'rip' : '') + '">' +
    regs[i] + '</td></tr>').join('') + '</table>';
}

function renderState() {
  const f = DATA.frames[cur];
  const m = DATA.meta;
  $('pos').textContent = 'frame ' + cur + ' / ' + m.events + '  rip ' + f.rip +
    '  dirty pages ' + f.dirty + (f.snap ? '  snapshot' : '');
  let html = regTable(f.regs);
  html += '<p class="status">output</p><pre class="out"></pre>';
  html += f.event
    ? '<p class="status">event</p><div>frame ' + cur + ' — ' + f.event.kind + ': ' + esc(f.event.detail) + '</div>'
    : '<p class="status">event</p><div>frame 0 — initial machine state</div>';
  const windows = DATA.windows;
  if (windows.length) {
    html += '<div class="win"><b>memory</b></div>';
    windows.forEach((w, i) => {
      html += '<div class="win"><b>0x' + w.addr.toString(16) + '</b><pre class="out">' +
        esc(f.mem[i]) + '</pre></div>';
    });
  }
  $('state').innerHTML = html;
  $('state').querySelector('pre.out').textContent = DATA.strings[f.out];
  document.querySelectorAll('.evt').forEach((e) => e.classList.toggle('sel', +e.dataset.f === cur));
  const sel = document.querySelector('.evt[data-f="' + cur + '"]');
  if (sel) sel.scrollIntoView({ block: 'center' });
}

function renderEvents() {
  $('events').innerHTML = DATA.frames.map((f) => {
    const e = f.event;
    const kind = e ? e.kind : '';
    const det = e ? esc(e.detail) : 'initial machine state';
    return '<div class="evt" data-f="' + f.f + '"><span class="fr">' + f.f +
      '</span><span class="kind ' + kind + '">' + (kind || '---') + '</span>' + det + '</div>';
  }).join('');
  $('events').addEventListener('click', (ev) => {
    const row = ev.target.closest('.evt');
    if (row) { cur = +row.dataset.f; renderState(); }
  });
}

function nav(delta) {
  cur = Math.max(0, Math.min(DATA.frames.length - 1, cur + delta));
  renderState();
}

document.addEventListener('DOMContentLoaded', () => {
  const m = DATA.meta;
  $('meta').textContent = 'entry ' + m.entry + '  events ' + m.events +
    '  snapshots ' + m.snapshots + '  exit ' + m.exit_kind + ' ' + m.exit_value +
    '  image ' + m.image_hash;
  renderEvents();
  renderState();
  $('start').addEventListener('click', () => { cur = 0; renderState(); });
  $('prev').addEventListener('click', () => nav(-1));
  $('next').addEventListener('click', () => nav(1));
  $('end').addEventListener('click', () => { cur = DATA.frames.length - 1; renderState(); });
  $('jump').addEventListener('click', () => {
    const v = parseInt($('goto').value, 10);
    if (!isNaN(v)) { cur = Math.max(0, Math.min(DATA.frames.length - 1, v)); renderState(); }
  });
  $('goto').addEventListener('keydown', (e) => { if (e.key === 'Enter') $('jump').click(); });
});
</script>
</body>
</html>
"""


def _intern(pool: list[str], value: str) -> int:
    try:
        return pool.index(value)
    except ValueError:
        pool.append(value)
        return len(pool) - 1


def _build_payload(trace: Trace, windows: list[tuple[int, int]]) -> dict[str, Any]:
    last = trace.frame_count()
    snapshots = set(trace.snapshot_frames())
    summary = trace.summary()
    strings: list[str] = []

    frames: list[dict[str, Any]] = []
    for frame in range(0, last + 1):
        state = trace.state_at(frame)
        event = trace.event_at(frame)
        producer = None
        if event is not None:
            kind = str(event.get("kind", ""))
            producer = {"kind": kind, "detail": detail(kind, event)}
        record: dict[str, Any] = {
            "f": frame,
            "rip": f"0x{state.rip():x}",
            "regs": [f"0x{int(state.regs()[name]):x}" for name in _REG_ORDER],
            "out": _intern(strings, state.output().decode("latin-1")),
            "dirty": state.dirty_page_count(),
            "snap": frame in snapshots,
            "event": producer,
        }
        if windows:
            record["mem"] = [
                _intern(strings, state.read_memory(addr, length).hex(" "))
                for addr, length in windows
            ]
        frames.append(record)

    return {
        "meta": {
            "entry": f"0x{trace.entry():x}",
            "image_hash": trace.image_hash(),
            "events": trace.len(),
            "snapshots": len(snapshots),
            "final_rip": f"0x{int(summary['final_rip']):x}",
            "exit_kind": str(summary.get("exit_kind", "none")),
            "exit_value": f"0x{int(summary.get('exit_value', 0)):x}",
        },
        "reg_names": list(_REG_ORDER),
        "strings": strings,
        "windows": [{"addr": addr, "len": length} for addr, length in windows],
        "frames": frames,
    }


def export_trace(
    trace: Trace, out: Path, windows: list[tuple[int, int]] | None = None
) -> Path:
    """Write a self-contained HTML report for `trace` to `out`."""
    out = Path(out)
    payload = _build_payload(trace, windows or [])
    data = json.dumps(payload).replace("</", "<\\/")
    html = _TEMPLATE.replace("__TRACE_DATA__", data)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(html, encoding="utf-8")
    return out
