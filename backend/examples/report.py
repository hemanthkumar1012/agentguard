"""Self-contained HTML report of a demo run: a flow diagram and a step-by-step timeline."""
from __future__ import annotations

from datetime import datetime, timezone
import html

COLOURS = {"allow": "#1a7f4b", "require_approval": "#b26a00", "block": "#c62828"}
LABELS = {"allow": "allowed", "require_approval": "needs approval", "block": "blocked"}
RULES = {
    "F0": "unknown session", "F1": "lethal trifecta", "F2": "private data outside its readers",
    "F3": "fingerprint evidence", "F4": "untrusted input steering a change", "F5": "secret sent in pieces",
    "S1": "secret handle misuse", "O1": "leaking URL in the reply",
}


def _e(text) -> str:
    return html.escape(str(text), quote=True)


def _short(text: str, limit: int) -> str:
    """Cut at a word boundary and say so, instead of chopping a word in half."""
    if len(text) <= limit:
        return text
    cut = text[: limit - 1].rsplit(" ", 1)[0]
    return cut + "…"


def _diagram(log) -> str:
    reads = [r for r in log if r.kind == "read"]
    outs = [r for r in log if r.kind != "read"]
    row, top = 46, 40
    height = top + max(len(reads), len(outs)) * row + 20
    lx, rx, w = 20, 520, 300
    y_read = {id(r): top + i * row for i, r in enumerate(reads)}
    y_out = {id(r): top + i * row for i, r in enumerate(outs)}
    by_event = {r.event_id: r for r in reads if r.event_id}
    parts = [f'<svg viewBox="0 0 840 {height}" role="img" aria-label="Data flow between reads and outbound requests">',
             '<text x="20" y="22" class="col">What the agent read</text>',
             '<text x="520" y="22" class="col">What it tried to send or show</text>']
    for out in outs:
        colour = COLOURS[out.decision]
        sources = [by_event[e["source_event_id"]] for e in out.lineage if e.get("source_event_id") in by_event]
        dashed = False
        if not sources and out.rule in {"F1", "F2", "F4"}:
            sources = [r for r in reads if r.session == out.session and r.decision == "allow"]
            dashed = True
        for src in sources:
            y1, y2 = y_read[id(src)] + 16, y_out[id(out)] + 16
            dash = 'stroke-dasharray="5 4"' if dashed else ""   # kept out of the f-string for Python 3.11
            parts.append(f'<path d="M{lx + w} {y1} C {lx + w + 100} {y1}, {rx - 100} {y2}, {rx} {y2}" fill="none" '
                         f'stroke="{colour}" stroke-width="{1.5 if dashed else 2.5}" {dash} opacity="0.75"/>')
    for r in reads:
        y = y_read[id(r)]
        parts.append(f'<rect x="{lx}" y="{y}" width="{w}" height="32" rx="6" class="node"/>'
                     f'<text x="{lx + 10}" y="{y + 20}" class="nt">{_e(_short(r.title, 44))}<title>{_e(r.title)}</title></text>')
    for r in outs:
        y = y_out[id(r)]
        colour = COLOURS[r.decision]
        parts.append(f'<rect x="{rx}" y="{y}" width="{w}" height="32" rx="6" class="node" style="stroke:{colour}"/>'
                     f'<circle cx="{rx + 14}" cy="{y + 16}" r="5" fill="{colour}"/>'
                     f'<text x="{rx + 26}" y="{y + 20}" class="nt">{_e(_short(r.title, 40))}<title>{_e(r.title)}</title></text>')
    parts.append("</svg>")
    return "".join(parts)


def render(log, title: str, subtitle: str, commit: str = "") -> str:
    counts = {k: sum(1 for r in log if r.decision == k) for k in COLOURS}
    met = sum(1 for r in log if r.met)
    cards = []
    for i, r in enumerate(log, 1):
        rule = f'<span class="chip">{_e(r.rule)} · {_e(RULES.get(r.rule, ""))}</span>' if r.rule else ""
        lineage = "".join(
            f'<li>{_e(e.get("tool"))}.{_e(e.get("action"))} '
            f'({_e(e.get("kind", "fingerprints"))}{", " + _e(e.get("encoding")) if e.get("encoding") not in (None, "plain") else ""})'
            f' — event {_e(e.get("source_event_id"))}</li>' for e in r.lineage)
        cards.append(f'''
        <li class="step">
          <div class="num">{i}</div>
          <div class="body">
            <div class="head"><span class="badge" style="background:{COLOURS[r.decision]}">{LABELS[r.decision]}</span>
              <strong>{_e(r.title)}</strong>{rule}<span class="sess">session: {_e(r.session)}</span></div>
            <div class="detail"><code>{_e(r.tool)}</code> {_e(r.detail)}</div>
            <p>{_e(r.reason)}</p>
            {f'<div class="lin">Where the data came from:<ul>{lineage}</ul></div>' if lineage else ''}
            {'' if r.met else '<p class="miss">Did not match the expected outcome.</p>'}
          </div>
        </li>''')
    stamp = datetime.now(timezone.utc).strftime("%d %b %Y, %H:%M UTC")
    return f'''<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>{_e(title)}</title>
<style>
  :root {{ --ink:#1d2330; --muted:#5b6472; --line:#e3e6ec; --bg:#f7f8fa; --card:#fff; }}
  * {{ box-sizing:border-box; }}
  body {{ margin:0; font:15px/1.55 -apple-system, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; color:var(--ink); background:var(--bg); }}
  main {{ max-width:900px; margin:0 auto; padding:40px 20px 60px; }}
  h1 {{ font-size:28px; margin:0 0 6px; letter-spacing:-0.01em; }}
  .sub {{ color:var(--muted); margin:0 0 24px; max-width:70ch; }}
  .tiles {{ display:grid; grid-template-columns:repeat(4,1fr); gap:12px; margin-bottom:28px; }}
  .tile {{ background:var(--card); border:1px solid var(--line); border-radius:10px; padding:14px 16px; }}
  .tile b {{ display:block; font-size:26px; }}
  .tile span {{ color:var(--muted); font-size:13px; }}
  section {{ background:var(--card); border:1px solid var(--line); border-radius:12px; padding:20px; margin-bottom:24px; }}
  h2 {{ font-size:17px; margin:0 0 12px; }}
  svg {{ width:100%; height:auto; }}
  svg .col {{ font-size:13px; fill:var(--muted); font-weight:600; }}
  svg .node {{ fill:#fff; stroke:#cfd5df; stroke-width:1.5; }}
  svg .nt {{ font-size:12.5px; fill:var(--ink); }}
  .legend {{ color:var(--muted); font-size:13px; margin-top:8px; }}
  ol {{ list-style:none; padding:0; margin:0; }}
  .step {{ display:flex; gap:14px; padding:14px 0; border-top:1px solid var(--line); }}
  .step:first-child {{ border-top:0; }}
  .num {{ flex:0 0 28px; height:28px; border-radius:50%; background:var(--bg); border:1px solid var(--line); display:grid; place-items:center; font-size:13px; color:var(--muted); }}
  .body {{ flex:1; min-width:0; }}
  .head {{ display:flex; flex-wrap:wrap; align-items:center; gap:8px; }}
  .badge {{ color:#fff; font-size:12px; padding:2px 8px; border-radius:999px; }}
  .chip {{ font-size:12px; padding:2px 8px; border-radius:999px; background:#eef1f6; color:#344055; }}
  .sess {{ margin-left:auto; color:var(--muted); font-size:12px; }}
  .detail {{ color:var(--muted); font-size:13px; margin-top:4px; overflow-wrap:anywhere; }}
  code {{ background:#f0f2f6; padding:1px 5px; border-radius:4px; font-size:12.5px; }}
  .body p {{ margin:6px 0 0; }}
  .lin {{ font-size:13px; color:var(--muted); margin-top:6px; }}
  .lin ul {{ margin:4px 0 0 18px; padding:0; }}
  .miss {{ color:#c62828; font-weight:600; }}
  footer {{ color:var(--muted); font-size:13px; }}
  @media (max-width:640px) {{ .tiles {{ grid-template-columns:repeat(2,1fr); }} .sess {{ margin-left:0; }} }}
</style></head>
<body><main>
  <h1>{_e(title)}</h1>
  <p class="sub">{_e(subtitle)}</p>
  <div class="tiles">
    <div class="tile"><b>{len(log)}</b><span>tool calls and replies checked</span></div>
    <div class="tile"><b style="color:{COLOURS['allow']}">{counts['allow']}</b><span>allowed (normal work)</span></div>
    <div class="tile"><b style="color:{COLOURS['block']}">{counts['block'] + counts['require_approval']}</b><span>stopped or sent to a human</span></div>
    <div class="tile"><b>{met}/{len(log)}</b><span>matched the expected outcome</span></div>
  </div>
  <section><h2>Where data tried to go</h2>{_diagram(log)}
    <p class="legend">Solid line: AgentGuard found the data itself in the request (fingerprints or secret pieces).
    Dashed line: the session label alone stopped it. Colour shows the decision.</p></section>
  <section><h2>Step by step</h2><ol>{"".join(cards)}</ol></section>
  <footer>Generated {stamp} by <code>make demo</code> (AgentGuard{", commit " + _e(commit) if commit else ""}). Every
  decision above came from the real gateway, run in-process; nothing is mocked except the tools' outputs.</footer>
</main></body></html>'''
