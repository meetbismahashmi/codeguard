"""
HTML dashboard: turns a scan into report.html and opens it in the browser.
No extra installs needed (plain HTML + CSS).
"""
import html
import os
import time
import webbrowser

COLORS = {"MALICIOUS": "#ef4444", "SUSPICIOUS": "#f59e0b", "SAFE": "#22c55e"}


def _e(s):
    return html.escape(str(s))


def _explanation(text):
    out = []
    for line in text.replace("**", "").replace("`", "").splitlines():
        line = line.strip()
        if not line:
            continue
        if ":" in line and line.split(":")[0].isupper():
            head, rest = line.split(":", 1)
            out.append(f"<p><b>{_e(head)}:</b>{_e(rest)}</p>")
        else:
            out.append(f"<p>{_e(line)}</p>")
    return "".join(out)


def build(project, rows, source, agent, integrity, out_path="report.html", open_browser=True):
    total = len(rows)
    bad = sum(1 for r in rows if r["verdict"] == "MALICIOUS")
    sus = sum(1 for r in rows if r["verdict"] == "SUSPICIOUS")
    safe = total - bad - sus
    max_depth = max((r["pkg"]["depth"] for r in rows), default=0)

    tree = []
    for r in rows:
        p, v = r["pkg"], r["verdict"]
        tree.append(
            f'<div class="node" style="margin-left:{(p["depth"]-1)*28}px">'
            f'<span class="dot" style="background:{COLORS[v]}"></span>'
            f'<span class="pkg">{_e(p["name"])}@{_e(p["version"])}</span>'
            f'<span class="tag" style="color:{COLORS[v]};border-color:{COLORS[v]}">{v}</span>'
            f'<span class="muted">score {r["score"]}</span></div>')

    cards = []
    for r in rows:
        if r["verdict"] == "SAFE":
            continue
        p, v, entry = r["pkg"], r["verdict"], r.get("entry") or {}
        rules = "".join(f"<li><b>{_e(f[0])}</b> &mdash; {_e(f[2])}</li>" for f in r["findings"])
        ev = _e("\n".join(r["evidence"][:6])) or "(none)"
        if entry.get("explorer"):
            chain = (f'<a class="btn" href="{_e(entry["explorer"])}" target="_blank">'
                     f'View verdict on Solana Explorer &rarr;</a>')
        else:
            chain = f'<span class="muted">Simulated log &middot; hash {_e(entry.get("record_hash", "")[:24])}&hellip;</span>'
        cards.append(f"""
<div class="card" style="border-left:5px solid {COLORS[v]}">
  <div class="cardhead"><h3>{_e(p['name'])}@{_e(p['version'])}</h3>
    <span class="tag big" style="color:{COLORS[v]};border-color:{COLORS[v]}">{v} &middot; {r['score']}/100</span></div>
  <p class="path">Path: {_e(' > '.join(p['chain']))} &nbsp;<span class="muted">(depth {p['depth']})</span></p>
  <div class="grid2">
    <div><h4>Rules triggered</h4><ul>{rules}</ul></div>
    <div class="gemma"><h4>&#10024; Plain-English explanation <span class="muted">({_e(r['engine'])})</span></h4>{_explanation(r['explanation'])}</div>
  </div>
  <details><summary>Code evidence</summary><pre>{ev}</pre></details>
  <div class="chain">&#9939; {chain}</div>
</div>""")

    page = f"""<!doctype html><html><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>CodeGuard Report</title>
<style>
body{{margin:0;background:#0b1020;color:#e5e7eb;font-family:Segoe UI,Inter,Arial,sans-serif}}
.wrap{{max-width:1100px;margin:0 auto;padding:28px 20px}}
header{{display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:12px}}
h1{{margin:0;font-size:30px}} h1 span{{color:#60a5fa}}
.sub{{color:#94a3b8;margin-top:4px}}
.stats{{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px;margin:24px 0}}
.stat{{background:#111833;border:1px solid #1f2a4d;border-radius:12px;padding:16px}}
.stat b{{font-size:30px;display:block}} .stat span{{color:#94a3b8;font-size:13px}}
.panel{{background:#111833;border:1px solid #1f2a4d;border-radius:12px;padding:18px;margin-bottom:20px}}
.panel h2{{margin:0 0 12px;font-size:18px}}
.node{{display:flex;align-items:center;gap:10px;padding:7px 0;border-bottom:1px solid #1a2342}}
.dot{{width:10px;height:10px;border-radius:50%}} .pkg{{font-family:Consolas,monospace;font-size:15px}}
.tag{{border:1px solid;border-radius:999px;padding:1px 9px;font-size:12px;font-weight:600}}
.tag.big{{font-size:13px;padding:3px 12px}}
.muted{{color:#94a3b8;font-size:13px}}
.card{{background:#111833;border:1px solid #1f2a4d;border-radius:12px;padding:18px;margin-bottom:18px}}
.cardhead{{display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:8px}}
.cardhead h3{{margin:0;font-family:Consolas,monospace}}
.path{{color:#cbd5e1;margin:8px 0 14px}}
.grid2{{display:grid;grid-template-columns:1fr 1fr;gap:18px}}
@media(max-width:760px){{.grid2{{grid-template-columns:1fr}}}}
h4{{margin:0 0 8px;font-size:14px;color:#93c5fd}} ul{{margin:0;padding-left:18px}} li{{margin-bottom:5px;font-size:14px}}
.gemma{{background:#0d1530;border-radius:10px;padding:12px}} .gemma p{{margin:0 0 8px;font-size:14px;line-height:1.45}}
details{{margin-top:12px}} summary{{cursor:pointer;color:#93c5fd}}
pre{{background:#070b18;padding:12px;border-radius:8px;overflow:auto;font-size:12px;color:#fca5a5}}
.chain{{margin-top:14px}} .btn{{background:#7c3aed;color:#fff;text-decoration:none;padding:7px 14px;border-radius:8px;font-size:14px}}
.badges span{{display:inline-block;background:#1f2a4d;border-radius:8px;padding:5px 10px;margin:3px;font-size:13px}}
footer{{color:#64748b;font-size:12px;text-align:center;margin-top:24px}}
</style></head><body><div class="wrap">
<header><div><h1>&#128737; Code<span>Guard</span></h1>
<div class="sub">Supply-chain audit of <b>{_e(project)}</b> &middot; {time.strftime('%Y-%m-%d %H:%M')}</div></div>
<div class="badges"><span>&#129302; Gemma 4</span><span>&#10052; Snowflake</span><span>&#9678; Solana</span><span>&#129489;&#8205;&#9992; Copilot-tested</span></div></header>

<div class="stats">
<div class="stat"><b>{total}</b><span>packages scanned</span></div>
<div class="stat"><b>{max_depth}</b><span>max nesting depth</span></div>
<div class="stat"><b style="color:#ef4444">{bad}</b><span>malicious</span></div>
<div class="stat"><b style="color:#f59e0b">{sus}</b><span>suspicious</span></div>
<div class="stat"><b style="color:#22c55e">{safe}</b><span>safe</span></div>
</div>

<div class="panel"><h2>Dependency tree</h2>{''.join(tree)}</div>
<h2 style="font-size:18px">Findings</h2>
{''.join(cards) or '<p>No risky packages found.</p>'}

<div class="panel"><h2>Agent &amp; data sources</h2>
<p><b>Agent identity (Solana):</b> <code>{_e(agent)}</code></p>
<p><b>Vulnerability data:</b> {_e(source)}</p>
<p><b>Audit log integrity:</b> <span style="color:{'#22c55e' if integrity else '#ef4444'};font-weight:600">{'VALID - no records tampered with' if integrity else 'TAMPERED!'}</span></p>
</div>
<footer>CodeGuard &middot; MIT License &middot; test fixtures are inert</footer>
</div></body></html>"""

    with open(out_path, "w", encoding="utf-8") as f:
        f.write(page)
    if open_browser and os.getenv("CODEGUARD_NO_BROWSER") != "1":
        webbrowser.open("file://" + os.path.abspath(out_path))
    return out_path
