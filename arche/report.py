# Save a scan as a self-contained HTML page (to read or share) or as JSON (for scripts).
import html, json, platform
from . import core
from .core import CHECKS, ALERT, WARN


def write(path, results, base):
    from .cli import as_json
    if str(path).endswith('.json'): return core.write_private(path, json.dumps(as_json(results, base), indent=2))
    sev = lambda r: 'alert' if r.sev == ALERT else 'warn' if r.sev == WARN else 'new' if r.new else ''
    out = []
    for fam in dict.fromkeys(CHECKS[n].family for n in results):
        out.append(f'<h2>{html.escape(fam)}</h2>')
        for n, rows in results.items():
            if CHECKS[n].family != fam: continue
            flagged = sum(1 for r in rows if r.sev or r.new)
            out.append(f'<details{" open" if flagged else ""}><summary>{html.escape(n)} <span class="n">{len(rows)} items'
                       f'{f", {flagged} flagged" if flagged else ""}</span></summary><ul>')
            out += [f'<li class="{sev(r)}">{html.escape(r.text)}' + (f'<div class="fix">{html.escape(r.fix)}</div>' if r.fix and (r.sev or r.new) else '')
                    + '</li>' for r in rows]
            out.append('</ul></details>')
    s = core.score(results)
    page = f'''<!doctype html><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Arche Defender report</title>
<style>
:root{{--bg:#fff;--fg:#1d1f23;--muted:#666;--alert:#c62828;--warn:#d9480f;--new:#a06800;--line:#e4e4e4}}
@media (prefers-color-scheme:dark){{:root{{--bg:#14161a;--fg:#e8eaed;--muted:#9aa0a6;--alert:#ff6b6b;--warn:#ff9f5a;--new:#f5c451;--line:#2a2e35}}}}
body{{background:var(--bg);color:var(--fg);font:14px/1.5 system-ui,sans-serif;max-width:960px;margin:0 auto;padding:24px 16px}}
h1{{margin:0}} .meta,.n,.fix{{color:var(--muted)}} .score{{font-size:32px;font-weight:700}}
details{{border-top:1px solid var(--line);padding:6px 0}} summary{{cursor:pointer;font-weight:600}}
ul{{margin:6px 0;padding-left:20px;font-family:ui-monospace,monospace;font-size:12.5px;overflow-wrap:anywhere}}
li.alert{{color:var(--alert)}} li.warn{{color:var(--warn)}} li.new{{color:var(--new)}} .fix{{font-family:system-ui;font-size:12.5px}}
</style>
<h1>Arche Defender report</h1>
<p class="meta">{html.escape(platform.node())} &middot; {html.escape(platform.platform())} &middot; {core.stamp()}
{"" if base is not None else " &middot; no baseline accepted yet"}</p>
<p class="score">{s}/100</p>
{"".join(out)}
<p class="meta">This report lists software, accounts and settings on this machine. Share it only with people you trust.</p>'''
    core.write_private(path, page)
