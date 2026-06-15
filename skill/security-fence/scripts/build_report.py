#!/usr/bin/env python3
"""
ai-security-fence :: report builder.

Renders a combined findings JSON into a single self-contained interactive HTML
dashboard (no CDN / no external assets -> safe to open offline & share).

Input shape (see run_scan.py): {generated_at, scanned[], coverage[], guidelines[], findings[]}
Each finding: {id, severity, surface, title, location, evidence, impact, remediation, fix_prompt, engine?}

Importable: render(src_json, out_html)
CLI:        python3 build_report.py findings.json report.html
"""
import json, sys, html

SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
SEV_COLOR = {"critical": "#e5484d", "high": "#f76808", "medium": "#ffb224",
             "low": "#46a758", "info": "#5b9dd9"}


def esc(s):
    return html.escape(str(s if s is not None else ""))


def donut(counts):
    total = sum(counts.values()) or 1
    segs, off, C = [], 0.0, 2 * 3.141592653589793 * 52
    for sev in ["critical", "high", "medium", "low", "info"]:
        v = counts.get(sev, 0)
        if not v:
            continue
        frac = v / total
        segs.append(f'<circle r="52" cx="70" cy="70" fill="none" stroke="{SEV_COLOR[sev]}" '
                    f'stroke-width="20" stroke-dasharray="{frac*C:.2f} {C:.2f}" '
                    f'stroke-dashoffset="{-off*C:.2f}" transform="rotate(-90 70 70)"/>')
        off += frac
    return (f'<svg viewBox="0 0 140 140" width="150" height="150">{"".join(segs)}'
            f'<text x="70" y="64" text-anchor="middle" class="dnum">{sum(counts.values())}</text>'
            f'<text x="70" y="84" text-anchor="middle" class="dlbl">findings</text></svg>')


def bars(by_surface):
    if not by_surface:
        return ""
    mx = max(by_surface.values()) or 1
    return "".join(
        f'<div class="bar-row"><span class="bar-lbl">{esc(s)}</span>'
        f'<span class="bar-track"><span class="bar-fill" style="width:{v/mx*100:.0f}%"></span></span>'
        f'<span class="bar-val">{v}</span></div>'
        for s, v in sorted(by_surface.items(), key=lambda x: -x[1]))


def coverage_html(cov):
    if not cov:
        return ""
    items = []
    for c in cov:
        skipped = "SKIPPED" in c
        cls = "cov-skip" if skipped else "cov-ok"
        icon = "○" if skipped else "●"
        items.append(f'<li class="{cls}"><span class="cov-i">{icon}</span>{esc(c)}</li>')
    return f'<div class="card cov"><b style="font-size:13px;color:var(--mut)">SCAN COVERAGE (what actually ran)</b><ul>{"".join(items)}</ul></div>'


def render(src, out):
    data = json.load(open(src))
    findings = sorted(data.get("findings", []),
                      key=lambda f: (SEV_ORDER.get(f.get("severity", "info"), 9), f.get("surface", "")))
    counts, by_surface = {}, {}
    for f in findings:
        sev = f.get("severity", "info")
        counts[sev] = counts.get(sev, 0) + 1
        by_surface[f.get("surface", "Other")] = by_surface.get(f.get("surface", "Other"), 0) + 1

    rows = []
    for f in findings:
        sev = f.get("severity", "info")
        eng = f.get("engine", "")
        engtag = f'<span class="eng">{esc(eng)}</span>' if eng else ""
        rows.append(f'''
<div class="finding" data-sev="{esc(sev)}" data-surface="{esc(f.get('surface',''))}"
     data-text="{esc((f.get('title','')+' '+f.get('location','')+' '+f.get('surface','')+' '+eng).lower())}">
  <div class="f-head" onclick="this.parentElement.classList.toggle('open')">
    <span class="sev-pill" style="background:{SEV_COLOR.get(sev,'#888')}">{esc(sev.upper())}</span>
    <span class="f-id">{esc(f.get('id',''))}</span>
    <span class="f-title">{esc(f.get('title',''))}</span>
    <span class="f-surface">{esc(f.get('surface',''))}</span>{engtag}
    <span class="chev">▸</span>
  </div>
  <div class="f-body">
    <div class="kv"><b>Location</b><code>{esc(f.get('location',''))}</code></div>
    <div class="kv"><b>Evidence</b><code>{esc(f.get('evidence',''))}</code></div>
    <div class="kv"><b>Impact</b><span>{esc(f.get('impact',''))}</span></div>
    <div class="kv"><b>Remediation</b><span>{esc(f.get('remediation',''))}</span></div>
    <div class="f-actions">
      <button class="fixbtn" data-fix="{esc(f.get('fix_prompt',''))}">🔧 Fix with Claude</button>
      <span class="copied">copied — paste into your AI coding agent ↩</span>
    </div>
  </div>
</div>''')

    kpis = "".join(
        f'<div class="kpi" style="border-color:{SEV_COLOR[s]}"><div class="kpi-n" style="color:{SEV_COLOR[s]}">{counts.get(s,0)}</div><div class="kpi-l">{s.upper()}</div></div>'
        for s in ["critical", "high", "medium", "low"])
    scanned = " · ".join(esc(x) for x in data.get("scanned", []))
    guidelines = "".join(f"<li>{esc(g)}</li>" for g in data.get("guidelines", []))
    gen = esc(data.get("generated_at", ""))

    page = f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>AI Security Fence Report</title>
<style>
:root{{--bg:#0f1115;--card:#171a21;--bd:#262b36;--tx:#e6e9ef;--mut:#8b93a7;--acc:#5b9dd9;--ok:#46a758;}}
.light{{--bg:#f5f6f8;--card:#fff;--bd:#e2e5ea;--tx:#1a1d23;--mut:#5d6470;--acc:#2563eb;}}
*{{box-sizing:border-box}}
body{{margin:0;font:14px/1.5 -apple-system,Segoe UI,Roboto,sans-serif;background:var(--bg);color:var(--tx)}}
.wrap{{max-width:1080px;margin:0 auto;padding:28px 20px 80px}}
header{{display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:12px}}
h1{{font-size:22px;margin:0}}.sub{{color:var(--mut);font-size:13px;margin-top:4px}}
.toggle{{background:var(--card);border:1px solid var(--bd);color:var(--tx);border-radius:8px;padding:7px 12px;cursor:pointer}}
.top{{display:grid;grid-template-columns:170px 1fr;gap:18px;margin:22px 0;align-items:center}}
@media(max-width:680px){{.top{{grid-template-columns:1fr}}}}
.card{{background:var(--card);border:1px solid var(--bd);border-radius:14px;padding:18px;margin-bottom:14px}}
.kpis{{display:flex;gap:12px;flex-wrap:wrap}}
.kpi{{flex:1;min-width:90px;background:var(--card);border:1px solid var(--bd);border-left-width:4px;border-radius:12px;padding:14px}}
.kpi-n{{font-size:28px;font-weight:700;line-height:1}}.kpi-l{{font-size:11px;color:var(--mut);letter-spacing:.5px;margin-top:6px}}
.dnum{{font-size:26px;font-weight:700;fill:var(--tx)}}.dlbl{{font-size:10px;fill:var(--mut)}}
.bar-row{{display:flex;align-items:center;gap:10px;margin:8px 0;font-size:13px}}
.bar-lbl{{width:170px;color:var(--mut)}}.bar-track{{flex:1;height:10px;background:var(--bd);border-radius:6px;overflow:hidden}}
.bar-fill{{display:block;height:100%;background:var(--acc)}}.bar-val{{width:24px;text-align:right;color:var(--mut)}}
.cov ul{{list-style:none;padding:0;margin:10px 0 0;font-size:12.5px;columns:2}}
@media(max-width:680px){{.cov ul{{columns:1}}}}
.cov li{{padding:3px 0}}.cov-ok .cov-i{{color:var(--ok)}}.cov-skip{{color:var(--mut)}}.cov-skip .cov-i{{color:var(--mut)}}
.cov-i{{display:inline-block;width:16px}}
.controls{{display:flex;gap:8px;flex-wrap:wrap;margin:22px 0 12px;align-items:center}}
.fbtn{{background:var(--card);border:1px solid var(--bd);color:var(--tx);border-radius:20px;padding:6px 14px;cursor:pointer;font-size:13px}}
.fbtn.on{{background:var(--acc);border-color:var(--acc);color:#fff}}
#q{{flex:1;min-width:160px;background:var(--card);border:1px solid var(--bd);color:var(--tx);border-radius:20px;padding:7px 14px}}
.finding{{background:var(--card);border:1px solid var(--bd);border-radius:12px;margin:10px 0;overflow:hidden}}
.f-head{{display:flex;align-items:center;gap:12px;padding:13px 16px;cursor:pointer}}
.sev-pill{{color:#fff;font-size:10px;font-weight:700;padding:3px 8px;border-radius:6px;letter-spacing:.5px}}
.f-id{{color:var(--mut);font-size:12px;font-family:ui-monospace,monospace}}
.f-title{{flex:1;font-weight:600}}
.f-surface{{color:var(--mut);font-size:12px;border:1px solid var(--bd);padding:2px 8px;border-radius:6px}}
.eng{{color:var(--acc);font-size:11px;font-family:ui-monospace,monospace}}
.chev{{color:var(--mut);transition:.2s}}.finding.open .chev{{transform:rotate(90deg)}}
.f-body{{display:none;padding:4px 16px 16px;border-top:1px solid var(--bd)}}.finding.open .f-body{{display:block}}
.kv{{display:grid;grid-template-columns:110px 1fr;gap:10px;padding:8px 0;border-bottom:1px dashed var(--bd)}}
.kv b{{color:var(--mut);font-weight:600;font-size:12px}}
.kv code{{font-family:ui-monospace,monospace;font-size:12.5px;word-break:break-all;background:var(--bg);padding:2px 6px;border-radius:5px}}
.f-actions{{margin-top:14px;display:flex;align-items:center;gap:12px}}
.fixbtn{{background:var(--acc);color:#fff;border:0;border-radius:8px;padding:9px 16px;font-weight:600;cursor:pointer;font-size:13px}}
.fixbtn:hover{{filter:brightness(1.1)}}
.copied{{color:var(--ok);font-size:12px;opacity:0;transition:.2s}}.copied.show{{opacity:1}}
.meth ul{{color:var(--mut);font-size:13px}}
.foot{{color:var(--mut);font-size:12px;margin-top:24px;text-align:center}}
</style></head><body><div class="wrap">
<header>
  <div><h1>🛡️ AI Security Fence</h1><div class="sub">Scanned: {scanned} &nbsp;·&nbsp; Generated {gen}</div></div>
  <button class="toggle" onclick="document.body.classList.toggle('light')">☀ / ☾</button>
</header>
<div class="top">
  <div class="card" style="text-align:center;margin:0">{donut(counts)}</div>
  <div class="kpis">{kpis}</div>
</div>
<div class="card"><b style="font-size:13px;color:var(--mut)">FINDINGS BY SURFACE</b><div style="margin-top:10px">{bars(by_surface)}</div></div>
{coverage_html(data.get("coverage", []))}
<div class="controls">
  <button class="fbtn on" data-f="all">All</button>
  <button class="fbtn" data-f="critical">Critical</button>
  <button class="fbtn" data-f="high">High</button>
  <button class="fbtn" data-f="medium">Medium</button>
  <button class="fbtn" data-f="low">Low</button>
  <input id="q" placeholder="🔍 filter by title, file, surface, engine…">
</div>
<div id="list">{"".join(rows) if rows else '<div class="card">✅ No findings on the surfaces that were scanned. Check the coverage panel above for what ran.</div>'}</div>
<div class="meth card">
  <b>How the Fix buttons work</b>
  <p class="sub" style="margin:8px 0">Each <b>🔧 Fix with Claude</b> button copies a ready-to-run remediation instruction to your clipboard. Paste it into your AI coding agent (Claude Code, etc.) and it applies that specific fix — it will ask before any destructive change. Live credentials must be <b>rotated</b> by you; the report only flags and guides.</p>
  <b>Guidelines applied</b><ul>{guidelines}</ul>
</div>
<div class="foot">Self-contained &amp; offline. Secret values are redacted to fingerprints — but this file lists secret <i>locations</i>, so treat it as sensitive. No scanner finds everything; coverage above is the honest list of what ran.</div>
</div>
<script>
document.querySelectorAll('.fbtn').forEach(b=>b.onclick=()=>{{
  document.querySelectorAll('.fbtn').forEach(x=>x.classList.remove('on'));b.classList.add('on');
  const f=b.dataset.f;document.querySelectorAll('.finding').forEach(c=>{{c.style.display=(f==='all'||c.dataset.sev===f)?'':'none';}});
}});
document.getElementById('q').oninput=e=>{{const q=e.target.value.toLowerCase();
  document.querySelectorAll('.finding').forEach(c=>{{c.style.display=c.dataset.text.includes(q)?'':'none';}});}};
document.querySelectorAll('.fixbtn').forEach(b=>b.onclick=ev=>{{ev.stopPropagation();
  navigator.clipboard.writeText(b.dataset.fix).then(()=>{{const m=b.nextElementSibling;m.classList.add('show');setTimeout(()=>m.classList.remove('show'),2600);}});}});
</script></body></html>"""
    with open(out, "w") as fh:
        fh.write(page)
    return len(findings)


def main():
    n = render(sys.argv[1], sys.argv[2])
    print(f"wrote {sys.argv[2]} ({n} findings)")


if __name__ == "__main__":
    main()
