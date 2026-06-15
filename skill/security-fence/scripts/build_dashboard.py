#!/usr/bin/env python3
"""
ai-security-fence :: analytics dashboard renderer.

Renders a rich, self-contained HTML security dashboard from an analytics payload:
posture score gauge, KPI strip, control-coverage bars, visibility & severity
charts, a sortable/filterable Repository Security Matrix (the real data), and a
risk-ranked findings list with Fix-with-Claude buttons.

All sections are optional — render only what the payload provides — so the same
renderer serves the GitHub auditor and the full local scan.

Importable: render(src_json, out_html)
CLI:        python3 build_dashboard.py audit.json dashboard.html
"""
import json, sys, html

SEV = {"critical": "#dc2626", "high": "#ea580c", "medium": "#d97706",
       "low": "#16a34a", "info": "#2563eb"}
SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
GRADE_COLOR = {"A": "#16a34a", "B": "#65a30d", "C": "#d97706", "D": "#ea580c", "F": "#dc2626"}
TONE = {"ok": "#16a34a", "warn": "#d97706", "bad": "#dc2626"}


def e(s):
    return html.escape(str(s if s is not None else ""))


def score_ring(score):
    val = score.get("value", 0)
    grade = score.get("grade", "?")
    col = GRADE_COLOR.get(grade, "#6b7280")
    C = 2 * 3.141592653589793 * 54
    dash = (val / 100) * C
    return f'''<svg viewBox="0 0 130 130" width="132" height="132" class="ring">
  <circle cx="65" cy="65" r="54" fill="none" stroke="var(--track)" stroke-width="12"/>
  <circle cx="65" cy="65" r="54" fill="none" stroke="{col}" stroke-width="12" stroke-linecap="round"
    stroke-dasharray="{dash:.1f} {C:.1f}" transform="rotate(-90 65 65)"/>
  <text x="65" y="60" text-anchor="middle" class="ring-num" fill="{col}">{val}</text>
  <text x="65" y="80" text-anchor="middle" class="ring-sub">/ 100</text>
</svg>
<div class="grade-wrap"><span class="grade" style="background:{col}">{e(grade)}</span>
<span class="grade-lbl">{e(score.get("label",""))}</span></div>'''


def kpi_html(kpis):
    out = []
    for k in kpis:
        col = TONE.get(k.get("tone", ""), "var(--tx)")
        out.append(f'<div class="kpi"><div class="kpi-v" style="color:{col}">{e(k.get("value",""))}</div>'
                   f'<div class="kpi-l">{e(k.get("label",""))}</div></div>')
    return "".join(out)


def coverage_html(bars):
    rows = []
    for b in bars:
        p = b.get("pct", 0)
        col = "#16a34a" if p >= 75 else "#d97706" if p >= 40 else "#dc2626"
        rows.append(f'''<div class="cov-row">
  <div class="cov-top"><span>{e(b["label"])}</span><span class="cov-frac">{b.get("count",0)}/{b.get("total",0)} · <b style="color:{col}">{p}%</b></span></div>
  <div class="cov-track"><div class="cov-fill" style="width:{p}%;background:{col}"></div></div>
</div>''')
    return "".join(rows)


def donut(d, palette):
    total = sum(d.values()) or 1
    segs, off, C = [], 0.0, 2 * 3.141592653589793 * 46
    legend = []
    for i, (k, v) in enumerate(sorted(d.items(), key=lambda x: -x[1])):
        if not v:
            continue
        col = palette(k, i)
        frac = v / total
        segs.append(f'<circle r="46" cx="60" cy="60" fill="none" stroke="{col}" stroke-width="16" '
                    f'stroke-dasharray="{frac*C:.2f} {C:.2f}" stroke-dashoffset="{-off*C:.2f}" transform="rotate(-90 60 60)"/>')
        off += frac
        legend.append(f'<div class="lg"><span class="dot" style="background:{col}"></span>{e(k)} <b>{v}</b></div>')
    svg = f'<svg viewBox="0 0 120 120" width="120" height="120">{"".join(segs)}<text x="60" y="66" text-anchor="middle" class="donut-c">{sum(d.values())}</text></svg>'
    return f'<div class="donut-wrap">{svg}<div class="legend">{"".join(legend)}</div></div>'


def sev_bars(counts):
    mx = max(counts.values()) if counts and max(counts.values()) else 1
    rows = []
    for s in ["critical", "high", "medium", "low", "info"]:
        v = counts.get(s, 0)
        if not v and s == "info":
            continue
        rows.append(f'''<div class="sb-row"><span class="sb-lbl" style="color:{SEV[s]}">{s.title()}</span>
  <span class="sb-track"><span class="sb-fill" style="width:{v/mx*100:.0f}%;background:{SEV[s]}"></span></span>
  <span class="sb-v">{v}</span></div>''')
    return "".join(rows)


def _cell(val):
    if val is True:
        return '<td class="c ok" data-v="2">✓</td>'
    if val is False:
        return '<td class="c bad" data-v="0">✗</td>'
    return '<td class="c na" data-v="1">–</td>'


def matrix_html(repos):
    if not repos:
        return ""
    body = []
    for r in repos:
        ov = r.get("open_vulns", {})
        vt = sum(ov.values())
        vcol = SEV["critical"] if ov.get("critical") else SEV["high"] if ov.get("high") else "var(--mut)"
        risk = r.get("risk", "low")
        tags = ""
        if r.get("archived"):
            tags += '<span class="tag">archived</span>'
        if r.get("fork"):
            tags += '<span class="tag">fork</span>'
        vis = r.get("visibility", "")
        viscol = "#d97706" if vis == "PUBLIC" else "#16a34a"
        body.append(f'''<tr data-risk="{risk}" data-name="{e(r.get("name","").lower())}">
  <td class="repo"><a href="https://github.com/{e(r.get("full",""))}" target="_blank" rel="noopener">{e(r.get("name",""))}</a>{tags}</td>
  <td data-v="{0 if vis=="PUBLIC" else 2}"><span class="vis" style="color:{viscol}">{e(vis)}</span></td>
  {_cell(r.get("secret_scanning"))}
  {_cell(r.get("push_protection"))}
  {_cell(r.get("branch_protection"))}
  {_cell(r.get("vuln_alerts"))}
  <td data-v="{vt}" style="color:{vcol};font-weight:600">{vt or "0"}</td>
  <td data-v="{4-SEV_ORDER.get(risk,3)}"><span class="risk" style="background:{SEV.get(risk,'#6b7280')}">{risk.upper()}</span></td>
</tr>''')
    return f'''<div class="card matrix-card">
  <div class="card-h"><b>Repository Security Matrix</b><input id="mq" placeholder="filter repos…">
    <span class="mfilters"><button class="mf on" data-r="all">All</button><button class="mf" data-r="critical">Crit</button><button class="mf" data-r="high">High</button><button class="mf" data-r="medium">Med</button><button class="mf" data-r="low">Low</button></span>
  </div>
  <div class="tbl-wrap"><table id="mtx"><thead><tr>
    <th data-i="0">Repository</th><th data-i="1">Visibility</th><th data-i="2">Secret scan</th>
    <th data-i="3">Push prot.</th><th data-i="4">Branch prot.</th><th data-i="5">Vuln alerts</th>
    <th data-i="6">Open vulns</th><th data-i="7">Risk</th>
  </tr></thead><tbody>{"".join(body)}</tbody></table></div>
  <div class="legend-row"><span><span class="c ok">✓</span> enabled</span><span><span class="c bad">✗</span> missing</span><span><span class="c na">–</span> n/a / unknown</span> · click a column header to sort</div>
</div>'''


def findings_html(findings):
    if not findings:
        return '<div class="card">No risk-ranked findings.</div>'
    rows = []
    for f in findings:
        s = f.get("severity", "info")
        rows.append(f'''<div class="finding" data-sev="{s}" data-text="{e((f.get('title','')+' '+f.get('location','')+' '+f.get('surface','')).lower())}">
  <div class="f-h" onclick="this.parentElement.classList.toggle('open')">
    <span class="pill" style="background:{SEV.get(s,'#888')}">{s.upper()}</span>
    <span class="f-id">{e(f.get('id',''))}</span><span class="f-t">{e(f.get('title',''))}</span>
    <span class="f-loc">{e(f.get('location',''))}</span><span class="chev">▸</span>
  </div>
  <div class="f-b">
    <div class="kv"><b>Impact</b><span>{e(f.get('impact',''))}</span></div>
    <div class="kv"><b>Remediation</b><span>{e(f.get('remediation',''))}</span></div>
    <div class="kv"><b>Evidence</b><code>{e(f.get('evidence',''))}</code></div>
    <button class="fix" data-fix="{e(f.get('fix_prompt',''))}">🔧 Fix with Claude</button><span class="copied">copied ↩</span>
  </div></div>''')
    return "".join(rows)


def render(src, out):
    d = json.load(open(src))
    findings = sorted(d.get("findings", []), key=lambda f: SEV_ORDER.get(f.get("severity", "info"), 9))
    fcounts = {}
    for f in findings:
        fcounts[f["severity"]] = fcounts.get(f["severity"], 0) + 1
    # attach full owner/name for matrix links
    subj = d.get("subject", "")
    owner = subj.split("/")[-1] if "/" in subj else ""
    for r in d.get("repos", []):
        r["full"] = f"{owner}/{r.get('name','')}"

    vis_palette = lambda k, i: ("#d97706" if k == "PUBLIC" else "#16a34a" if k == "PRIVATE" else "#2563eb")
    charts = d.get("charts", {})
    vis_chart = donut(charts["visibility"], vis_palette) if charts.get("visibility") else ""
    vulns = charts.get("vulns_by_severity", {})
    has_vulns = sum(vulns.values()) > 0 if vulns else False
    right_chart_title = "Open vulnerabilities" if has_vulns else "Findings by severity"
    right_chart = sev_bars(vulns if has_vulns else fcounts)

    cov = d.get("coverage_bars", [])
    notes = "".join(f"<li>{e(x)}</li>" for x in d.get("coverage_notes", []))
    guides = " · ".join(e(g) for g in d.get("guidelines", []))

    page = f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>{e(d.get('title','Security Dashboard'))}</title>
<style>
:root{{--bg:#f5f6f8;--card:#fff;--bd:#e5e7eb;--tx:#0e1116;--mut:#6b7280;--acc:#4f46e5;--track:#eceef1;--head:#fafbfc;}}
.dark{{--bg:#0d0f13;--card:#15181e;--bd:#262b33;--tx:#e7eaf0;--mut:#8b93a3;--acc:#818cf8;--track:#222630;--head:#11141a;}}
*{{box-sizing:border-box}}html{{-webkit-font-smoothing:antialiased}}
body{{margin:0;font:14px/1.55 ui-sans-serif,-apple-system,Segoe UI,Roboto,Helvetica,Arial;background:var(--bg);color:var(--tx)}}
.wrap{{max-width:1180px;margin:0 auto;padding:26px 22px 90px}}
a{{color:var(--acc);text-decoration:none}}a:hover{{text-decoration:underline}}
.bar{{display:flex;justify-content:space-between;align-items:flex-start;gap:16px;flex-wrap:wrap}}
.title{{font-size:21px;font-weight:680;margin:0;letter-spacing:-.2px}}
.sub{{color:var(--mut);font-size:13px;margin-top:3px}}
.sub b{{color:var(--tx);font-weight:600}}
.toggle{{background:var(--card);border:1px solid var(--bd);color:var(--mut);border-radius:8px;padding:7px 11px;cursor:pointer;font-size:13px}}
.card{{background:var(--card);border:1px solid var(--bd);border-radius:12px;padding:18px;box-shadow:0 1px 2px rgba(0,0,0,.03)}}
.grid{{display:grid;gap:14px;margin-top:18px}}
.hero{{grid-template-columns:280px 1fr}}
@media(max-width:820px){{.hero{{grid-template-columns:1fr}}}}
.score-card{{display:flex;flex-direction:column;align-items:center;justify-content:center;gap:6px}}
.ring .ring-num{{font-size:30px;font-weight:720}}.ring .ring-sub{{font-size:11px;fill:var(--mut)}}
.grade-wrap{{display:flex;align-items:center;gap:8px;margin-top:2px}}
.grade{{color:#fff;font-weight:700;font-size:13px;width:26px;height:26px;border-radius:7px;display:grid;place-items:center}}
.grade-lbl{{font-weight:600}}
.kpis{{display:grid;grid-template-columns:repeat(5,1fr);gap:12px}}
@media(max-width:760px){{.kpis{{grid-template-columns:repeat(2,1fr)}}}}
.kpi{{background:var(--card);border:1px solid var(--bd);border-radius:11px;padding:15px 16px}}
.kpi-v{{font-size:26px;font-weight:700;line-height:1}}.kpi-l{{font-size:11.5px;color:var(--mut);margin-top:7px;letter-spacing:.2px;text-transform:uppercase}}
.two{{grid-template-columns:1fr 1fr}}@media(max-width:760px){{.two{{grid-template-columns:1fr}}}}
.card-h{{display:flex;align-items:center;gap:12px;margin-bottom:14px}}.card-h b{{font-size:14px}}
.section-t{{font-size:12px;font-weight:600;color:var(--mut);text-transform:uppercase;letter-spacing:.6px;margin:0 0 14px}}
.cov-row{{margin:13px 0}}.cov-top{{display:flex;justify-content:space-between;font-size:13px;margin-bottom:6px}}
.cov-frac{{color:var(--mut)}}.cov-track{{height:8px;background:var(--track);border-radius:5px;overflow:hidden}}
.cov-fill{{height:100%;border-radius:5px;transition:width .5s}}
.donut-wrap{{display:flex;align-items:center;gap:18px}}.donut-c{{font-size:22px;font-weight:700;fill:var(--tx)}}
.legend{{display:flex;flex-direction:column;gap:7px;font-size:13px}}.lg{{display:flex;align-items:center;gap:8px;color:var(--mut)}}
.lg b{{color:var(--tx)}}.dot{{width:10px;height:10px;border-radius:3px;display:inline-block}}
.sb-row{{display:flex;align-items:center;gap:10px;margin:9px 0;font-size:13px}}.sb-lbl{{width:64px;font-weight:600}}
.sb-track{{flex:1;height:8px;background:var(--track);border-radius:5px;overflow:hidden}}.sb-fill{{display:block;height:100%}}.sb-v{{width:26px;text-align:right;color:var(--mut)}}
.matrix-card .card-h{{flex-wrap:wrap}}
#mq{{flex:1;min-width:140px;background:var(--bg);border:1px solid var(--bd);color:var(--tx);border-radius:8px;padding:7px 11px;font-size:13px}}
.mfilters{{display:flex;gap:5px}}.mf{{background:var(--bg);border:1px solid var(--bd);color:var(--mut);border-radius:7px;padding:5px 11px;cursor:pointer;font-size:12.5px}}.mf.on{{background:var(--acc);border-color:var(--acc);color:#fff}}
.tbl-wrap{{overflow-x:auto;border:1px solid var(--bd);border-radius:10px}}
table{{width:100%;border-collapse:collapse;font-size:13px;min-width:720px}}
thead th{{position:sticky;top:0;background:var(--head);text-align:left;padding:11px 12px;font-weight:600;color:var(--mut);font-size:11.5px;text-transform:uppercase;letter-spacing:.4px;cursor:pointer;white-space:nowrap;border-bottom:1px solid var(--bd)}}
thead th:hover{{color:var(--tx)}}
tbody td{{padding:10px 12px;border-bottom:1px solid var(--bd)}}tbody tr:last-child td{{border-bottom:0}}
tbody tr:hover{{background:var(--head)}}
td.c{{text-align:center;font-weight:700}}.c.ok{{color:#16a34a}}.c.bad{{color:#dc2626}}.c.na{{color:var(--mut)}}
.repo a{{font-weight:600}}.tag{{margin-left:7px;font-size:10px;color:var(--mut);border:1px solid var(--bd);border-radius:5px;padding:1px 5px;text-transform:uppercase}}
.vis{{font-weight:600;font-size:12px}}
.risk{{color:#fff;font-size:10.5px;font-weight:700;padding:3px 8px;border-radius:6px;letter-spacing:.4px}}
.legend-row{{display:flex;gap:18px;flex-wrap:wrap;margin-top:11px;font-size:12px;color:var(--mut)}}
.legend-row .c{{font-weight:700;margin-right:3px}}
.finding{{border:1px solid var(--bd);border-radius:10px;margin:9px 0;overflow:hidden;background:var(--card)}}
.f-h{{display:flex;align-items:center;gap:11px;padding:12px 14px;cursor:pointer}}
.pill{{color:#fff;font-size:9.5px;font-weight:700;padding:3px 7px;border-radius:5px;letter-spacing:.4px}}
.f-id{{color:var(--mut);font-size:11.5px;font-family:ui-monospace,monospace}}.f-t{{flex:1;font-weight:600}}
.f-loc{{color:var(--mut);font-size:12px;font-family:ui-monospace,monospace;max-width:38%;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}}
.chev{{color:var(--mut);transition:.2s}}.finding.open .chev{{transform:rotate(90deg)}}
.f-b{{display:none;padding:2px 14px 15px;border-top:1px solid var(--bd)}}.finding.open .f-b{{display:block}}
.kv{{display:grid;grid-template-columns:96px 1fr;gap:10px;padding:8px 0;border-bottom:1px dashed var(--bd)}}.kv b{{color:var(--mut);font-size:12px}}
.kv code{{font-family:ui-monospace,monospace;font-size:12px;background:var(--bg);padding:2px 6px;border-radius:5px;word-break:break-all}}
.fix{{margin-top:13px;background:var(--acc);color:#fff;border:0;border-radius:8px;padding:9px 15px;font-weight:600;cursor:pointer;font-size:13px}}
.copied{{margin-left:10px;color:#16a34a;font-size:12px;opacity:0;transition:.2s}}.copied.show{{opacity:1}}
.foot{{color:var(--mut);font-size:12px;margin-top:22px}}.foot ul{{margin:8px 0;padding-left:18px}}
</style></head><body><div class="wrap">

<div class="bar">
  <div><h1 class="title">{e(d.get('title','Security Dashboard'))}</h1>
  <div class="sub">Subject: <b>{e(subj)}</b> · {e(', '.join(d.get('scope',[])))} · Generated {e(d.get('generated_at',''))}</div></div>
  <button class="toggle" onclick="document.body.classList.toggle('dark')">◐ Theme</button>
</div>

<div class="grid hero">
  <div class="card score-card"><div class="section-t" style="margin:0 0 8px">Posture score</div>{score_ring(d.get('score',{}))}</div>
  <div class="card"><div class="section-t">Key metrics</div><div class="kpis">{kpi_html(d.get('kpis',[]))}</div>
    <div class="section-t" style="margin:22px 0 6px">Security-control coverage <span style="text-transform:none;font-weight:400">(share of active repos with each control enabled)</span></div>
    {coverage_html(cov)}
  </div>
</div>

<div class="grid two">
  <div class="card"><div class="section-t">Repository visibility</div>{vis_chart}</div>
  <div class="card"><div class="section-t">{right_chart_title}</div>{right_chart}</div>
</div>

<div class="grid">{matrix_html(d.get('repos',[]))}</div>

<div class="grid"><div class="card">
  <div class="section-t">Risk-ranked findings ({len(findings)})</div>
  {findings_html(findings)}
</div></div>

<div class="foot card">
  <b style="color:var(--tx)">Methodology &amp; coverage</b>
  <ul>{notes}</ul>
  <div>Posture score = weighted security-control coverage, penalised for live secret alerts and open critical/high vulnerabilities. Frameworks: {guides}.</div>
  <div style="margin-top:8px">Click <b>🔧 Fix with Claude</b> on any finding to copy a remediation instruction to your clipboard, or run <code>/security-fence fix &lt;ID&gt;</code>. Read-only audit — no repo or setting was modified.</div>
</div>
</div>
<script>
// matrix: search + risk filter + column sort
const mq=document.getElementById('mq');
function applyMatrix(){{
  const q=(mq?mq.value.toLowerCase():'');const rf=document.querySelector('.mf.on').dataset.r;
  document.querySelectorAll('#mtx tbody tr').forEach(tr=>{{
    const okq=tr.dataset.name.includes(q);const okr=(rf==='all'||tr.dataset.risk===rf);
    tr.style.display=(okq&&okr)?'':'none';}});}}
if(mq)mq.oninput=applyMatrix;
document.querySelectorAll('.mf').forEach(b=>b.onclick=()=>{{document.querySelectorAll('.mf').forEach(x=>x.classList.remove('on'));b.classList.add('on');applyMatrix();}});
document.querySelectorAll('#mtx thead th').forEach((th,i)=>{{let asc=true;th.onclick=()=>{{
  const tb=th.closest('table').querySelector('tbody');const rows=[...tb.rows];
  rows.sort((a,b)=>{{const av=a.cells[i].dataset.v??a.cells[i].innerText;const bv=b.cells[i].dataset.v??b.cells[i].innerText;
    const na=parseFloat(av),nb=parseFloat(bv);let r=(!isNaN(na)&&!isNaN(nb))?na-nb:(''+av).localeCompare(''+bv);return asc?r:-r;}});
  asc=!asc;rows.forEach(r=>tb.appendChild(r));}};}});
// findings search not needed; severity already grouped. Fix buttons:
document.querySelectorAll('.fix').forEach(b=>b.onclick=ev=>{{ev.stopPropagation();
  navigator.clipboard.writeText(b.dataset.fix).then(()=>{{const m=b.nextElementSibling;m.classList.add('show');setTimeout(()=>m.classList.remove('show'),2400);}});}});
</script></body></html>"""
    with open(out, "w") as fh:
        fh.write(page)
    return len(findings)


def main():
    n = render(sys.argv[1], sys.argv[2])
    print(f"wrote {sys.argv[2]} ({n} findings)")


if __name__ == "__main__":
    main()
