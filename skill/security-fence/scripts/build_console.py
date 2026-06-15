#!/usr/bin/env python3
"""
ai-security-fence :: security-ops console renderer.

Renders the analytics payload as a dense, monospace, dark "terminal / SIEM"
dashboard — box-drawn panels, block-character meters, green/amber/red only.
Same payload contract as build_dashboard.py (score, kpis, coverage_bars,
charts, repos, findings) so any scanner can target it.

Importable: render(src_json, out_html)
CLI:        python3 build_console.py audit.json console.html
"""
import json, sys, html

OK, WARN, BAD, MUT = "#3fb950", "#d29922", "#f85149", "#6b7785"
SEVCOL = {"critical": BAD, "high": BAD, "medium": WARN, "low": OK, "info": MUT}
SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
GRADECOL = {"A": OK, "B": OK, "C": WARN, "D": WARN, "F": BAD}


def e(s):
    return html.escape(str(s if s is not None else ""))


def pct_col(p):
    return OK if p >= 75 else WARN if p >= 40 else BAD


def meter(pct, width=16):
    """Block-character meter -> (filled_span, empty_span)."""
    fill = round(pct / 100 * width)
    col = pct_col(pct)
    return (f'<span style="color:{col}">{"█"*fill}</span>'
            f'<span style="color:#222a35">{"░"*(width-fill)}</span>')


def panel(legend, body, accent=OK):
    return (f'<section class="panel"><span class="legend" style="color:{accent}">{e(legend)}</span>'
            f'{body}</section>')


def posture(score):
    val = score.get("value", 0)
    grade = score.get("grade", "?")
    col = GRADECOL.get(grade, MUT)
    bar = meter(val, 24)
    return (f'<div class="posture"><span class="pk">POSTURE</span> '
            f'<span class="pbar">[{bar}]</span> '
            f'<span class="pv" style="color:{col}">{val}</span><span class="pmax">/100</span> '
            f'<span class="grade" style="border-color:{col};color:{col}">GRADE {e(grade)}</span> '
            f'<span class="plabel" style="color:{col}">{e(score.get("label",""))}</span></div>')


def stat_line(kpis):
    parts = []
    for k in kpis:
        tone = {"ok": OK, "warn": WARN, "bad": BAD}.get(k.get("tone", ""), "#c9d3df")
        key = e(k.get("label", "")).lower().replace(" ", "-")
        parts.append(f'<span class="st"><span class="sk">{key}:</span>'
                     f'<span style="color:{tone}">{e(k.get("value",""))}</span></span>')
    return '<div class="stats">' + "  ".join(parts) + "</div>"


def coverage(bars):
    rows = []
    for b in bars:
        p = b.get("pct", 0)
        flag = ' <span style="color:#f85149">!!</span>' if p < 40 else ""
        rows.append(f'<div class="cov"><span class="cl">{e(b["label"])}</span>'
                    f'<span class="cm">{meter(p)}</span>'
                    f'<span class="cp" style="color:{pct_col(p)}">{p:>3}%</span>'
                    f'<span class="cf">{b.get("count",0)}/{b.get("total",0)}</span>{flag}</div>')
    return "".join(rows)


def hbars(d, colorfn):
    if not d:
        return '<div class="muted">no data</div>'
    mx = max(d.values()) or 1
    rows = []
    for k, v in sorted(d.items(), key=lambda x: -x[1]):
        col = colorfn(k)
        rows.append(f'<div class="hb"><span class="hbl">{e(k)}</span>'
                    f'<span class="hbm">{meter(round(v/mx*100))}</span>'
                    f'<span class="hbv" style="color:{col}">{v}</span></div>')
    return "".join(rows)


def risk_dot(risk):
    if risk in ("critical", "high"):
        return BAD, "●"
    if risk == "medium":
        return WARN, "●"
    return OK, "○"


def cell(v):
    if v is True:
        return f'<td class="x" data-v="2" style="color:{OK}">✓</td>'
    if v is False:
        return f'<td class="x" data-v="0" style="color:{BAD}">✗</td>'
    return f'<td class="x" data-v="1" style="color:#3a4452">–</td>'


def matrix(repos, owner):
    if not repos:
        return ""
    rows = []
    for r in repos:
        risk = r.get("risk", "low")
        rc, rd = risk_dot(risk)
        vt = sum(r.get("open_vulns", {}).values())
        vis = r.get("visibility", "")
        viscol = WARN if vis == "PUBLIC" else OK
        tag = ""
        if r.get("archived"):
            tag += '<span class="tg">arch</span>'
        if r.get("fork"):
            tag += '<span class="tg">fork</span>'
        rows.append(f'''<tr data-risk="{risk}" data-name="{e(r.get("name","").lower())}">
<td class="rn"><a href="https://github.com/{e(owner)}/{e(r.get("name",""))}" target="_blank" rel="noopener">{e(r.get("name",""))}</a>{tag}</td>
<td data-v="{0 if vis=="PUBLIC" else 2}" style="color:{viscol}">{e(vis.lower())}</td>
{cell(r.get("secret_scanning"))}{cell(r.get("push_protection"))}{cell(r.get("branch_protection"))}{cell(r.get("vuln_alerts"))}
<td class="x" data-v="{vt}" style="color:{BAD if vt else MUT}">{vt}</td>
<td data-v="{4-SEV_ORDER.get(risk,3)}"><span style="color:{rc}">{rd} {risk.upper()}</span></td></tr>''')
    return f'''<div class="mbar"><input id="mq" placeholder="grep repos…">
<span class="mf-wrap"><button class="mf on" data-r="all">all</button><button class="mf" data-r="high">high</button><button class="mf" data-r="medium">med</button><button class="mf" data-r="low">low</button></span></div>
<div class="twrap"><table id="mtx"><thead><tr>
<th data-i="0">repository</th><th data-i="1">vis</th><th data-i="2" title="secret scanning">ss</th><th data-i="3" title="push protection">pp</th><th data-i="4" title="branch protection">bp</th><th data-i="5" title="vuln alerts">va</th><th data-i="6" title="open vulns">cve</th><th data-i="7">risk</th>
</tr></thead><tbody>{"".join(rows)}</tbody></table></div>
<div class="hint">ss·secret-scan  pp·push-prot  bp·branch-prot  va·vuln-alerts  ·  click header to sort</div>'''


def findings(fs):
    if not fs:
        return '<div class="muted">no findings.</div>'
    out = []
    for f in fs:
        s = f.get("severity", "info")
        col = SEVCOL.get(s, MUT)
        out.append(f'''<div class="fd" data-sev="{s}">
<div class="fh" onclick="this.parentElement.classList.toggle('o')">
<span class="sev" style="color:{col};border-color:{col}">{s.upper():>4}</span>
<span class="fid">{e(f.get("id",""))}</span><span class="ft">{e(f.get("title",""))}</span>
<span class="floc">{e(f.get("location",""))}</span></div>
<div class="fb">
<div class="kv"><span class="kk">impact </span>{e(f.get("impact",""))}</div>
<div class="kv"><span class="kk">remedy </span>{e(f.get("remediation",""))}</div>
<div class="kv"><span class="kk">evidence</span><code>{e(f.get("evidence",""))}</code></div>
<button class="fix" data-fix="{e(f.get("fix_prompt",""))}">[ fix with claude ▸ ]</button><span class="cp2">copied ↩</span>
</div></div>''')
    return "".join(out)


def render(src, out):
    d = json.load(open(src))
    fs = sorted(d.get("findings", []), key=lambda f: SEV_ORDER.get(f.get("severity", "info"), 9))
    fcounts = {}
    for f in fs:
        fcounts[f["severity"]] = fcounts.get(f["severity"], 0) + 1
    subj = d.get("subject", "")
    owner = subj.split("/")[-1] if "/" in subj else ""
    charts = d.get("charts", {})
    vis = charts.get("visibility", {})
    vulns = charts.get("vulns_by_severity", {})
    has_vulns = bool(vulns) and sum(vulns.values()) > 0
    right_title = "VULNS BY SEVERITY" if has_vulns else "FINDINGS BY SEVERITY"
    right = hbars(vulns if has_vulns else fcounts, lambda k: SEVCOL.get(k, MUT))
    vis_panel = hbars(vis, lambda k: WARN if k == "PUBLIC" else OK)
    notes = "".join(f"<div>· {e(x)}</div>" for x in d.get("coverage_notes", []))
    guides = "  ".join(e(g) for g in d.get("guidelines", []))

    page = f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>{e(d.get('title','security-fence'))}</title>
<style>
:root{{--bg:#0a0e14;--panel:#0c1118;--line:#1c2531;--tx:#c9d3df;--mut:{MUT};--ok:{OK};--warn:{WARN};--bad:{BAD};}}
*{{box-sizing:border-box}}
body{{margin:0;background:var(--bg);color:var(--tx);
 font:13px/1.5 ui-monospace,"SF Mono","JetBrains Mono",Menlo,Consolas,monospace;
 background-image:radial-gradient(circle at 50% -20%,#10161f 0,#0a0e14 60%);}}
.wrap{{max-width:1080px;margin:0 auto;padding:22px 18px 80px}}
.muted{{color:var(--mut)}}
a{{color:var(--ok)}}a:hover{{text-decoration:underline}}
.prompt{{color:var(--mut);font-size:13px;margin-bottom:4px}}
.prompt .u{{color:var(--ok)}}.prompt .c{{color:var(--tx)}}.cursor{{background:var(--ok);color:var(--bg);animation:bl 1.1s steps(1) infinite}}
@keyframes bl{{50%{{opacity:0}}}}
.title{{font-size:18px;font-weight:700;letter-spacing:.5px;margin:6px 0 2px}}
.sub{{color:var(--mut);font-size:12px;margin-bottom:6px}}.sub b{{color:var(--tx)}}
.panel{{position:relative;border:1px solid var(--line);border-radius:4px;padding:20px 16px 15px;margin-top:20px;background:var(--panel)}}
.legend{{position:absolute;top:-8px;left:13px;background:var(--bg);padding:0 9px;font-size:11px;letter-spacing:2px;text-transform:uppercase}}
.posture{{display:flex;align-items:center;gap:10px;flex-wrap:wrap;font-size:15px}}
.pk{{color:var(--mut);letter-spacing:2px}}.pbar{{letter-spacing:-1px}}.pv{{font-size:22px;font-weight:700}}.pmax{{color:var(--mut)}}
.grade{{border:1px solid;border-radius:3px;padding:2px 8px;font-weight:700;font-size:12px;letter-spacing:1px}}
.plabel{{font-weight:600}}
.stats{{margin-top:12px;color:var(--mut);font-size:13px;display:flex;flex-wrap:wrap;gap:6px 22px}}
.sk{{color:var(--mut);margin-right:3px}}.st{{white-space:nowrap}}
.cov{{display:flex;align-items:center;gap:12px;margin:7px 0;white-space:nowrap}}
.cl{{width:210px;color:var(--tx)}}.cm{{letter-spacing:-1px}}.cp{{width:38px;text-align:right;font-weight:700}}.cf{{color:var(--mut)}}
.cols{{display:grid;grid-template-columns:1fr 1fr;gap:20px}}@media(max-width:720px){{.cols{{grid-template-columns:1fr}}}}
.hb{{display:flex;align-items:center;gap:12px;margin:7px 0;white-space:nowrap}}
.hbl{{width:96px;color:var(--tx)}}.hbm{{letter-spacing:-1px}}.hbv{{font-weight:700}}
.mbar{{display:flex;gap:10px;align-items:center;flex-wrap:wrap;margin-bottom:12px}}
#mq{{flex:1;min-width:140px;background:#070a0f;border:1px solid var(--line);color:var(--tx);border-radius:3px;padding:6px 10px;font:inherit}}
#mq::placeholder{{color:#46505e}}
.mf-wrap{{display:flex;gap:4px}}.mf{{background:#070a0f;border:1px solid var(--line);color:var(--mut);border-radius:3px;padding:5px 11px;cursor:pointer;font:inherit}}
.mf.on{{border-color:var(--ok);color:var(--ok)}}
.twrap{{overflow-x:auto;border:1px solid var(--line);border-radius:3px}}
table{{width:100%;border-collapse:collapse;font-size:12.5px;min-width:680px}}
thead th{{position:sticky;top:0;background:#0e141c;text-align:left;padding:9px 11px;color:var(--mut);
 font-weight:600;letter-spacing:.5px;cursor:pointer;border-bottom:1px solid var(--line);white-space:nowrap;text-transform:uppercase;font-size:11px}}
thead th:hover{{color:var(--ok)}}
tbody td{{padding:7px 11px;border-bottom:1px solid #141b24}}
tbody tr:hover{{background:#0f161f}}tbody tr:last-child td{{border-bottom:0}}
td.x{{text-align:center;font-weight:700}}.rn a{{font-weight:600}}
.tg{{margin-left:7px;color:var(--mut);border:1px solid var(--line);border-radius:3px;padding:0 5px;font-size:10px}}
.hint{{color:var(--mut);font-size:11px;margin-top:9px}}
.fd{{border:1px solid var(--line);border-radius:3px;margin:7px 0;background:#0a0f16}}
.fh{{display:flex;align-items:center;gap:11px;padding:9px 12px;cursor:pointer}}
.sev{{border:1px solid;border-radius:3px;padding:1px 6px;font-size:10px;font-weight:700;letter-spacing:.5px;white-space:pre}}
.fid{{color:var(--mut);font-size:11px}}.ft{{flex:1;font-weight:600}}
.floc{{color:var(--mut);font-size:11.5px;max-width:40%;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}}
.fb{{display:none;padding:4px 12px 13px;border-top:1px solid var(--line)}}.fd.o .fb{{display:block}}
.kv{{display:flex;gap:10px;padding:6px 0;border-bottom:1px dashed #141b24;align-items:baseline}}
.kk{{color:var(--mut);width:74px;flex:none}}.kv code{{color:var(--warn);word-break:break-all}}
.fix{{margin-top:12px;background:transparent;border:1px solid var(--ok);color:var(--ok);border-radius:3px;padding:7px 13px;cursor:pointer;font:inherit}}
.fix:hover{{background:var(--ok);color:var(--bg)}}
.cp2{{margin-left:10px;color:var(--ok);font-size:12px;opacity:0;transition:.2s}}.cp2.show{{opacity:1}}
.foot{{color:var(--mut);font-size:12px;margin-top:18px;border-top:1px solid var(--line);padding-top:14px}}
.foot .gd{{margin-top:8px;color:#52606e}}
</style></head><body><div class="wrap">

<div class="prompt"><span class="u">{e(owner or "user")}@security-fence</span><span class="c">:~$</span> audit {e(subj)} --read-only</div>
<div class="title">{e(d.get('title','security audit'))}</div>
<div class="sub">{e(', '.join(d.get('scope',[])))} · generated {e(d.get('generated_at',''))} · <b>read-only</b></div>

<section class="panel"><span class="legend" style="color:var(--ok)">posture</span>
  {posture(d.get('score',{}))}
  {stat_line(d.get('kpis',[]))}
</section>

{panel("control coverage", coverage(d.get('coverage_bars',[])), WARN)}

<div class="cols">
  {panel("repository visibility", vis_panel)}
  {panel(right_title.lower(), right)}
</div>

{panel("repositories", matrix(d.get('repos',[]), owner))}

{panel(f"findings · {len(fs)}", findings(fs), BAD if any(f.get('severity') in ('critical','high') for f in fs) else WARN)}

<div class="foot">
  <div style="color:var(--tx);letter-spacing:1px">// methodology</div>
  {notes}
  <div class="gd">score = weighted control-coverage, penalised for live secret alerts + open critical/high vulns · frameworks: {guides}</div>
  <div class="gd">[ fix with claude ▸ ] copies a remediation prompt to your clipboard · or run <code style="color:var(--ok)">/security-fence fix &lt;ID&gt;</code> · no repo or setting was modified</div>
  <div style="margin-top:10px;color:var(--ok)">$ <span class="cursor">&nbsp;</span></div>
</div>
</div>
<script>
const mq=document.getElementById('mq');
function applyM(){{const q=mq?mq.value.toLowerCase():'';const rf=document.querySelector('.mf.on').dataset.r;
 document.querySelectorAll('#mtx tbody tr').forEach(tr=>{{tr.style.display=((tr.dataset.name.includes(q))&&(rf==='all'||tr.dataset.risk===rf||(rf==='high'&&tr.dataset.risk==='critical')))?'':'none';}});}}
if(mq)mq.oninput=applyM;
document.querySelectorAll('.mf').forEach(b=>b.onclick=()=>{{document.querySelectorAll('.mf').forEach(x=>x.classList.remove('on'));b.classList.add('on');applyM();}});
document.querySelectorAll('#mtx thead th').forEach((th,i)=>{{let asc=true;th.onclick=()=>{{const tb=th.closest('table').querySelector('tbody');const rows=[...tb.rows];
 rows.sort((a,b)=>{{const av=a.cells[i].dataset.v??a.cells[i].innerText,bv=b.cells[i].dataset.v??b.cells[i].innerText;const na=parseFloat(av),nb=parseFloat(bv);
 let r=(!isNaN(na)&&!isNaN(nb))?na-nb:(''+av).localeCompare(''+bv);return asc?r:-r;}});asc=!asc;rows.forEach(r=>tb.appendChild(r));}};}});
document.querySelectorAll('.fix').forEach(b=>b.onclick=ev=>{{ev.stopPropagation();navigator.clipboard.writeText(b.dataset.fix).then(()=>{{const m=b.nextElementSibling;m.classList.add('show');setTimeout(()=>m.classList.remove('show'),2400);}});}});
</script></body></html>"""
    with open(out, "w") as fh:
        fh.write(page)
    return len(fs)


def main():
    print(f"wrote {sys.argv[2]} ({render(sys.argv[1], sys.argv[2])} findings)")


if __name__ == "__main__":
    main()
