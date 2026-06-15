#!/usr/bin/env python3
"""
ai-security-fence :: security-ops console renderer (monochrome).

Renders the analytics payload as a dense, monospace, near-monochrome dark
"scanner" UI: black + grayscale + a SINGLE blue accent (no green/amber/red).
Flat hairline chrome, collapsible sections, and risk/severity-grouped
collapsible tables. Same payload contract as build_dashboard.py.

Importable: render(src_json, out_html)
CLI:        python3 build_console.py audit.json console.html
"""
import json, sys, html

# severity -> text brightness only (no hue); worst = brightest/heaviest
SEV_TX = {"critical": "#ffffff", "high": "#e4ebf2", "medium": "#929ca7",
          "low": "#646d77", "info": "#646d77"}
SEV_MARK = {"critical": "■", "high": "■", "medium": "▪", "low": "·", "info": "·"}
SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
RISK_ORDER = ["critical", "high", "medium", "low"]


def e(s):
    return html.escape(str(s if s is not None else ""))


def meter(pct, width=18):
    fill = round(pct / 100 * width)
    return (f'<span class="mf">{"█" * fill}</span>'
            f'<span class="me">{"█" * (width - fill)}</span>')


def section(legend, body, count=None, open_=True):
    cnt = f'<span class="cnt">{count}</span>' if count is not None else ""
    return (f'<section class="sec{" open" if open_ else ""}">'
            f'<div class="sh" onclick="this.parentElement.classList.toggle(\'open\')">'
            f'<span class="tw">▸</span><span class="sl">{e(legend)}</span>{cnt}</div>'
            f'<div class="sb">{body}</div></section>')


def posture(score):
    val = score.get("value", 0)
    grade = score.get("grade", "?")
    return (f'<div class="posture"><span class="pk">POSTURE</span>'
            f'<span class="pbar">[{meter(val, 26)}]</span>'
            f'<span class="pv">{val}</span><span class="pmax">/100</span>'
            f'<span class="grade">GRADE {e(grade)}</span>'
            f'<span class="plabel">{e(score.get("label",""))}</span></div>')


def stat_line(kpis):
    parts = []
    for k in kpis:
        key = e(k.get("label", "")).lower().replace(" ", "-")
        strong = k.get("tone") in ("warn", "bad")
        cls = "sv hot" if strong else "sv"
        parts.append(f'<span class="st"><span class="sk">{key}</span>'
                     f'<span class="{cls}">{e(k.get("value",""))}</span></span>')
    return '<div class="stats">' + "".join(parts) + "</div>"


def coverage(bars):
    rows = []
    for b in bars:
        p = b.get("pct", 0)
        flag = '<span class="lowflag">below&nbsp;baseline</span>' if p < 40 else ""
        rows.append(f'<div class="cov"><span class="cl">{e(b["label"])}</span>'
                    f'<span class="cm">{meter(p)}</span>'
                    f'<span class="cp">{p:>3}%</span>'
                    f'<span class="cf">{b.get("count",0)}/{b.get("total",0)}</span>{flag}</div>')
    return "".join(rows)


def hbars(d):
    if not d:
        return '<div class="dim">no data</div>'
    mx = max(d.values()) or 1
    rows = []
    for k, v in sorted(d.items(), key=lambda x: -x[1]):
        lbl = e(k).lower()
        rows.append(f'<div class="hb"><span class="hbl" title="{lbl}">{lbl}</span>'
                    f'<span class="hbm">{meter(round(v/mx*100), 12)}</span>'
                    f'<span class="hbv">{v}</span></div>')
    return "".join(rows)


def cell(v):
    if v is True:
        return '<td class="x on" data-v="2">✓</td>'
    if v is False:
        return '<td class="x off" data-v="0">✗</td>'
    return '<td class="x na" data-v="1">·</td>'


def matrix(repos, owner):
    if not repos:
        return ""
    groups = {r: [] for r in RISK_ORDER}
    for r in repos:
        groups.setdefault(r.get("risk", "low"), []).append(r)
    rows = []
    for risk in RISK_ORDER:
        grp = groups.get(risk, [])
        if not grp:
            continue
        bright = SEV_TX.get(risk, "#646d77")
        rows.append(f'<tr class="grp open" data-g="{risk}" onclick="tg(this)">'
                    f'<td colspan="8"><span class="tw">▸</span>'
                    f'<span style="color:{bright}">{SEV_MARK.get(risk,"·")} {risk.upper()}</span>'
                    f'<span class="gc">{len(grp)}</span></td></tr>')
        for r in grp:
            vt = sum(r.get("open_vulns", {}).values())
            vis = r.get("visibility", "").lower()
            tag = ""
            if r.get("archived"):
                tag += '<span class="tg">arch</span>'
            if r.get("fork"):
                tag += '<span class="tg">fork</span>'
            rows.append(f'''<tr class="r" data-g="{risk}" data-name="{e(r.get("name","").lower())}">
<td class="rn"><a href="https://github.com/{e(owner)}/{e(r.get("name",""))}" target="_blank" rel="noopener">{e(r.get("name",""))}</a>{tag}</td>
<td class="{'pub' if vis=='public' else 'dim'}">{e(vis)}</td>
{cell(r.get("secret_scanning"))}{cell(r.get("push_protection"))}{cell(r.get("branch_protection"))}{cell(r.get("vuln_alerts"))}
<td class="x {'hot' if vt else 'na'}">{vt}</td>
<td><span class="rsk" style="color:{SEV_TX.get(risk,'#646d77')}">{SEV_MARK.get(risk,'·')} {risk.upper()}</span></td></tr>''')
    return f'''<div class="mbar"><input id="mq" placeholder="grep repository name…"></div>
<div class="twrap"><table id="mtx"><thead><tr>
<th>repository</th><th>vis</th><th title="secret scanning">ss</th><th title="push protection">pp</th><th title="branch protection">bp</th><th title="vuln alerts">va</th><th title="open vulns">cve</th><th>risk</th>
</tr></thead><tbody>{"".join(rows)}</tbody></table></div>
<div class="hint">ss secret-scan · pp push-prot · bp branch-prot · va vuln-alerts · click a group to fold</div>'''


def findings_grouped(fs):
    if not fs:
        return '<div class="dim">no findings.</div>'
    groups = {}
    for f in fs:
        groups.setdefault(f.get("severity", "info"), []).append(f)
    out = []
    for sev in ["critical", "high", "medium", "low", "info"]:
        grp = groups.get(sev, [])
        if not grp:
            continue
        bright = SEV_TX.get(sev, "#646d77")
        items = []
        for f in grp:
            items.append(f'''<div class="fd">
<div class="fh" onclick="this.parentElement.classList.toggle('o')">
<span class="tw">▸</span><span class="fid">{e(f.get("id",""))}</span>
<span class="ft">{e(f.get("title",""))}</span><span class="floc">{e(f.get("location",""))}</span></div>
<div class="fb">
<div class="kv"><span class="kk">impact</span><span>{e(f.get("impact",""))}</span></div>
<div class="kv"><span class="kk">remedy</span><span>{e(f.get("remediation",""))}</span></div>
<div class="kv"><span class="kk">evidence</span><code>{e(f.get("evidence",""))}</code></div>
<button class="fix" data-fix="{e(f.get("fix_prompt",""))}">[ fix with claude ]</button><span class="cp2">copied to clipboard</span>
</div></div>''')
        out.append(f'''<div class="fgrp open">
<div class="fgh" onclick="this.parentElement.classList.toggle('open')">
<span class="tw">▸</span><span style="color:{bright}">{SEV_MARK.get(sev,'·')} {sev.upper()}</span><span class="gc">{len(grp)}</span></div>
<div class="fgb">{"".join(items)}</div></div>''')
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

    # Build the analytics grid: severity always, visibility if present, plus any
    # extra panels the scanner injected (works for GitHub and the full local scan).
    mini = []
    if vis:
        mini.append(("repository visibility", vis))
    mini.append(("vulns by severity" if has_vulns else "findings by severity",
                 {k.upper(): v for k, v in (vulns if has_vulns else fcounts).items()}))
    for p in d.get("panels", []):
        if p.get("bars"):
            mini.append((p.get("title", ""), p["bars"]))
    panels_grid = '<div class="cols">' + "".join(section(t, hbars(b)) for t, b in mini) + "</div>"
    notes = "".join(f"<div>· {e(x)}</div>" for x in d.get("coverage_notes", []))
    guides = "  ·  ".join(e(g) for g in d.get("guidelines", []))

    page = f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>{e(d.get('title','security-fence'))}</title>
<style>
:root{{--bg:#0a0c0f;--panel:#0c0f13;--line:#181d23;--line2:#11151a;--tx:#cdd4db;--dim:#79828c;--faint:#49525b;
 --acc:#4c9eff;--accdim:#21384f;--meterempty:#1b2128;}}
*{{box-sizing:border-box}}
body{{margin:0;background:var(--bg);color:var(--tx);
 font:13px/1.55 ui-monospace,"SF Mono","JetBrains Mono",Menlo,Consolas,monospace}}
.wrap{{max-width:1060px;margin:0 auto;padding:24px 20px 90px}}
.dim{{color:var(--dim)}}
a{{color:var(--acc);text-decoration:none}}a:hover{{text-decoration:underline}}
.prompt{{color:var(--faint);font-size:13px;margin-bottom:6px}}
.prompt .u{{color:var(--acc)}}.prompt .arg{{color:var(--dim)}}
.cursor{{display:inline-block;width:8px;height:14px;background:var(--acc);vertical-align:-2px;animation:bl 1.1s steps(1) infinite}}
@keyframes bl{{50%{{opacity:0}}}}
.title{{font-size:18px;font-weight:700;letter-spacing:.4px;margin:4px 0 2px;color:#e9eef3}}
.sub{{color:var(--dim);font-size:12px;margin-bottom:14px}}.sub b{{color:var(--tx);font-weight:600}}

.sec{{border:1px solid var(--line);border-radius:3px;margin-top:14px;background:var(--panel)}}
.sh{{display:flex;align-items:center;gap:8px;padding:10px 13px;cursor:pointer;user-select:none}}
.sh:hover .sl{{color:var(--tx)}}
.sl{{font-size:11px;letter-spacing:2px;text-transform:uppercase;color:var(--dim)}}
.cnt{{color:var(--faint);font-size:11px}}
.tw{{color:var(--acc);font-size:10px;transition:transform .15s;display:inline-block}}
.sec.open>.sh>.tw,.grp.open>td>.tw,.fgrp.open>.fgh>.tw,.fd.o>.fh>.tw{{transform:rotate(90deg)}}
.sb{{display:none;padding:4px 14px 15px;border-top:1px solid var(--line2)}}.sec.open>.sb{{display:block}}

.posture{{display:flex;align-items:center;gap:12px;flex-wrap:wrap;font-size:15px;padding-top:8px}}
.pk{{color:var(--dim);letter-spacing:2px;font-size:12px}}
.pbar .mf{{color:var(--acc)}}.pbar .me{{color:var(--meterempty)}}.pbar{{letter-spacing:-1px}}
.pv{{font-size:22px;font-weight:700;color:#fff}}.pmax{{color:var(--faint)}}
.grade{{border:1px solid var(--accdim);color:var(--tx);border-radius:3px;padding:2px 9px;font-weight:700;font-size:12px;letter-spacing:1px}}
.plabel{{color:var(--dim);font-weight:600}}
.stats{{margin-top:14px;display:flex;flex-wrap:wrap;gap:7px 26px;font-size:13px}}
.st{{white-space:nowrap}}.sk{{color:var(--faint);margin-right:7px}}.sv{{color:var(--tx)}}.sv.hot{{color:#fff;font-weight:600}}

.mf{{color:var(--acc)}}.me{{color:var(--meterempty)}}
.cov{{display:flex;align-items:center;gap:14px;margin:8px 0;white-space:nowrap}}
.cl{{width:220px;color:var(--tx)}}.cm{{letter-spacing:-1px;font-size:12px}}
.cp{{width:40px;text-align:right;font-weight:700;color:var(--tx)}}.cf{{color:var(--faint)}}
.lowflag{{color:var(--acc);font-size:11px;border:1px solid var(--accdim);border-radius:3px;padding:0 6px}}
.cols{{display:grid;grid-template-columns:repeat(auto-fit,minmax(280px,1fr));gap:14px}}
.hb{{display:grid;grid-template-columns:1fr auto auto;align-items:center;gap:10px;margin:8px 0}}
.hbl{{color:var(--dim);overflow:hidden;text-overflow:ellipsis;white-space:nowrap}}
.hbm{{letter-spacing:-1px;font-size:12px;white-space:nowrap}}.hbv{{font-weight:700;color:var(--tx);text-align:right;min-width:26px}}

.mbar{{margin:4px 0 12px}}
#mq{{width:100%;background:#06080b;border:1px solid var(--line);color:var(--tx);border-radius:3px;padding:8px 11px;font:inherit}}
#mq:focus{{outline:none;border-color:var(--accdim)}}#mq::placeholder{{color:var(--faint)}}
.twrap{{border:1px solid var(--line);border-radius:3px;overflow-x:auto}}
table{{width:100%;border-collapse:collapse;font-size:12.5px;min-width:660px}}
thead th{{text-align:left;padding:9px 12px;color:var(--faint);font-weight:600;letter-spacing:.5px;
 text-transform:uppercase;font-size:11px;border-bottom:1px solid var(--line);white-space:nowrap;background:#0a0d11}}
tbody td{{padding:7px 12px;border-bottom:1px solid var(--line2)}}
tbody tr.r:hover{{background:#0f141a}}
tr.grp{{cursor:pointer;user-select:none;background:#0b0e12}}tr.grp:hover td{{color:var(--tx)}}
tr.grp td{{padding:8px 12px;border-bottom:1px solid var(--line);letter-spacing:1px;font-size:11.5px}}
tr.grp .tw{{margin-right:8px}}.gc{{color:var(--faint);margin-left:9px}}
td.x{{text-align:center;font-weight:700}}.x.on{{color:var(--tx)}}.x.off{{color:var(--dim)}}.x.na{{color:var(--faint)}}.x.hot{{color:#fff}}
.rn a{{font-weight:600}}.pub{{color:var(--tx)}}
.tg{{margin-left:8px;color:var(--faint);border:1px solid var(--line);border-radius:3px;padding:0 5px;font-size:10px}}
.rsk{{font-size:11.5px;letter-spacing:.5px}}
.hint{{color:var(--faint);font-size:11px;margin-top:10px}}

.fgrp{{border:1px solid var(--line);border-radius:3px;margin:8px 0;background:var(--panel)}}
.fgh{{display:flex;align-items:center;gap:9px;padding:9px 12px;cursor:pointer;user-select:none;letter-spacing:1px;font-size:12px}}
.fgb{{display:none;padding:2px 10px 10px}}.fgrp.open>.fgb{{display:block}}
.fd{{border:1px solid var(--line);border-radius:3px;margin:6px 0;background:#0a0d11}}
.fh{{display:flex;align-items:center;gap:10px;padding:8px 11px;cursor:pointer}}
.fh:hover .ft{{color:#fff}}
.fid{{color:var(--faint);font-size:11px;min-width:52px}}.ft{{flex:1;color:var(--tx)}}
.floc{{color:var(--faint);font-size:11.5px;max-width:42%;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}}
.fb{{display:none;padding:3px 12px 12px;border-top:1px solid var(--line2)}}.fd.o>.fb{{display:block}}
.kv{{display:flex;gap:10px;padding:6px 0;border-bottom:1px solid var(--line2)}}
.kk{{color:var(--faint);width:72px;flex:none;text-transform:uppercase;font-size:11px}}
.kv code{{color:var(--acc);word-break:break-all}}
.fix{{margin-top:12px;background:transparent;border:1px solid var(--accdim);color:var(--acc);border-radius:3px;padding:7px 14px;cursor:pointer;font:inherit}}
.fix:hover{{background:var(--acc);color:#04070a}}
.cp2{{margin-left:11px;color:var(--acc);font-size:12px;opacity:0;transition:.2s}}.cp2.show{{opacity:1}}
.foot{{color:var(--faint);font-size:12px;margin-top:18px;border-top:1px solid var(--line);padding-top:14px}}
.foot .lbl{{color:var(--dim);letter-spacing:1px}}.foot code{{color:var(--acc)}}
/* responsive */
@media(max-width:640px){{
  .wrap{{padding:16px 12px 70px}}
  .prompt,.title,.sub{{word-break:break-word}}
  .title{{font-size:16px}}
  .posture{{font-size:13px;gap:8px}}.pv{{font-size:19px}}
  .stats{{gap:6px 16px;font-size:12px}}
  .cov{{flex-wrap:wrap;gap:4px 10px}}.cl{{width:100%;}}.cm{{order:3}}.cp{{order:2}}.cf{{order:4}}
  .hb{{gap:8px}}.hbl{{width:78px}}
  .floc{{display:none}}
  table{{min-width:520px;font-size:12px}}
  thead th,tbody td{{padding:7px 8px}}
  .kv{{flex-direction:column;gap:2px}}.kk{{width:auto}}
}}
@media(max-width:380px){{table{{min-width:440px}}.cm .me,.cm .mf{{letter-spacing:-2px}}}}
</style></head><body><div class="wrap">

<div class="prompt"><span class="u">{e(owner or "user")}@security-fence</span>:~$ <span class="arg">audit {e(subj)} --read-only</span></div>
<div class="title">{e(d.get('title','security audit'))}</div>
<div class="sub">{e(', '.join(d.get('scope',[])))} · generated {e(d.get('generated_at',''))} · <b>read-only</b></div>

<section class="sec open"><div class="sh" onclick="this.parentElement.classList.toggle('open')"><span class="tw">▸</span><span class="sl">posture</span></div>
<div class="sb">{posture(d.get('score',{}))}{stat_line(d.get('kpis',[]))}</div></section>

{section("control coverage", coverage(d.get('coverage_bars',[]))) if d.get('coverage_bars') else ""}

{panels_grid}

{section("repositories", matrix(d.get('repos',[]), owner), count=len(d.get('repos',[]))) if d.get('repos') else ""}

{section("findings", findings_grouped(fs), count=len(fs))}

<div class="foot">
  <div class="lbl">// methodology</div>
  {notes}
  <div style="margin-top:8px">score = weighted control-coverage, penalised for live secret alerts &amp; open critical/high vulns · {guides}</div>
  <div style="margin-top:6px">[ fix with claude ] copies a remediation prompt · or run <code>/security-fence fix &lt;ID&gt;</code> · no repo or setting was modified</div>
  <div style="margin-top:12px"><span class="dim">$</span> <span class="cursor"></span></div>
</div>
</div>
<script>
function tg(tr){{tr.classList.toggle('open');const g=tr.dataset.g,show=tr.classList.contains('open');
 let n=tr.nextElementSibling;while(n&&!n.classList.contains('grp')){{if(n.dataset.g===g)n.style.display=show?'':'none';n=n.nextElementSibling;}}}}
const mq=document.getElementById('mq');
if(mq)mq.oninput=()=>{{const q=mq.value.toLowerCase();
 document.querySelectorAll('#mtx tbody tr.r').forEach(tr=>{{tr.style.display=tr.dataset.name.includes(q)?'':'none';}});
 document.querySelectorAll('#mtx tbody tr.grp').forEach(g=>{{g.style.display=q?'none':'';}});}};
document.querySelectorAll('.fix').forEach(b=>b.onclick=ev=>{{ev.stopPropagation();
 navigator.clipboard.writeText(b.dataset.fix).then(()=>{{const m=b.nextElementSibling;m.classList.add('show');setTimeout(()=>m.classList.remove('show'),2400);}});}});
</script></body></html>"""
    with open(out, "w") as fh:
        fh.write(page)
    return len(fs)


def main():
    print(f"wrote {sys.argv[2]} ({render(sys.argv[1], sys.argv[2])} findings)")


if __name__ == "__main__":
    main()
