#!/usr/bin/env python3
"""
ai-security-fence :: deterministic scan orchestrator.

Runs the local-surface scanner + the external OSS-engine orchestrator, merges
and de-duplicates the findings, records honest coverage (what ran / was skipped),
and writes a combined findings JSON. Optionally renders the HTML dashboard.

This covers everything that does NOT need network/MCP access. The skill then
appends GitHub / Redash / MCP findings to the JSON before the final render.

Usage:
    python3 run_scan.py --target . --out findings.json [--html report.html]
                        [--no-config-surface] [--no-engines]
"""
import argparse, json, os, re, sys, datetime

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import scan_local
import scan_engines

SEV_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
_FP = re.compile(r"fp=([0-9a-f]{6})")


def aggregate(findings):
    """Collapse the SAME secret value found in many places into one finding."""
    groups, singles = {}, []
    for f in findings:
        m = _FP.search(f.get("evidence", ""))
        if m and f.get("surface") in ("Local", "Secrets"):
            groups.setdefault((f.get("title", ""), m.group(1)), []).append(f)
        else:
            singles.append(f)
    out = list(singles)
    for grp in groups.values():
        if len(grp) == 1:
            out.append(grp[0])
            continue
        grp.sort(key=lambda f: SEV_RANK.get(f.get("severity", "info"), 9))
        locs = [g.get("location", "?") for g in grp]
        shown = "; ".join(locs[:5]) + (f"  (+{len(locs)-5} more)" if len(locs) > 5 else "")
        base = dict(grp[0])  # most-severe
        base["location"] = f"{len(locs)} locations: {shown}"
        base["impact"] = (f"The SAME secret value is hardcoded in {len(locs)} places — "
                          "so one rotation must update all of them. ") + base.get("impact", "")
        base["fix_prompt"] = (f"This identical secret appears in {len(locs)} files ({shown}). "
                              "Remove it from ALL of them, replace with a single env/secret-store "
                              "reference, and rotate the credential.")
        out.append(base)
    return out


def merge(*lists):
    out, seen = [], set()
    for lst in lists:
        for f in lst:
            key = (f.get("title", ""), f.get("location", ""))
            if key in seen:
                continue
            seen.add(key)
            out.append(f)
    out = aggregate(out)
    out.sort(key=lambda f: (SEV_RANK.get(f.get("severity", "info"), 9), f.get("surface", "")))
    for i, f in enumerate(out, 1):
        f["id"] = "SEC-%03d" % i
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--target", default=os.getcwd())
    ap.add_argument("--out", default="findings.json")
    ap.add_argument("--html", default=None)
    ap.add_argument("--no-config-surface", action="store_true")
    ap.add_argument("--no-engines", action="store_true")
    ap.add_argument("--stamp", default=None, help="generated_at label (callers pass a timestamp)")
    a = ap.parse_args()

    coverage, findings = [], []
    local_f, local_cov = scan_local.collect_local(
        target=a.target, config_surface=not a.no_config_surface)
    findings += local_f
    coverage += ["[local] " + c for c in local_cov]

    if not a.no_engines:
        eng_f, eng_cov = scan_engines.collect_engines(a.target)
        findings += eng_f
        coverage += ["[engine] " + c for c in eng_cov]
    else:
        coverage.append("[engine] external scanners skipped (--no-engines)")

    merged = merge(findings)
    stamp = a.stamp or datetime.datetime.now().strftime("%Y-%m-%d %H:%M")
    doc = {
        "generated_at": stamp,
        "scanned": ["Local config & memory", "Project secrets", "Code (SAST)", "Dependencies (SCA)"],
        "coverage": coverage,
        "guidelines": ["OWASP Top 10", "OWASP LLM Top 10 (LLM06/LLM08)",
                       "CWE-798 hardcoded credentials", "CWE-312 cleartext storage",
                       "CIS file-permission benchmarks", "12-Factor config/secrets"],
        "findings": merged,
    }
    with open(a.out, "w") as fh:
        json.dump(doc, fh, indent=2)
    print(f"wrote {a.out}: {len(merged)} findings")
    for c in coverage:
        print("  " + c)

    if a.html:
        import build_report
        build_report.render(a.out, a.html)
        print(f"wrote {a.html}")


if __name__ == "__main__":
    main()
