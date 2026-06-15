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


def analytics(findings, coverage, target, stamp):
    """Turn merged findings into the dashboard payload (score, kpis, panels)."""
    import collections
    sev = collections.Counter(f.get("severity", "info") for f in findings)
    surf = collections.Counter(f.get("surface", "Other") for f in findings)
    types = collections.Counter(f.get("title", "?").replace("Plaintext ", "").replace(" on disk", "")
                                for f in findings)

    def root(loc):
        p = loc.split(":")[0].split(";")[0]
        if p.startswith(("0", "1", "2", "3", "4", "5", "6", "7", "8", "9")) and "locations" in loc:
            p = loc.split(":", 1)[-1].split(";")[0].strip()
        parts = p.strip().strip("~/").split("/")
        return "/".join(parts[:3]) if len(parts) > 3 else "/".join(parts[:-1]) or p
    dirs = collections.Counter(root(f.get("location", "?")) for f in findings)

    crit, high, med, low = sev["critical"], sev["high"], sev["medium"], sev["low"]
    score = max(0, min(100, round(100 - 18 * crit - 6 * high - 1 * med - 0.2 * low)))
    grade = ("A" if score >= 90 else "B" if score >= 75 else "C" if score >= 60
             else "D" if score >= 40 else "F")
    label = {"A": "Strong", "B": "Good", "C": "Needs work", "D": "At risk", "F": "Critical"}[grade]
    secrets = sum(1 for f in findings if f.get("surface") in ("Local", "Secrets"))

    return {
        "title": "Local & Project Security Audit",
        "subject": os.path.abspath(os.path.expanduser(target)),
        "scope": ["Local config & memory", "Project secrets", "Code (SAST)", "Dependencies (SCA)"],
        "generated_at": stamp,
        "score": {"value": score, "grade": grade, "label": label},
        "kpis": [
            {"label": "Findings", "value": len(findings)},
            {"label": "Critical", "value": crit, "tone": "bad" if crit else "ok"},
            {"label": "High", "value": high, "tone": "bad" if high else "ok"},
            {"label": "Secrets", "value": secrets, "tone": "warn" if secrets else "ok"},
            {"label": "Surfaces", "value": len(surf)},
        ],
        "panels": [
            {"title": "findings by surface", "bars": dict(surf)},
            {"title": "findings by type", "bars": dict(types.most_common(8))},
            {"title": "most-affected locations", "bars": dict(dirs.most_common(8))},
        ],
        "coverage": coverage,
        "coverage_notes": coverage,
        "guidelines": ["OWASP Top 10", "OWASP LLM Top 10 (LLM06/LLM08)",
                       "CWE-798 hardcoded credentials", "CWE-312 cleartext storage", "CIS benchmarks"],
        "findings": findings,
    }


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
    doc = analytics(merged, coverage, a.target, stamp)
    with open(a.out, "w") as fh:
        json.dump(doc, fh, indent=2)
    print(f"wrote {a.out}: {len(merged)} findings · score {doc['score']['value']}/{doc['score']['grade']}")
    for c in coverage:
        print("  " + c)

    if a.html:
        import build_console
        build_console.render(a.out, a.html)
        print(f"wrote {a.html}")


if __name__ == "__main__":
    main()
