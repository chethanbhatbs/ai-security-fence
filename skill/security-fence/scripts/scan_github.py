#!/usr/bin/env python3
"""
ai-security-fence :: GitHub security auditor (READ-ONLY).

Uses the authenticated `gh` CLI to pull REAL structured security data for every
repo on an account/org, then emits an analytics payload (posture score, control
coverage, per-repo security matrix, vulnerability breakdown) + risk-ranked
findings — consumed by build_dashboard.py.

Read-only: only GET/list calls. Never changes a repo or remote setting.

Usage:
    python3 scan_github.py [--owner LOGIN] [--limit 300] > github.json
"""
import argparse, json, subprocess, datetime, re

SEV_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
# repo-name signals that a PUBLIC repo might hold internal/work content
SENSITIVE_HINT = re.compile(r"(eval|internal|qa|client|secret|cred|private|prod|staging|backend|infra|admin|customer|invoice|payroll|worklog)", re.I)


def gh(args, timeout=60):
    try:
        p = subprocess.run(["gh"] + args, capture_output=True, text=True, timeout=timeout)
        return p.returncode, p.stdout, p.stderr
    except Exception as e:
        return -1, "", str(e)


def gh_json(args):
    rc, out, _ = gh(args)
    if rc != 0 or not out.strip():
        return None
    try:
        return json.loads(out)
    except Exception:
        return None


def api_status(path):
    """Return ('ok'|'missing'|'forbidden'|'error', json_or_None) for a GET."""
    rc, out, err = gh(["api", "-i", path])
    head = out[:400] if out else err
    if "HTTP/" in head:
        code = re.search(r"HTTP/[\d.]+ (\d+)", head)
        code = int(code.group(1)) if code else 0
        body = out.split("\r\n\r\n", 1)[-1] if "\r\n\r\n" in out else out.split("\n\n", 1)[-1]
        data = None
        try:
            data = json.loads(body)
        except Exception:
            pass
        if code in (200, 204):
            return "ok", data
        if code in (403, 401):
            return "forbidden", data
        if code == 404:
            return "missing", data
        return "error", data
    if "404" in err:
        return "missing", None
    if "403" in err or "401" in err:
        return "forbidden", None
    return "error", None


def audit_repo(owner, r):
    name = r["name"]
    full = f"{owner}/{name}"
    vis = (r.get("visibility") or ("PRIVATE" if r.get("isPrivate") else "PUBLIC")).upper()
    rec = {"name": name, "visibility": vis, "archived": r.get("isArchived", False),
           "fork": r.get("isFork", False), "pushed_at": (r.get("pushedAt") or "")[:10],
           "default_branch": (r.get("defaultBranchRef") or {}).get("name") or "main",
           "secret_scanning": None, "push_protection": None, "branch_protection": None,
           "vuln_alerts": None, "open_vulns": {"critical": 0, "high": 0, "medium": 0, "low": 0},
           "secret_alerts": 0}

    detail = gh_json(["api", f"repos/{full}"])
    if isinstance(detail, dict):
        saa = detail.get("security_and_analysis") or {}
        ss = (saa.get("secret_scanning") or {}).get("status")
        pp = (saa.get("secret_scanning_push_protection") or {}).get("status")
        rec["secret_scanning"] = (ss == "enabled") if ss else None
        rec["push_protection"] = (pp == "enabled") if pp else None

    st, _ = api_status(f"repos/{full}/branches/{rec['default_branch']}/protection")
    rec["branch_protection"] = (st == "ok") if st in ("ok", "missing") else None

    st, _ = api_status(f"repos/{full}/vulnerability-alerts")
    rec["vuln_alerts"] = (st == "ok") if st in ("ok", "missing") else None

    alerts = gh_json(["api", f"repos/{full}/dependabot/alerts?state=open&per_page=100"])
    if isinstance(alerts, list):
        for a in alerts:
            sev = ((a.get("security_advisory") or {}).get("severity") or "low").lower()
            sev = {"moderate": "medium"}.get(sev, sev)
            if sev in rec["open_vulns"]:
                rec["open_vulns"][sev] += 1

    sa = gh_json(["api", f"repos/{full}/secret-scanning/alerts?state=open&per_page=100"])
    if isinstance(sa, list):
        rec["secret_alerts"] = len(sa)

    # risk rollup for the matrix
    v = rec["open_vulns"]
    if rec["secret_alerts"] or v["critical"]:
        rec["risk"] = "critical"
    elif v["high"] or (vis == "PUBLIC" and SENSITIVE_HINT.search(name)):
        rec["risk"] = "high"
    elif (rec["secret_scanning"] is False) or (rec["push_protection"] is False) or v["medium"]:
        rec["risk"] = "medium"
    else:
        rec["risk"] = "low"
    return rec


def build_findings(owner, repos):
    out = []

    def add(sev, surface, title, location, evidence, impact, remediation, fix_prompt):
        out.append({"severity": sev, "surface": surface, "title": title, "location": location,
                    "evidence": evidence, "impact": impact, "remediation": remediation,
                    "fix_prompt": fix_prompt})

    for r in repos:
        full = f"{owner}/{r['name']}"
        if r["secret_alerts"]:
            add("critical", "Secret scanning", f"{r['secret_alerts']} open secret-scanning alert(s)",
                full, f"{r['secret_alerts']} live secret(s) detected",
                "GitHub detected committed secrets that are still active in this repo.",
                "Revoke/rotate each secret, then resolve the alerts; purge from history.",
                f"List the open secret-scanning alerts for {full} and walk me through rotating and resolving each one.")
        v = r["open_vulns"]
        if v["critical"] or v["high"]:
            sev = "critical" if v["critical"] else "high"
            add(sev, "Dependencies", f"{v['critical']+v['high']} critical/high Dependabot alert(s)",
                full, f"critical={v['critical']} high={v['high']}",
                "Known-vulnerable dependencies with available fixes are in use.",
                "Merge Dependabot PRs / bump the affected packages; enable auto-merge for security updates.",
                f"Show the open critical/high Dependabot alerts for {full} and prepare the dependency upgrades.")
        if r["visibility"] == "PUBLIC" and SENSITIVE_HINT.search(r["name"]) and not r["archived"]:
            add("high", "Visibility", "Public repo with internal-sounding name",
                full, f"visibility=PUBLIC, name='{r['name']}'",
                "The name suggests internal/work/eval/client content; if so, it is world-readable including its full history.",
                "Confirm the contents; if internal, switch the repo to private (Settings → Danger Zone → Change visibility).",
                f"Help me review whether {full} should be public; if not, give the exact steps to make it private safely.")
        if r["secret_scanning"] is False:
            add("medium", "Hardening", "Secret scanning disabled", full, "secret_scanning=disabled",
                "Committed secrets won't be detected automatically.",
                "Enable secret scanning (free on public repos) in repo Settings → Code security.",
                f"Give steps to enable secret scanning for {full}.")
        if r["push_protection"] is False:
            add("medium", "Hardening", "Push protection disabled", full, "push_protection=disabled",
                "Secrets can be pushed without being blocked.",
                "Enable push protection in Settings → Code security.",
                f"Give steps to enable secret-scanning push protection for {full}.")
        if r["branch_protection"] is False and not r["archived"] and not r["fork"]:
            add("low", "Hardening", "No branch protection on default branch",
                f"{full}@{r['default_branch']}", "no protection rule",
                "Anyone with write access can force-push or bypass review on the default branch.",
                "Add a branch protection / ruleset requiring PR review on the default branch.",
                f"Give steps to add branch protection on {r['default_branch']} for {full}.")
    out.sort(key=lambda f: SEV_RANK.get(f["severity"], 9))
    for i, f in enumerate(out, 1):
        f["id"] = "GH-%03d" % i
    return out


def pct(num, den):
    return round(100 * num / den) if den else 0


def collect(owner, limit):
    repos_raw = gh_json(["repo", "list", owner, "--limit", str(limit), "--json",
                         "name,visibility,isPrivate,isArchived,isFork,pushedAt,defaultBranchRef"]) or []
    repos = [audit_repo(owner, r) for r in repos_raw]
    n = len(repos)
    active = [r for r in repos if not r["archived"]]

    # coverage of controls (over active, non-fork repos where the control is knowable)
    def cov(key):
        applicable = [r for r in active if not r["fork"] and r[key] is not None]
        on = [r for r in applicable if r[key]]
        return {"count": len(on), "total": len(applicable), "pct": pct(len(on), len(applicable))}

    coverage = [
        {"label": "Secret scanning", **cov("secret_scanning")},
        {"label": "Push protection", **cov("push_protection")},
        {"label": "Branch protection (default)", **cov("branch_protection")},
        {"label": "Dependabot / vuln alerts", **cov("vuln_alerts")},
    ]
    vis = {}
    for r in repos:
        vis[r["visibility"]] = vis.get(r["visibility"], 0) + 1
    vulns = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for r in repos:
        for k in vulns:
            vulns[k] += r["open_vulns"][k]
    total_secret_alerts = sum(r["secret_alerts"] for r in repos)
    public = vis.get("PUBLIC", 0)

    findings = build_findings(owner, repos)

    # posture score: weighted control coverage, penalised by live exposures
    base = 0.0
    weights = {"Secret scanning": 0.25, "Push protection": 0.20,
               "Branch protection (default)": 0.20, "Dependabot / vuln alerts": 0.15}
    for c in coverage:
        base += weights.get(c["label"], 0) * (c["pct"] / 100)
    base += 0.20  # baseline for being audited / no account-level red flags
    score = base * 100
    score -= 12 * total_secret_alerts + 8 * vulns["critical"] + 3 * vulns["high"]
    score = max(0, min(100, round(score)))
    grade = ("A" if score >= 90 else "B" if score >= 75 else "C" if score >= 60
             else "D" if score >= 40 else "F")
    label = {"A": "Strong", "B": "Good", "C": "Needs work", "D": "At risk", "F": "Critical"}[grade]

    kpis = [
        {"label": "Repositories", "value": n},
        {"label": "Public", "value": public, "tone": "warn" if public else "ok"},
        {"label": "Private", "value": vis.get("PRIVATE", 0), "tone": "ok"},
        {"label": "Live secret alerts", "value": total_secret_alerts,
         "tone": "bad" if total_secret_alerts else "ok"},
        {"label": "Open crit/high vulns", "value": vulns["critical"] + vulns["high"],
         "tone": "bad" if (vulns["critical"] + vulns["high"]) else "ok"},
    ]
    return {
        "title": "GitHub Security Audit",
        "subject": f"github.com/{owner}",
        "scope": ["GitHub"],
        "score": {"value": score, "grade": grade, "label": label},
        "kpis": kpis,
        "coverage_bars": coverage,
        "charts": {"visibility": vis, "vulns_by_severity": vulns},
        "repos": sorted(repos, key=lambda r: (SEV_RANK.get(r["risk"], 9), r["name"].lower())),
        "findings": findings,
        "guidelines": ["GitHub security hardening", "OWASP Top 10", "CWE-798",
                       "Supply-chain (Dependabot/SCA)", "Least-privilege repo visibility"],
        "coverage_notes": [
            f"GitHub: {n} repos audited for owner '{owner}'",
            "controls read live via gh API (secret scanning, push protection, branch protection, vuln alerts, Dependabot & secret-scanning alerts)",
            "READ-ONLY: no repo or setting was modified",
        ],
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--owner")
    ap.add_argument("--limit", type=int, default=300)
    ap.add_argument("--stamp")
    a = ap.parse_args()
    owner = a.owner
    if not owner:
        u = gh_json(["api", "user"])
        owner = (u or {}).get("login") or "me"
    rc, _, _ = gh(["auth", "status"])
    if rc != 0:
        print(json.dumps({"error": "gh not authenticated. Run: gh auth login"}))
        return
    doc = collect(owner, a.limit)
    doc["generated_at"] = a.stamp or datetime.datetime.now().strftime("%Y-%m-%d %H:%M")
    print(json.dumps(doc, indent=2))


if __name__ == "__main__":
    main()
