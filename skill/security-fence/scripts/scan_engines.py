#!/usr/bin/env python3
"""
ai-security-fence :: external scanner orchestrator (READ-ONLY).

Detects and runs best-in-class open-source security scanners against a target
directory, then normalizes their output into the common findings schema:

  Secrets       : gitleaks, trufflehog
  Code (SAST)   : semgrep
  Dependencies  : grype, pip-audit, npm audit (osv-scanner if present)

Every engine is OPTIONAL. If a tool isn't installed it is recorded as "skipped"
in coverage (never silently dropped) so the report is honest about what ran.
Nothing is written, uploaded, or mutated. Secret values are redacted.

Importable: collect_engines(target) -> (findings, coverage)
CLI:        python3 scan_engines.py [--target DIR] [--per-engine-cap N] > engines.json
"""
import argparse, json, os, re, subprocess, shutil, hashlib, tempfile

SEV_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
PER_ENGINE_CAP = 80


def _which(b):
    return shutil.which(b) is not None


def _run(cmd, cwd=None, timeout=300):
    try:
        p = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, timeout=timeout)
        return p.returncode, p.stdout, p.stderr
    except subprocess.TimeoutExpired:
        return -1, "", "timeout"
    except Exception as e:
        return -2, "", str(e)


def _redact(val):
    if not val:
        return "(value hidden)"
    val = str(val).strip()
    if len(val) <= 8:
        return (val[0] if val else "?") + "***"
    return f"{val[:3]}…{val[-2:]} (len={len(val)}, fp={hashlib.sha256(val.encode()).hexdigest()[:6]})"


def _cap(findings, coverage, engine):
    findings.sort(key=lambda f: SEV_RANK.get(f["severity"], 9))
    if len(findings) > PER_ENGINE_CAP:
        coverage.append(f"{engine}: showing top {PER_ENGINE_CAP} of {len(findings)} findings (capped — re-run the tool directly for the full list)")
        return findings[:PER_ENGINE_CAP]
    return findings


# --------------------------------------------------------------------------- #
# Secret scanners
# --------------------------------------------------------------------------- #
def run_gitleaks(target, cov):
    if not _which("gitleaks"):
        cov.append("gitleaks: SKIPPED (not installed — `brew install gitleaks`)")
        return []
    out = []
    with tempfile.NamedTemporaryFile("r", suffix=".json", delete=False) as tf:
        rpt = tf.name
    # try v8 `dir`, fall back to `detect --source`
    rc, _, _ = _run(["gitleaks", "dir", target, "-f", "json", "-r", rpt, "--no-banner"])
    if rc not in (0, 1):
        _run(["gitleaks", "detect", "--source", target, "--no-git", "-f", "json", "-r", rpt, "--no-banner"])
    try:
        data = json.load(open(rpt))
    except Exception:
        data = []
    finally:
        try:
            os.unlink(rpt)
        except OSError:
            pass
    for r in (data or []):
        rule = (r.get("RuleID") or r.get("Rule") or "").lower()
        sev = "critical" if any(k in rule for k in ("private", "aws", "gcp", "key", "token", "stripe")) else "high"
        f = os.path.relpath(r.get("File", "?"), target) if r.get("File") else "?"
        out.append(_finding(sev, "Secrets", f"Secret detected: {r.get('Description') or rule}",
                            f"{f}:{r.get('StartLine','?')}", _redact(r.get("Secret")),
                            "gitleaks matched a credential pattern in tracked content. If this is committed, it is in git history even after deletion.",
                            "Remove the secret, purge it from git history (git filter-repo/BFG) if committed, and rotate it.",
                            f"A secret was found in {f} line {r.get('StartLine','?')} (rule: {rule}). Remove it, tell me how to purge it from git history, and give rotation steps.",
                            "gitleaks"))
    cov.append(f"gitleaks: ran ({len(out)} hits)")
    return _cap(out, cov, "gitleaks")


def run_trufflehog(target, cov):
    if not _which("trufflehog"):
        cov.append("trufflehog: SKIPPED (not installed — `brew install trufflehog`)")
        return []
    rc, so, _ = _run(["trufflehog", "filesystem", target, "--json", "--no-update"], timeout=420)
    out = []
    for line in so.splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            r = json.loads(line)
        except Exception:
            continue
        det = r.get("DetectorName", "secret")
        verified = r.get("Verified", False)
        sev = "critical" if verified else "high"
        meta = (r.get("SourceMetadata") or {}).get("Data", {}).get("Filesystem", {})
        f = meta.get("file", "?")
        try:
            f = os.path.relpath(f, target)
        except ValueError:
            pass
        vtag = "VERIFIED-LIVE" if verified else "unverified"
        out.append(_finding(sev, "Secrets", f"{det} secret ({vtag})", f, _redact(r.get("Raw")),
                            f"trufflehog detected a {det} credential ({vtag}). Verified means it was confirmed live against the provider.",
                            "Rotate immediately if verified; remove from source and git history.",
                            f"trufflehog found a {vtag} {det} secret in {f}. Remove it and give rotation + history-purge steps.",
                            "trufflehog"))
    cov.append(f"trufflehog: ran ({len(out)} hits)")
    return _cap(out, cov, "trufflehog")


# --------------------------------------------------------------------------- #
# SAST
# --------------------------------------------------------------------------- #
def run_semgrep(target, cov):
    if not _which("semgrep"):
        cov.append("semgrep: SKIPPED (not installed — `pipx install semgrep`)")
        return []
    rc, so, se = _run(["semgrep", "scan", "--config", "auto", "--json", "--quiet",
                       "--timeout", "30", "--max-target-bytes", "1000000", target], timeout=480)
    out = []
    try:
        data = json.loads(so or "{}")
    except Exception:
        cov.append("semgrep: ran but output unparseable")
        return []
    smap = {"ERROR": "high", "WARNING": "medium", "INFO": "low"}
    for r in data.get("results", []):
        extra = r.get("extra", {})
        sev = smap.get(str(extra.get("severity", "WARNING")).upper(), "medium")
        f = r.get("path", "?")
        try:
            f = os.path.relpath(f, target)
        except ValueError:
            pass
        line = (r.get("start") or {}).get("line", "?")
        msg = (extra.get("message") or r.get("check_id", "")).strip().split("\n")[0][:240]
        out.append(_finding(sev, "Code", f"SAST: {r.get('check_id','rule').split('.')[-1]}",
                            f"{f}:{line}", f"rule `{r.get('check_id','')}`",
                            msg or "semgrep flagged a code-level security issue.",
                            "Review the flagged code and apply the rule's suggested fix; add a test.",
                            f"Review {f} line {line}. semgrep rule {r.get('check_id','')} says: {msg}. Confirm if it's a real issue and fix it.",
                            "semgrep"))
    cov.append(f"semgrep: ran ({len(out)} findings)")
    return _cap(out, cov, "semgrep")


# --------------------------------------------------------------------------- #
# Dependency / SCA
# --------------------------------------------------------------------------- #
def run_grype(target, cov):
    if not _which("grype"):
        cov.append("grype: SKIPPED (not installed — `brew install grype`)")
        return []
    rc, so, _ = _run(["grype", f"dir:{target}", "-o", "json", "-q"], timeout=420)
    out = []
    try:
        data = json.loads(so or "{}")
    except Exception:
        cov.append("grype: ran but output unparseable")
        return []
    for m in data.get("matches", []):
        v = m.get("vulnerability", {})
        art = m.get("artifact", {})
        sev = str(v.get("severity", "Low")).lower()
        if sev not in SEV_RANK:
            sev = "medium"
        fix = (v.get("fix") or {}).get("versions") or []
        fixtxt = f"upgrade to {', '.join(fix)}" if fix else "no fixed version yet — assess/replace"
        out.append(_finding(sev, "Dependencies", f"{v.get('id','CVE')} in {art.get('name','?')}",
                            f"{art.get('name','?')}@{art.get('version','?')}",
                            f"{v.get('id','')} severity={v.get('severity','')}",
                            (v.get("description") or "Vulnerable dependency version.")[:240],
                            f"{fixtxt}.",
                            f"Dependency {art.get('name')}@{art.get('version')} has {v.get('id')}. {fixtxt}. Update it and verify nothing breaks.",
                            "grype"))
    cov.append(f"grype: ran ({len(out)} CVEs)")
    return _cap(out, cov, "grype")


def run_pip_audit(target, cov):
    has_req = any(os.path.exists(os.path.join(target, n)) for n in
                  ("requirements.txt", "pyproject.toml", "Pipfile.lock", "poetry.lock"))
    if not has_req:
        return []
    if not _which("pip-audit"):
        cov.append("pip-audit: SKIPPED (python deps present but not installed — `pipx install pip-audit`)")
        return []
    rc, so, _ = _run(["pip-audit", "-f", "json", "--progress-spinner", "off"], cwd=target, timeout=300)
    out = []
    try:
        data = json.loads(so or "{}")
    except Exception:
        return []
    deps = data.get("dependencies", data) if isinstance(data, dict) else data
    for d in (deps or []):
        for vuln in d.get("vulns", []):
            out.append(_finding("high", "Dependencies",
                                f"{vuln.get('id','VULN')} in {d.get('name','?')}",
                                f"{d.get('name','?')}=={d.get('version','?')}",
                                vuln.get("id", ""),
                                (vuln.get("description") or "")[:240],
                                f"upgrade to {', '.join(vuln.get('fix_versions', [])) or 'a patched version'}.",
                                f"Python dep {d.get('name')}=={d.get('version')} has {vuln.get('id')}. Upgrade and verify.",
                                "pip-audit"))
    cov.append(f"pip-audit: ran ({len(out)} vulns)")
    return _cap(out, cov, "pip-audit")


def run_npm_audit(target, cov):
    if not os.path.exists(os.path.join(target, "package-lock.json")) and \
       not os.path.exists(os.path.join(target, "package.json")):
        return []
    if not _which("npm"):
        cov.append("npm audit: SKIPPED (node project present but npm not installed)")
        return []
    rc, so, _ = _run(["npm", "audit", "--json"], cwd=target, timeout=300)
    out = []
    try:
        data = json.loads(so or "{}")
    except Exception:
        return []
    for name, v in (data.get("vulnerabilities") or {}).items():
        sev = str(v.get("severity", "moderate")).lower()
        sev = {"moderate": "medium", "info": "low"}.get(sev, sev)
        if sev not in SEV_RANK:
            sev = "medium"
        out.append(_finding(sev, "Dependencies", f"npm advisory: {name}", name,
                            f"severity={v.get('severity','')}",
                            "npm audit flagged a vulnerable dependency (transitive or direct).",
                            "Run `npm audit fix` (or upgrade the offending package) and re-test.",
                            f"npm dependency {name} is flagged {v.get('severity','')} by npm audit. Fix it safely and verify.",
                            "npm-audit"))
    cov.append(f"npm audit: ran ({len(out)} advisories)")
    return _cap(out, cov, "npm audit")


def _finding(sev, surface, title, location, evidence, impact, remediation, fix_prompt, engine):
    return {"severity": sev, "surface": surface, "title": title, "location": location,
            "evidence": evidence, "impact": impact, "remediation": remediation,
            "fix_prompt": fix_prompt, "engine": engine}


def collect_engines(target):
    target = os.path.abspath(os.path.expanduser(target))
    cov, findings = [], []
    if not os.path.isdir(target):
        return [], [f"target not a directory: {target}"]
    for fn in (run_gitleaks, run_trufflehog, run_semgrep, run_grype, run_pip_audit, run_npm_audit):
        try:
            findings.extend(fn(target, cov))
        except Exception as e:
            cov.append(f"{fn.__name__}: error ({e})")
    # assign ids
    findings.sort(key=lambda f: SEV_RANK.get(f["severity"], 9))
    for i, f in enumerate(findings, 1):
        f["id"] = "ENG-%03d" % i
    return findings, cov


def main():
    global PER_ENGINE_CAP
    ap = argparse.ArgumentParser()
    ap.add_argument("--target", default=os.getcwd())
    ap.add_argument("--per-engine-cap", type=int, default=PER_ENGINE_CAP)
    a = ap.parse_args()
    PER_ENGINE_CAP = a.per_engine_cap
    findings, cov = collect_engines(a.target)
    print(json.dumps({"surface": "engines", "coverage": cov, "findings": findings}, indent=2))


if __name__ == "__main__":
    main()
