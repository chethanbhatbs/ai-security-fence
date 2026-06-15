---
name: security-fence
description: Audit your AI-connected attack surface for exposed secrets, vulnerable code/dependencies, and unsafe agent configuration, then produce an interactive HTML dashboard of severity-ranked findings — each with an action item and a "Fix with Claude" button. Scans the local AI/agent config + memory + credential files, a target codebase (orchestrating gitleaks/trufflehog/semgrep/grype when installed), and optionally connected services (GitHub, MCP servers, BI tools). Use when the user wants a security audit, secret/credential scan, dependency CVE check, a "fence" around their system, or asks "am I exposed / any security issues". Trigger on "/security-fence", "security audit", "scan my secrets", "check my exposure".
---

# Security Fence

Build a fence around the user's system, code, and data. No scanner finds
*everything* — this one is strong on the AI/agent attack surface (where few tools
look) and orchestrates proven OSS scanners for the rest. Be honest about coverage.

`SKILL_DIR = directory containing this file.`

Two modes:
- **scan** (default) — audit the requested surface(s), score, render the dashboard.
- **fix `<FINDING-ID>`** — apply one finding's remediation (what the report's "Fix with Claude" buttons paste back).

## Scope — HONOR EXACTLY WHAT THE USER ASKED FOR
Parse the request for a surface and scan ONLY that. Do not expand scope.
- "check GitHub" / "scan my repos" → **GitHub only** (Step G). Do NOT touch local files.
- "scan this project" / a path → project + engines only (Step 1 with `--no-config-surface`).
- "scan my secrets" / "audit everything" / no surface named → full scan (all steps).
State the scope you inferred in one line before scanning.

## Hard rules
1. **READ-ONLY scanning.** Never write, delete, POST, mutate a repo, or change a remote setting during a scan. Inventory and report only.
2. **Redact, never reprint.** Never echo a live secret value in chat or the report. The scanners already fingerprint them — keep it that way.
3. **Fixes require confirmation.** In `fix` mode, show the exact change first and get a yes. Rotating a live credential is the user's action — give precise steps, never attempt it silently.
4. **Honest coverage.** If a surface/engine can't run (tool missing, not authenticated), say so in the coverage list. Never imply full coverage you didn't achieve.
5. Save the report somewhere durable (default `./security-fence-report.html`, or the user's reports dir).

---

## SCAN mode

### Step G — GitHub-only audit (when the user asks for GitHub)
This is a self-contained analytics audit; do NOT run the local steps.
```bash
python3 "$SKILL_DIR/scripts/scan_github.py" > /tmp/sf_github.json   # add --owner ORG for an org
python3 "$SKILL_DIR/scripts/build_dashboard.py" /tmp/sf_github.json ./github_security_audit.html
open ./github_security_audit.html
```
`scan_github.py` (read-only `gh` API) pulls per-repo controls — secret scanning, push protection, branch protection, vuln alerts, open Dependabot & secret-scanning alerts, visibility — and emits a posture score, control-coverage, a repository security matrix, and risk-ranked findings. `build_dashboard.py` renders the analytics dashboard (gauge, KPIs, coverage bars, charts, sortable matrix, Fix buttons). If `gh auth status` fails, tell the user to run `gh auth login` and stop. Then report back per Step 4.

### Step 0 — refresh guidelines (fast)
Read `reference/guidelines.md`. Optionally run ONE `WebSearch` for current-year
updates (e.g. "OWASP LLM Top 10", "leaked secret patterns", "MCP security best
practices") and fold in anything materially new. One search, then move on.

### Step 1 — deterministic scan (local + OSS engines)
Pick the target codebase (ask the user, or default to the current repo). Then:
```bash
python3 "$SKILL_DIR/scripts/run_scan.py" --target <PROJECT_DIR> --out /tmp/sf_findings.json
```
This runs, with honest skip-reporting:
- **Local surface** — AI/agent config (`~/.claude/*`, `~/.cursor/*`, `~/.codeium/*`), memory files, dotfiles, and credential stores (`~/.aws`, `~/.ssh`, `~/.pgpass`, `~/.netrc`…); plus permission/sandbox analysis of agent settings.
- **Project secrets** — walks the codebase for ~25 secret signatures + entropy.
- **Secrets engines** — `gitleaks`, `trufflehog` (verified secrets) if installed.
- **Code (SAST)** — `semgrep --config auto` if installed.
- **Dependencies (SCA)** — `grype`, `pip-audit`, `npm audit` if installed.

> Secrets sitting in an AI's auto-loaded context (`CLAUDE.md`, memory files) are escalated to **Critical** automatically — they're fed to every prompt.

To scan only the local config surface (no project): add `--no-config-surface` to skip home, or pass `--target` to a tiny dir. To skip external tools: `--no-engines`.

### Step 2 — connected services (optional, agent-driven)
Append findings to the JSON for any service the user has connected. Read-only; metadata only.
- **GitHub** (`gh` CLI, if `gh auth status` works): public repos that look private/internal (**High**); secret-scanning/push-protection disabled (**Medium**); missing branch protection (**Low/Med**); secrets in history. If not authenticated, record "GitHub: skipped".
- **MCP servers** (read `~/.claude.json`, `~/.mcp.json`, project `.mcp.json`): inline plaintext tokens (**Critical**); servers with broad write/send/delete/charge scope that isn't needed → excessive agency, OWASP LLM08 (**Medium**); prefer read-only scoping. OAuth-managed servers are lower risk than inline-token ones.
- **BI / data tools** (e.g. Redash, Metabase via their MCP/API): public dashboards or queries exposing data (**High**); hardcoded credentials in query text (**Critical**); over-broad data-source access. Metadata only — do not execute queries.

Merge by appending objects to `findings[]` (keep the schema below) and re-deriving unique IDs. Add a `coverage` line for each service you checked or skipped.

### Step 3 — render
For a service/analytics audit (GitHub etc.) use the dashboard renderer
`build_dashboard.py` (posture gauge, coverage, matrix). For a plain findings list
from the local/project scan use `build_report.py`:
```bash
python3 "$SKILL_DIR/scripts/build_report.py" /tmp/sf_findings.json ./security-fence-report.html
open ./security-fence-report.html   # or xdg-open on Linux
```

### Step 4 — report back (concise)
Give ONLY: counts by severity, the top 3 Critical/High items (one line each), the
saved path, and "Open the report and click 🔧 Fix with Claude on any finding, or
run `/security-fence fix <ID>`." Do not dump the full list — it's in the dashboard.

### Findings schema
```json
{"id":"SEC-NNN","severity":"critical|high|medium|low","surface":"Local|Config|Secrets|Code|Dependencies|GitHub|MCP|BI",
 "title":"...","location":"file:line or resource","evidence":"<redacted>",
 "impact":"why it matters","remediation":"what to do","fix_prompt":"exact instruction the Fix button copies back","engine":"optional tool name"}
```

---

## FIX mode — `/security-fence fix <ID>`
1. Read the findings JSON, locate the finding by ID.
2. Restate the finding + the exact change you'll make. **Wait for confirmation.**
3. Apply ONLY that remediation:
   - plaintext secret → remove/replace the literal with a secret-store/env reference, keep `.env` out of git, and print the **rotation** steps (user performs rotation; the exposed value is compromised).
   - committed secret → guide history purge (`git filter-repo` / BFG) + rotate.
   - loose perms → `chmod 600` the file.
   - over-broad agent permission → propose tightened allow-rules (edit only after OK).
   - dependency CVE → bump to the fixed version and verify the build/tests.
   - SAST finding → review file:line, confirm it's real, apply the fix, add a test.
   - GitHub/MCP/BI → remote: give precise console/CLI steps; do NOT change remote state without explicit go-ahead.
4. Mark it fixed and tell the user to re-run `/security-fence` to confirm.

## Notes
- The HTML is self-contained and offline. It lists secret *locations*, so treat the file as sensitive.
- Install optional engines for fuller coverage: `brew install gitleaks trufflehog grype` · `pipx install semgrep pip-audit`.
