# Security Fence — baked-in checklist

Authoritative baseline so the scan works offline. At runtime, optionally run one
`WebSearch` for the current year's updates and fold anything new into findings.

## Standards drawn from
- **OWASP Top 10** + **OWASP API Security Top 10**
- **OWASP LLM / Agentic Top 10** — esp. LLM06 Sensitive Info Disclosure, LLM07 Insecure Plugin/Tool Design, LLM08 Excessive Agency, prompt injection
- **CIS Benchmarks** — file permissions, least privilege
- **NIST 800-63 / 800-53** — credential storage & rotation
- **CWE-798** Hardcoded credentials, **CWE-312** Cleartext storage of sensitive info
- **12-Factor** — config & secrets in environment, never in code/files

## What "good" looks like (the fence)
1. **No plaintext secrets at rest.** Keys/tokens/passwords live in a secret manager
   (OS keychain, 1Password, `pass`, env vars, Vault) — never in `.md`/`.json`/`.env`
   committed files or AI context/memory files.
2. **Secrets never in LLM context.** Anything in an agent's `CLAUDE.md`/memory is fed
   to every prompt — treat it as published. Keep credentials out entirely.
3. **Least privilege on tools.** No blanket auto-approve (`Bash(*)`, `Write`,
   `WebFetch`). Sandbox on. MCP servers scoped read-only where possible (LLM08).
4. **Clean code & deps.** No SAST high-severity issues shipped; no known-vulnerable
   dependency versions (SCA); secrets never committed (and purged from history if they were).
5. **Source-control hygiene.** Repos no more public than needed; secret-scanning &
   push-protection on; branch protection on default.
6. **Data tools locked down.** Dashboards/queries not public unless intended; no
   credentials embedded in query text; data-source access scoped.
7. **Rotation.** Any credential that was exposed is compromised — rotate, don't just hide.

## Severity rubric
- **Critical** — live secret (cloud key, private key, prod DB/API token) in cleartext
  or on a public surface; verified-live secret; critical-severity CVE. Rotate/patch now.
- **High** — over-broad permission, loose perms on a secret store, public repo that
  should be private, password-bearing connection string, high-severity CVE/SAST.
- **Medium** — JWT/bearer literal, missing push-protection, medium CVE/SAST.
- **Low** — hygiene / hardening recommendations, test keys, low CVEs.

## Surfaces & tooling
| Surface | How | Tool |
|---|---|---|
| Local AI config, memory, dotfiles, cred stores | regex + entropy + perms + settings analysis | `scripts/scan_local.py` |
| Project secrets | walk codebase, ~25 signatures + entropy | `scripts/scan_local.py --target` |
| Secrets (deep) | verified-secret detection | `gitleaks`, `trufflehog` |
| Code (SAST) | static analysis | `semgrep --config auto` |
| Dependencies (SCA) | CVE matching | `grype`, `pip-audit`, `npm audit` |
| GitHub | repo visibility, secret-scanning, history, branch protection | `gh` CLI |
| MCP / connected tools | server scopes, inline tokens, excessive agency | config files + MCP list |
| BI / data tools | public dashboards/queries, secrets in query text | service MCP/API (metadata only) |
