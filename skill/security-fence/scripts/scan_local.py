#!/usr/bin/env python3
"""
ai-security-fence :: local surface scanner (READ-ONLY).

Scans two surfaces for exposed secrets and unsafe configuration:
  1. The AI/agent CONFIG surface  — Claude/agent config + memory + dotfiles +
     credential stores in $HOME. (Disable with --no-config-surface.)
  2. A target PROJECT directory    — walks a codebase / repo for secrets in
     source, .env files, and config. (--target DIR, default: cwd.)

It NEVER writes, deletes, or transmits anything. Secret VALUES are redacted to a
fingerprint so the output (and the HTML report) is safe to share.

Importable: `collect_local(home, target, config_surface=True) -> (findings, coverage)`
CLI:        python3 scan_local.py [--target DIR] [--no-config-surface] > local.json
"""
import argparse, json, os, re, math, stat, hashlib, glob

HOME = os.path.expanduser("~")

# ---------------------------------------------------------------------------
# Secret signatures: (id, severity, label, regex). severity: critical|high|medium|low
# ---------------------------------------------------------------------------
SIGNATURES = [
    ("aws-akia",      "critical", "AWS access key id",         re.compile(r"\b(AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("aws-secret",    "critical", "AWS secret access key",     re.compile(r"(?i)aws_secret_access_key\s*[:=]\s*[\"']?([A-Za-z0-9/+=]{40})")),
    ("private-key",   "critical", "Private key block",         re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----")),
    ("gh-token",      "critical", "GitHub token",              re.compile(r"\b(ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{30,}\b")),
    ("gh-pat-fine",   "critical", "GitHub fine-grained PAT",   re.compile(r"\bgithub_pat_[A-Za-z0-9_]{60,}\b")),
    ("gitlab-token",  "critical", "GitLab token",              re.compile(r"\bglpat-[A-Za-z0-9_-]{20,}\b")),
    ("slack-token",   "critical", "Slack token",               re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b")),
    ("slack-webhook", "high",     "Slack webhook URL",         re.compile(r"https://hooks\.slack\.com/services/[A-Za-z0-9/]+")),
    ("anthropic-key", "critical", "Anthropic API key",         re.compile(r"\bsk-ant-[A-Za-z0-9_-]{20,}\b")),
    ("openai-key",    "critical", "OpenAI/LLM API key",        re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9]{20,}\b")),
    ("google-key",    "high",     "Google API key",            re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b")),
    ("gcp-sa",        "critical", "GCP service-account key",   re.compile(r"\"type\"\s*:\s*\"service_account\"")),
    ("stripe-live",   "critical", "Stripe live secret key",    re.compile(r"\b(sk|rk)_live_[A-Za-z0-9]{20,}\b")),
    ("stripe-test",   "low",      "Stripe test key",           re.compile(r"\b(sk|rk)_test_[A-Za-z0-9]{20,}\b")),
    ("twilio",        "high",     "Twilio account SID",        re.compile(r"\bAC[a-f0-9]{32}\b")),
    ("sendgrid",      "critical", "SendGrid API key",          re.compile(r"\bSG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}\b")),
    ("npm-token",     "high",     "npm access token",          re.compile(r"\bnpm_[A-Za-z0-9]{36}\b")),
    ("pypi-token",    "high",     "PyPI upload token",         re.compile(r"\bpypi-AgEIcHlwaS[A-Za-z0-9_-]{50,}\b")),
    ("hf-token",      "high",     "HuggingFace token",         re.compile(r"\bhf_[A-Za-z0-9]{30,}\b")),
    ("azure-conn",    "critical", "Azure storage conn string", re.compile(r"AccountKey=[A-Za-z0-9+/=]{60,}")),
    ("jwt",           "medium",   "JSON Web Token",            re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b")),
    ("db-url",        "high",     "DB conn URL with password", re.compile(r"\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqp)://[^\s:@/]+:[^\s:@/]+@[^\s/]+", re.I)),
    ("pwd-assign",    "high",     "Hardcoded credential assignment", re.compile(r"(?i)\b(password|passwd|pwd|secret|api[_-]?key|access[_-]?token|auth[_-]?token|client[_-]?secret|private[_-]?key)\b\s*[:=]\s*[\"']?([^\s\"'#,;]{6,})")),
    ("bearer",        "medium",   "Bearer token literal",      re.compile(r"(?i)bearer\s+[A-Za-z0-9._-]{20,}")),
]

PLACEHOLDERS = {"password", "passwd", "changeme", "xxx", "xxxx", "your_password",
                "your-password", "none", "null", "true", "false", "example",
                "redacted", "placeholder", "secret", "token", "test", "dummy",
                "yourkeyhere", "api_key", "apikey", "<password>", "..."}

# Credential stores whose loose file perms are a finding (config surface)
SENSITIVE_PATHS = [
    "~/.aws/credentials", "~/.aws/config", "~/.netrc", "~/.pgpass",
    "~/.ssh/id_rsa", "~/.ssh/id_dsa", "~/.ssh/id_ecdsa", "~/.ssh/id_ed25519",
    "~/.config/gh/hosts.yml", "~/.docker/config.json", "~/.kube/config",
    "~/.npmrc", "~/.pypirc",
]

# AI/agent config + memory + dotfile globs (config surface, $HOME)
CONFIG_GLOBS = [
    "~/.claude/CLAUDE.md", "~/.claude/settings.json", "~/.claude/settings.local.json",
    "~/.claude/.credentials.json", "~/.claude/projects/*/memory/*.md",
    "~/.claude/skills/*/CREDENTIALS.md", "~/.claude.json", "~/.mcp.json",
    "~/.cursor/mcp.json", "~/.codeium/**/config*.json", "~/.config/**/mcp*.json",
    "~/.env", "~/.envrc", "~/.bashrc", "~/.zshrc", "~/.profile", "~/.bash_profile",
]

TEXT_EXT = {".md", ".json", ".txt", ".env", ".envrc", ".py", ".sh", ".yml", ".yaml",
            ".cfg", ".ini", ".toml", ".js", ".ts", ".jsx", ".tsx", ".rb", ".go",
            ".java", ".php", ".cs", ".properties", ".conf", ".xml", ".html", ""}
SKIP_DIRS = {"node_modules", ".git", "__pycache__", ".venv", "venv", "env", "dist",
             "build", ".next", ".cache", "vendor", "target", ".terraform", "coverage",
             ".pytest_cache", ".mypy_cache", "site-packages"}
MAX_BYTES = 800_000


def shannon(s):
    if not s:
        return 0.0
    counts = {}
    for c in s:
        counts[c] = counts.get(c, 0) + 1
    n = len(s)
    return -sum((v / n) * math.log2(v / n) for v in counts.values())


def redact(val):
    val = val.strip().strip("'\"")
    if len(val) <= 8:
        return (val[0] if val else "?") + "***"
    fp = hashlib.sha256(val.encode()).hexdigest()[:6]
    return f"{val[:3]}…{val[-2:]} (len={len(val)}, fp={fp})"


def is_textfile(path):
    return os.path.splitext(path)[1].lower() in TEXT_EXT


def _expand(globs):
    out = []
    for g in globs:
        out.extend(glob.glob(os.path.expanduser(g), recursive=True))
    return sorted(set(out))


class Collector:
    def __init__(self, home):
        self.home = home
        self.findings = []
        self._seen = set()

    def add(self, sev, surface, title, location, evidence, impact, remediation, fix_prompt):
        key = title + "|" + location
        if key in self._seen:
            return
        self._seen.add(key)
        self.findings.append({
            "id": "SEC-%03d" % (len(self.findings) + 1),
            "severity": sev, "surface": surface, "title": title,
            "location": location, "evidence": evidence, "impact": impact,
            "remediation": remediation, "fix_prompt": fix_prompt,
        })

    def disp(self, path):
        try:
            rel = os.path.relpath(path, self.home)
            return "~/" + rel if not rel.startswith("..") else path
        except ValueError:
            return path

    def scan_file_secrets(self, path, in_context=False):
        try:
            if os.path.getsize(path) > MAX_BYTES:
                return
            with open(path, "r", errors="ignore") as fh:
                lines = fh.readlines()
        except Exception:
            return
        for ln, line in enumerate(lines, 1):
            if len(line) > 4000:
                continue
            for sid, sev, label, rx in SIGNATURES:
                for m in rx.finditer(line):
                    raw = m.group(0)
                    if sid in ("pwd-assign", "aws-secret"):
                        val = m.group(m.lastindex) if m.lastindex else raw
                        low = val.lower().strip()
                        if low in PLACEHOLDERS or "${" in val or val.startswith("<") or "*****" in val or "your" in low:
                            continue
                        if sid == "pwd-assign" and shannon(val) < 2.6 and not re.search(r"[A-Z]", val) and not re.search(r"\d", val):
                            continue
                        shown = redact(val)
                    else:
                        shown = redact(raw)
                    sev2 = sev
                    note = ""
                    if in_context and sid in ("pwd-assign", "db-url", "bearer", "jwt", "aws-secret"):
                        sev2 = "critical"
                        note = " — and this file is auto-loaded into EVERY AI session context, so the secret is exposed on every prompt/response"
                    d = self.disp(path)
                    self.add(sev2, "Local",
                             f"Plaintext {label} on disk",
                             f"{d}:{ln}",
                             f"`{shown}`",
                             f"A {label.lower()} is stored in cleartext{note}. Anyone with read access to this machine, a backup, or a synced cloud copy can use it.",
                             f"Remove the literal value, move it into a secret manager / env var, and ROTATE the credential — it must be treated as compromised.",
                             f"Open {d} line {ln}, remove the plaintext {label.lower()}, replace it with a secret-store/env reference, and give me the exact rotation steps for this credential.")

    def scan_config_surface(self):
        for path in _expand(CONFIG_GLOBS):
            if not os.path.isfile(path) or not is_textfile(path):
                continue
            in_context = "memory" in path or path.endswith("CLAUDE.md")
            self.scan_file_secrets(path, in_context=in_context)
        self.scan_sensitive_perms()
        self.scan_settings()

    def scan_project(self, target):
        target = os.path.abspath(os.path.expanduser(target))
        if not os.path.isdir(target):
            return
        for root, dirs, files in os.walk(target):
            dirs[:] = [d for d in dirs if d not in SKIP_DIRS and not d.startswith(".git")]
            for name in files:
                path = os.path.join(root, name)
                if not is_textfile(path):
                    continue
                self.scan_file_secrets(path, in_context=False)
                if name.startswith("id_") and "PRIVATE KEY" not in name:
                    pass  # private key body caught by signature

    def scan_sensitive_perms(self):
        for raw in SENSITIVE_PATHS:
            path = os.path.expanduser(raw)
            if not os.path.exists(path):
                continue
            try:
                perm = stat.S_IMODE(os.stat(path).st_mode)
            except Exception:
                continue
            if perm & 0o077:
                d = self.disp(path)
                self.add("high", "Local", "Secret file has loose permissions", d,
                         f"mode {oct(perm)} (group/other readable)",
                         "Credential files readable by group/other can be read by any other local account or a compromised process.",
                         f"Tighten: `chmod 600 {d}` (700 for ~/.ssh dir).",
                         f"Run chmod 600 on {d} and confirm it is no longer group/other readable.")

    def scan_settings(self):
        for sp in ["~/.claude/settings.json", "~/.claude/settings.local.json"]:
            path = os.path.expanduser(sp)
            if not os.path.isfile(path):
                continue
            try:
                data = json.load(open(path))
            except Exception:
                continue
            d = self.disp(path)
            perms = data.get("permissions", {})
            allow = perms.get("allow", []) if isinstance(perms, dict) else []
            DANGER = {
                "Bash": "all shell commands auto-approved", "Bash(*)": "all shell commands auto-approved",
                "Bash(*:*)": "all shell commands auto-approved", "Bash(rm:*)": "destructive deletes auto-approved",
                "Bash(curl:*)": "arbitrary network egress auto-approved", "Bash(sudo:*)": "privilege escalation auto-approved",
                "Bash(eval:*)": "arbitrary code execution auto-approved", "WebFetch": "unrestricted web fetch auto-approved",
                "Write": "unrestricted file writes auto-approved", "Edit": "unrestricted file edits auto-approved",
            }
            for rule in allow:
                if rule in DANGER:
                    self.add("high", "Config", "Over-broad auto-approve permission",
                             f"{d} (permissions.allow)", f"`{rule}`",
                             f"This rule means {DANGER[rule]} with no prompt. A prompt-injection or mistaken instruction can run unchecked (OWASP LLM08 Excessive Agency).",
                             "Replace the wildcard with narrowly-scoped rules (specific binaries/paths); let everything else prompt.",
                             f"Show the permissions.allow list in {d}, find wildcard rules like `{rule}`, and propose tightly-scoped replacements.")
            if data.get("dangerouslyDisableSandbox") or data.get("dangerously_disable_sandbox"):
                self.add("high", "Config", "Sandbox globally disabled", d,
                         "`dangerouslyDisableSandbox: true`",
                         "Disabling the sandbox removes a key containment layer for tool execution.",
                         "Remove the global flag; disable per-command only when strictly necessary.",
                         f"Remove dangerouslyDisableSandbox from {d} and explain the safe per-command alternative.")


def collect_local(home=HOME, target=None, config_surface=True):
    c = Collector(home)
    coverage = []
    if config_surface:
        c.scan_config_surface()
        coverage.append("config-surface ($HOME AI config, memory, dotfiles, credential stores)")
    if target:
        c.scan_project(target)
        coverage.append(f"project: {os.path.abspath(os.path.expanduser(target))}")
    return c.findings, coverage


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--target", default=os.getcwd(), help="project directory to scan (default: cwd)")
    ap.add_argument("--no-config-surface", action="store_true", help="skip the $HOME AI-config surface")
    ap.add_argument("--home", default=HOME)
    a = ap.parse_args()
    findings, coverage = collect_local(home=a.home, target=a.target,
                                       config_surface=not a.no_config_surface)
    print(json.dumps({"surface": "local", "engine": "scan_local",
                      "coverage": coverage, "findings": findings}, indent=2))


if __name__ == "__main__":
    main()
