# Contributing to AI Security Fence

Thanks for helping build the fence. The bar: **no false confidence** — be precise
about what each check proves, and keep coverage honest.

## Good first contributions
- **New secret signatures** — add to `SIGNATURES` in `scripts/scan_local.py`. Include
  a realistic (fake) example in your PR description and a severity justification.
- **New engine adapters** — add a `run_<tool>()` to `scripts/scan_engines.py` that
  shells out read-only, parses output, and normalizes to the findings schema. It must
  degrade gracefully (record a `SKIPPED` coverage line) when the tool is absent.
- **Connected-service checks** — GitHub/MCP/BI logic lives in `SKILL.md` (agent-driven).

## Rules
1. **Read-only.** No scanner may write, delete, POST, or mutate anything.
2. **Redact secrets.** Never emit a raw secret value — use the `redact()` helper.
3. **Honest coverage.** Anything skipped/capped must appear in the `coverage` list.
4. **Stdlib only** for the built-in scanner (`scan_local.py`, `run_scan.py`,
   `build_report.py`) so it runs with zero install. External tools stay optional.
5. **No telemetry, no network calls** in the scanners themselves.

## Testing
```bash
python3 -m py_compile skill/security-fence/scripts/*.py
# planted-secret smoke test
T=$(mktemp -d); printf 'KEY=sk-proj-ABCD1234efgh5678IJKL9012mnop3456\n' > "$T/.env"
python3 skill/security-fence/scripts/run_scan.py --target "$T" --no-config-surface \
        --no-engines --out "$T/out.json" && cat "$T/out.json"; rm -rf "$T"
```

## Findings schema
```json
{"id","severity":"critical|high|medium|low","surface","title","location",
 "evidence":"<redacted>","impact","remediation","fix_prompt","engine"}
```
