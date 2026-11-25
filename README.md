# Agent Environment Diagnostic Package

Run a health-check on your **AI agent deployment** — locally, read-only.
**No secret values and no file contents ever leave your machine.** The report
contains only names, counts, versions, permissions, domains and
recommendations, so it is safe to share back with us for a remediation
proposal.

## What it checks

- **Platform footprint** — OS, Python, Docker, and which agent/LLM frameworks
  are actually installed (LangChain, OpenAI, Anthropic, Dify, vLLM, ...)
- **Key hygiene** — are model API keys in environment variables, world-readable
  `.env` files, or hardcoded in source code? (Names and counts only — values
  are never extracted.)
- **Observability** — logging, monitoring stack, retry/backoff handling for
  rate limits and timeouts
- **Data boundary** — every external service domain your configs reference,
  and a flag on any non-HTTPS endpoint
- **Cost visibility** — whether token usage / cost is being tracked at all
- **Version control** — are prompts and agent configs under git, or changing
  with no history?

## Quick start (2 steps)

Requires Python 3.8+. **No dependencies to install** — standard library only.

1. Unzip and point it at the directory where your agent project lives:

   ```bash
   python env_diagnose.py /path/to/your/agent/project
   ```

2. Open the report — written to `env_diag_reports/env_diagnostic_report.md`
   (and `.json` for machine reading).

## Options

```bash
python env_diagnose.py <project_dir> \
    --output ./my-reports \      # where reports are written
    --json                       # also print JSON to stdout
python env_diagnose.py <project_dir> \
    --compare env_diag_reports/env_diagnostic_report.json
                                 # diff with a previous run: new/resolved/persisting
```

## Fix verification: finding IDs and before/after comparison

Every finding carries a stable ID (e.g. `KEYS-HARDCODED`, `OBS-NO-LOGGING`,
`ENVFILE-WORLD-READABLE:<file>`) and a rough self-fix effort estimate in
person-hours. After fixing, re-run with `--compare` against the previous
JSON report: the report lists **resolved**, **new**, **severity changes**
and **persisting** findings. Use "high N→0" as the acceptance criterion
instead of a gut feeling.

## Reading the report

Findings are ranked **high → medium → low → info**. Each finding carries a
concrete recommendation. Typical first-run results on an unreviewed
deployment: hardcoded keys (high), no monitoring (high), no retry handling
(medium), prompts without version control (medium).

## Sharing the report

Send `env_diagnostic_report.md` (or the `.json` file) back to us — we will
turn it into a phased remediation proposal: fix the high-severity items
first, then add observability and cost controls, then scale.
