#!/usr/bin/env python3
"""
Agent Environment Diagnostic — local health-check for AI agent deployments.

Read-only survey of the machine's agent/LLM setup. Produces a report that
contains NO secret values and NO file contents — only names, counts,
versions, permissions and recommendations, so the report is safe to share
back with a consultant for a remediation proposal.

Usage:
    python env_diagnose.py [project_dir] [--output DIR] [--json]
    python env_diagnose.py [project_dir] --compare OLD_REPORT.json

Default project_dir is the current working directory.
"""
import argparse
import json
import os
import platform
import re
import shutil
import subprocess
import sys
import datetime

TOOL_VERSION = "1.1.0"
SCHEMA_VERSION = 2

# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------

SEV_RANK = {"high": 0, "medium": 1, "low": 2, "info": 3}

# Stable finding ID -> self-fix effort baseline (person-hours, rough).
# IDs with a <suffix> part look up by the base ID before the colon.
SELF_FIX_HOURS = {
    "NO-AGENT-STACK": 0,
    "DOCKER-IDLE": 0.5,
    "KEYS-ENV-OK": 0,
    "KEYS-NO-ENV": 1,             # locate keys, move to env/secret manager
    "ENVFILE-WORLD-READABLE": 0.5,
    "KEYS-HARDCODED": 3,          # move out of source + rotate committed keys
    "OBS-NO-LOGGING": 4,          # structured logging per model call + alert
    "OBS-NO-RETRY": 2,
    "DATA-HTTP": 1,
    "DATA-DOMAINS": 0,
    "DATA-NO-ENDPOINTS": 0,
    "COST-NO-TRACKING": 3,
    "COST-INFO": 0,
    "VCS-NO-GIT": 1,
    "VCS-PROMPTS-NO-GIT": 1,
}


def fix_hours(fid):
    base = fid.split(":", 1)[0]
    return SELF_FIX_HOURS.get(base, 0)


def finding(fid, category, severity, title, detail="", advice=""):
    return {
        "id": fid,
        "category": category,
        "severity": severity,
        "title": title,
        "detail": detail,
        "advice": advice,
        "self_fix_hours": fix_hours(fid),
    }

def which(prog):
    return shutil.which(prog)

def safe_read(path, limit=200_000):
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            return f.read(limit)
    except Exception:
        return ""

def walk_files(root, depth=2, max_files=2000):
    """Shallow walk with depth limit; skips heavy/irrelevant dirs."""
    skip = {".git", "node_modules", "__pycache__", ".venv", "venv",
            "site-packages", "dist-info", ".cache", "data", "logs"}
    count = 0
    root_depth = root.rstrip(os.sep).count(os.sep)
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in skip]
        if dirpath.rstrip(os.sep).count(os.sep) - root_depth >= depth:
            dirnames[:] = []
        for name in filenames:
            yield os.path.join(dirpath, name)
            count += 1
            if count >= max_files:
                return

# --------------------------------------------------------------------------
# A. Platform footprint
# --------------------------------------------------------------------------

ORCHESTRATION_PKGS = [
    "langchain", "langgraph", "llama-index", "llama_index", "autogen",
    "crewai", "openai", "anthropic", "dashscope", "google-generativeai",
    "litellm", "dify", "fastapi", "uvicorn", "flask", "streamlit",
    "tiktoken", "tiktoken_async", "httpx", "requests", "semantic-kernel",
    "haystack", "chromadb", "qdrant-client", "pinecone", "faiss",
]

def pip_packages():
    pkgs = {}
    try:
        out = subprocess.run([sys.executable, "-m", "pip", "list", "--format=freeze"],
                             capture_output=True, text=True, timeout=60)
        for line in out.stdout.splitlines():
            if "==" in line:
                name, ver = line.split("==", 1)
                pkgs[name.strip().lower()] = ver.strip()
    except Exception:
        pass
    return pkgs

def docker_info():
    info = {"installed": bool(which("docker")), "containers": []}
    if info["installed"]:
        try:
            out = subprocess.run(["docker", "ps", "--format", "{{.Names}}|{{.Image}}|{{.Status}}"],
                                 capture_output=True, text=True, timeout=20)
            for line in out.stdout.splitlines():
                parts = (line.split("|") + ["", "", ""])[:3]
                info["containers"].append({"name": parts[0], "image": parts[1], "status": parts[2]})
        except Exception:
            pass
    return info

def check_platform(project_dir, pip, docker):
    findings, facts = [], {}
    facts["os"] = f"{platform.system()} {platform.release()} ({platform.machine()})"
    facts["python"] = platform.python_version()
    facts["docker"] = docker

    found = [p for p in ORCHESTRATION_PKGS if p in pip]
    facts["agent_packages"] = found

    if not found and not docker["containers"]:
        findings.append(finding(
            "NO-AGENT-STACK", "platform", "info",
            "No agent/LLM stack detected in this Python environment",
            "No common agent frameworks (langchain, openai, anthropic, ...) "
            "found via pip, and no running Docker containers.",
            "If your agents run elsewhere (another venv, another machine), "
            "run this tool there too — one report per deployment."))
    if docker["installed"] and not docker["containers"]:
        findings.append(finding(
            "DOCKER-IDLE", "platform", "low",
            "Docker is installed but no containers are running",
            "", "If agents were deployed via Docker, confirm they are running; "
            "silent container exits are a common failure mode."))
    return findings, facts

# --------------------------------------------------------------------------
# B. Model access & key hygiene
# --------------------------------------------------------------------------

KEY_ENV_RE = re.compile(
    r"(OPENAI|ANTHROPIC|DASHSCOPE|QWEN|MOONSHOT|DEEPSEEK|ZHIPU|GLM|GEMINI|"
    r"GOOGLE|AZURE|HF_|HUGGING|COHERE|MISTRAL|GROQ|TOGETHER|FIREWORKS|"
    r"VOLC|ARK_|SILICONFLOW|MINIMAX|BAICHUAN|YI_|SPARK|ERNIE|QIANFAN)"
    r".*?(API_?KEY|TOKEN|SECRET)", re.IGNORECASE)

KEY_VALUE_RE = re.compile(
    r"\b(sk-[A-Za-z0-9_-]{16,}|[A-Za-z0-9_-]{28,}\.(?:[A-Za-z0-9_-]{6,})"
    r"(?:\.[A-Za-z0-9_-]{6,})?)")

ENV_FILES = [".env", ".env.local", ".env.production", "config.ini", "settings.py", "config.py"]

def check_keys(project_dir, env):
    findings, facts = [], {}
    # 1. Environment variables: report name + set/unset + length ONLY.
    key_vars = []
    for name in sorted(os.environ):
        if KEY_ENV_RE.search(name):
            val = os.environ[name]
            key_vars.append({"name": name, "set": bool(val.strip()),
                             "value_length": len(val) if val.strip() else 0})
    facts["key_env_vars"] = key_vars
    set_keys = [k for k in key_vars if k["set"]]
    if set_keys:
        findings.append(finding(
            "KEYS-ENV-OK", "keys", "info",
            f"{len(set_keys)} model API key(s) found in environment variables",
            "Names only: " + ", ".join(k["name"] for k in set_keys),
            "Environment variables are the right place for keys. Make sure the "
            "processes that need them can read them, and nothing else can."))
    else:
        findings.append(finding(
            "KEYS-NO-ENV", "keys", "medium",
            "No model API keys detected in environment variables",
            "", "If agents call model APIs, keys may be hardcoded in scripts or "
            "config files — a leak risk. Move them to environment variables "
            "or a secret manager."))

    # 2. .env / config files: existence + world-readable check + key-like line COUNT.
    env_hits = []
    for rel in ENV_FILES:
        p = os.path.join(project_dir, rel)
        if os.path.isfile(p):
            entry = {"file": rel, "key_like_lines": 0, "world_readable": None}
            try:
                st = os.stat(p)
                if hasattr(st, "st_mode"):
                    entry["world_readable"] = bool(st.st_mode & 0o004)
                text = safe_read(p)
                entry["key_like_lines"] = sum(
                    1 for line in text.splitlines()
                    if KEY_ENV_RE.search(line) and re.search(r"[=:]\s*\S+", line))
            except Exception:
                pass
            env_hits.append(entry)
            if entry["world_readable"]:
                findings.append(finding(
                    f"ENVFILE-WORLD-READABLE:{rel}", "keys", "high",
                    f"Secrets file '{rel}' is readable by other users on this machine",
                    "", "Restrict permissions: chmod 600 " + rel +
                    ". Anyone with an account on this host could read the keys."))
    facts["env_files"] = env_hits

    # 3. Hardcoded key patterns in project source files (count only, never values).
    hardcoded = 0
    scanned = 0
    for fp in walk_files(project_dir, depth=2):
        if not fp.endswith((".py", ".js", ".ts", ".json", ".yaml", ".yml", ".sh", ".md")):
            continue
        scanned += 1
        text = safe_read(fp, 100_000)
        if text and KEY_VALUE_RE.search(text):
            hardcoded += 1
    facts["files_scanned_for_hardcoded_keys"] = scanned
    facts["files_with_hardcoded_key_pattern"] = hardcoded
    if hardcoded:
        findings.append(finding(
            "KEYS-HARDCODED", "keys", "high",
            f"{hardcoded} file(s) contain strings that look like hardcoded API keys",
            "Files scanned: %d (depth 2 under the project directory). Values are "
            "never extracted or included in this report." % scanned,
            "Move keys out of source files into environment variables or a secret "
            "manager, and rotate any key that has been committed to git."))
    return findings, facts

# --------------------------------------------------------------------------
# C. Observability
# --------------------------------------------------------------------------

def check_observability(project_dir, pip, docker):
    findings, facts = [], {}
    has_logging = any(p in pip for p in ("structlog", "loguru"))
    has_monitoring = any(p in pip for p in ("prometheus-client", "sentry-sdk", "opentelemetry-*"))
    monitoring_containers = [c for c in docker.get("containers", [])
                             if any(k in c["image"].lower()
                                    for k in ("prometheus", "grafana", "sentry", "loki"))]
    facts["logging_lib"] = has_logging
    facts["monitoring_stack"] = monitoring_containers or ("pip" if has_monitoring else None)

    # log files present?
    log_files = [fp for fp in walk_files(project_dir, depth=2) if fp.endswith(".log")]
    facts["log_files_in_project"] = len(log_files)

    if not has_logging and not monitoring_containers and not log_files:
        findings.append(finding(
            "OBS-NO-LOGGING", "observability", "high",
            "No logging or monitoring detected for the agent stack",
            "", "When an agent fails silently you lose trust and money. Add "
            "structured logging for every model call (prompt size, latency, "
            "tokens, errors) and a simple alert on failure rate."))
    retry_hint = any("retry" in p or "backoff" in p or "tenacity" in p for p in pip)
    facts["retry_lib"] = retry_hint
    if not retry_hint:
        findings.append(finding(
            "OBS-NO-RETRY", "observability", "medium",
            "No retry/backoff library detected",
            "", "Model APIs rate-limit and time out. Without retries with "
            "backoff, one busy hour can break your workflow."))
    return findings, facts

# --------------------------------------------------------------------------
# D. Data boundary
# --------------------------------------------------------------------------

URL_RE = re.compile(r"https?://([A-Za-z0-9.-]+)")

def check_data_boundary(project_dir):
    findings, facts = [], {}
    domains, insecure = set(), set()
    for fp in walk_files(project_dir, depth=2):
        if not fp.endswith((".py", ".js", ".ts", ".json", ".yaml", ".yml", ".env",
                            ".env.local", ".env.production", ".txt", ".md")):
            continue
        text = safe_read(fp, 100_000)
        if not text:
            continue
        for m in URL_RE.finditer(text):
            dom = m.group(1).lower()
            if dom in ("localhost", "127.0.0.1", "0.0.0.0") or dom.endswith(".local"):
                continue
            domains.add(dom)
            if m.group(0).startswith("http://"):
                insecure.add(dom)
    facts["outbound_domains"] = sorted(domains)
    facts["insecure_http_endpoints"] = sorted(insecure)
    if insecure:
        findings.append(finding(
            "DATA-HTTP", "data", "high",
            f"{len(insecure)} non-HTTPS endpoint(s) referenced in configs",
            "Domains: " + ", ".join(sorted(insecure)),
            "Switch to HTTPS. Plain HTTP sends prompts and business data in "
            "the clear across the network."))
    if domains:
        findings.append(finding(
            "DATA-DOMAINS", "data", "info",
            f"{len(domains)} external service domain(s) referenced",
            "Domains: " + ", ".join(sorted(domains)[:20]),
            "Review this list: every domain is a place your prompts or data "
            "can travel to. Remove integrations you no longer use."))
    else:
        findings.append(finding(
            "DATA-NO-ENDPOINTS", "data", "low",
            "No external endpoints found in the scanned project files",
            "", "If agents call external APIs, configs may live outside the "
            "scanned directory — run this tool where the services actually run."))
    return findings, facts

# --------------------------------------------------------------------------
# E. Cost visibility
# --------------------------------------------------------------------------

def check_cost(pip):
    findings, facts = [], {}
    has_usage = any(p in pip for p in ("litellm", "openai", "tiktoken", "helicone", "langfuse"))
    facts["usage_tracking_hint"] = has_usage
    if not has_usage:
        findings.append(finding(
            "COST-NO-TRACKING", "cost", "medium",
            "No token usage / cost tracking detected",
            "", "Add per-call token accounting (most model APIs return usage in "
            "the response). Log it per workflow so you can see cost per business "
            "process, not just a monthly bill."))
    else:
        findings.append(finding(
            "COST-INFO", "cost", "info",
            "Model client libraries present — usage fields are available",
            "", "Make sure usage numbers are actually persisted per call; "
            "libraries return them but rarely store them."))
    return findings, facts

# --------------------------------------------------------------------------
# F. Version control
# --------------------------------------------------------------------------

def check_version_control(project_dir):
    findings, facts = [], {}
    has_git = os.path.isdir(os.path.join(project_dir, ".git"))
    facts["git_repo"] = has_git
    prompt_files = [fp for fp in walk_files(project_dir, depth=2)
                    if os.path.basename(fp).lower().startswith(("prompt", "system_prompt"))
                    or "prompt" in os.path.basename(fp).lower()]
    facts["prompt_like_files"] = [os.path.relpath(p, project_dir) for p in prompt_files[:20]]
    if not has_git:
        findings.append(finding(
            "VCS-NO-GIT", "vcs", "medium",
            "Project directory is not a git repository",
            "", "Prompts, configs and agent logic change constantly. Without "
            "version control you cannot answer 'what changed when it broke'. "
            "Run: git init && git add -A && git commit -m init"))
    if prompt_files and not has_git:
        findings.append(finding(
            "VCS-PROMPTS-NO-GIT", "vcs", "medium",
            f"{len(prompt_files)} prompt file(s) with no version control",
            "", "Treat prompts like code: track every change, keep the working "
            "version reviewable."))
    return findings, facts

# --------------------------------------------------------------------------
# Report assembly
# --------------------------------------------------------------------------

def build_report(project_dir):
    pip = pip_packages()
    docker = docker_info()
    all_findings = []
    facts = {"generated_at": datetime.datetime.now().isoformat(),
             "project_dir": os.path.abspath(project_dir)}

    for fn in (check_platform, check_keys, check_observability,
               check_data_boundary, check_cost, check_version_control):
        if fn is check_platform:
            f, fa = fn(project_dir, pip, docker)
        elif fn is check_keys:
            f, fa = fn(project_dir, os.environ)
        elif fn is check_observability:
            f, fa = fn(project_dir, pip, docker)
        elif fn is check_cost:
            f, fa = fn(pip)
        else:
            f, fa = fn(project_dir)
        all_findings.extend(f)
        facts.update(fa)

    all_findings.sort(key=lambda x: (SEV_RANK.get(x["severity"], 9), x.get("id", "")))
    summary = {s: sum(1 for f in all_findings if f["severity"] == s)
               for s in ("high", "medium", "low", "info")}
    return {
        "report_type": "agent_environment_diagnostic",
        "tool_version": TOOL_VERSION,
        "schema_version": SCHEMA_VERSION,
        "generated_at": facts["generated_at"],
        "summary": summary,
        "findings": all_findings,
        "facts": facts,
        "note": ("This report contains NO secret values and NO file contents — "
                 "only names, counts, versions, permissions, domains and "
                 "recommendations. It is safe to share back for a remediation "
                 "proposal."),
    }

def compare_reports(current, old_path):
    """Diff two diagnostic reports by stable finding ID: new/resolved/persisting."""
    with open(old_path, encoding="utf-8") as f:
        old = json.load(f)

    def idmap(rep):
        return {f["id"]: f for f in rep.get("findings", []) if f.get("id")}

    cur, oldm = idmap(current), idmap(old)
    new_ids = sorted(set(cur) - set(oldm))
    resolved_ids = sorted(set(oldm) - set(cur))
    persist_ids = sorted(set(cur) & set(oldm))
    sev_changed = [{"id": i, "from": oldm[i]["severity"], "to": cur[i]["severity"]}
                   for i in persist_ids if oldm[i]["severity"] != cur[i]["severity"]]
    return {
        "compared_against": os.path.abspath(old_path),
        "old_generated_at": old.get("generated_at"),
        "new": [cur[i] for i in new_ids],
        "resolved": [{"id": i, "severity": oldm[i]["severity"], "title": oldm[i]["title"]}
                     for i in resolved_ids],
        "persisting": [cur[i] for i in persist_ids],
        "severity_changed": sev_changed,
    }


def render_markdown(report):
    lines = [
        "# Agent Environment Diagnostic Report",
        "",
        "Generated: %s  |  Project: %s  |  Tool: v%s (schema v%s)" % (
            report["generated_at"], report["facts"].get("project_dir", ""),
            report.get("tool_version", "?"), report.get("schema_version", "?")),
        "",
        "**Summary:** %d high · %d medium · %d low · %d info" % (
            report["summary"]["high"], report["summary"]["medium"],
            report["summary"]["low"], report["summary"]["info"]),
        "",
        "> %s" % report["note"],
        "",
    ]
    for f in report["findings"]:
        hours = f.get("self_fix_hours")
        hours_txt = " · self-fix ~%s h" % hours if hours else ""
        lines.append("### [%s] %s" % (f["severity"].upper(), f["title"]))
        lines.append("- Finding ID: `%s`%s" % (f.get("id", "?"), hours_txt))
        if f["detail"]:
            lines.append("- %s" % f["detail"])
        if f["advice"]:
            lines.append("- **Advice:** %s" % f["advice"])
        lines.append("")
    cmp_ = report.get("compare")
    if cmp_:
        lines += ["## Comparison with previous report", "",
                  "- Baseline: `%s` (generated %s)" % (
                      cmp_["compared_against"], cmp_.get("old_generated_at") or "unknown"), ""]
        if cmp_["resolved"]:
            lines.append("**Resolved:**")
            for r in cmp_["resolved"]:
                lines.append("- RESOLVED `%s` %s" % (r["id"], r["title"]))
            lines.append("")
        if cmp_["new"]:
            lines.append("**New:**")
            for n in cmp_["new"]:
                lines.append("- NEW `%s` %s" % (n["id"], n["title"]))
            lines.append("")
        if cmp_["severity_changed"]:
            lines.append("**Severity changed:**")
            for s in cmp_["severity_changed"]:
                lines.append("- CHANGED `%s`: %s -> %s" % (s["id"], s["from"], s["to"]))
            lines.append("")
        if cmp_["persisting"]:
            lines.append("**Persisting** (not yet fixed, follow the advice):")
            for p in cmp_["persisting"]:
                lines.append("- `%s` %s" % (p["id"], p["title"]))
            lines.append("")
        if not (cmp_["resolved"] or cmp_["new"] or cmp_["severity_changed"] or cmp_["persisting"]):
            lines.append("No changes between the two runs.", "")
    return "\n".join(lines)

def main():
    ap = argparse.ArgumentParser(description="Agent environment diagnostic (read-only)")
    ap.add_argument("project_dir", nargs="?", default=os.getcwd())
    ap.add_argument("--output", default=None, help="Directory for reports (default: <project_dir>/env_diag_reports)")
    ap.add_argument("--compare", metavar="OLD_REPORT.json",
                    help="Compare with a previous JSON report (new/resolved/persisting)")
    ap.add_argument("--json", action="store_true", help="Also print JSON to stdout")
    args = ap.parse_args()

    report = build_report(args.project_dir)
    if args.compare:
        if not os.path.exists(args.compare):
            print("Compare failed: old report not found: %s" % args.compare)
            sys.exit(2)
        try:
            report["compare"] = compare_reports(report, args.compare)
        except Exception as e:
            print("Compare failed: old report unreadable (%s)" % type(e).__name__)
            sys.exit(2)

    outdir = args.output or os.path.join(args.project_dir, "env_diag_reports")
    os.makedirs(outdir, exist_ok=True)
    md_path = os.path.join(outdir, "env_diagnostic_report.md")
    js_path = os.path.join(outdir, "env_diagnostic_report.json")
    with open(md_path, "w", encoding="utf-8") as f:
        f.write(render_markdown(report))
    with open(js_path, "w", encoding="utf-8") as f:
        json.dump(report, f, ensure_ascii=False, indent=2)

    s = report["summary"]
    print("Agent environment diagnostic complete.")
    print("  high: %d | medium: %d | low: %d | info: %d" % (
        s["high"], s["medium"], s["low"], s["info"]))
    cmp_ = report.get("compare")
    if cmp_:
        print("  compare: %d new | %d resolved | %d persisting" % (
            len(cmp_["new"]), len(cmp_["resolved"]), len(cmp_["persisting"])))
    print("Report: %s" % md_path)
    print("        %s" % js_path)
    if args.json:
        print(json.dumps(report, ensure_ascii=False, indent=2))

if __name__ == "__main__":
    main()
