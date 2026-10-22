"""Patrol: defensive, consent-based, static-only repo security scanner.

Never sends traffic at a target service, never attempts auth, never exploits.
Reads: a shallow git clone + read-only GitHub API calls via the signed-in gh CLI.
"""
import argparse, json, os, re, subprocess, sys, tempfile, datetime

# ---- HARD-CODED OWNER GUARD (v1) -------------------------------------------
ALLOWED_OWNERS = frozenset({"fitzyracing1"})

class ScopeError(Exception):
    pass

def guard(full_name):
    if "/" not in full_name:
        full_name = "fitzyracing1/" + full_name
    owner = full_name.split("/", 1)[0]
    if owner.lower() not in ALLOWED_OWNERS:
        raise ScopeError(f"refusing {full_name}: v1 only scans repos owned by {sorted(ALLOWED_OWNERS)}")
    return full_name

# ---- consent check (for FUTURE outside use; informational in v1) -----------
KNOWN_BOUNTY_HINTS = re.compile(r"hackerone\.com|bugcrowd\.com|intigriti\.com|yeswehack\.com|bug bounty|safe harbor", re.I)

def consent_signals(root):
    sig = {"security_md": None, "security_txt": None, "bounty_reference": False}
    for p in ("SECURITY.md", ".github/SECURITY.md", "docs/SECURITY.md"):
        if os.path.isfile(os.path.join(root, p)):
            sig["security_md"] = p
    for p in (".well-known/security.txt", "security.txt", "public/.well-known/security.txt"):
        if os.path.isfile(os.path.join(root, p)):
            sig["security_txt"] = p
    for p in (sig["security_md"], sig["security_txt"]):
        if p and KNOWN_BOUNTY_HINTS.search(open(os.path.join(root, p), errors="ignore").read()):
            sig["bounty_reference"] = True
    sig["invites_reports"] = bool(sig["security_md"] or sig["security_txt"])
    return sig

# ---- helpers ---------------------------------------------------------------
def gh_api(path):
    r = subprocess.run(["gh", "api", "-H", "Accept: application/vnd.github+json", "--paginate", path],
                       capture_output=True, text=True)
    if r.returncode != 0:
        return None, (r.stderr.strip() or r.stdout.strip())[:200]
    try:
        return json.loads(r.stdout or "null"), None
    except json.JSONDecodeError:
        # paginate concatenates arrays: ][  -> ,
        return json.loads(r.stdout.replace("]\n[", ",").replace("][", ",")), None

SKIP_DIRS = {".git", "node_modules", "vendor", "dist", "build", ".venv", "venv", "__pycache__"}

def walk(root):
    for d, dirs, files in os.walk(root):
        dirs[:] = [x for x in dirs if x not in SKIP_DIRS]
        for f in files:
            yield os.path.join(d, f)

# ---- checks ----------------------------------------------------------------
SECRET_PATTERNS = {
    "aws_access_key": re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    "github_token": re.compile(r"\b(gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{60,})\b"),
    "slack_token": re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}\b"),
    "private_key": re.compile(r"-----BEGIN (RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----"),
    "google_api_key": re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b"),
    "openai_key": re.compile(r"\bsk-(proj-)?[A-Za-z0-9]{32,}\b"),
    "stripe_live_key": re.compile(r"\b[sr]k_live_[0-9a-zA-Z]{20,}\b"),
    "generic_assignment": re.compile(r"""(?i)\b(api[_-]?key|secret|passwd|password|token)\b\s*[:=]\s*['"][A-Za-z0-9_\-/+=]{16,}['"]"""),
}
PLACEHOLDER = re.compile(r"(?i)example|dummy|placeholder|your[_-]|xxxx|changeme|<|\$\{|process\.env|os\.environ|test")

def check_secrets(root):
    out = []
    for path in walk(root):
        try:
            if os.path.getsize(path) > 1_000_000:
                continue
            with open(path, errors="ignore") as fh:
                for i, line in enumerate(fh, 1):
                    for name, rx in SECRET_PATTERNS.items():
                        m = rx.search(line)
                        if m and not (name == "generic_assignment" and PLACEHOLDER.search(line)):
                            v = m.group(0)
                            out.append({"type": name, "file": os.path.relpath(path, root), "line": i,
                                        "redacted": v[:4] + "…" + str(len(v))})
        except (OSError, UnicodeDecodeError):
            continue
    return out

def check_workflows(root):
    out = []
    wf_dir = os.path.join(root, ".github", "workflows")
    if not os.path.isdir(wf_dir):
        return out
    for f in sorted(os.listdir(wf_dir)):
        if not f.endswith((".yml", ".yaml")):
            continue
        text = open(os.path.join(wf_dir, f), errors="ignore").read()
        rel = f".github/workflows/{f}"
        if not re.search(r"(?m)^permissions\s*:", text) and not re.search(r"(?m)^\s+permissions\s*:", text):
            out.append({"file": rel, "issue": "no permissions block (inherits repo default token scope)", "severity": "medium"})
        if re.search(r"permissions\s*:\s*write-all", text):
            out.append({"file": rel, "issue": "permissions: write-all", "severity": "high"})
        if re.search(r"\bpull_request_target\b", text):
            sev = "high" if re.search(r"github\.event\.pull_request\.head\.(sha|ref)", text) else "medium"
            out.append({"file": rel, "issue": "uses pull_request_target" + (" with PR head checkout" if sev == "high" else ""), "severity": sev})
        if re.search(r"\$\{\{\s*github\.event\.(issue|pull_request|comment|review)\.[a-z_.]*(title|body)", text):
            out.append({"file": rel, "issue": "untrusted event text interpolated in expression (script injection risk)", "severity": "high"})
    return out

def check_dependencies(full, root):
    res = {"dependabot_alerts": None, "local_audit": [], "notes": []}
    data, err = gh_api(f"repos/{full}/dependabot/alerts?state=open&per_page=100")
    if data is None:
        res["notes"].append(f"dependabot alerts unavailable: {err}")
    else:
        res["dependabot_alerts"] = [{
            "package": a["dependency"]["package"]["name"],
            "ecosystem": a["dependency"]["package"]["ecosystem"],
            "severity": a["security_advisory"]["severity"],
            "ghsa": a["security_advisory"]["ghsa_id"],
            "cve": a["security_advisory"].get("cve_id"),
            "manifest": a["dependency"].get("manifest_path"),
        } for a in data]
    # optional local audit, only against the package registry advisory DB (never the target)
    if os.path.isfile(os.path.join(root, "package-lock.json")) and _which("npm"):
        r = subprocess.run(["npm", "audit", "--json", "--package-lock-only"], cwd=root, capture_output=True, text=True, timeout=180)
        try:
            for name, v in (json.loads(r.stdout).get("vulnerabilities") or {}).items():
                res["local_audit"].append({"package": name, "severity": v.get("severity"), "tool": "npm audit"})
        except json.JSONDecodeError:
            res["notes"].append("npm audit output unparsable")
    return res

def _which(b):
    return any(os.access(os.path.join(p, b), os.X_OK) for p in os.environ.get("PATH", "").split(os.pathsep))

def check_settings(full, root):
    s = {}
    _, err = gh_api(f"repos/{full}/vulnerability-alerts")
    s["dependabot_alerts_enabled"] = err is None
    s["dependabot_config"] = os.path.isfile(os.path.join(root, ".github", "dependabot.yml")) or os.path.isfile(os.path.join(root, ".github", "dependabot.yaml"))
    data, err = gh_api(f"repos/{full}/code-scanning/default-setup")
    default_on = bool(data and data.get("state") == "configured")
    wf = os.path.join(root, ".github", "workflows")
    codeql_wf = os.path.isdir(wf) and any("codeql" in open(os.path.join(wf, f), errors="ignore").read().lower() for f in os.listdir(wf))
    s["codeql_enabled"] = default_on or codeql_wf
    return s

# ---- driver ----------------------------------------------------------------
def scan_repo(full, local=None):
    full = guard(full)
    tmp = None
    root = local
    if root is None:
        tmp = tempfile.TemporaryDirectory()
        root = os.path.join(tmp.name, "r")
        r = subprocess.run(["gh", "repo", "clone", full, root, "--", "--depth=1", "-q"], capture_output=True, text=True)
        if r.returncode != 0:
            return {"repo": full, "error": r.stderr.strip()[:300]}
    try:
        consent = consent_signals(root)
        deps = check_dependencies(full, root)
        rep = {
            "repo": full,
            "scanned_at": datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds"),
            "consent": consent,
            "missing_security_md": consent["security_md"] is None,
            "dependencies": deps,
            "secrets": check_secrets(root),
            "workflows": check_workflows(root),
            "settings": check_settings(full, root),
        }
        rep["summary"] = summarize(rep)
        return rep
    finally:
        if tmp:
            tmp.cleanup()

def summarize(rep):
    d = rep["dependencies"]
    cves = len(d["dependabot_alerts"] or []) + len(d["local_audit"])
    return {"missing_security_md": rep["missing_security_md"], "vulnerable_deps": cves,
            "secrets": len(rep["secrets"]), "risky_workflow_findings": len(rep["workflows"]),
            "dependabot": rep["settings"]["dependabot_alerts_enabled"], "codeql": rep["settings"]["codeql_enabled"]}

def to_markdown(reports):
    L = ["# Patrol report", "", "_Static, defensive, owner-only scan. No live-service traffic, no auth attempts, no exploits._", "",
         "| Repo | SECURITY.md | Vuln deps | Secrets | Risky workflow findings | Dependabot | CodeQL |",
         "|---|---|---|---|---|---|---|"]
    for r in reports:
        if "error" in r:
            L.append(f"| {r['repo']} | error | | | | | |"); continue
        s = r["summary"]
        L.append(f"| {r['repo']} | {'missing' if s['missing_security_md'] else 'present'} | {s['vulnerable_deps']} | {s['secrets']} | {s['risky_workflow_findings']} | {'on' if s['dependabot'] else 'off'} | {'on' if s['codeql'] else 'off'} |")
    for r in reports:
        L += ["", f"## {r['repo']}"]
        if "error" in r:
            L.append(f"Error: {r['error']}"); continue
        c = r["consent"]
        L.append(f"- Consent signals: SECURITY.md={c['security_md'] or 'none'}, security.txt={c['security_txt'] or 'none'}, bounty reference={c['bounty_reference']}")
        d = r["dependencies"]
        alerts = d["dependabot_alerts"]
        L.append(f"- Dependabot open alerts: {len(alerts) if alerts is not None else 'n/a'}")
        for a in (alerts or [])[:25]:
            L.append(f"  - [{a['severity']}] {a['ecosystem']}/{a['package']} {a['cve'] or a['ghsa']} ({a['manifest']})")
        for a in d["local_audit"][:25]:
            L.append(f"  - [{a['severity']}] {a['package']} ({a['tool']})")
        for n in d["notes"]:
            L.append(f"  - note: {n}")
        L.append(f"- Secrets (redacted): {len(r['secrets'])}")
        for s in r["secrets"][:25]:
            L.append(f"  - {s['type']} at {s['file']}:{s['line']} ({s['redacted']})")
        L.append(f"- Workflow findings: {len(r['workflows'])}")
        for w in r["workflows"]:
            L.append(f"  - [{w['severity']}] {w['file']}: {w['issue']}")
        st = r["settings"]
        L.append(f"- Dependabot alerts: {'on' if st['dependabot_alerts_enabled'] else 'off'}; dependabot.yml: {'yes' if st['dependabot_config'] else 'no'}; CodeQL: {'on' if st['codeql_enabled'] else 'off'}")
    return "\n".join(L) + "\n"

def main(argv=None):
    ap = argparse.ArgumentParser(prog="patrol", description="Owner-only static security scan of GitHub repos.")
    ap.add_argument("repos", nargs="+", help="owner/name or name (defaults to fitzyracing1)")
    ap.add_argument("-o", "--out", default="patrol-out")
    a = ap.parse_args(argv)
    try:
        targets = [guard(x) for x in a.repos]   # refuse BEFORE touching anything
    except ScopeError as e:
        print(e, file=sys.stderr); return 2
    os.makedirs(a.out, exist_ok=True)
    reports = []
    for t in targets:
        print(f"patrol: scanning {t}", file=sys.stderr)
        rep = scan_repo(t)
        reports.append(rep)
        base = os.path.join(a.out, t.replace("/", "__"))
        json.dump(rep, open(base + ".json", "w"), indent=2)
        open(base + ".md", "w").write(to_markdown([rep]))
    open(os.path.join(a.out, "report.md"), "w").write(to_markdown(reports))
    json.dump(reports, open(os.path.join(a.out, "report.json"), "w"), indent=2)
    print(os.path.join(a.out, "report.md"))
    return 0

if __name__ == "__main__":
    sys.exit(main())
