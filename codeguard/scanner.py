"""
Scanner: walks a project's node_modules tree (including deeply nested
sub-dependencies) and flags suspicious code using simple heuristic rules.
"""
import json
import os
import re

# Each rule: (rule_id, regex, points, plain-English reason)
RULES = [
    ("INSTALL_SCRIPT", None, 25, "Runs a script automatically when the package is installed"),
    ("ENV_ACCESS", r"process\.env", 20, "Reads environment variables (where secrets/API keys live)"),
    ("NETWORK_CALL", r"(https?\.request|\)\.request\(|fetch\(|axios\.|XMLHttpRequest|net\.connect)", 20,
     "Makes network requests"),
    ("EVAL", r"\beval\(|new Function\(", 25, "Executes dynamically built code (eval)"),
    ("BASE64_DECODE", r"Buffer\.from\([^)]*['\"]base64['\"]\)|atob\(", 15,
     "Decodes hidden base64 strings (common obfuscation trick)"),
    ("SENSITIVE_FILES", r"(\.npmrc|\.ssh|id_rsa|\.aws/credentials)", 30,
     "Touches credential files like .npmrc or SSH keys"),
    ("CHILD_PROCESS", r"child_process|\bexecSync\(|\bspawn\(", 20, "Runs shell commands"),
]

POPULAR = ["express", "react", "lodash", "axios", "chalk", "request", "moment", "debug"]


def _levenshtein(a, b):
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


def typosquat_of(name):
    """Return the popular package this name imitates, if any (1-2 letters off)."""
    for pop in POPULAR:
        if name != pop and _levenshtein(name, pop) <= 1:
            return pop
    return None


def walk_tree(project_dir):
    """Recursively find every package in node_modules, with its nesting depth and parent chain."""
    found = []

    def _walk(modules_dir, depth, chain):
        if not os.path.isdir(modules_dir):
            return
        for name in sorted(os.listdir(modules_dir)):
            pkg_dir = os.path.join(modules_dir, name)
            manifest = os.path.join(pkg_dir, "package.json")
            if not os.path.isfile(manifest):
                continue
            with open(manifest, encoding="utf-8") as f:
                meta = json.load(f)
            found.append({
                "name": meta.get("name", name),
                "version": meta.get("version", "0.0.0"),
                "path": pkg_dir,
                "depth": depth,
                "chain": chain + [meta.get("name", name)],
                "scripts": meta.get("scripts", {}),
            })
            _walk(os.path.join(pkg_dir, "node_modules"), depth + 1, chain + [meta.get("name", name)])

    _walk(os.path.join(project_dir, "node_modules"), 1, [])
    return found


def scan_package(pkg):
    """Apply heuristic rules to one package. Returns findings + evidence lines."""
    findings, evidence = [], []
    for hook in ("preinstall", "install", "postinstall"):
        if hook in pkg["scripts"]:
            findings.append(("INSTALL_SCRIPT", 25, f"Runs '{hook}' automatically on install"))
            evidence.append(f"package.json -> {hook}: {pkg['scripts'][hook]}")

    for root, _, files in os.walk(pkg["path"]):
        if "node_modules" in root.split(os.sep)[len(pkg["path"].split(os.sep)):]:
            continue  # nested packages are scanned separately
        for fn in files:
            if not fn.endswith(".js"):
                continue
            path = os.path.join(root, fn)
            with open(path, encoding="utf-8", errors="ignore") as f:
                lines = f.readlines()
            for rule_id, pattern, pts, reason in RULES:
                if pattern is None:
                    continue
                for i, line in enumerate(lines, 1):
                    if re.search(pattern, line):
                        if rule_id not in [x[0] for x in findings]:
                            findings.append((rule_id, pts, reason))
                        evidence.append(f"{fn}:{i}: {line.strip()[:120]}")
                        break

    squat = typosquat_of(pkg["name"])
    if squat:
        findings.append(("TYPOSQUAT", 30, f"Name looks like a copy of the popular package '{squat}'"))
    return findings, evidence


def verdict_for(score):
    if score >= 60:
        return "MALICIOUS"
    if score >= 25:
        return "SUSPICIOUS"
    return "SAFE"
