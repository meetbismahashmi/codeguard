"""
CodeGuard CLI

    python main.py sample_project            # scan a project
    python main.py --reputation string-padder # look up past verdicts
    python main.py --verify                   # check audit log hasn't been tampered with
"""
import sys

from codeguard import scanner, snowflake_source, gemma, solana_log

RESET, RED, YEL, GRN, BOLD = "\033[0m", "\033[91m", "\033[93m", "\033[92m", "\033[1m"
COLOR = {"MALICIOUS": RED, "SUSPICIOUS": YEL, "SAFE": GRN}


def scan(project_dir):
    print(f"{BOLD}CodeGuard - supply-chain audit of '{project_dir}'{RESET}")
    print(f"Agent identity (Solana): {solana_log.agent_identity()}\n")

    known, source = snowflake_source.load_known_compromised()
    print(f"[1] Loaded {len(known)} known-compromised records from {source}")

    pkgs = scanner.walk_tree(project_dir)
    print(f"[2] Found {len(pkgs)} packages (max depth {max((p['depth'] for p in pkgs), default=0)})\n")

    results = []
    for p in pkgs:
        findings, evidence = scanner.scan_package(p)
        hit = snowflake_source.lookup(known, p["name"], p["version"])
        if hit:
            findings.append(("SNOWFLAKE_KNOWN_BAD", 60,
                             f"Listed in Snowflake index: {hit['advisory_id']} ({hit['severity']}) - {hit['summary']}"))
        score = min(100, sum(f[1] for f in findings))
        verdict = scanner.verdict_for(score)
        results.append((p, findings, evidence, score, verdict))

        indent = "  " * p["depth"]
        print(f"{indent}{COLOR[verdict]}{verdict:<10}{RESET} {p['name']}@{p['version']}  (score {score})")

    flagged = [r for r in results if r[4] != "SAFE"]
    print(f"\n[3] {len(flagged)} risky package(s). Explaining with Gemma 4 + logging to Solana...\n")

    for p, findings, evidence, score, verdict in flagged:
        text, engine = gemma.explain(p, findings, evidence)
        entry = solana_log.log_verdict(p["name"], p["version"], verdict, score)
        print(f"{COLOR[verdict]}{BOLD}== {p['name']}@{p['version']} [{verdict}, score {score}] =={RESET}")
        print(f"Path: {' > '.join(p['chain'])}  (depth {p['depth']})")
        for f in findings:
            print(f"  - {f[0]}: {f[2]}")
        print(f"\n{text}\n   (explained by {engine})")
        print(f"Audit log [{entry['mode']}]: hash {entry['record_hash'][:16]}...")
        if entry["explorer"]:
            print(f"   View onchain: {entry['explorer']}")
        print()

    for p, _, _, score, verdict in results:
        if verdict == "SAFE":
            solana_log.log_verdict(p["name"], p["version"], verdict, score)

    print(f"Audit log integrity: {'VALID' if solana_log.verify_chain() else 'TAMPERED!'}")
    return results


def main():
    args = sys.argv[1:]
    if not args:
        print(__doc__)
    elif args[0] == "--reputation":
        for e in solana_log.reputation(args[1]):
            print(f"{e['pkg']:<28} {e['verdict']:<10} score={e['score']:<3} {e['mode']}  {e['explorer'] or e['record_hash'][:16]}")
    elif args[0] == "--verify":
        print("Audit log VALID" if solana_log.verify_chain() else "Audit log TAMPERED!")
    else:
        scan(args[0])


if __name__ == "__main__":
    main()
