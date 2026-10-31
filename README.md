# 🛡️ CodeGuard — Open-Source Dependency Trap Detector

![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)

**Supply-chain attacks hide malicious code 3, 4, 5 levels deep in your dependency tree — where nobody ever reads.**
CodeGuard is an autonomous security agent that walks the *entire* nested dependency tree, flags backdoors,
explains them in plain English for junior developers, and writes every verdict to an untamperable audit log on Solana.

```
manifest ─► walk nested node_modules ─► Snowflake known-bad lookup ─► heuristic code scan
        ─► Gemma 4 plain-English explanation ─► Solana onchain audit record ─► report
```

## Quick start (2 minutes)

```bash
pip install -r requirements.txt
python main.py sample_project              # scan the demo project
python main.py --reputation string-padder  # pull past verdicts for a package
python main.py --verify                    # prove the audit log wasn't edited
pytest -v                                  # run the test suite
```

The demo project contains a hijacked package hidden **3 levels deep**
(`express-lite > body-helper > string-padder`) and a **typosquat** (`axioss` imitating `axios`).
CodeGuard catches both and marks the 3 clean packages as SAFE.

> ⚠️ `sample_project/` contains **inert test fixtures only**. The suspicious functions are never called
> and point to the reserved `example.invalid` domain. Do not `npm install` it.

## How each sponsor track is used

### 🤖 Google Gemma 4 — plain-English explainer (`codeguard/gemma.py`)
For each risky package, Gemma 4 receives the raw evidence lines and the rules that fired, and returns:
**WHAT IT DOES / WHY IT'S DANGEROUS / WHAT TO DO** in under 90 words, written for junior developers.
```bash
export GEMINI_API_KEY=your_google_ai_studio_key
export GEMMA_MODEL=<gemma-4 model id from AI Studio>
```
Without a key, a template explanation is used so the demo never breaks.

### ❄️ Snowflake + CoCo — vulnerability data pipeline (`snowflake/`, `codeguard/snowflake_source.py`)
- **Dataset:** [OSV.dev](https://osv.dev) open-source vulnerability database (free, public), npm ecosystem — loaded into Snowflake.
- `snowflake/01_setup_and_load.sql` — builds `CODEGUARD_DB.SECURITY.KNOWN_COMPROMISED_PACKAGES` from raw OSV JSON.
- `snowflake/02_anomaly_views.sql` — publishing-anomaly views: `MALWARE_PACKAGES`, `PUBLISHING_BURSTS`
  (coordinated malware campaigns), `TYPOSQUAT_SUSPECTS` (edit distance 1 from popular packages).
- We attempted to use **Snowflake Cortex Code (CoCo)** to generate the pipeline SQL, but CoCo isn't enabled on Snowflake trial accounts, so the team wrote the SQL by hand following the same pipeline design. The agent queries the live Snowflake table at runtime.
- The agent queries Snowflake live when credentials are set:
```bash
export SNOWFLAKE_ACCOUNT=xxx SNOWFLAKE_USER=xxx SNOWFLAKE_PASSWORD=xxx
```
  otherwise it uses `data/known_compromised.csv`, an export of the same table.

### ◎ Solana — agent identity + onchain audit log (`codeguard/solana_log.py`)
- The agent has its own **Solana keypair** = its onchain identity (`agent-keypair.json`).
- Every verdict becomes a JSON record → SHA-256 hash → written to **Solana devnet via the Memo program**,
  signed by the agent. Each record also stores the previous record's hash (hash chain), so editing any
  past verdict is detected by `python main.py --verify`.
- `--reputation <pkg>` pulls a package's verdict history with Solana Explorer links.
```bash
pip install solders
python -c "from codeguard.solana_log import agent_identity; print(agent_identity())"
solana airdrop 1 <AGENT_PUBKEY> --url devnet      # or https://faucet.solana.com
export SOLANA_LIVE=1
python main.py sample_project                      # prints explorer.solana.com links
```
Without `SOLANA_LIVE=1` it runs in **simulated mode** (same records and hash chain, stored locally).

### 🧑‍✈️ How GitHub Copilot helped
- **Unfamiliar parsing APIs:** we had never parsed nested `node_modules` trees. We asked Copilot
  *"walk node_modules recursively and record each package's depth and parent chain"* — it produced the
  recursive `walk_tree()` approach, which we adapted.
- **Solana transactions:** Copilot explained how to build a Memo-program instruction with `solders`
  (`Instruction`, `AccountMeta`, `Message`, `Transaction`) and send it over raw JSON-RPC.
- **Mock vulnerable scripts:** we prompted Copilot to *"write an npm package fixture with a subtle install-time
  credential leak that is never executed"* → `string-padder/setup.js` and the `axioss` typosquat.
- **Test suite:** Copilot generated `tests/test_scanner.py` — 7 tests covering deep nesting, malicious and
  typosquat detection, no false positives on clean packages, Snowflake lookups, and audit-log tamper detection.

## Detection rules
| Rule | Why it matters |
|---|---|
| INSTALL_SCRIPT | Code runs automatically on `npm install` |
| ENV_ACCESS | Environment variables hold API keys |
| NETWORK_CALL | Can send stolen data out |
| EVAL | Runs hidden, dynamically built code |
| BASE64_DECODE | Common way to hide URLs/payloads |
| SENSITIVE_FILES | Touches `.npmrc`, SSH keys, AWS credentials |
| CHILD_PROCESS | Runs shell commands |
| TYPOSQUAT | Name 1 letter off a popular package |
| SNOWFLAKE_KNOWN_BAD | Listed in the Snowflake vulnerability index |

Score ≥ 60 = MALICIOUS, ≥ 25 = SUSPICIOUS, else SAFE.

## Project structure
```
main.py                  CLI entry point
codeguard/scanner.py     tree walker + heuristic rules
codeguard/snowflake_source.py   Snowflake data source
codeguard/gemma.py       Gemma 4 explainer
codeguard/solana_log.py  Solana identity + onchain audit log
snowflake/*.sql          CoCo-built pipeline
data/known_compromised.csv   Snowflake export (offline fallback)
sample_project/          inert demo fixtures
tests/                   Copilot-generated test suite
```

## License
MIT — see [LICENSE](LICENSE).
