"""
Solana audit log.

Every verdict is turned into a small JSON record, hashed (SHA-256), and the
hash is written onchain to Solana devnet using the Memo program, signed by
the CodeGuard agent's own keypair (its onchain identity).

- LIVE mode: needs `pip install solders` and a funded devnet keypair at
  SOLANA_KEYPAIR (default ./agent-keypair.json). Fund it with:
      solana airdrop 1 <AGENT_PUBKEY> --url devnet
  (or https://faucet.solana.com)
- SIMULATED mode (allowed by the challenge): same records + hashes are
  appended to audit_log.jsonl as a hash chain, so tampering is detectable.
"""
import hashlib
import json
import os
import time

import requests

RPC = os.getenv("SOLANA_RPC", "https://api.devnet.solana.com")
MEMO_PROGRAM = "MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr"
KEYPAIR_PATH = os.getenv("SOLANA_KEYPAIR", "agent-keypair.json")
LOCAL_LOG = "audit_log.jsonl"


def _rpc(method, params):
    r = requests.post(RPC, json={"jsonrpc": "2.0", "id": 1, "method": method, "params": params}, timeout=30)
    r.raise_for_status()
    out = r.json()
    if "error" in out:
        raise RuntimeError(out["error"])
    return out["result"]


def load_agent():
    """Load (or create) the agent keypair = the agent's identity."""
    from solders.keypair import Keypair
    if os.path.exists(KEYPAIR_PATH):
        with open(KEYPAIR_PATH) as f:
            return Keypair.from_bytes(bytes(json.load(f)))
    kp = Keypair()
    with open(KEYPAIR_PATH, "w") as f:
        json.dump(list(bytes(kp)), f)
    return kp


def agent_identity():
    try:
        return str(load_agent().pubkey())
    except ImportError:
        return "SIMULATED-AGENT (install 'solders' for a real Solana identity)"


def _send_memo(memo_text):
    from solders.instruction import Instruction, AccountMeta
    from solders.message import Message
    from solders.pubkey import Pubkey
    from solders.hash import Hash
    from solders.transaction import Transaction
    import base64

    kp = load_agent()
    ix = Instruction(Pubkey.from_string(MEMO_PROGRAM), memo_text.encode(),
                     [AccountMeta(kp.pubkey(), is_signer=True, is_writable=False)])
    bh = Hash.from_string(_rpc("getLatestBlockhash", [{"commitment": "finalized"}])["value"]["blockhash"])
    tx = Transaction([kp], Message([ix], kp.pubkey()), bh)
    sig = _rpc("sendTransaction", [base64.b64encode(bytes(tx)).decode(), {"encoding": "base64"}])
    return sig


def _prev_hash():
    if not os.path.exists(LOCAL_LOG):
        return "GENESIS"
    with open(LOCAL_LOG) as f:
        lines = f.read().strip().splitlines()
    return json.loads(lines[-1])["record_hash"] if lines else "GENESIS"


def log_verdict(name, version, verdict, score):
    record = {"agent": "CodeGuard", "pkg": f"{name}@{version}", "verdict": verdict,
              "score": score, "ts": int(time.time()), "prev": _prev_hash()}
    record_hash = hashlib.sha256(json.dumps(record, sort_keys=True).encode()).hexdigest()
    memo = f"CodeGuard|{name}@{version}|{verdict}|{score}|{record_hash[:32]}"

    sig, mode = None, "SIMULATED"
    if os.getenv("SOLANA_LIVE") == "1":
        try:
            sig = _send_memo(memo)
            mode = "LIVE devnet"
        except Exception as e:
            print(f"[solana] live write failed ({e}); recording in simulated log")

    entry = {**record, "record_hash": record_hash, "memo": memo, "mode": mode, "signature": sig,
             "explorer": f"https://explorer.solana.com/tx/{sig}?cluster=devnet" if sig else None}
    with open(LOCAL_LOG, "a") as f:
        f.write(json.dumps(entry) + "\n")
    return entry


def reputation(name):
    """Pull past verdicts for a package from the audit log."""
    if not os.path.exists(LOCAL_LOG):
        return []
    with open(LOCAL_LOG) as f:
        return [json.loads(l) for l in f if json.loads(l)["pkg"].split("@")[0] == name]


def verify_chain():
    """Recompute every hash; returns True if nobody edited the log."""
    if not os.path.exists(LOCAL_LOG):
        return True
    prev = "GENESIS"
    with open(LOCAL_LOG) as f:
        for line in f:
            e = json.loads(line)
            rec = {k: e[k] for k in ("agent", "pkg", "verdict", "score", "ts", "prev")}
            if rec["prev"] != prev or hashlib.sha256(json.dumps(rec, sort_keys=True).encode()).hexdigest() != e["record_hash"]:
                return False
            prev = e["record_hash"]
    return True
