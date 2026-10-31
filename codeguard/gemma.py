"""
Gemma 4 explainer: turns raw suspicious code into plain-English advice
for junior developers.

Uses Google AI Studio (set GEMINI_API_KEY). Set GEMMA_MODEL to the exact
Gemma 4 model id shown in AI Studio. Without a key, a built-in template
explanation is used so the demo never breaks.
"""
import os
import time

import requests

MODEL = os.getenv("GEMMA_MODEL", "gemma-4-27b-it")

PROMPT = """You are CodeGuard, a friendly security mentor for JUNIOR developers.
A dependency in their project was flagged. Explain it in plain, simple English.

Package: {name}@{version}
Where it sits: {chain}  (depth {depth} in the dependency tree)
Rules that fired: {rules}
Code evidence:
{evidence}

Reply in exactly this format (max 90 words total, no jargon):
WHAT IT DOES: <1 sentence>
WHY IT'S DANGEROUS: <1-2 sentences>
WHAT TO DO: <1 concrete action>
"""


def _fallback(pkg, findings):
    reasons = "; ".join(f[2] for f in findings) or "No risky behaviour found"
    return (f"WHAT IT DOES: {reasons}.\n"
            f"WHY IT'S DANGEROUS: Together these behaviours can quietly steal secrets "
            f"(like API keys) from anyone who installs your project.\n"
            f"WHAT TO DO: Remove '{pkg['name']}' or replace the package that pulls it in "
            f"({' > '.join(pkg['chain'])}), then rotate any keys on affected machines.")


def explain(pkg, findings, evidence):
    key = os.getenv("GEMINI_API_KEY")
    if not key:
        return _fallback(pkg, findings), "template (no GEMINI_API_KEY set)"
    prompt = PROMPT.format(
        name=pkg["name"], version=pkg["version"], chain=" > ".join(pkg["chain"]),
        depth=pkg["depth"], rules=", ".join(f[0] for f in findings),
        evidence="\n".join(evidence[:8]) or "(none)")
    # Try the chosen model first, then the other Gemma 4 model; retry once each.
    models = [MODEL] + [m for m in ("gemma-4-31b-it", "gemma-4-26b-a4b-it") if m != MODEL]
    for model in models:
        url = f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent"
        for attempt in range(2):
            try:
                # Key goes in a header, never in the URL, so it can't leak into logs.
                r = requests.post(url, headers={"x-goog-api-key": key},
                                  json={"contents": [{"parts": [{"text": prompt}]}]}, timeout=90)
                if r.status_code != 200:
                    print(f"[gemma] {model} returned HTTP {r.status_code}: {r.text[:150]}")
                    time.sleep(2)
                    continue
                parts = r.json()["candidates"][0]["content"]["parts"]
                text = "\n".join(p["text"] for p in parts if "text" in p and not p.get("thought"))
                return text.strip(), f"Gemma ({model})"
            except Exception as e:
                print(f"[gemma] {model} request failed: {type(e).__name__}")
                time.sleep(2)
    return _fallback(pkg, findings), "template (API error)"
