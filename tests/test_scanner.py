"""Test suite (generated with GitHub Copilot, then reviewed by the team).
Checks that CodeGuard catches every planted flaw and does NOT flag clean packages."""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from codeguard import scanner, snowflake_source, solana_log  # noqa: E402

SAMPLE = os.path.join(os.path.dirname(__file__), "..", "sample_project")


def _by_name():
    return {p["name"]: p for p in scanner.walk_tree(SAMPLE)}


def _score(pkg):
    findings, _ = scanner.scan_package(pkg)
    return findings, sum(f[1] for f in findings)


def test_finds_all_packages_including_deeply_nested():
    pkgs = _by_name()
    assert set(pkgs) == {"express-lite", "body-helper", "string-padder", "axioss", "color-utils"}
    assert pkgs["string-padder"]["depth"] == 3
    assert pkgs["string-padder"]["chain"] == ["express-lite", "body-helper", "string-padder"]


def test_deep_hijacked_package_is_malicious():
    findings, score = _score(_by_name()["string-padder"])
    ids = {f[0] for f in findings}
    assert {"INSTALL_SCRIPT", "SENSITIVE_FILES", "BASE64_DECODE", "ENV_ACCESS", "NETWORK_CALL"} <= ids
    assert scanner.verdict_for(score) == "MALICIOUS"


def test_typosquat_detected():
    findings, score = _score(_by_name()["axioss"])
    assert "TYPOSQUAT" in {f[0] for f in findings}
    assert scanner.verdict_for(score) == "MALICIOUS"


def test_clean_packages_are_safe():
    pkgs = _by_name()
    for name in ("express-lite", "body-helper", "color-utils"):
        _, score = _score(pkgs[name])
        assert scanner.verdict_for(score) == "SAFE", name


def test_typosquat_does_not_flag_real_names():
    assert scanner.typosquat_of("axios") is None
    assert scanner.typosquat_of("lodahs") is None or scanner.typosquat_of("lodash") is None


def test_snowflake_lookup():
    rows, _ = snowflake_source.load_known_compromised()
    assert snowflake_source.lookup(rows, "string-padder", "2.1.4")
    assert snowflake_source.lookup(rows, "axioss", "9.9.9")          # wildcard version
    assert snowflake_source.lookup(rows, "color-utils", "2.0.3") is None


def test_audit_log_detects_tampering(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    solana_log.log_verdict("a", "1.0.0", "SAFE", 0)
    solana_log.log_verdict("b", "1.0.0", "MALICIOUS", 90)
    assert solana_log.verify_chain()
    text = open("audit_log.jsonl").read().replace('"score": 90', '"score": 5')
    open("audit_log.jsonl", "w").write(text)
    assert not solana_log.verify_chain()
