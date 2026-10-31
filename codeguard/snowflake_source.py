"""
Snowflake data source.

CodeGuard checks every package against the KNOWN_COMPROMISED_PACKAGES table
built in Snowflake (see /snowflake/*.sql, written with Snowflake Cortex Code "CoCo").

- If SNOWFLAKE_ACCOUNT / SNOWFLAKE_USER / SNOWFLAKE_PASSWORD are set, it queries Snowflake live.
- Otherwise it falls back to data/known_compromised.csv, an export of the same table,
  so the demo still runs offline.
"""
import csv
import os

TABLE = os.getenv("SNOWFLAKE_TABLE", "CODEGUARD_DB.SECURITY.KNOWN_COMPROMISED_PACKAGES")
LOCAL_CSV = os.path.join(os.path.dirname(__file__), "..", "data", "known_compromised.csv")


def _from_snowflake():
    import snowflake.connector  # pip install snowflake-connector-python
    conn = snowflake.connector.connect(
        account=os.environ["SNOWFLAKE_ACCOUNT"],
        user=os.environ["SNOWFLAKE_USER"],
        password=os.environ["SNOWFLAKE_PASSWORD"],
        warehouse=os.getenv("SNOWFLAKE_WAREHOUSE", "COMPUTE_WH"),
    )
    cur = conn.cursor()
    cur.execute(f"SELECT PACKAGE_NAME, VERSION, SEVERITY, ADVISORY_ID, SUMMARY FROM {TABLE}")
    rows = [dict(zip(["package_name", "version", "severity", "advisory_id", "summary"], r))
            for r in cur.fetchall()]
    conn.close()
    return rows


def _from_csv():
    with open(LOCAL_CSV, encoding="utf-8") as f:
        return list(csv.DictReader(f))


def load_known_compromised():
    """Returns (rows, source_label)."""
    if os.getenv("SNOWFLAKE_ACCOUNT"):
        try:
            return _from_snowflake(), f"Snowflake live ({TABLE})"
        except Exception as e:  # keep demo alive if network fails
            print(f"[snowflake] live query failed ({e}); using local export")
    return _from_csv(), "Snowflake export (data/known_compromised.csv)"


def lookup(rows, name, version):
    for r in rows:
        if r["package_name"] == name and (r["version"] in ("*", version)):
            return r
    return None
