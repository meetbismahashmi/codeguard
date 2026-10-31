-- CodeGuard Snowflake pipeline (drafted with Snowflake Cortex Code "CoCo")
-- Source data: OSV.dev open-source vulnerability database (free, public)
--   npm dump: https://osv-vulnerabilities.storage.googleapis.com/npm/all.zip
-- Also usable: any free vulnerability/CVE dataset from Snowflake Marketplace.

CREATE DATABASE IF NOT EXISTS CODEGUARD_DB;
CREATE SCHEMA IF NOT EXISTS CODEGUARD_DB.SECURITY;
USE SCHEMA CODEGUARD_DB.SECURITY;

-- Raw table: one OSV JSON advisory per row
CREATE OR REPLACE TABLE OSV_RAW (DATA VARIANT);

-- Upload the JSON files to a stage (Snowsight: Data > Add Data > Load files), then:
CREATE OR REPLACE STAGE OSV_STAGE FILE_FORMAT = (TYPE = JSON);
-- COPY INTO OSV_RAW FROM @OSV_STAGE;

-- Clean table the CodeGuard agent queries
CREATE OR REPLACE TABLE KNOWN_COMPROMISED_PACKAGES AS
SELECT
    a.value:package:name::STRING                       AS PACKAGE_NAME,
    COALESCE(v.value::STRING, '*')                     AS VERSION,
    COALESCE(DATA:database_specific:severity::STRING,
             IFF(DATA:id::STRING LIKE 'MAL-%', 'CRITICAL', 'UNKNOWN')) AS SEVERITY,
    DATA:id::STRING                                    AS ADVISORY_ID,
    LEFT(DATA:summary::STRING, 200)                    AS SUMMARY,
    DATA:published::TIMESTAMP_NTZ                      AS PUBLISHED_AT
FROM OSV_RAW,
     LATERAL FLATTEN(input => DATA:affected) a,
     LATERAL FLATTEN(input => a.value:versions, OUTER => TRUE) v
WHERE a.value:package:ecosystem::STRING = 'npm';

-- Quick check
SELECT SEVERITY, COUNT(*) FROM KNOWN_COMPROMISED_PACKAGES GROUP BY 1 ORDER BY 2 DESC;
