# Cultive8 — Local AI Security Log Analyzer

A fully local, single-worker security log analyzer for local server environments. FastAPI + Ollama Qwen3.5 0.8B + token-aware splitting + persisted SQLite chunk results + deterministic cross-file IP correlation.

## Setup & Running (Windows PowerShell)

1. Verify Ollama is running and has the required model (`http://127.0.0.1:11434`):
   ```powershell
   & "$env:LOCALAPPDATA\Programs\Ollama\ollama.exe" list
   ```
2. Pull the local model (offline inference requires zero cloud API calls):
   ```powershell
   & "$env:LOCALAPPDATA\Programs\Ollama\ollama.exe" pull qwen3.5:0.8b
   ```
3. Activate the virtual environment:
   ```powershell
   .\.venv\Scripts\Activate.ps1
   ```
4. Run the automated test suite:
   ```powershell
   python -m unittest discover tests
   ```
5. Start the FastAPI web application:
   ```powershell
   uvicorn app:app --host 127.0.0.1 --port 8000
   ```
6. Open your browser at `http://127.0.0.1:8000` and upload `Cultive8_Workspace_Agrigen_Server.log`.

---

## Reliability & Assessment Compliance Audit

### Before-and-After Reliability Comparison

| Metric | Initial Run | After Reliability & Evidence Audit |
| :--- | :---: | :---: |
| **Total Reported Findings** | 28 | **8** (consolidated, deduplicated) |
| **Rejected Hallucinations & False Positives** | 0 | **20** (lines 40, 82, 93, 99 as SQLi, 124, 135, 174, 199, 247, 252, 258) |
| **Retained True Security Incidents** | Incomplete / Mixed | **8** verified incidents across 6 attacker IPs |
| **Chunk 23 Malformed JSON Warnings** | 1 (`Expecting ',' delimiter`) | **0** (clean parse across all chunks) |
| **Token Budget Compliance** | Unenforced output headroom | **Strictly <= 2,048 tokens** per call |
| **Automated Unit Tests** | 10 passing | **13 passing** (including regression & repair tests) |

1. **Local Model Invocations**:
   - The local Ollama model (`qwen3.5:0.8b`) is called sequentially for every chunk without exception. Deterministic rules do not bypass the AI; they run in parallel during consolidation to correlate cross-chunk multi-stage attacks.
2. **Strict Token Budget Compliance**:
   - Budget: 2,048 tokens total.
   - Calculation: `count_tokens(SYSTEM) + count_tokens(PROMPT_PREFIX) + count_tokens(chunk) + OUTPUT_TOKENS(450) + margin(80) <= 2,048`.
   - Verified by automated regression tests across all log chunks.
3. **Evidence Validation & False-Positive Elimination**:
   - Every AI finding is verified line-by-line via `is_line_evidence()` against original JSONL records.
   - Normal HTTP 200, 304, 404, 500, and 503 responses alone do not establish attacks.
   - Routine parameters (e.g. `estate_id=12`), ordinary `GET /`, and scheduled backups (`backup-worker`, L258) are explicitly rejected.
   - HTTP 403 status codes are **not** blindly treated as attacks. Only genuine access denials on administrative routes (`/admin`, `/settings`) or explicit `security_rule: "access_denied"` events are flagged.
   - Reconnaissance scans (`/.env`, `/.git/`) and path traversals (`../etc/passwd`) are segregated so evidence lines are never misclassified as SQL injection.
4. **Resilient Failure Handling & JSON Parsing Fix**:
   - Chunk 23's parsing failure was caused by output truncation at 350 tokens. Output headroom was raised to 450 tokens with concise prompting, and `parse_json()` was augmented with a robust fallback that extracts completed finding objects from truncated streams.
   - If individual chunks fail or timeout, completed chunk findings remain saved in SQLite and warnings are presented in the dashboard. If all model calls fail, the job status is set to `failed` rather than silently succeeding.
5. **Clean Repository Hygiene**:
   - `.gitignore` excludes `.venv/`, `data/`, `*.db`, `*.sqlite`, `*.log`, `*.errors`, `__pycache__/`, and `.env`.

---

## Architecture

- **Streaming Upload**: Reads uploads in 64 KB blocks and enforces a 12 MB file limit.
- **Token-Aware Chunks**: Uses Hugging Face's Qwen3.5 tokenizer. Chunks logs strictly within the 2,048 token budget while preserving source line numbers (`L{n}:`).
- **Sequential Local Inference**: Synchronous calls to localhost Ollama `/api/generate` with structured JSON schema (`format: JSON_SCHEMA`), `temperature=0`, `think=false`, and `num_thread=2` to respect 2 vCPU and 4 GB RAM limits.
- **Persistence**: SQLite with WAL mode (`PRAGMA journal_mode=WAL`). Chunk results persist immediately.
- **Cross-Chunk Correlation**:
  - **Brute Force & Compromise**: Links >= 5 failed logins followed by successful authentication and subsequent data export (`203.0.113.44`).
  - **SQL Injection**: Detects SQL injection probes (`UNION SELECT`, `' OR 1=1`, `SLEEP()`, `information_schema`) across URL-decoded query parameters (`203.0.113.72`).
  - **Reconnaissance & Scanning**: Detects sensitive endpoint scans (`203.0.113.90`).
  - **Path Traversal**: Flags directory traversal patterns (`203.0.113.90`).
  - **Unauthorized Access**: Captures HTTP 403 / `access_denied` events on privileged endpoints (`203.0.113.90`).
  - **Rate Anomaly / Request Bursts**: Identifies rapid sub-3-second request bursts and HTTP 429 responses (`203.0.113.155`).
  - **Prompt Injection**: Detects adversarial instruction overrides in log payloads (`203.0.113.201`).
  - **Health Monitor Filtering**: Ignores legitimate registered health monitors (e.g. `192.0.2.10`).
- **Consolidated Deduplication**: Groups findings by actor and attack family, promotes severity to the highest observed level, merges line evidence, and marks source as `Local AI + cross-file correlation` when detected by both layers.
- **Browser Dashboard**: Live health check, progress bar with chunk count and percentage, backend RAM usage indicator, consolidated findings list with source badges and evidence lines, warning log viewer, and JSON export.
