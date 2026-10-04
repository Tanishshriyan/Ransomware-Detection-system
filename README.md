# RansomGuard

RansomGuard is a Windows-focused ransomware detection prototype built around:

- a FastAPI backend for monitoring, alerting, and operator actions
- a browser dashboard for live status, events, and kill-switch decisions
- a behavioral analysis and ML pipeline for suspicious process scoring
- controlled-folder enforcement and external process execution from dashboard

## Current Status

This repository is a serious prototype, not a production endpoint security product.

What it does well:

- monitors suspicious file and process behavior
- exposes a usable web dashboard and API
- supports real host process monitoring and dashboard-triggered execution
- persists events and alerts in SQLite

What it does not claim:

- kernel-mode visibility
- guaranteed zero-day detection
- enterprise-grade hardening out of the box

## Project Phases

### Phase 1: Setup and Installation
- Install Python 3.12.
- Start the application with `start.ps1`, `start.bat`, or `python run.py`.
- The launcher creates `.venv`, installs the pinned dependencies, and opens the dashboard.
- Configure `config.yaml` only when you need to change server, database, or monitoring settings.
- Verify the health endpoint and dashboard accessibility.

### Phase 2: Detection and Monitoring
- Monitor file system changes and process behaviors in real-time
- Use ML models to score suspicious activities
- Controlled folder access with allowlist for legitimate processes
- External process registration and strict PID tracking

### Phase 3: Response and Management
- Receive alerts via dashboard or Windows notifications
- Make manual decisions on detected threats (Kill, Quarantine, Whitelist, Ignore)
- Automated kill-switch for high-confidence threats
- Chat assistant for threat analysis and recommendations
- Persistent logging and forensic data collection

## Engineering Updates

### 2026-10-01

Changes made in this pass:

- Added a single-command Windows entry point (`start.ps1` and `start.bat`).
- Standardized the automatic environment to `.venv` so manual and launcher commands agree.
- Fixed incompatible dependency pins between FastAPI, AnyIO, HTTPX, WebSockets, and the Google GenAI SDK.
- Launcher dependency failures now stop with a clear actionable error.
- The published change set is limited to runtime, launcher, model-contract, dashboard, test, and documentation updates.
- Research artifacts, generated traces, virtual environments, logs, caches, and local monitoring data remain excluded.
- Dataset-generation utilities and generated training data are not part of the runtime repository.
- API keys and other credentials must be supplied through environment variables; real secrets are not stored in source control.

### 2026-03-25

Changes made in this pass:

- Fixed ransomware demo launch path for both `python run.py` and packaged `RansomGuard.exe`.
- Added strict simulator process tracking in backend status (`pid`, `process_name`, `started_at`) for Process Lab.
- Added explicit demo failure visibility via `demo.error` and simulator stdout/stderr log files (no silent fallback path).
- Simplified Process Lab UI to only `Start Ransomware`, `Stop Ransomware`, and process table columns (`Process ID`, `Name`, `Time`).
- Mapped demo lifecycle to three phases for status reporting:
  - `phase_1_preparation`
  - `phase_2_execution`
  - `phase_3_result`

### 2026-03-23

Changes made in this pass:

- Removed demo-event endpoints and simulator workflow from runtime path.
- Enforced automatic termination for process threats at the configured threshold (85 by default).
- Added strict PID-only containment (no process-name mass-kill fallback).
- Added external process start/list/stop APIs and dashboard controls.
- Added post-termination protection events for clear dashboard visibility.
- Aligned controlled-folder flow to terminate first, then notify.

## Repository Layout

- `backend/`: FastAPI app, monitor, detector, policy enforcement, kill-switch, chat assistant
- `dashboard/`: static frontend assets
- `ml_model/`: feature extraction, training code, serialized model artifacts
- `utils/`: config, database, and resource helpers
- `data/`: runtime databases, logs, and training data
- `run.py`: local launcher for Windows development and packaged execution

## Configuration

`config.yaml` is the primary runtime configuration for the backend and launcher.

Important sections:

- `server`: host and port
- `database`: SQLite path
- `ml_model`: model and scaler paths
- `killswitch`: auto-kill behavior and threshold
- `monitoring`: watched paths and process behavior settings
- `alerts`: alert thresholds and rate limits

Environment overrides supported by `utils/config.py`:

- `RG_SERVER_HOST`
- `RG_SERVER_PORT`
- `RG_DB_PATH`
- `RG_KILLSWITCH_ENABLED`
- `RG_KILLSWITCH_THRESHOLD`
- `RG_API_KEY`
- `RG_GEMINI_API_KEY`

Security behavior:

- `security.cors_origins` controls allowed browser origins
- if `security.enable_authentication` is `true`, operator routes and the WebSocket require `X-API-Key` (the WebSocket accepts `?api_key=`)
- startup now fails fast if authentication is enabled but `security.api_key` is blank

Legacy note:

- `config.json` is still accepted by `run.py` as an override layer for launcher-specific behavior, but it is no longer the primary source of runtime truth.

## Getting Started

1. Install Python 3.12.
2. Open PowerShell in the repository folder.
3. Run `.\start.ps1`.

The first run creates `.venv` and installs dependencies. Later runs use the existing environment.

Equivalent commands are `.\start.bat` or `python run.py`.

The launcher now defaults to safer behavior:

- dependency installation is automatic on first run
- `git pull` is opt-in
- host and port default to the values in `config.yaml`

If you enable API auth, call protected endpoints with:

- header: `X-API-Key: <your configured key>`

For the browser dashboard, set the key in its origin's local storage as
`ransomguard_api_key` before connecting.

## EXE Build And Run

Build command:

- `python -m PyInstaller --noconfirm --clean RansomGuard.spec`

Verified executable artifact:

- `dist/RansomGuard/RansomGuard.exe`

How it was verified:

- the packaged EXE was launched locally
- `GET /health` returned `ok: true`
- `GET /api/status` returned `status: online`

Run notes:

- start `dist/RansomGuard/RansomGuard.exe`
- the app serves on the configured host and port from packaged `config.yaml`
- the packaged resources live under the PyInstaller internal directory and are resolved automatically

## Backend Entry Points

- Health: `GET /health`
- Status: `GET /api/status`
- Recent events: `GET /api/events/recent`
- Logs: `GET /api/logs`
- Kill-switch toggle: `POST /api/killswitch/toggle`
- Controlled folders (get/set): `GET/POST /api/controlled-folders`
- External process start: `POST /api/process/start`
- External process list: `GET /api/processes`
- External process stop: `POST /api/process/stop`
- Demo start: `POST /api/demo/start`
- Demo status: `GET /api/demo/status`
- Demo stop: `POST /api/demo/stop`
- Chat: `POST /api/chat`

## Data Model Notes

The primary runtime database is configured under `database.path` in `config.yaml`.

Current SQLite tables managed by `utils/database.py`:

- `events`
- `predictions`
- `alerts`
- `model_metadata`

The chat assistant reads from this schema and derives high-risk context from recent event payloads.

## External Process Execution

Dashboard process controls launch real executables and register their PIDs.
The monitoring engine uses that exact PID to score, terminate (at the configured threshold),
and emit post-action events to the dashboard.

## Development Priorities

If you want to push this project toward production quality, focus on:

1. hardening the monitor and kill-switch behavior on real Windows workloads
2. expanding automated tests and CI coverage
3. formalizing the event schema and API contracts
4. hardening external-process launch validation and PID containment
5. documenting model training, evaluation, and threshold calibration

## Testing

The repository now has two testing layers.

Deterministic CI-safe tests:

- `quality_tests/`
- run with `python -m unittest discover -s quality_tests -v`

Manual or environment-dependent harnesses:

- root-level `test_*.py` files
- these are useful for local validation but are not used as the default CI quality gate because they depend more heavily on machine-specific Windows runtime behavior

Recommended baseline:

- `fastapi`
- `uvicorn`
- `watchdog`
- `psutil`
- `aiosqlite`
- `python-dotenv`
- `windows-toasts`
- `google-genai`
- `pandas`
- `lightgbm`
- `xgboost`

## CI/CD

CI workflow:

- file: `.github/workflows/ci.yml`
- runs on Windows
- installs runtime dependencies
- compiles Python sources
- smoke-imports backend and launcher
- runs deterministic tests from `quality_tests/`

CD workflow:

- file: `.github/workflows/cd.yml`
- runs on tags matching `v*` or manual dispatch
- installs runtime dependencies
- builds `dist/ransomguard-release.zip`
- uploads the release artifact

## Improvement Backlog

The repo is stronger now, but a real 10/10 production score still needs:

1. authentication and authorization for all operator endpoints
2. role-based authorization instead of a single shared API key
3. a formal API schema and event contract versioning
4. migration of ad hoc root test scripts into deterministic automated suites
5. packaging and installer work for reproducible Windows deployment
6. model evaluation documentation with thresholds, false-positive analysis, and rollback strategy
7. CI checks for formatting, linting, and security scanning

## Completion Status

All requested implementation work in this pass is completed.

Current state:

- codebase hardened
- CI/CD files added
- README updated with each major change
- executable built
- packaged app smoke-tested successfully
- application is ready to use

## Security Notes

- change placeholder secrets before exposing the service beyond local development
- restrict CORS and authentication before multi-user or networked deployment
- validate kill-switch allowlists and protected process rules carefully
- treat model outputs as one input to operator action, not as perfect truth

