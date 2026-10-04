"""
==============================================================================
RansomGuard - Main Backend Server (Production Rewrite)

==============================================================================
"""

import asyncio
import hmac
import json
import logging
import os
import subprocess
import sys
import threading
import time
from typing import Dict, List, Optional
from pathlib import Path
import psutil
from backend.detector import ThreatDetector


from fastapi import Depends, FastAPI, Header, HTTPException, Query, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, JSONResponse, HTMLResponse
from pydantic import BaseModel, Field
from collections import deque
from backend.response import AutomatedResponse
from backend.chat_assistant import RansomGuardChatbot
from dotenv import load_dotenv
load_dotenv()
       
import io

# Force UTF-8 encoding for Windows console
if sys.platform == 'win32':
    if sys.stdout and hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding='utf-8', errors='replace')
    if sys.stderr and hasattr(sys.stderr, "reconfigure"):
        sys.stderr.reconfigure(encoding='utf-8', errors='replace')

from backend.threat_state import ThreatStateMachine
from backend.ml_scheduler import MLScheduler
from backend.policy_enforcer import PolicyEnforcer
from backend.user_decision import (
    UserDecisionHandler,
    UserDecision,
    WhitelistStore,
)
from utils.config import config
from utils.resource_path import resolve_runtime_path, resource_path, runtime_path


# --------------------- Path setup (optional) ---------------------------------
BACKEND_DIR = os.path.dirname(os.path.abspath(__file__))
BASE_DIR = os.path.dirname(BACKEND_DIR)
sys.path.insert(0, BASE_DIR)
sys.path.insert(0, BACKEND_DIR)
DASHBOARD_DIR = resource_path("dashboard")
DB_PATH = resolve_runtime_path(config.get("database.path", "data/ransomguard.db"))

# --------------------- Logging ------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("ransomguard")

# --------------------- Import project modules ----------------------------------
try:
    from utils.database import Database
    logger.info(" Database imported")
except Exception as e:
    logger.warning(f"Database import failed: {e}")
# --------------------- ML Model Loading (REAL) -------------------------
try:
    import joblib
    import os
    from ml_model.schema import MODEL_FEATURE_NAMES, SCHEMA_VERSION, canonicalize_features
    
    class RealMLDetector:
        def __init__(self):
            self.loaded = False
            self.model = None
            self.scaler = None
            self.threshold = 0.5
            
        def load_model(self) -> bool:
            try:
                model_path = resource_path(
                    config.get("ml.model_path", "ml_model/models/lightgbm_model_v3.0.pkl")
                )
                scaler_path = resource_path(
                    config.get("ml.scaler_path", "ml_model/models/lightgbm_scaler_v3.0.pkl")
                )
                
                if not os.path.exists(model_path):
                    logger.error(f"Model file not found: {model_path}")
                    return False
                    
                if not os.path.exists(scaler_path):
                    logger.error(f" Scaler file not found: {scaler_path}")
                    return False
                
                self.model = joblib.load(model_path)
                self.scaler = joblib.load(scaler_path)
                self.loaded = True
                
                logger.info(f" ML Model loaded successfully")
                logger.info(f"   Model: {model_path}")
                logger.info(f"   Scaler: {scaler_path}")
                return True
                
            except Exception as e:
                logger.error(f" ML model load failed: {e}")
                import traceback
                traceback.print_exc()
                return False
        
        def predict(self, features: dict) -> dict:
            """Predict ransomware from behavioral features"""
            if not self.loaded:
                return {"decision": "UNAVAILABLE", "confidence": None, "reason": "model_not_loaded"}
            
            try:
                # Extract feature values in correct order
                import numpy as np
                ordered = canonicalize_features(features)
                if len(ordered) != len(MODEL_FEATURE_NAMES):
                    raise ValueError(f"{SCHEMA_VERSION} produced {len(ordered)} features")
                X = np.array([[ordered[name] for name in MODEL_FEATURE_NAMES]], dtype=float)
                
                # Scale features
                X_scaled = self.scaler.transform(X)
                
                # Predict probability
                proba = self.model.predict_proba(X_scaled)[0]
                ransomware_prob = proba[1]  # Probability of class 1 (ransomware)
                
                # Decision logic
                if ransomware_prob >= 0.85:
                    decision = "KILL"
                elif ransomware_prob >= self.threshold:
                    decision = "RANSOMWARE"
                else:
                    decision = "SAFE"
                
                return {
                    "decision": decision,
                    "confidence": float(ransomware_prob * 100),
                    "score": float(ransomware_prob),
                    "threshold": self.threshold
                }
                
            except Exception as e:
                logger.exception(f"ML prediction error: {e}")
                return {"decision": "ERROR", "confidence": None, "reason": str(e)}
    
    RansomwareMLModel = RealMLDetector  # Alias for compatibility
    logger.info(" Real ML model class loaded")
    
except Exception as e:
    logger.error(f" CRITICAL: Cannot load ML dependencies: {e}")
    # NO STUB - Fail hard
    raise ImportError(f"ML model loading failed: {e}")


try:
    from ml_model.feature_extractor import FeatureExtractor
    logger.info(" FeatureExtractor imported")
except Exception as e:
    logger.error(f"FeatureExtractor import failed: {e}")
    raise ImportError(f"Cannot start without FeatureExtractor: {e}")
# ========================================================================
# CRITICAL: Import Real SystemMonitor (NO STUB FALLBACK)
# ========================================================================
try:
    from backend.monitor import SystemMonitor
    logger.info("Real SystemMonitor imported from monitor.py")
    USING_REAL_MONITOR = True
    
    # Verify it's the real one
    if hasattr(SystemMonitor, '_loop'):
        logger.error("CRITICAL: Imported STUB monitor instead of real one!")
        raise ImportError("Wrong monitor imported - stub instead of real")
    
except Exception as e:
    logger.error("="*70)
    logger.error(" CRITICAL FAILURE: Cannot import real SystemMonitor!")
    logger.error(f"   Error: {e}")
    logger.error("   System will NOT detect any threats!")
    logger.error("="*70)
    
    # Print full traceback for debugging
    import traceback
    traceback.print_exc()
    
    # REFUSE to start without real monitor
    raise ImportError(f"Cannot start RansomGuard without real monitor: {e}")

try:
    from backend.threat_manager import ThreatManager
    logger.info("ThreatManager imported")
except Exception as e:
    logger.error(f"ThreatManager import failed: {e}")
    raise

try:
    from backend.killswitch import KillSwitch
    logger.info(" KillSwitch imported")
except Exception as e:
    logger.warning(f"KillSwitch import failed: {e} ")

try:
    from backend.behavioral_analyzer import BehavioralAnalyzer
    logger.info("BehavioralAnalyzer imported")
except Exception as e:
    logger.warning(f"BehavioralAnalyzer import failed: {e}")

# --------------------- FastAPI app -------------------------------------------

app = FastAPI(
    title=config.get('system.name', 'RansomGuard Detection System'),
    version=config.get('system.version', '2.0.0'),
    description="Advanced AI-Powered Ransomware Detection System",
    docs_url="/api/docs",
    redoc_url="/api/redoc",

)
monitor: Optional[SystemMonitor] = None


class AlertDecisionRequest(BaseModel):
    alert_id: str
    decision: str


class ProcessDecisionRequest(BaseModel):
    pid: int
    process_name: str
    decision: str

class ExternalProcessStartRequest(BaseModel):
    executable_path: str
    args: List[str] = Field(default_factory=list)
    cwd: Optional[str] = None


class ExternalProcessStopRequest(BaseModel):
    pid: int



class ControlledFolderConfigRequest(BaseModel):
    enabled: Optional[bool] = None
    auto_suspend: Optional[bool] = None
    paths: Optional[List[str]] = None
    allowlist_processes: Optional[List[str]] = None

# Initialize chatbot
GEMINI_API_KEY = (
    os.getenv("GEMINI_API_KEY", "")
    or os.getenv("RG_GEMINI_API_KEY", "")
    or config.get("integrations.gemini.api_key", "")
)
chatbot = RansomGuardChatbot(
    api_key=GEMINI_API_KEY,
    db_path=DB_PATH,
)



def _cors_origins() -> List[str]:
    origins = config.get("security.cors_origins", ["http://127.0.0.1:8000"])
    if not isinstance(origins, list) or not origins:
        return ["http://127.0.0.1:8000"]
    return [str(origin).strip() for origin in origins if str(origin).strip()]


def _cors_allow_credentials(origins: List[str]) -> bool:
    return "*" not in origins


def require_api_key(x_api_key: Optional[str] = Header(default=None)) -> None:
    if not config.get("security.enable_authentication", False):
        return

    expected = str(config.get("security.api_key", "") or "").strip()
    if not expected:
        raise HTTPException(status_code=503, detail="Authentication is enabled but no API key is configured")

    supplied = str(x_api_key or "").strip()
    if not hmac.compare_digest(supplied, expected):
        raise HTTPException(status_code=401, detail="Invalid or missing API key")


cors_origins = _cors_origins()

app.add_middleware(
    CORSMiddleware,
    allow_origins=cors_origins,
    allow_credentials=_cors_allow_credentials(cors_origins),
    allow_methods=["*"],
    allow_headers=["*"],
)

# Static dashboard mounting
if os.path.isdir(DASHBOARD_DIR):
    app.mount("/dashboard", StaticFiles(directory=DASHBOARD_DIR), name="dashboard")
    logger.info(" Dashboard mounted from: %s", DASHBOARD_DIR)
else:
    logger.info("Dashboard directory not found: %s", DASHBOARD_DIR)

@app.post("/api/decision")
async def process_user_decision(req: dict, _: None = Depends(require_api_key)):
    success = app_state.user_decision_handler.apply_decision(
        pid=req["pid"],
        process_name=req["process_name"],
        decision=UserDecision[req["decision"]],
    )
    return {"success": success}


@app.get("/api/pending_alerts")
async def get_pending_alerts(_: None = Depends(require_api_key)):
    if not app_state.monitor:
        return []
    return app_state.monitor.notification_manager.get_pending_alerts()


@app.post("/api/alert-decision")
async def process_alert_decision(req: AlertDecisionRequest, _: None = Depends(require_api_key)):
    """Process user action for a pending threat alert."""
    if not app_state.monitor or not getattr(app_state.monitor, "notification_manager", None):
        raise HTTPException(status_code=503, detail="Monitor is not available")

    decision = req.decision.upper().strip()
    if decision not in {"KILL", "QUARANTINE", "WHITELIST", "IGNORE"}:
        raise HTTPException(status_code=400, detail="Invalid decision")

    success = app_state.monitor.notification_manager.process_user_decision(
        alert_id=req.alert_id,
        decision=decision,
    )
    return {"success": success, "alert_id": req.alert_id, "decision": decision}


@app.get("/api/controlled-folders")
async def get_controlled_folders(_: None = Depends(require_api_key)):
    if not app_state.monitor:
        return {"success": True, "config": {}}
    try:
        return {"success": True, "config": app_state.monitor.get_controlled_folder_config()}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/controlled-folders")
async def set_controlled_folders(req: ControlledFolderConfigRequest, _: None = Depends(require_api_key)):
    if not app_state.monitor:
        raise HTTPException(status_code=503, detail="Monitor is not available")
    try:
        cfg = app_state.monitor.set_controlled_folder_config(
            enabled=req.enabled,
            auto_suspend=req.auto_suspend,
            paths=req.paths,
            allowlist_processes=req.allowlist_processes,
        )
        return {"success": True, "config": cfg}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/process-decision")
async def process_manual_process_decision(req: ProcessDecisionRequest, _: None = Depends(require_api_key)):
    """
    Handle user decision for standard alerts that are not part of pending
    NotificationManager alerts.
    """
    decision = req.decision.upper().strip()
    if decision not in {"KILL", "REMOVE", "UNSAFE", "ALLOW", "SAFE", "IGNORE"}:
        raise HTTPException(status_code=400, detail="Invalid decision")

    if decision in {"ALLOW", "SAFE", "IGNORE"}:
        resumed = app_state.kill_switch.resume_process(req.pid)
        return {
            "success": True,
            "action": "allowed",
            "pid": req.pid,
            "process_name": req.process_name,
            "resumed": resumed,
        }

    killed = app_state.kill_switch.kill_process_tree(req.process_name, req.pid)
    if killed:
        app_state.stats["processes_killed"] += 1
        app_state.threat_manager.mark_blocked(
            pid=req.pid,
            process_name=req.process_name,
            score=int(config.killswitch_threshold),
            operation="manual_kill",
        )

    return {
        "success": killed,
        "action": "killed" if killed else "kill_failed",
        "pid": req.pid,
        "process_name": req.process_name,
    }


@app.post("/api/process/start")
async def start_external_process(req: ExternalProcessStartRequest, _: None = Depends(require_api_key)):
    """Start an external process from dashboard controls and register its PID."""
    await ensure_detection_services_started()

    executable_raw = str(req.executable_path or "").strip()
    if not executable_raw:
        raise HTTPException(status_code=400, detail="executable_path is required")

    exe_path = Path(executable_raw)
    if not exe_path.is_absolute():
        exe_path = (Path(BASE_DIR) / exe_path).resolve()

    if not exe_path.exists():
        raise HTTPException(status_code=404, detail=f"Executable not found: {exe_path}")

    args = [str(a) for a in (req.args or [])]

    if req.cwd:
        cwd_path = Path(req.cwd)
        if not cwd_path.is_absolute():
            cwd_path = (Path(BASE_DIR) / cwd_path).resolve()
    else:
        cwd_path = exe_path.parent

    if not cwd_path.exists():
        raise HTTPException(status_code=400, detail=f"Working directory not found: {cwd_path}")

    try:
        proc = subprocess.Popen([str(exe_path), *args], cwd=str(cwd_path))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to start process: {e}")

    process_name = exe_path.name
    if app_state.monitor:
        app_state.monitor.register_external_process(
            pid=proc.pid,
            process_name=process_name,
            exe_path=str(exe_path),
        )

    return {
        "success": True,
        "pid": proc.pid,
        "process_name": process_name,
        "executable_path": str(exe_path),
        "cwd": str(cwd_path),
        "args": args,
        "timestamp": time.time(),
    }


@app.get("/api/processes")
async def list_external_processes(_: None = Depends(require_api_key)):
    if not app_state.monitor:
        return {"success": True, "processes": []}
    return {"success": True, "processes": app_state.monitor.get_registered_external_processes()}


@app.post("/api/process/stop")
async def stop_external_process(req: ExternalProcessStopRequest, _: None = Depends(require_api_key)):
    pid = int(req.pid or 0)
    if pid <= 0:
        raise HTTPException(status_code=400, detail="Valid pid is required")

    try:
        proc = psutil.Process(pid)
        process_name = proc.name() or "unknown"
    except psutil.NoSuchProcess:
        process_name = "unknown"
        if app_state.monitor:
            app_state.monitor.registered_external_processes.pop(pid, None)
        return {"success": True, "pid": pid, "action": "already_stopped"}

    killed = app_state.kill_switch.kill_process_tree(process_name, pid)
    if app_state.monitor:
        app_state.monitor.registered_external_processes.pop(pid, None)

    return {
        "success": bool(killed),
        "pid": pid,
        "process_name": process_name,
        "action": "stopped" if killed else "stop_failed",
    }

# --------------------- Connection Manager -----------------------------------
class ConnectionManager:
    def __init__(self, max_connections: int = 50):
        self.active_connections: List[WebSocket] = []
        self.max_connections = max_connections
        self._lock = asyncio.Lock()

    async def connect(self, websocket: WebSocket) -> bool:
        async with self._lock:
            if len(self.active_connections) >= self.max_connections:
                await websocket.close(code=1008, reason="Max connections")
                return False
            self.active_connections.append(websocket)
            logger.info(" Client connected (Total: %d)", len(self.active_connections))
            return True

    async def disconnect(self, websocket: WebSocket):
        async with self._lock:
            if websocket in self.active_connections:
                self.active_connections.remove(websocket)
                logger.info(" Client disconnected (Total: %d)", len(self.active_connections))

    async def broadcast(self, message: dict):
        to_remove = []
        async with self._lock:
            conns = list(self.active_connections)
        for ws in conns:
            try:
                await ws.send_json(message)
            except Exception:
                to_remove.append(ws)
        for ws in to_remove:
            await self.disconnect(ws)

    async def send_to(self, websocket: WebSocket, message: dict) -> bool:
        try:
            await websocket.send_json(message)
            return True
        except Exception:
            await self.disconnect(websocket)
            return False

    def count(self) -> int:
        return len(self.active_connections)

# --------------------- Application State ------------------------------------
class ApplicationState:
    def __init__(self):
        self.manager = ConnectionManager()
        self.db = Database(DB_PATH)
        self.ml_model = RansomwareMLModel()
        self.feature_extractor: Optional[FeatureExtractor] = None
        self.behavioral_analyzer = BehavioralAnalyzer()
        self.kill_switch = KillSwitch(
            enable_auto_kill=config.killswitch_enabled,
            threat_threshold=config.killswitch_threshold,
        )
        # =========================
        # NEW: Threat management core
        # =========================
        self.threat_state = ThreatStateMachine()
        self.whitelist = WhitelistStore()

        self.policy_enforcer = PolicyEnforcer(
            state_machine=self.threat_state,
            killswitch=self.kill_switch,
            suspend_timeout_seconds=30,
        )

        self.user_decision_handler = UserDecisionHandler(
            state_machine=self.threat_state,
            policy_enforcer=self.policy_enforcer,
            whitelist=self.whitelist,
        )

        self.ml_scheduler: Optional[MLScheduler] = None
        self.ml_task: Optional[asyncio.Task] = None
        self.ml_thread = None

        self.monitor: Optional[SystemMonitor] = None
        threat_block_threshold = min(int(config.killswitch_threshold), 70)
        self.threat_manager = ThreatManager(block_threshold=threat_block_threshold)
        self.detector = None  # Will be initialized in startup()
        self.response = None  # Will be initialized in startup()
        self.detection_services_started = False
        self.detection_services_lock = asyncio.Lock()

        # Demo runner state (for process-lab quick demo button)
        self.demo_process = None
        self.demo_state = "idle"  # idle, running, completed, failed
        self.demo_start_time = None
        self.demo_duration_seconds = 0
        self.demo_target_dir = None
        self.demo_process_name = "safe_file_churn_simulator"
        self.demo_stdout_log = None
        self.demo_stderr_log = None
        self.demo_last_error = None
        self.demo_lock = threading.RLock()

        # Async queue used by event processor (bounded to prevent memory leak)
        self.event_queue: asyncio.Queue = asyncio.Queue(maxsize=10000)
        self.active_feed: Dict[int, dict] = {}
        self.feed_last_sent: Dict[int, float] = {}
        self.feed_lock = threading.RLock()
        self.feed_debounce_seconds = 1.0

        # History and stats
        self.events_history: List[dict] = []
        self.max_events = config.get('performance.max_events', 500)

        self.stats = {
            'total_events': 0,
            'high_risk_events': 0,
            'processes_killed': 0,
            'alerts_sent': 0,
            'dropped_events': 0,
            'dropped_low_priority_events': 0,
            'queue_recovered_events': 0,
            'background_restarts': 0,
            'uptime_start': time.time(),
            'last_threat': None,
        }

        self.alert_timestamps = deque()
        self.max_alerts_per_minute = config.get('alerts.max_per_minute', 20)

    def add_event_history(self, event: dict):
        self.events_history.insert(0, event)
        if len(self.events_history) > self.max_events:
            self.events_history.pop()

        self.stats['total_events'] += 1
        score = event.get('suspicion_score', 0)
        if score >= int(config.killswitch_threshold):
            self.stats['high_risk_events'] += 1
            self.stats['last_threat'] = time.time()
    
    def can_send_alert(self) -> bool:
        """Check if we can send an alert based on rate limiting.
            Uses deque for O(1) operations instead of list filtering.
        """
        now = time.time()
        # Remove expired timestamps from left (older entries)
        while self.alert_timestamps and now - self.alert_timestamps[0] > 60:
            self.alert_timestamps.popleft()
        
        # Check if we've hit the limit
        if len(self.alert_timestamps) >= self.max_alerts_per_minute:
            return False
        
        # Add current timestamp
        self.alert_timestamps.append(now)
        return True

    def get_feed_snapshot(self) -> List[dict]:
        with self.feed_lock:
            rows = list(self.active_feed.values())
        rows.sort(key=lambda item: (item.get("status") != "ACTIVE", item.get("status") != "BLOCKED", -(item.get("score") or 0), -(item.get("pid") or 0)))
        return rows

    def upsert_feed_entry(self, event: dict) -> Optional[dict]:
        metadata = (event.get("metadata", {}) or {}) if isinstance(event, dict) else {}
        pid = int(event.get("pid") or 0)
        if pid <= 0:
            return None

        threat = self.threat_manager.get_threat(pid)
        if not threat:
            return None

        now = time.time()
        entry = {
            "pid": pid,
            "process_name": threat.get("process_name") or event.get("process") or "unknown",
            "status": threat.get("status") or metadata.get("threat_status") or "ACTIVE",
            "score": int(threat.get("score") or event.get("suspicion_score") or 0),
            "files_affected": int(threat.get("files_affected") or 0),
            "was_blocked": bool(threat.get("was_blocked")),
            "first_seen": threat.get("first_seen"),
            "last_seen": threat.get("last_seen"),
            "file_path": threat.get("last_file_path") or event.get("file_path") or "",
            "event_type": event.get("event_type") or event.get("type") or "unknown",
            "operation": event.get("operation") or event.get("event_type") or "unknown",
            "timestamp": float(event.get("timestamp") or now),
        }

        with self.feed_lock:
            previous = self.active_feed.get(pid)
            if previous:
                merged = dict(previous)
                merged.update(entry)
                entry = merged
            self.active_feed[pid] = entry

            last_sent = self.feed_last_sent.get(pid, 0.0)
            if previous and (now - last_sent) < self.feed_debounce_seconds:
                logger.info("DUPLICATE FEED SKIPPED pid=%s", pid)
                return None

            self.feed_last_sent[pid] = now

        logger.info("FEED UPDATED pid=%s", pid)
        return dict(entry)

    def get_statistics(self) -> dict:
        uptime = int(time.time() - self.stats['uptime_start'])
        threat_summary = self.threat_manager.get_summary(include_closed=True)
        return {
            **self.stats,
            **threat_summary,
            'feed': self.get_feed_snapshot(),
            'blocked_today': int(threat_summary.get('blocked_threats', 0)),
            'uptime_seconds': uptime,
            'events_in_memory': len(self.events_history),
            'active_connections': self.manager.count(),
            'monitoring_active': bool(self.monitor) and getattr(self.monitor, 'monitoring', False),
            'killswitch': self.kill_switch.get_statistics(),
            'behavioral': self.behavioral_analyzer.get_statistics(),
            'monitor': self.monitor.get_statistics() if self.monitor and hasattr(self.monitor, 'get_statistics') else {},
        }

    def get_demo_status(self) -> dict:
        with self.demo_lock:
            now = time.time()
            if self.demo_process and self.demo_process.poll() is None:
                elapsed = int(now - (self.demo_start_time or now))
                state = 'running'
            elif self.demo_process is not None:
                elapsed = int(self.demo_duration_seconds or 0)
                state = self.demo_state or 'completed'
            else:
                elapsed = 0
                state = self.demo_state or 'idle'

            if state in {"idle", "starting"}:
                phase, phase_label = 1, "phase_1_preparation"
            elif state == "running":
                phase, phase_label = 2, "phase_2_execution"
            else:
                phase, phase_label = 3, "phase_3_result"

            return {
                'state': state,
                'phase': phase,
                'phase_label': phase_label,
                'pid': self.demo_process.pid if self.demo_process else None,
                'process_name': self.demo_process_name,
                'started_at': self.demo_start_time,
                'elapsed_seconds': elapsed,
                'duration_seconds': self.demo_duration_seconds,
                'target_dir': self.demo_target_dir,
                'stdout_log': self.demo_stdout_log,
                'stderr_log': self.demo_stderr_log,
                'error': self.demo_last_error,
            }

    def stop_demo(self) -> bool:
        with self.demo_lock:
            if self.demo_process and self.demo_process.poll() is None:
                pid = int(self.demo_process.pid)
                stop_reason = "manual_stop"
                try:
                    self.demo_process.terminate()
                    self.demo_process.wait(timeout=5)
                    self.demo_state = 'stopped'
                except Exception as e:
                    logger.warning("Demo terminate failed for PID %s: %s", pid, e)
                    try:
                        self.demo_process.kill()
                        self.demo_process.wait(timeout=5)
                        self.demo_state = 'stopped'
                    except Exception as kill_error:
                        logger.exception("Demo kill failed for PID %s: %s", pid, kill_error)
                        self.demo_last_error = f"Failed to stop demo process {pid}: {kill_error}"
                        return False
                finally:
                    if self.demo_start_time:
                        self.demo_duration_seconds = int(max(0, time.time() - self.demo_start_time))

                if self.monitor:
                    self.monitor.registered_external_processes.pop(pid, None)

                # A manual stop is still a containment action. Mark an
                # already-recorded incident as blocked so it cannot remain in
                # the dashboard's active-threat list after the process exits.
                existing_threat = self.threat_manager.get_threat(pid)
                if existing_threat and existing_threat.get("status") == "ACTIVE":
                    self.threat_manager.mark_blocked(
                        pid=pid,
                        process_name=self.demo_process_name or "safe_file_churn_simulator",
                        score=int(existing_threat.get("score") or config.killswitch_threshold),
                        operation=stop_reason,
                    )

                cleanup = self.cleanup_demo_artifacts()
                logger.warning(
                    "[DEMO] Manual stop completed pid=%s restored_files=%s removed_notes=%s",
                    pid,
                    cleanup.get("restored_files", 0),
                    cleanup.get("removed_notes", 0),
                )
                self.threat_manager.remove_pid_exemption(pid)
                return True
            return False

    def cleanup_demo_artifacts(self) -> dict:
        """Restore only the benign simulator artifacts in its dedicated folder."""
        if not self.demo_target_dir:
            return {"restored_files": 0, "removed_notes": 0}
        try:
            from utils.safe_file_churn_simulator import cleanup_simulation_artifacts

            return cleanup_simulation_artifacts(Path(self.demo_target_dir))
        except Exception:
            logger.exception("[DEMO] Failed to clean simulator artifacts")
            return {"restored_files": 0, "removed_notes": 0}

app_state = ApplicationState()
app_state._main_loop = None
LOW_PRIORITY_EVENT_TYPES = {"process_scanned"}

# --------------------- Async callback & thread-safe bridge ------------------
def _drop_one_low_priority_event() -> bool:
    """Drop one low-priority queued event to make room for a fresher event."""
    queue_items = app_state.event_queue._queue
    original_len = len(queue_items)
    dropped = False

    for _ in range(original_len):
        queued_event = queue_items.popleft()
        event_type = str(getattr(queued_event, "get", lambda *_: "")("type", "") or "")
        if not dropped and event_type in LOW_PRIORITY_EVENT_TYPES:
            dropped = True
            continue
        queue_items.append(queued_event)

    return dropped


def _enqueue_event_nowait(event: dict) -> None:
    event_type = str(event.get("type", "") or "")

    try:
        app_state.event_queue.put_nowait(event)
        return
    except asyncio.QueueFull:
        pass

    if event_type in LOW_PRIORITY_EVENT_TYPES:
        app_state.stats["dropped_low_priority_events"] += 1
        logger.debug("Dropping low-priority event because queue is full: %s", event_type)
        return

    if _drop_one_low_priority_event():
        app_state.stats["queue_recovered_events"] += 1
        try:
            app_state.event_queue.put_nowait(event)
            return
        except asyncio.QueueFull:
            pass

    try:
        dropped_event = app_state.event_queue.get_nowait()
        app_state.stats["dropped_events"] += 1
        logger.warning(
            "Event queue full; evicting oldest event type=%s for incoming type=%s",
            dropped_event.get("type", "unknown") if isinstance(dropped_event, dict) else "unknown",
            event_type or "unknown",
        )
        app_state.event_queue.put_nowait(event)
    except asyncio.QueueEmpty:
        app_state.stats["dropped_events"] += 1
        logger.warning("Event queue overflow with no recoverable slot for event type=%s", event_type or "unknown")
    except asyncio.QueueFull:
        app_state.stats["dropped_events"] += 1
        logger.warning("Event queue remained full after recovery attempt for event type=%s", event_type or "unknown")


def thread_safe_callback(event: dict):
    """
    Called from SystemMonitor threads; safely forwards events into
    the main asyncio loop without blocking monitor threads.
    """
    loop = app_state._main_loop
    if loop is None or not loop.is_running():
        logger.warning("No running event loop - buffering event")

        # Buffer events for later processing
        if not hasattr(app_state, '_event_buffer'):
            app_state._event_buffer = []
        app_state._event_buffer.append(event)

        # Limit buffer size to prevent memory issues
        if len(app_state._event_buffer) > 1000:
            app_state._event_buffer.pop(0)  # Remove oldest
        return

    try:
        loop.call_soon_threadsafe(_enqueue_event_nowait, event)
    except Exception as e:
        logger.exception("Failed to deliver event from thread: %s", e)

# --------------------- Event Processor (async) ------------------------------

async def process_event(event: dict):
    try:
        # Pass-through control messages emitted by monitor/notification manager.
        passthrough_types = {"threat_alert", "decision_result", "protection_action"}
        if event.get("type") in passthrough_types:
            if event.get("type") == "protection_action":
                data = event.get("data", {}) or {}
                action_event = {
                    "event_type": "protection_action",
                    "process": data.get("process", "unknown"),
                    "pid": data.get("pid"),
                    "suspicion_score": int(data.get("score", 0) or 0),
                    "timestamp": data.get("timestamp", time.time()),
                    "action": data.get("action", "unknown"),
                    "source": data.get("source", "unknown"),
                    "type": "protection_action",
                }
                app_state.add_event_history(action_event)
                try:
                    await app_state.db.log_event(action_event)
                except Exception:
                    logger.exception("DB log_event failed for protection_action")
                if data.get("success") and data.get("action") == "terminated":
                    app_state.stats["processes_killed"] += 1
                    app_state.stats["last_threat"] = time.time()
                feed_update = app_state.upsert_feed_entry({
                    "pid": data.get("pid"),
                    "process": data.get("process"),
                    "suspicion_score": data.get("score"),
                    "timestamp": data.get("timestamp"),
                    "event_type": "protection_action",
                    "operation": data.get("action"),
                    "metadata": {
                        "threat_status": "BLOCKED" if data.get("success") else "ACTIVE",
                    },
                })
                if feed_update:
                    await send_threat_update(feed_update)
            await app_state.manager.broadcast(event)
            return

        # if app_state.detector:
        #     event = app_state.detector.analyze_event(event)
            
        score = event.get('suspicion_score', 0)
        process_name = event.get('process', 'unknown')
        event_type = event.get('event_type') or event.get('type', 'unknown')

        logger.info("Processing event: %s | type=%s | score=%s", process_name, event_type, score)

        # --- Detection mode assignment (CRITICAL) ---
        # Initialize with default first
        event["detection_mode"] = "UNKNOWN"
        
        if (
            event.get("rapid_file_ops", 0) > 20
            or event.get("mass_file_activity") is True
            or event.get("pre_encryption_indicator") is True
        ):
            event["detection_mode"] = "PRE_ENCRYPTION"

        elif (
            event.get("ml_prediction", {}).get("decision") in {"RANSOMWARE", "KILL"}
            and event.get("ml_prediction", {}).get("confidence", 0) >= 70
        ):
            event["detection_mode"] = "ML_CONFIRMED"

        elif event.get('suspicion_score', 0) >= int(config.killswitch_threshold):
            event["detection_mode"] = "SCORE_BASED"
        
        elif event.get('suspicion_score', 0) > 0:
            event["detection_mode"] = "LOW_RISK"
        # else: remains "UNKNOWN"                   

        # Add to history
        app_state.add_event_history(event)

        # Store to DB (fire-and-forget but awaited to handle DB errors)
        try:
            await app_state.db.log_event(event)
        except Exception:
            logger.exception("DB log_event failed")

        # Update feature extractor (non-blocking)
        pid = event.get('pid')
        if app_state.feature_extractor and pid:
            if event_type == 'process_event':
                app_state.feature_extractor.update_process_metrics(
                    pid=pid,
                    cpu=event.get('cpu_percent', 0),
                    memory=event.get('memory_percent', 0),
                    threads=event.get('threads', 0),
                )
            elif event_type == 'file_event':
                app_state.feature_extractor.update_process_activity(
                    pid=pid,
                    event_type=event.get('operation', 'unknown'),
                    event_data=event,
                )

        # # Run ML model prediction
        # try:
        #     if (
        #         app_state.ml_model
        #         and getattr(app_state.ml_model, 'loaded', True)
        #         and pid
        #         and app_state.feature_extractor
        #     ):
        #         features = app_state.feature_extractor.extract_features(pid)

        #         # Do not run ML if feature window is invalid
        #         if not features or not features.get("valid"):
        #             event["ml_prediction"] = {
        #                 "decision": "UNAVAILABLE",
        #                 "confidence": None,
        #                 "reason": features.get("reason") if features else "no_features"
        #             }
        #         else:
        #             ml_result = app_state.ml_model.predict(features)
        #             event["ml_prediction"] = ml_result

        #             # ðŸ”’ HARD GATE: only explicit ransomware decisions affect score
        #             if (
        #                 ml_result.get("decision") in {"KILL", "RANSOMWARE"}
        #                 and ml_result.get("confidence") is not None
        #                 and ml_result.get("confidence") >= 70
        #             ):
        #                 event["suspicion_score"] = min(
        #                     100, event.get("suspicion_score", 0) + 30
        #                 )
        #                 event["indicators"] = event.get("indicators", []) + [
        #                     "ml_ransomware_detected"
        #                 ]

        #                 logger.warning(
        #                     "ML confirmed ransomware | PID=%s | confidence=%s",
        #                     pid,
        #                     ml_result.get("confidence"),
        #                 )

        # except Exception:
        #     logger.exception("ML prediction failed")


        # --- STEP 3: Automated response for HIGH threats ---
        if event.get("threat_level") == "HIGH":
            logger.critical(
                f"[AUTO-RESPONSE] HIGH threat | "
                f"PID={event.get('pid')} | "
                f"SCORE={event.get('suspicion_score')}"
            )
        
            logger.warning(
        f"[PIPELINE] SCORE={event.get('suspicion_score')} "
        f"LEVEL={event.get('threat_level')} "
        f"PID={event.get('pid')}"
)
            if app_state.response:
                response_result = await app_state.response.execute(event)
                event["response"] = response_result

        # Kill-switch
        # try:
        #     if config.killswitch_enabled:
        #         kill_result = app_state.kill_switch.evaluate_threat(event)
        #         if kill_result.get('action_taken') == 'terminated':
        #             app_state.stats['processes_killed'] += 1
        #             app_state.stats['threats_blocked'] += 1

        #         # Broadcast kill result
        #         await app_state.manager.broadcast({
        #             'type': 'killswitch',
        #             'data': kill_result,
        #         })
        #         logger.info("Kill-switch evaluated for %s: %s", process_name, kill_result.get('action_taken'))
        # except Exception:
        #     logger.exception("Kill-switch evaluation failed")

        try:
            feed_update = app_state.upsert_feed_entry(event)
            if feed_update:
                await send_threat_update(feed_update)
        except Exception:
            logger.exception("Threat feed broadcast failed")


        # Send alert if high severity
        try:
            alert_threshold = config.get('alerts.threshold', 70)
            if config.get('alerts.enabled') and event.get('suspicion_score', 0) >= alert_threshold:
                registry_action = (event.get("metadata", {}) or {}).get("threat_registry_action")
                if registry_action != "updated" and app_state.can_send_alert():
                    await send_alert(event)
        except Exception:
            logger.exception("Alert sending failed")

    except Exception:
        logger.exception("Unexpected error processing event")


async def event_processor():
    logger.info(" Event processor started")
    interval = config.get('performance.update_interval', 0.1)

    try:
        while True:
            try:
                event = await asyncio.wait_for(app_state.event_queue.get(), timeout=interval)
            except asyncio.TimeoutError:
                # Nothing to do, loop again
                await asyncio.sleep(0)
                continue

            # Process the event
            await process_event(event)

    except asyncio.CancelledError:
        logger.info("Event processor cancelled")
    except Exception:
        logger.exception("Event processor crashed")

async def periodic_stats_broadcaster():
    """Broadcast system stats every 5 seconds."""
    logger.info(" Stats broadcaster started")
    try:
        while True:
            await asyncio.sleep(5)
            
            try:
                await ensure_background_services_healthy()
                stats = app_state.get_statistics()
                threat_summary = app_state.threat_manager.get_summary(include_closed=True)
                monitor_stats = stats.get('monitor', {}) or {}
                monitor_detail = monitor_stats.get('monitor', {}) or {}
                file_stats = monitor_detail.get('file_stats', {}) or monitor_stats.get('file_stats', {}) or {}
                files_monitored = file_stats.get('files_monitored', 0)
                blocked_today = int(threat_summary.get('blocked_threats', 0))
                active_threats = int(threat_summary.get('active_threats', 0))
                
                # STRICT CONTRACT - All fields required
                stats_data = {
                    'type': 'stats',  # âœ… Changed from 'system'
                    'data': {
                        'active_threats': active_threats,
                        'blocked_today': blocked_today,
                        'blocked_threats': blocked_today,
                        'total_threats': int(threat_summary.get('total_threats', 0)),
                        'threats': list(threat_summary.get('threats', [])),
                        'files_monitored': files_monitored,
                        'protection_rate': 100,
                    }
                }
                
                # Validate required fields
                required = ['active_threats', 'blocked_today', 'files_monitored', 'protection_rate']
                for field in required:
                    if field not in stats_data['data']:
                        raise ValueError(f"Missing required field: {field}")
                
                await app_state.manager.broadcast(stats_data)
                logger.debug(f"Stats: threats={stats_data['data']['active_threats']}, blocked={stats_data['data']['blocked_today']}, files={stats_data['data']['files_monitored']}")
                
            except Exception:
                logger.exception("Stats broadcast failed")
                
    except asyncio.CancelledError:
        logger.info("Stats broadcaster cancelled")


# --------------------- Alerts ------------------------------------------------
async def send_threat_update(threat: dict):
    await app_state.manager.broadcast({
        "type": "threat_update",
        "data": threat,
    })


async def send_alert(event: dict):
    score = event.get('suspicion_score', 0)
    process = event.get('process', 'unknown')

    app_state.stats['alerts_sent'] += 1

    alert = {
        "type": "alert",
        "data": {
            "severity": "critical" if score >= 85 else "high",
            "process": process,
            "pid": event.get("pid"),
            "score": score,
            "timestamp": event.get('timestamp', time.time()),
            "status": (event.get('metadata', {}) or {}).get('threat_status'),
            "indicators": event.get('indicators', []),
            "file_path": event.get('file_path', ''),
            "operation": event.get('operation', ''),
            "message": f"High-risk activity: {process}",
        },
    }

    await app_state.manager.broadcast(alert)
    logger.warning(" ALERT: %s (Score: %s)", process, score)


def _start_ml_scheduler_thread() -> bool:
    if app_state.ml_scheduler is None:
        return False
    if app_state.ml_thread and app_state.ml_thread.is_alive():
        return True

    def start_ml_scheduler():
        try:
            asyncio.run(app_state.ml_scheduler.run())
        except Exception:
            logger.exception("[DETECTION] ML scheduler thread crashed")

    app_state.ml_thread = threading.Thread(
        target=start_ml_scheduler,
        name="RansomGuard-MLScheduler",
        daemon=True,
    )
    app_state.ml_thread.start()
    logger.info("[DETECTION] ML scheduler started in background thread")
    return True


def _flush_buffered_events() -> None:
    buffered = getattr(app_state, "_event_buffer", None) or []
    if not buffered:
        return

    for event in list(buffered):
        _enqueue_event_nowait(event)
    app_state._event_buffer = []
    logger.info("[DETECTION] Flushed %s buffered events into the async queue", len(buffered))


def _run_background_housekeeping(active_pids: List[int]) -> None:
    active_pid_set = {int(pid) for pid in active_pids if int(pid) > 0}
    try:
        cleaned_states = app_state.threat_state.cleanup(active_pid_set, ttl_seconds=600)
        if cleaned_states:
            logger.debug("[HOUSEKEEPING] Cleaned %s stale threat states", cleaned_states)
    except Exception:
        logger.debug("[HOUSEKEEPING] Threat-state cleanup failed", exc_info=True)

    try:
        cleaned_threats = app_state.threat_manager.cleanup_stale(ttl_seconds=300)
        if cleaned_threats:
            logger.debug("[HOUSEKEEPING] Closed %s stale PID threats", cleaned_threats)
    except Exception:
        logger.debug("[HOUSEKEEPING] Threat-manager cleanup failed", exc_info=True)

    try:
        if app_state.feature_extractor:
            app_state.feature_extractor.cleanup_old_processes(active_pid_set, max_age_seconds=600)
    except Exception:
        logger.debug("[HOUSEKEEPING] Feature-extractor cleanup failed", exc_info=True)

    try:
        cleaned_behavioral = app_state.behavioral_analyzer.cleanup()
        if cleaned_behavioral:
            logger.debug("[HOUSEKEEPING] Cleaned %s stale behavioral windows", cleaned_behavioral)
    except Exception:
        logger.debug("[HOUSEKEEPING] Behavioral-analyzer cleanup failed", exc_info=True)


async def ensure_background_services_healthy() -> None:
    if not app_state.detection_services_started:
        return

    try:
        if app_state.monitor and not app_state.monitor.is_healthy():
            logger.warning("[DETECTION] Monitor thread was not healthy; restarting")
            if app_state.monitor.ensure_running():
                app_state.stats["background_restarts"] += 1

        if app_state.ml_scheduler and (app_state.ml_thread is None or not app_state.ml_thread.is_alive()):
            logger.warning("[DETECTION] ML scheduler thread was not healthy; restarting")
            if _start_ml_scheduler_thread():
                app_state.stats["background_restarts"] += 1
    except Exception:
        logger.exception("[DETECTION] Background health check failed")


async def ensure_detection_services_started():
    if app_state.detection_services_started:
        return True

    async with app_state.detection_services_lock:
        if app_state.detection_services_started:
            return True

        try:
            logger.info("[DETECTION] Starting monitor and ML scheduler after dashboard activation")

            if app_state.monitor is None:
                logger.info("[DETECTION] Creating SystemMonitor instance...")
                app_state.monitor = SystemMonitor(
                    callback=thread_safe_callback,
                    threat_manager=app_state.threat_manager,
                    analyzer=app_state.behavioral_analyzer,
                    detector=app_state.detector,
                )
                logger.info("[DETECTION] SystemMonitor instance created")

            if app_state.ml_scheduler is None:
                app_state.ml_scheduler = MLScheduler(
                    state_machine=app_state.threat_state,
                    analyzer=app_state.behavioral_analyzer,
                    detector=app_state.detector,
                    dashboard_broadcast=app_state.manager.broadcast,
                    whitelist=app_state.whitelist,
                    list_active_processes=app_state.monitor.list_active_processes,
                    maintenance_callback=_run_background_housekeeping,
                    interval_seconds=5.0,
                )

            _start_ml_scheduler_thread()

            watch_paths = []
            if hasattr(app_state.monitor, "_get_default_watch_paths"):
                try:
                    watch_paths.extend(app_state.monitor._get_default_watch_paths())
                except Exception:
                    logger.exception("Failed to collect default watch paths")

            started = app_state.monitor.start_monitoring(watch_paths=watch_paths)
            logger.info("[DETECTION] start_monitoring() returned: %s", started)

            if not started:
                logger.warning("[DETECTION] System monitor did not start")
                return False

            try:
                app_state.monitor.notification_manager.send_startup_notification(
                    host=config.get('server.host'),
                    port=config.get('server.port'),
                )
            except Exception as e:
                logger.warning(f"[STARTUP TOAST] Could not send: {e}")

            await asyncio.sleep(0.5)
            stats = app_state.monitor.get_statistics()
            logger.info(
                "[DETECTION] File observers active: %s",
                stats.get('monitor', {}).get('file_observers', 0),
            )
            _flush_buffered_events()
            app_state.detection_services_started = True
            return True

        except Exception as e:
            logger.exception("[DETECTION] Initialization failed: %s", e)
            return False


# --------------------- Startup / Shutdown -----------------------------------
# Keep references to background tasks so we can cancel on shutdown
_background_tasks: List[asyncio.Task] = []

@app.on_event("startup")
async def startup():
    app_state._main_loop = asyncio.get_running_loop()
    logger.info("\n Starting RansomGuard backend (production rewrite)")

    if config.get("security.enable_authentication", False):
        configured_api_key = str(config.get("security.api_key", "") or "").strip()
        if not configured_api_key:
            raise RuntimeError("security.enable_authentication is true but security.api_key is empty")

    # Initialize DB
    try:
        await app_state.db.init_db()
        logger.info(" Database ready")
    except Exception:
        logger.exception("Database initialization failed")

    # Do not block startup by loading ML twice.
    # ThreatDetector initializes and loads the model immediately after this.
    app_state.ml_model.loaded = False
    logger.info("Skipping duplicate standalone ML preload at startup")

    # Feature extractor
    app_state.feature_extractor = FeatureExtractor()
    logger.info(" Feature extractor initialized")

    # Initialize threat detector
    app_state.detector = ThreatDetector(config=config)
    logger.info(" Threat detector initialized")

    # Initialize automated response engine
    app_state.response = AutomatedResponse()
    logger.info(" Automated response engine initialized")

    # Start event processor
    task = asyncio.create_task(event_processor())
    _background_tasks.append(task)
    logger.info(" Event processor running")

    # Start periodic stats broadcaster (dashboard heartbeat)
    stats_task = asyncio.create_task(periodic_stats_broadcaster())
    _background_tasks.append(stats_task)
    logger.info(" Stats broadcaster running")

    logger.info(" Detection services are idle until the dashboard activates them")

@app.on_event("shutdown")
async def shutdown():
    logger.info("\n Shutting down RansomGuard backend...")

    # Stop monitor
    try:
        if app_state.monitor:
            app_state.monitor.stop_monitoring()
            logger.info("Monitor stop requested")
    except Exception:
        logger.exception("Monitor shutdown failed")

    # Cancel background tasks
    for t in _background_tasks:
        t.cancel()

    await asyncio.sleep(0.1)
    if app_state.ml_scheduler:
        app_state.ml_scheduler.stop()

    if app_state.ml_task:
        app_state.ml_task.cancel()


    # Close DB
    try:
        await app_state.db.close()
        logger.info("Database closed")
    except Exception:
        logger.exception("Database close failed")

    logger.info(" Shutdown complete\n")

# --------------------- API Endpoints ----------------------------------------
@app.get("/", response_class=HTMLResponse)
async def root():
    if not app_state.detection_services_started:
        asyncio.create_task(ensure_detection_services_started())
    index_path = os.path.join(DASHBOARD_DIR, "index.html")
    if os.path.isfile(index_path):
        return FileResponse(index_path)
    return HTMLResponse("<h1>RansomGuard</h1><p>Dashboard not installed.</p>")

@app.get("/api/status")
async def get_status(_: None = Depends(require_api_key)):
    stats = app_state.get_statistics()
    threat_summary = app_state.threat_manager.get_summary(include_closed=True)
    return JSONResponse({
        "status": "online",
        "timestamp": time.time(),
        "version": config.get('system.version'),
        "statistics": stats,
        "threat_summary": threat_summary,
        "configuration": {
            "killswitch_enabled": config.killswitch_enabled,
            "threat_threshold": config.killswitch_threshold,
            "monitoring_active": bool(app_state.monitor) and getattr(app_state.monitor, 'monitoring', False),
        },
    })

@app.get("/api/events/recent")
async def get_recent_events(limit: int = Query(50, le=100), _: None = Depends(require_api_key)):
    return JSONResponse(app_state.events_history[:limit])

@app.get("/api/events/count")
async def get_event_count(_: None = Depends(require_api_key)):
    return JSONResponse({
        "total": app_state.stats['total_events'],
        "high_risk": app_state.stats['high_risk_events'],
        "in_memory": len(app_state.events_history),
    })

@app.get("/api/statistics")
async def get_statistics(_: None = Depends(require_api_key)):
    return JSONResponse(app_state.get_statistics())


@app.get("/api/logs")
async def get_logs(limit: int = Query(50, le=100), _: None = Depends(require_api_key)):
    try:
        logs = await app_state.db.get_recent_logs(limit)
        return JSONResponse(logs)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/demo/start")
async def demo_start(payload: Optional[dict] = None, _: None = Depends(require_api_key)):
    await ensure_detection_services_started()
    payload = payload or {}

    with app_state.demo_lock:
        if app_state.demo_process and app_state.demo_process.poll() is None:
            raise HTTPException(status_code=409, detail="Demo already running")

        duration = int(payload.get("duration", 30) or 30)
        batch_size = int(payload.get("batch_size", 30) or 30)
        rename_ext = str(payload.get("rename_ext", ".lockbit") or ".lockbit").strip()
        create_note = bool(payload.get("create_ransom_note", True))

        duration = max(5, min(duration, 600))
        batch_size = max(1, min(batch_size, 500))
        if not rename_ext:
            rename_ext = ".lockbit"
        if not rename_ext.startswith("."):
            rename_ext = f".{rename_ext}"

        demo_dir = runtime_path("data/test_monitoring/demo_ransomware")
        os.makedirs(demo_dir, exist_ok=True)

        # Ensure the demo directory is being monitored
        if app_state.monitor:
            app_state.monitor.start_monitoring(watch_paths=[demo_dir])

        logs_dir = runtime_path("logs")
        os.makedirs(logs_dir, exist_ok=True)
        stamp = time.strftime("%Y%m%d_%H%M%S", time.localtime())
        stdout_log_path = os.path.join(logs_dir, f"demo_sim_{stamp}_out.log")
        stderr_log_path = os.path.join(logs_dir, f"demo_sim_{stamp}_err.log")

        command = [sys.executable]
        runner_identity = sys.executable
        if not getattr(sys, "frozen", False):
            run_script = resource_path("run.py")
            if not os.path.exists(run_script):
                raise HTTPException(status_code=500, detail=f"Demo runner not found: {run_script}")
            command.append(run_script)
            runner_identity = run_script

        command.extend(
            [
                "--run-safe-simulator",
                "--target-dir",
                demo_dir,
                "--duration",
                str(duration),
                "--batch-size",
                str(batch_size),
                "--rename-ext",
                rename_ext,
            ]
        )
        if create_note:
            command.append("--create-ransom-note")

        stdout_handle = None
        stderr_handle = None
        try:
            stdout_handle = open(stdout_log_path, "ab")
            stderr_handle = open(stderr_log_path, "ab")
            app_state.demo_state = "starting"
            proc = subprocess.Popen(
                command,
                cwd=BASE_DIR,
                stdout=stdout_handle,
                stderr=stderr_handle,
            )
            # Do not exempt the simulator PID. It intentionally produces
            # ransomware-like telemetry, so the normal exact-PID containment
            # path must be able to terminate it on the first high-risk event.
            if app_state.monitor:
                app_state.monitor.register_external_process(
                    proc.pid,
                    "safe_file_churn_simulator",
                    sys.executable,
                    target_paths=[demo_dir],
                )
        except Exception as e:
            if stdout_handle:
                stdout_handle.close()
            if stderr_handle:
                stderr_handle.close()
            app_state.demo_state = "failed"
            app_state.demo_last_error = f"Failed to launch safe simulator: {e}"
            raise HTTPException(status_code=500, detail=app_state.demo_last_error)

        app_state.demo_process = proc
        app_state.demo_start_time = time.time()
        app_state.demo_duration_seconds = duration
        app_state.demo_state = "running"
        app_state.demo_target_dir = demo_dir
        app_state.demo_process_name = "safe_file_churn_simulator"
        app_state.demo_stdout_log = stdout_log_path
        app_state.demo_stderr_log = stderr_log_path
        app_state.demo_last_error = None

        logger.info(
            "[DEMO] Started safe simulator pid=%s duration=%ss batch=%s target=%s",
            proc.pid,
            duration,
            batch_size,
            demo_dir,
        )

        if app_state.monitor:
            app_state.monitor.register_external_process(
                pid=proc.pid,
                process_name=app_state.demo_process_name,
                exe_path=str(runner_identity),
                target_paths=[demo_dir],
            )

        def monitor_demo(open_stdout, open_stderr):
            ret = None
            try:
                ret = proc.wait()
            except Exception as e:
                logger.exception("[DEMO] Failed while waiting for simulator process: %s", e)
                with app_state.demo_lock:
                    if app_state.demo_state != "stopped":
                        app_state.demo_state = "failed"
                        app_state.demo_last_error = f"Demo monitor error: {e}"
            finally:
                try:
                    open_stdout.close()
                except Exception:
                    logger.debug("[DEMO] Failed to close stdout log handle", exc_info=True)
                try:
                    open_stderr.close()
                except Exception:
                    logger.debug("[DEMO] Failed to close stderr log handle", exc_info=True)

                with app_state.demo_lock:
                    if app_state.demo_start_time:
                        app_state.demo_duration_seconds = int(max(0, time.time() - app_state.demo_start_time))
                    existing_threat = app_state.threat_manager.get_threat(proc.pid)
                    blocked_by_guard = bool(existing_threat and existing_threat.get("was_blocked"))
                    if app_state.demo_state != "stopped":
                        if blocked_by_guard:
                            app_state.demo_state = "blocked"
                            app_state.demo_last_error = None
                            cleanup = app_state.cleanup_demo_artifacts()
                            logger.warning(
                                "[DEMO] Automatic containment completed pid=%s restored_files=%s removed_notes=%s",
                                proc.pid,
                                cleanup.get("restored_files", 0),
                                cleanup.get("removed_notes", 0),
                            )
                        elif ret == 0:
                            app_state.demo_state = "completed"
                        else:
                            app_state.demo_state = "failed"
                            if ret is not None:
                                app_state.demo_last_error = (
                                    f"Safe simulator exited with code {ret}. "
                                    f"See log: {app_state.demo_stderr_log}"
                                )

                if app_state.monitor:
                    app_state.monitor.registered_external_processes.pop(proc.pid, None)
                app_state.threat_manager.remove_pid_exemption(proc.pid)

        threading.Thread(target=monitor_demo, args=(stdout_handle, stderr_handle), daemon=True).start()
        return JSONResponse({"success": True, "demo": app_state.get_demo_status()})


@app.get("/api/demo/status")
async def demo_status(_: None = Depends(require_api_key)):
    threat_summary = app_state.threat_manager.get_summary(include_closed=True)
    return JSONResponse({
        "success": True,
        "demo": app_state.get_demo_status(),
        **threat_summary,
    })


@app.post("/api/demo/stop")
async def demo_stop(_: None = Depends(require_api_key)):
    stopped = app_state.stop_demo()
    if not stopped:
        raise HTTPException(status_code=404, detail="Demo not running")
    return JSONResponse({"success": True, "demo": app_state.get_demo_status()})

@app.post("/api/killswitch/toggle")
async def toggle_killswitch(enabled: bool, _: None = Depends(require_api_key)):
    app_state.kill_switch.enabled = enabled
    await app_state.manager.broadcast({
        "type": "system",
        "data": {
            "message": f"Kill-switch {'enabled' if enabled else 'disabled'}",
            "killswitch_enabled": enabled,
            "timestamp": time.time(),
        },
    })
    return JSONResponse({"success": True, "killswitch_enabled": enabled, "threshold": app_state.kill_switch.threat_threshold})

@app.get("/api/killswitch/history")
async def get_kill_history(limit: int = Query(50, le=100), _: None = Depends(require_api_key)):
    return JSONResponse(app_state.kill_switch.get_kill_history(limit))

@app.get("/api/killswitch/blocked")
async def get_blocked(_: None = Depends(require_api_key)):
    blocked = app_state.kill_switch.get_blocked_processes()
    return JSONResponse({"blocked_processes": blocked, "count": len(blocked)})

@app.get("/health")
async def health():
    return JSONResponse({
        "ok": True,
        "timestamp": time.time(),
        "uptime": int(time.time() - app_state.stats['uptime_start']),
        "version": config.get('system.version'),
    })
# --------------------- WebSocket Endpoint ----------------------------------
@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket, api_key: Optional[str] = Query(default=None)):
    logger.info("[WEBSOCKET] New connection attempt from client")

    if config.get("security.enable_authentication", False):
        expected = str(config.get("security.api_key", "") or "").strip()
        supplied = str(api_key or websocket.headers.get("x-api-key") or "").strip()
        if not expected or not hmac.compare_digest(supplied, expected):
            await websocket.close(code=1008)
            logger.warning("[WEBSOCKET] Connection rejected by API authentication")
            return

    if not app_state.detection_services_started:
        await ensure_detection_services_started()
    
    try:
        await websocket.accept()
        logger.info("[WEBSOCKET] Connection accepted")
    except Exception as e:
        logger.error(f"[WEBSOCKET] Failed to accept connection: {e}")
        return

    if not await app_state.manager.connect(websocket):
        logger.warning("[WEBSOCKET] Connection rejected (max connections reached)")
        return

    logger.info(f"[WEBSOCKET] Client connected successfully (Total: {app_state.manager.count()})")
    keepalive_task = None

    try:
        # Send initial bulk events
        await websocket.send_json({
            "type": "bulk",
            "data": app_state.get_feed_snapshot(),
        })
        logger.info("[WEBSOCKET] Sent initial bulk events")

        initial_stats = app_state.get_statistics()
        initial_threat_summary = app_state.threat_manager.get_summary(include_closed=True)
        initial_monitor = initial_stats.get("monitor", {}) or {}
        initial_monitor_detail = initial_monitor.get("monitor", {}) or {}
        initial_file_stats = initial_monitor_detail.get("file_stats", {}) or initial_monitor.get("file_stats", {}) or {}

        await websocket.send_json({
            "type": "stats",
            "data": {
                "active_threats": int(initial_threat_summary.get("active_threats", 0)),
                "blocked_today": int(initial_threat_summary.get("blocked_threats", 0)),
                "blocked_threats": int(initial_threat_summary.get("blocked_threats", 0)),
                "total_threats": int(initial_threat_summary.get("total_threats", 0)),
                "threats": list(initial_threat_summary.get("threats", [])),
                "files_monitored": int(initial_file_stats.get("files_monitored", 0)),
                "protection_rate": 100,
            },
        })

        if app_state.monitor and getattr(app_state.monitor, "notification_manager", None):
            await websocket.send_json({
                "type": "pending_alerts",
                "data": app_state.monitor.notification_manager.get_pending_alerts(),
            })

        async def keepalive() -> None:
            while True:
                await asyncio.sleep(15)
                await websocket.send_json({
                    "type": "ping",
                    "data": {"timestamp": time.time()},
                })

        keepalive_task = asyncio.create_task(keepalive())

        while True:
            payload = await websocket.receive_text()
            if not payload:
                continue

            try:
                message = json.loads(payload)
            except json.JSONDecodeError:
                message = {"type": payload.strip().lower()}

            message_type = str(message.get("type", "") or "").lower()
            if message_type == "ping":
                await websocket.send_json({
                    "type": "pong",
                    "data": {"timestamp": time.time()},
                })

    except WebSocketDisconnect:
        logger.info("[WEBSOCKET] Client disconnected normally")

    except Exception as e:
        logger.error(f"[WEBSOCKET] Error during connection: {e}")

    finally:
        if keepalive_task:
            keepalive_task.cancel()
        await app_state.manager.disconnect(websocket)
        logger.info(f"[WEBSOCKET] Connection closed (Remaining: {app_state.manager.count()})")

# ===== NEW CHAT ENDPOINTS (ADD AT BOTTOM) =====
@app.post("/api/chat")
async def chat_endpoint(request: dict, _: None = Depends(require_api_key)):
    """Chat with RansomGuard AI Assistant"""
    user_message = request.get("message", "")
    
    if not user_message:
        return {"error": "Message is required"}
    
    result = await chatbot.chat(user_message)
    return result

@app.post("/api/chat/explain-threat")
async def explain_threat_endpoint(request: dict, _: None = Depends(require_api_key)):
    """Get AI explanation for specific threat"""
    pid = request.get("pid")
    features = request.get("features", {})
    
    if not pid or not features:
        return {"error": "PID and features are required"}
    
    explanation = await chatbot.explain_threat(pid, features)
    return {"explanation": explanation}

@app.post("/api/chat/reset")
async def reset_chat(_: None = Depends(require_api_key)):
    """Reset chat conversation history"""
    chatbot.reset_conversation()
    return {"success": True, "message": "Chat history cleared"}


# --------------------- Entry point for development --------------------------
if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host=config.get('server.host'), port=config.get('server.port'), log_level="info")



