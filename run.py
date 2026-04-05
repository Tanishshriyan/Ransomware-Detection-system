import argparse
import json
import logging
import os
import shutil
import subprocess
import sys
import threading
import time
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List

from utils.config import config as yaml_config
from utils.resource_path import app_root, resource_path

PROJECT_ROOT = app_root()
os.chdir(PROJECT_ROOT)
# # Force UTF-8 encoding for Windows console (safe version)
if sys.platform == 'win32':
    if sys.stdout and hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding='utf-8', errors='replace')
    if sys.stderr and hasattr(sys.stderr, "reconfigure"):
        sys.stderr.reconfigure(encoding='utf-8', errors='replace')
    os.environ['PYTHONIOENCODING'] = 'utf-8'
# --------------------------
# Basic configuration
# --------------------------
VENV_DIR = PROJECT_ROOT / "venv_rguard"
LOG_DIR = PROJECT_ROOT / "logs"
LOG_FILE = LOG_DIR / f"launcher_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}.log"
CONFIG_FILE = PROJECT_ROOT / "config.json"
ENV_FILE = PROJECT_ROOT / ".env"

DEFAULT_CONFIG = {
    "host": yaml_config.get("server.host", "127.0.0.1"),
    "port": yaml_config.get("server.port", 8000),
    "auto_open_browser": True,
    "auto_install_dependencies": True,
    "service_install_on_first_run": False,
    "service_name": "RansomGuardService",
    "auto_git_pull": False,
    "required_packages": [
        "fastapi", "uvicorn[standard]", "websockets", "psutil", "watchdog",
        "aiosqlite", "scikit-learn", "numpy", "pydantic", "pandas", "lightgbm",
        "xgboost", "windows-toasts", "openai", "python-dotenv", "joblib","google-generativeai"
    ],
    "max_start_retries": 3,
    "enable_crash_reporter": False,
    "crash_report_port": 9999
}

# --------------------------
# Logging
# --------------------------
LOG_DIR.mkdir(parents=True, exist_ok=True)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    handlers=[
        logging.FileHandler(LOG_FILE),
        logging.StreamHandler(sys.__stdout__ or sys.stdout)
    ],
)
logger = logging.getLogger("rguard.launcher")

# --------------------------
# Utils
# --------------------------
def color(text: str, c: str) -> str:
    codes = {"red": "\033[91m", "green": "\033[92m", "yellow": "\033[93m",
             "cyan": "\033[96m", "blue": "\033[94m", "end": "\033[0m"}
    return codes.get(c, "") + text + codes["end"]

def is_windows():
    return os.name == "nt"

def is_admin():
    if not is_windows():
        return False
    try:
        import ctypes
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception as e:
        logger.warning(f"Failed to check admin status: {e}")
        return False

def run_cmd(cmd: List[str], check=False):
    try:
        return subprocess.run(cmd, check=check).returncode
    except Exception as e:
        logger.error(f"Command execution failed: {cmd}: {e}")
        return -1
    
#PORT AVIALIABILITY CHECKING    

def is_port_available(host: str, port: int) -> bool:
    """Check if port is available"""
    import socket
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind((host, port))
            return True
    except OSError:
        return False


def is_backend_healthy(host: str, port: int, timeout: float = 2.0) -> bool:
    url = f"http://{host}:{port}/health"
    try:
        with urllib.request.urlopen(url, timeout=timeout) as response:
            body = response.read().decode("utf-8", errors="replace")
            return response.status == 200 and '"ok"' in body.lower()
    except Exception as e:
        logger.debug(f"Backend health check failed ({url}): {e}")
        return False


def cleanup_stale_port_owner(host: str, port: int) -> bool:
    """Terminate stale local Python processes occupying the configured port."""
    try:
        import psutil
    except Exception as e:
        logger.warning("psutil unavailable; cannot clean stale port owner: %s", e)
        return False

    candidate_pids = set()
    for conn in psutil.net_connections(kind="tcp"):
        laddr = getattr(conn, "laddr", None)
        if not laddr:
            continue
        local_ip = getattr(laddr, "ip", None) or (laddr[0] if len(laddr) > 0 else None)
        local_port = getattr(laddr, "port", None) or (laddr[1] if len(laddr) > 1 else None)
        if local_port == port and local_ip in {host, "0.0.0.0", "::", "::1"} and conn.pid:
            candidate_pids.add(conn.pid)

    if not candidate_pids:
        return False

    cleaned = False
    for pid in candidate_pids:
        try:
            proc = psutil.Process(pid)
            name = proc.name().lower()
            cmdline = " ".join(proc.cmdline()).lower()
            if "python" not in name and "python" not in cmdline:
                logger.warning("Port %s is owned by non-Python process PID=%s; leaving it alone", port, pid)
                continue

            logger.warning("Terminating stale Python process on port %s: PID=%s CMD=%s", port, pid, cmdline)
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except psutil.TimeoutExpired:
                proc.kill()
                proc.wait(timeout=5)
            cleaned = True
        except Exception as e:
            logger.warning("Failed to terminate stale PID %s: %s", pid, e)

    if cleaned:
        time.sleep(1)
    return cleaned
# --------------------------
# Config Loader
# --------------------------
def load_config() -> Dict:
    cfg = DEFAULT_CONFIG.copy()

    # Prefer the shared YAML config used by the backend.
    cfg["host"] = yaml_config.get("server.host", cfg["host"])
    cfg["port"] = yaml_config.get("server.port", cfg["port"])

    if CONFIG_FILE.exists():
        try:
            loaded = json.loads(CONFIG_FILE.read_text(encoding="utf-8"))
            cfg.update(loaded)
            logger.info("Loaded config.json overrides")
        except Exception as e:
            logger.error("Error parsing config.json: %s", e)

    if ENV_FILE.exists():
        try:
            for line in ENV_FILE.read_text().splitlines():
                if "=" in line and not line.strip().startswith("#"):
                    k, v = line.split("=", 1)
                    if k in cfg:
                        if v.lower() in ("true", "false"):
                            cfg[k] = v.lower() == "true"
                        else:
                            try:
                                cfg[k] = int(v)
                            except:
                                cfg[k] = v
            logger.info("Loaded .env overrides")
        except Exception as e:
            logger.warning("Failed to load .env: %s", e)

    return cfg

# --------------------------
# Venv
# --------------------------
def ensure_venv_and_reexec():
    # Skip venv if running as packaged EXE
    if getattr(sys, 'frozen', False):
        logger.info("Running packaged executable - skipping venv creation")
        return

    current_prefix = Path(sys.prefix).resolve()
    if VENV_DIR.resolve() in current_prefix.parents or current_prefix == VENV_DIR.resolve():
        return

    import venv
    if not VENV_DIR.exists():
        logger.info("Creating venv_rguard...")
        venv.EnvBuilder(with_pip=True).create(VENV_DIR)

    python = VENV_DIR / ("Scripts/python.exe" if is_windows() else "bin/python")
    os.execv(str(python), [str(python), str(Path(__file__).resolve())] + sys.argv[1:])
# --------------------------
# Dependency Installer
# --------------------------
def install_packages(packages: List[str]):
    """Install packages only if missing"""
    import importlib.util
    
    import_name_overrides = {
        "scikit-learn": "sklearn",
        "pycryptodome": "Crypto",
        "python-dotenv": "dotenv",
        "windows-toasts": "windows_toasts",
    }

    missing = []
    for p in packages:
        # Normalize package tokens like `uvicorn[standard]` or `pkg==1.2.3`
        base_pkg = p.split("[", 1)[0]
        base_pkg = base_pkg.split("==", 1)[0].split(">=", 1)[0].split("<=", 1)[0]

        # Map package name to import name
        import_name = import_name_overrides.get(base_pkg, base_pkg.replace("-", "_"))

        try:
            spec = importlib.util.find_spec(import_name)
        except Exception:
            spec = None

        if spec is None:
            missing.append(p)
    
    if missing:
        logger.info("Installing missing packages: %s", ", ".join(missing))
        run_cmd([sys.executable, "-m", "pip", "install", "--timeout", "300"] + missing)
    else:
        logger.info(" All dependencies already installed")


# --------------------------
# Git Auto Update (safe)
# --------------------------
def safe_git_pull():
    if not (PROJECT_ROOT / ".git").exists():
        logger.info("No git repo found.")
        return True
    logger.info("Running: git pull")
    return run_cmd(["git", "-C", str(PROJECT_ROOT), "pull"]) == 0

# --------------------------
# System Snapshot
# --------------------------
def print_system_snapshot():
    try:
        import psutil
        cpu = psutil.cpu_percent(interval=0.4)
        mem = psutil.virtual_memory()
        logger.info("CPU: %.1f%%, RAM: %.1f%%", cpu, mem.percent)
    except:
        logger.info("psutil not available.")

# --------------------------
# Crash Reporter
# --------------------------
def start_local_crash_server(port: int):
    import http.server, socketserver

    class CrashHandler(http.server.BaseHTTPRequestHandler):
        def do_POST(self):
            length = int(self.headers.get("Content-Length", 0))
            data = self.rfile.read(length).decode("utf-8")
            logger.error("CRASH REPORT: %s", data)
            self.send_response(200)
            self.end_headers()

        def log_message(self, format, *args): return

    def serve():
        with socketserver.TCPServer(("127.0.0.1", port), CrashHandler) as httpd:
            logger.info("Crash server running on 127.0.0.1:%s", port)
            httpd.serve_forever()

    threading.Thread(target=serve, daemon=True).start()

# --------------------------
# Banner
# --------------------------
def animated_banner():
    print(color("RansomGuard — Starting…", "cyan"))
    spinner = "|/-\\"
    steps = ["Checking environment", "Loading config", "Preparing venv", "Installing deps", "Starting backend"]
    for s in steps:
        for i in range(10):
            sys.stdout.write(f"\r{spinner[i % 4]} {s}")
            sys.stdout.flush()
            time.sleep(0.06)
    print("\r")

# --------------------------
# Backend Starter
# --------------------------
def start_backend_with_retries(cfg: Dict):
    """Start backend with retry logic"""
    host = cfg["host"]
    port = cfg["port"]
    retries = cfg["max_start_retries"]
    
    # Add PROJECT ROOT to path (not backend folder)
    project_root_str = str(PROJECT_ROOT)
    if project_root_str not in sys.path:
        sys.path.insert(0, project_root_str)
    
    for attempt in range(1, retries + 1):
        try:
            logger.info("Starting backend (attempt %d/%d)...", attempt, retries)
            
            # Import the app directly (not as string)
            from backend.main import app
            import uvicorn
            
            # Start uvicorn with app object
            uvicorn.run(
                app,  # Direct reference instead of string
                host=host,
                port=port,
                reload=False,
                log_level="info"
            )
            
            # If uvicorn returns, server stopped gracefully
            logger.info("Backend stopped normally")
            return True
            
        except KeyboardInterrupt:
            logger.info("User interrupted backend")
            return True
            
        except Exception as e:
            logger.exception("Backend crashed: %s", e)
            if attempt < retries:
                logger.warning("Retrying in 3 seconds...")
                time.sleep(3)
            else:
                logger.error("Max retries reached")
                return False
    
    return False

# --------------------------
# Safe simulator mode
# --------------------------
def maybe_run_safe_simulator(argv: List[str]) -> bool:
    """
    Run the benign ransomware simulator as a dedicated process mode.

    This mode is used by backend demo endpoints so the same command works in:
    - development (`python run.py --run-safe-simulator ...`)
    - packaged EXE (`RansomGuard.exe --run-safe-simulator ...`)
    """
    if "--run-safe-simulator" not in argv:
        return False

    filtered_argv = [arg for arg in argv if arg != "--run-safe-simulator"]
    parser = argparse.ArgumentParser(prog="run.py --run-safe-simulator")
    parser.add_argument("--target-dir", required=True)
    parser.add_argument("--duration", type=int, default=30)
    parser.add_argument("--batch-size", type=int, default=30)
    parser.add_argument("--rename-ext", default=".lockbit")
    parser.add_argument("--create-ransom-note", action="store_true")
    args = parser.parse_args(filtered_argv)

    from utils.safe_file_churn_simulator import run_simulation

    rename_ext = args.rename_ext if str(args.rename_ext).startswith(".") else f".{args.rename_ext}"
    duration = max(1, int(args.duration))
    batch_size = max(1, int(args.batch_size))

    logger.info(
        "[SIM-MODE] Running safe simulator target_dir=%s duration=%ss batch_size=%s rename_ext=%s ransom_note=%s",
        args.target_dir,
        duration,
        batch_size,
        rename_ext,
        bool(args.create_ransom_note),
    )
    run_simulation(
        target_dir=Path(args.target_dir),
        duration_seconds=duration,
        batch_size=batch_size,
        rename_ext=rename_ext,
        create_ransom_note=bool(args.create_ransom_note),
    )
    logger.info("[SIM-MODE] Safe simulator completed")
    return True

# --------------------------
# Main
# --------------------------
def main():
    try:
        animated_banner()
        cfg = load_config()

        ensure_venv_and_reexec()

        if cfg["auto_install_dependencies"] and not getattr(sys, "frozen", False):
            install_packages(cfg["required_packages"])

        print_system_snapshot()

        if cfg["auto_git_pull"]:
            safe_git_pull()

        if cfg["enable_crash_reporter"]:
            start_local_crash_server(cfg["crash_report_port"])

        if cfg["auto_open_browser"]:
            import webbrowser
            url = f"http://{cfg['host']}:{cfg['port']}"
            threading.Thread(target=lambda: webbrowser.open(url), daemon=True).start()
        
        if not is_port_available(cfg["host"], cfg["port"]):
            if is_backend_healthy(cfg["host"], cfg["port"]):
                logger.info("Healthy backend already running on %s:%s", cfg["host"], cfg["port"])
                if cfg["auto_open_browser"]:
                    import webbrowser
                    webbrowser.open(f"http://{cfg['host']}:{cfg['port']}")
                return

            logger.warning("Port %s is occupied by an unhealthy process; attempting cleanup", cfg["port"])
            cleaned = cleanup_stale_port_owner(cfg["host"], cfg["port"])
            if not cleaned or not is_port_available(cfg["host"], cfg["port"]):
                logger.error(f"Port {cfg['port']} already in use!")
                print(color(f" Port {cfg['port']} is busy. Change port in config.yaml or config.json", "red"))
                sys.exit(1)

        success = start_backend_with_retries(cfg)
        if not success:
            logger.error("Backend failed to start.")
            sys.exit(1)

        # Open browser AFTER backend starts
        if cfg["auto_open_browser"]:
            import webbrowser
            url = f"http://{cfg['host']}:{cfg['port']}"
            time.sleep(2)  # give server time to bind
            webbrowser.open(url)

    except Exception as e:
        logger.exception("Fatal launcher error: %s", e)
        print(color("Fatal launcher error. Check log.", "red"))
        sys.exit(1)

if __name__ == "__main__":
    if maybe_run_safe_simulator(sys.argv[1:]):
        sys.exit(0)
    main()
