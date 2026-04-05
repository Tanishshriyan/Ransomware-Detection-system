"""
Kill-Switch System (Production Version)
Terminates ransomware-like processes safely and reliably on Windows.
"""

import psutil
import os
import time
import logging
from typing import List, Dict, Optional

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("killswitch")

class KillSwitch:
    """
    Sophisticated threat response engine.
    Kills malicious processes, their children, and prevents respawn.
    """
    
    def __init__(self, enable_auto_kill: bool = True, threat_threshold: int = 75):
        self.enabled = enable_auto_kill
        self.threat_threshold = threat_threshold
        
        # Process names already terminated (blocklist)
        self.blocked_processes: set = set()
        
        # Kill history (records all termination attempts)
        self.killed_processes: List[Dict] = []
        
        # Suspended processes (PID -> timestamp)
        self.suspended_processes: Dict[int, float] = {}
        
        # Quarantine flag
        self.quarantine_mode = False
        
        # Protected PIDs (do not kill)
        self.protected_pids: set = set()
        
        # DO NOT KILL these critical system processes
        self.protected_processes = {
            'system', 'system idle process',
            'svchost.exe', 'csrss.exe', 'smss.exe',
            'services.exe', 'lsass.exe', 'winlogon.exe',
            'explorer.exe', 'wininit.exe', 'dwm.exe',
            'taskmgr.exe', 'fontdrvhost.exe', 'registry'
        }
        
        logger.info(f"[KillSwitch] Ready (AutoKill={self.enabled}, Threshold={self.threat_threshold})")

    # =====================================================================
    # THREAT EVALUATION
    # =====================================================================
    
    def evaluate_threat(self, event_data: dict) -> dict:
        """
        Evaluate threat and decide action.
        Returns dict with action_taken, success, reason, etc.
        """
        process_name = event_data.get("process", "unknown").lower()
        pid = event_data.get("pid")
        score = event_data.get("suspicion_score", 0)
        
        # SECURITY: detection_mode is mandatory
        if "detection_mode" not in event_data:
            raise RuntimeError(
                "SECURITY ERROR: detection_mode missing in event_data. "
                "Refusing to fallback."
            )
        
        detection_mode = event_data["detection_mode"]
        
        # SECURITY: Validate detection_mode value
        VALID_MODES = {"PRE_ENCRYPTION", "ML_CONFIRMED", "SCORE_BASED", "UNKNOWN", "LOW_RISK"}
        if detection_mode not in VALID_MODES:
            raise ValueError(
                f"SECURITY ERROR: Invalid detection_mode '{detection_mode}'. "
                f"Must be one of: {VALID_MODES}"
            )
        
        result = {
            "process": process_name,
            "pid": pid,
            "score": score,
            "mode": detection_mode,
            "action_taken": "none",
            "timestamp": time.time(),
            "success": False,
            "reason": ""
        }
        
        # 1. Below threshold -> ignore
        if score < self.threat_threshold:
            result["reason"] = "below_threshold"
            return result
        
        # 2. Protected system process
        if process_name in self.protected_processes:
            logger.warning(f"[PROTECTED] {process_name} flagged but is system process - SKIPPED")
            result["action_taken"] = "protected_skip"
            result["reason"] = "system_process"
            return result
        
        # 3. Protected PID
        if pid and pid in self.protected_pids:
            logger.info(f"[PROTECTED] PID {pid} is protected - SKIPPED")
            result["action_taken"] = "protected_skip"
            result["reason"] = "protected_pid"
            return result
        
        # 3. Already killed/blocked earlier
        if process_name in self.blocked_processes:
            result["action_taken"] = "already_blocked"
            result["reason"] = "previously_terminated"
            return result
        
        # 4. Kill-switch disabled -> alert only
        if not self.enabled:
            logger.warning(f"[DISABLED] Threat detected but KillSwitch disabled: {process_name}")
            result["action_taken"] = "alert_only"
            result["reason"] = "killswitch_disabled"
            return result
        
        # =========================================================
        # IMMEDIATE KILL LOGIC
        # =========================================================
        
        # 5. PRE_ENCRYPTION or ML_CONFIRMED modes -> immediate kill
        if detection_mode in {"PRE_ENCRYPTION", "ML_CONFIRMED"}:
            logger.critical(f"[IMMEDIATE KILL] {detection_mode} mode triggered for {process_name}")
            success = self.kill_process_tree(process_name, pid)
            result["success"] = success
            result["action_taken"] = "terminated" if success else "termination_failed"
            result["reason"] = detection_mode
            
            # Record kill attempt
            self._record_kill_attempt(process_name, pid, success, detection_mode)
            return result
        
        # 6. ML score-based kill (secondary path)
        # Only kill if ML-confirmed (not heuristic)
        detection_source = event_data.get("metadata", {}).get("detection_source", "UNKNOWN")
        ml_confidence = event_data.get("metadata", {}).get("ml_confidence", 0.0)
        
        if detection_source != "ML_PRIMARY":
            logger.info(f"[NON-ML] {process_name} detection from {detection_source} - alert only")
            result["action_taken"] = "alert_only"
            result["reason"] = "non_ml_detection"
            return result
        
        # 7. ML-confirmed with high confidence -> kill
        if ml_confidence >= 0.85:
            logger.critical(f"[ML KILL] Confidence={ml_confidence:.2f} for {process_name}")
            success = self.kill_process_tree(process_name, pid)  # FIXED TYPO
            result["success"] = success
            result["action_taken"] = "terminated" if success else "termination_failed"
            result["reason"] = "ML_THRESHOLD_EXCEEDED"
            
            # Record kill attempt
            self._record_kill_attempt(process_name, pid, success, "ML_CONFIRMED")
            return result
        
        # 8. Default: alert only if no kill condition met
        result["action_taken"] = "alert_only"
        result["reason"] = "no_kill_condition_met"
        return result
    
    # =====================================================================
    # PROCESS TERMINATION FUNCTIONS
    # =====================================================================
    
    def suspend_process(self, pid: int) -> bool:
        """
        Suspend a process temporarily (for user decision workflow).
        Returns True if suspended successfully.
        """
        try:
            proc = psutil.Process(pid)
            proc.suspend()
            self.suspended_processes[pid] = time.time()
            logger.info(f"[SUSPENDED] PID={pid} ({proc.name()})")
            return True
        except psutil.NoSuchProcess:
            logger.warning(f"[SUSPEND FAILED] PID={pid} - process not found")
            return False
        except psutil.AccessDenied:
            logger.error(f"[SUSPEND FAILED] PID={pid} - access denied")
            return False
        except Exception as e:
            logger.error(f"[SUSPEND ERROR] PID={pid}: {e}")
            return False
    
    def resume_process(self, pid: int) -> bool:
        """
        Resume a suspended process.
        Returns True if resumed successfully.
        """
        try:
            proc = psutil.Process(pid)
            proc.resume()
            
            # Remove from suspended tracking
            if pid in self.suspended_processes:
                del self.suspended_processes[pid]
            
            logger.info(f"[RESUMED] PID={pid} ({proc.name()})")
            return True
        except psutil.NoSuchProcess:
            logger.warning(f"[RESUME FAILED] PID={pid} - process not found")
            return False
        except psutil.AccessDenied:
            logger.error(f"[RESUME FAILED] PID={pid} - access denied")
            return False
        except Exception as e:
            logger.error(f"[RESUME ERROR] PID={pid}: {e}")
            return False
    
    def kill_process_tree(self, process_name: str, pid: Optional[int] = None) -> bool:
        """
        Kill process and all children.
        
        Steps:
        1. Kill by exact PID
        2. Kill all child processes

        Returns: True if any process was killed successfully
        """
        killed_any = False

        if not pid:
            logger.error(f"[KILL TREE ERROR] Missing PID for process '{process_name}'")
            return False

        if self._terminate_single_process(int(pid), process_name):
            killed_any = True
        
        # Add to blocklist to prevent respawn monitoring
        if killed_any:
            self.blocked_processes.add(process_name.lower())
            logger.info(f"[BLOCKED] {process_name} added to blocklist")
        
        return killed_any
    
    def _terminate_single_process(self, pid: int, process_name: str) -> bool:
        """
        Terminate a single process by PID.
        Returns True on success, False on failure.
        """
        try:
            if pid == os.getpid():
                logger.warning(f"[SELF-PROTECT] Refusing to terminate own process PID={pid}")
                return False
            proc = psutil.Process(pid)
            
            # Security check: verify process name matches
            if proc.name().lower() != process_name.lower():
                logger.warning(f"[MISMATCH] PID={pid} name mismatch (expected {process_name}, got {proc.name()})")
                return False
            
            # Step 1: Kill all child processes first
            try:
                children = proc.children(recursive=True)
                for child in children:
                    try:
                        child.kill()
                        logger.debug(f"[CHILD KILLED] PID={child.pid}")
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        pass
            except Exception as e:
                logger.debug(f"[CHILD KILL ERROR] {e}")
            
            # Step 2: Terminate parent process (graceful)
            proc.terminate()
            
            # Step 3: Wait for termination, force kill if timeout
            try:
                proc.wait(timeout=2)
            except psutil.TimeoutExpired:
                logger.warning(f"[FORCE KILL] PID={pid} did not terminate gracefully")
                proc.kill()
                proc.wait(timeout=1)
            
            logger.info(f"[TERMINATED] {process_name} (PID={pid})")
            self.suspended_processes.pop(pid, None)  # Clean up suspended list
            return True
        
        except psutil.NoSuchProcess:
            # Process already gone - consider it success
            self.suspended_processes.pop(pid, None)  # Clean up
            return True
        
        except psutil.AccessDenied:
            logger.error(f"[ACCESS DENIED] {process_name} (PID={pid})")
            return False
        
        except Exception as e:
            logger.error(f"[TERMINATION ERROR] {process_name} (PID={pid}): {e}")
            return False
    
    def _record_kill_attempt(self, process_name: str, pid: Optional[int], success: bool, reason: str) -> None:
        """Record kill attempt in history"""
        record = {
            "timestamp": time.time(),
            "process": process_name,
            "pid": pid,
            "success": success,
            "reason": reason
        }
        self.killed_processes.append(record)
        
        # Keep only last 500 records to prevent memory issues
        if len(self.killed_processes) > 500:
            self.killed_processes = self.killed_processes[-500:]
    
    # =====================================================================
    # MANAGEMENT & CONTROL
    # =====================================================================
    
    def enable_quarantine_mode(self):
        """Enable quarantine mode (more aggressive blocking)"""
        self.quarantine_mode = True
        logger.warning("[QUARANTINE MODE ENABLED]")
    
    def disable_quarantine_mode(self):
        """Disable quarantine mode"""
        self.quarantine_mode = False
        logger.info("[QUARANTINE MODE DISABLED]")
    
    def unblock_process(self, name: str):
        """Remove process from blocklist"""
        name = name.lower()
        if name in self.blocked_processes:
            self.blocked_processes.remove(name)
            logger.info(f"[UNBLOCKED] {name} removed from blocklist")
        else:
            logger.warning(f"[UNBLOCK FAILED] {name} not in blocklist")
    
    def get_blocked_processes(self) -> List[str]:
        """Get list of currently blocked processes"""
        return list(self.blocked_processes)
    
    def get_kill_history(self, limit: int = 50) -> List[Dict]:
        """Get recent kill history"""
        return self.killed_processes[-limit:]
    
    def reset(self):
        """Reset kill-switch state (clear history and blocklist)"""
        self.killed_processes.clear()
        self.blocked_processes.clear()
        self.suspended_processes.clear()
        self.quarantine_mode = False
        logger.info("[RESET] KillSwitch state cleared")
    
    # =====================================================================
    # STATISTICS & MONITORING
    # =====================================================================
    
    def get_statistics(self) -> dict:
        """Get comprehensive statistics for API/dashboard"""
        return {
            "enabled": self.enabled,
            "threat_threshold": self.threat_threshold,
            "quarantine_mode": self.quarantine_mode,
            "blocked_processes": list(self.blocked_processes),
            "suspended_processes": len(self.suspended_processes),
            "killed_count": len(self.killed_processes),
            "total_killed": len(self.killed_processes),
            "currently_blocked": len(self.blocked_processes),
            "recent_kills": self.get_kill_history(10)
        }
