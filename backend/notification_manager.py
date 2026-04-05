"""
Notification Manager - Dual Alert System (FIXED)
Sends alerts to both Web Dashboard (WebSocket) and Windows (Toast)
Uses windows-toasts library (modern, no callback bugs)
"""

import time
import threading
import queue
from typing import Optional, Callable, Dict, Any, List
from dataclasses import dataclass, asdict
import logging

# Windows notifications - NEW LIBRARY
try:
    from windows_toasts import Toast, WindowsToaster, ToastDisplayImage, ToastInputTextBox, ToastButton
    try:
        from windows_toasts import ToastDuration
    except ImportError:
        ToastDuration = None
    WINDOWS_TOAST_AVAILABLE = True
except ImportError:
    WINDOWS_TOAST_AVAILABLE = False
    ToastDuration = None

logger = logging.getLogger("notification_manager")

# Log import status
if not WINDOWS_TOAST_AVAILABLE:
    logger.warning("[NOTIFICATIONS] windows-toasts not available - Windows notifications disabled")
else:
    logger.info("[NOTIFICATIONS] windows-toasts library loaded successfully")

@dataclass
class ThreatAlert:
    """Threat alert requiring user decision"""
    alert_id: str
    process_name: str
    pid: int
    ml_confidence: float
    threat_score: int
    threat_level: str
    indicators: list
    exe_path: str
    timestamp: float
    status: str = "pending"  # pending, approved, denied, whitelisted, auto_killed, ignored
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization"""
        return asdict(self)


class NotificationManager:
    """
    Manages dual notification system:
    1. Web Dashboard (WebSocket real-time)
    2. Windows Toast (OS-level popup)
    """
    
    def __init__(self, websocket_callback: Optional[Callable] = None):
        self.websocket_callback = websocket_callback
        self.pending_alerts: Dict[str, ThreatAlert] = {}
        self._decision_callbacks: Dict[str, Callable[[str, str], None]] = {}
        self.user_decisions: queue.Queue = queue.Queue()
        
        # Windows toast notifier - NEW IMPLEMENTATION
        if WINDOWS_TOAST_AVAILABLE:
            try:
                self.toaster = WindowsToaster("RansomGuard")
                logger.info("[NOTIFICATIONS] Windows toast notifier initialized (windows-toasts)")
            except Exception as e:
                self.toaster = None
                logger.error(f"[NOTIFICATIONS] Failed to initialize toast notifier: {e}")
        else:
            self.toaster = None
        
        # Decision timeout (auto-kill after 30 seconds if no response)
        self.decision_timeout = 30  # seconds
        
        # Statistics
        self.stats = {
            'alerts_sent': 0,
            'web_alerts_sent': 0,
            'toast_alerts_sent': 0,
            'decisions_made': 0,
            'auto_kills': 0,
            'timeouts': 0
        }
        
        logger.info("[OK] Notification Manager initialized")
    
    def send_threat_alert(
        self,
        alert: ThreatAlert,
        on_decision: Callable[[str, str], None]
    ) -> None:
        """
        Send threat alert to both web and Windows
        Args:
            alert: ThreatAlert object
            on_decision: Callback function(alert_id, decision)
        """
        # Store alert
        self.pending_alerts[alert.alert_id] = alert
        self._decision_callbacks[alert.alert_id] = on_decision
        self.stats['alerts_sent'] += 1
        
        # 1. Send to Web Dashboard (WebSocket)
        self._send_web_alert(alert)
        
        # 2. Send Windows Toast Notification
        self._send_windows_toast(alert)
        
        # 3. Start decision timeout thread
        timeout_thread = threading.Thread(
            target=self._wait_for_decision,
            args=(alert, on_decision),
            daemon=True
        )
        timeout_thread.start()
    
    def _send_web_alert(self, alert: ThreatAlert) -> None:
        """Send alert to web dashboard via WebSocket"""
        if not self.websocket_callback:
            logger.debug("[WEB ALERT] No websocket callback registered")
            return
        
        web_message = {
            "type": "threat_alert",
            "alert_id": alert.alert_id,
            "data": {
                "process": alert.process_name,
                "pid": alert.pid,
                "confidence": alert.ml_confidence,
                "threat_score": alert.threat_score,
                "threat_level": alert.threat_level,
                "indicators": alert.indicators,
                "exe_path": alert.exe_path,
                "timestamp": alert.timestamp,
                "actions": ["KILL", "QUARANTINE", "WHITELIST", "IGNORE"]
            }
        }
        
        try:
            self.websocket_callback(web_message)
            self.stats['web_alerts_sent'] += 1
            logger.info(f"[WEB ALERT] Sent to dashboard: {alert.process_name} (PID {alert.pid})")
        except Exception as e:
            logger.error(f"[WEB ALERT] Failed to send: {e}")
    
    def _send_windows_toast(self, alert: ThreatAlert) -> None:
        """Send Windows 10/11 toast notification using windows-toasts library"""
        if not self.toaster:
            logger.debug("[TOAST] Windows toast not available")
            return
        
        try:
            # Create toast with modern API
            toast = Toast()
            
            # Title and message (no emoji issues)
            toast.text_fields = [
                f"RANSOMWARE DETECTED: {alert.process_name}",
                f"ML Confidence: {alert.ml_confidence * 100:.0f}% | Threat: {alert.threat_level.upper()}",
                f"PID: {alert.pid} | Click to take action"
            ]
            
            # Add action button that opens dashboard
            toast.AddAction(
                ToastButton(
                    "Open Dashboard",
                    arguments=f"alert_id={alert.alert_id}"
                )
            )
            
            # Set duration using library enum when available
            if ToastDuration is not None:
                toast.duration = ToastDuration.Long
            
            # Show toast with click handler
            toast.on_activated = lambda args: self._open_dashboard(alert.alert_id)
            
            # Display the toast
            self.toaster.show_toast(toast)
            
            self.stats['toast_alerts_sent'] += 1
            logger.info(f"[TOAST] Windows notification sent: {alert.process_name}")
            
        except Exception as e:
            logger.error(f"[TOAST] Failed to send: {e}")

    def send_startup_notification(self, host: str = "127.0.0.1", port: int = 8000) -> None:
        """Send a startup toast so users know dashboard is ready."""
        if not self.toaster:
            return
        try:
            toast = Toast()
            toast.text_fields = [
                "RansomGuard started",
                "Protection is active",
                f"Dashboard: http://{host}:{port}",
            ]
            if ToastDuration is not None:
                toast.duration = ToastDuration.Short
            self.toaster.show_toast(toast)
            logger.info("[STARTUP TOAST] Startup notification sent")
        except Exception as e:
            logger.warning(f"[STARTUP TOAST] Could not send: {e}")

    def send_info_notification(self, title: str, line1: str, line2: str = "") -> None:
        """Send a generic informational toast for demo/proof events."""
        if not self.toaster:
            return
        try:
            toast = Toast()
            text_fields = [title, line1]
            if line2:
                text_fields.append(line2)
            toast.text_fields = text_fields
            if ToastDuration is not None:
                toast.duration = ToastDuration.Short
            self.toaster.show_toast(toast)
            logger.info("[INFO TOAST] Sent: %s", title)
        except Exception as e:
            logger.warning(f"[INFO TOAST] Could not send: {e}")

    def _open_dashboard(self, alert_id: str) -> None:
        """Open web dashboard when user clicks toast"""
        import webbrowser
        try:
            webbrowser.open(f"http://127.0.0.1:8000/?alert={alert_id}")
            logger.info(f"[DASHBOARD] Opened for alert: {alert_id}")
        except Exception as e:
            logger.error(f"[DASHBOARD] Failed to open: {e}")
    
    def _wait_for_decision(
        self,
        alert: ThreatAlert,
        on_decision: Callable[[str, str], None]
    ) -> None:
        """
        Wait for user decision with timeout
        If no decision in 30s, auto-kill high-confidence threats
        """
        start_time = time.time()
        
        while time.time() - start_time < self.decision_timeout:
            # Check if decision was made
            if alert.alert_id not in self.pending_alerts:
                return  # Decision already processed
            
            if alert.status != "pending":
                # User made a decision
                cb = self._decision_callbacks.get(alert.alert_id)
                if cb:
                    cb(alert.alert_id, alert.status.upper())
                self.pending_alerts.pop(alert.alert_id, None)
                self._decision_callbacks.pop(alert.alert_id, None)
                return
            
            time.sleep(0.5)
        
        # Timeout reached - auto-kill high-confidence threats
        self.stats['timeouts'] += 1
        
        if alert.ml_confidence >= 0.85:
            logger.warning(
                f"[TIMEOUT] Auto-killing {alert.process_name} "
                f"(confidence={alert.ml_confidence:.2f})"
            )
            alert.status = "auto_killed_timeout"
            self.stats['auto_kills'] += 1
            cb = self._decision_callbacks.get(alert.alert_id)
            if cb:
                cb(alert.alert_id, "KILL")
        else:
            # Lower confidence - just log and ignore
            logger.warning(
                f"[TIMEOUT] Ignoring {alert.process_name} "
                f"(confidence={alert.ml_confidence:.2f} below auto-kill threshold)"
            )
            alert.status = "ignored_timeout"
            cb = self._decision_callbacks.get(alert.alert_id)
            if cb:
                cb(alert.alert_id, "IGNORE")
        self.pending_alerts.pop(alert.alert_id, None)
        self._decision_callbacks.pop(alert.alert_id, None)
    
    def process_user_decision(self, alert_id: str, decision: str) -> bool:
        """
        Process user decision from web dashboard
        Args:
            alert_id: Alert identifier
            decision: "KILL", "QUARANTINE", "WHITELIST", or "IGNORE"
        Returns:
            True if decision was processed, False if alert not found
        """
        if alert_id not in self.pending_alerts:
            logger.warning(f"[DECISION] Alert {alert_id} not found (already processed?)")
            return False
        
        alert = self.pending_alerts[alert_id]
        normalized = decision.upper()
        alert.status = normalized.lower()
        self.stats['decisions_made'] += 1
        
        logger.info(
            f"[OK] User decision: {normalized} for {alert.process_name} "
            f"(PID {alert.pid})"
        )

        # Execute callback immediately so action happens now.
        cb = self._decision_callbacks.get(alert_id)
        if cb:
            cb(alert_id, normalized)

        # Remove from pending
        self.pending_alerts.pop(alert_id, None)
        self._decision_callbacks.pop(alert_id, None)
        return True
    
    def get_pending_alerts(self) -> List[Dict[str, Any]]:
        """Get all pending alerts (for web dashboard)"""
        return [
            {
                "alert_id": alert.alert_id,
                "process": alert.process_name,
                "pid": alert.pid,
                "confidence": alert.ml_confidence,
                "threat_score": alert.threat_score,
                "threat_level": alert.threat_level,
                "indicators": alert.indicators,
                "timestamp": alert.timestamp,
                "status": alert.status
            }
            for alert in self.pending_alerts.values()
        ]
    
    def get_alert_by_id(self, alert_id: str) -> Optional[ThreatAlert]:
        """Get specific alert by ID"""
        return self.pending_alerts.get(alert_id)
    
    def clear_pending_alerts(self) -> int:
        """Clear all pending alerts (admin function)"""
        count = len(self.pending_alerts)
        self.pending_alerts.clear()
        self._decision_callbacks.clear()
        logger.info(f"[CLEAR] Cleared {count} pending alerts")
        return count
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get notification statistics"""
        return {
            **self.stats,
            'pending_alerts_count': len(self.pending_alerts),
            'toast_available': self.toaster is not None,
            'websocket_available': self.websocket_callback is not None
        }
