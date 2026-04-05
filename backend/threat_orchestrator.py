"""
backend/threat_orchestrator.py - NEW FILE

Integration orchestrator that connects:
monitor → behavioral_analyzer → detector → killswitch

This is the missing "glue code" that makes everything work together.
"""

import time
import logging
import psutil
import threading
from typing import Dict, Any, Optional, Callable, List
from collections import defaultdict

logger = logging.getLogger("orchestrator")


class ThreatOrchestrator:
    """
    Orchestrates threat detection pipeline:
    
    1. Receives events from monitor (file events, process events)
    2. Updates behavioral analyzer with events
    3. Periodically extracts features for active processes
    4. Runs ML prediction on features
    5. Routes threats to killswitch
    6. Broadcasts alerts to dashboard
    """
    
    def __init__(self, behavioral_analyzer, detector, killswitch, callback=None):
        """
        Initialize orchestrator
        
        Args:
            behavioral_analyzer: BehavioralAnalyzer instance
            detector: ThreatDetector instance
            killswitch: KillSwitch instance
            callback: Function to call with threat events for dashboard
        """
        self.behavioral_analyzer = behavioral_analyzer
        self.detector = detector
        self.killswitch = killswitch
        self.callback = callback
        
        # Track which PIDs have been analyzed
        self.analyzed_pids = set()
        self.last_analysis_time = {}
        
        # Analysis interval (don't re-analyze same PID too frequently)
        self.analysis_interval = 5.0  # seconds
        
        # Thread control
        self.running = False
        self.analysis_thread = None
        
        # Statistics
        self.stats = {
            'events_received': 0,
            'features_extracted': 0,
            'ml_analyses': 0,
            'threats_detected': 0,
            'processes_killed': 0,
            'alerts_sent': 0
        }
        
        logger.info("[ORCHESTRATOR] Initialized")
    
    def start(self):
        """Start background analysis thread"""
        if self.running:
            logger.warning("[ORCHESTRATOR] Already running")
            return
        
        self.running = True
        self.analysis_thread = threading.Thread(
            target=self._background_analysis_loop,
            daemon=True,
            name="ThreatOrchestrator"
        )
        self.analysis_thread.start()
        logger.info("[ORCHESTRATOR] Background analysis started")
    
    def stop(self):
        """Stop background analysis"""
        self.running = False
        if self.analysis_thread:
            self.analysis_thread.join(timeout=2.0)
        logger.info("[ORCHESTRATOR] Stopped")
    
    def ingest_event(self, event: Dict[str, Any]) -> None:
        """
        Receive event from monitor and update behavioral analyzer
        
        This is called by monitor for every file/process event
        
        Args:
            event: Event dict with keys: pid, event_type, path, entropy, etc.
        """
        if not event.get("valid", False):
            return
        
        self.stats['events_received'] += 1
        
        # Pass event to behavioral analyzer for feature tracking
        try:
            self.behavioral_analyzer.ingest_event(event)
            
            # Update process metrics if provided
            pid = event.get("pid")
            if pid and "cpu_percent" in event:
                self.behavioral_analyzer.update_process_metrics(
                    pid=pid,
                    cpu_percent=event.get("cpu_percent", 0.0),
                    memory_percent=event.get("memory_percent", 0.0),
                    threads=event.get("threads", 0),
                    network_connections=event.get("network_connections", 0)
                )
        except Exception as e:
            logger.error(f"[ORCHESTRATOR] Error ingesting event: {e}")
    
    def _background_analysis_loop(self):
        """Background thread that periodically analyzes processes"""
        logger.info("[ORCHESTRATOR] Analysis loop started")
        
        while self.running:
            try:
                self._analyze_active_processes()
                time.sleep(self.analysis_interval)
            except Exception as e:
                logger.exception(f"[ORCHESTRATOR] Error in analysis loop: {e}")
                time.sleep(1.0)
    
    def _analyze_active_processes(self):
        """Analyze all active processes for threats"""
        current_time = time.time()
        
        # Get list of processes with behavioral data
        with self.behavioral_analyzer.lock:
            active_pids = list(self.behavioral_analyzer.process_metrics.keys())
        
        for pid in active_pids:
            # Skip if analyzed too recently
            last_analyzed = self.last_analysis_time.get(pid, 0)
            if current_time - last_analyzed < self.analysis_interval:
                continue
            
            # Analyze this process
            try:
                self._analyze_single_process(pid)
                self.last_analysis_time[pid] = current_time
            except Exception as e:
                logger.error(f"[ORCHESTRATOR] Error analyzing PID {pid}: {e}")
    
    def _analyze_single_process(self, pid: int):
        """Analyze a single process for threats"""
        # Get process name
        try:
            proc = psutil.Process(pid)
            process_name = proc.name()
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            # Process died or can't access - cleanup
            with self.behavioral_analyzer.lock:
                if pid in self.behavioral_analyzer.process_metrics:
                    del self.behavioral_analyzer.process_metrics[pid]
            return
        
        # Run ML analysis
        result = self.detector.analyze_process(pid, process_name)
        
        if not result.get("valid", False):
            return
        
        self.stats['ml_analyses'] += 1
        
        ml_prediction = result.get("ml_prediction", {})
        decision = ml_prediction.get("decision", "SAFE")
        probability = ml_prediction.get("probability", 0.0)
        
        # Check if threat detected
        if decision in ["SUSPICIOUS", "RANSOMWARE"]:
            self.stats['threats_detected'] += 1
            self._handle_threat(result)
        
        logger.debug(
            f"[ORCHESTRATOR] PID {pid} ({process_name}): "
            f"{decision} (p={probability:.3f})"
        )
    
    def _handle_threat(self, result: Dict[str, Any]):
        """Handle detected threat"""
        pid = result.get("pid")
        process_name = result.get("process", "unknown")
        ml_prediction = result.get("ml_prediction", {})
        probability = ml_prediction.get("probability", 0.0)
        decision = ml_prediction.get("decision", "UNKNOWN")
        
        logger.warning(
            f"[ORCHESTRATOR] THREAT DETECTED: {process_name} (PID {pid}) "
            f"- Decision: {decision}, Probability: {probability:.3f}"
        )
        
        # Prepare event for killswitch
        threat_event = {
            "pid": pid,
            "process": process_name,
            "suspicion_score": result.get("suspicion_score", 0),
            "detection_mode": result.get("detection_mode", "SCORE_BASED"),
            "metadata": result.get("metadata", {})
        }
        
        # Send to killswitch
        try:
            ks_result = self.killswitch.evaluate_threat(threat_event)
            
            if ks_result.get("action_taken") == "terminated":
                self.stats['processes_killed'] += 1
                logger.critical(
                    f"[ORCHESTRATOR] Process killed: {process_name} (PID {pid})"
                )
        except Exception as e:
            logger.error(f"[ORCHESTRATOR] Killswitch error: {e}")
        
        # Broadcast alert to dashboard
        if self.callback:
            try:
                alert_data = {
                    "type": "threat",
                    "timestamp": time.time(),
                    "pid": pid,
                    "process": process_name,
                    "decision": decision,
                    "probability": probability,
                    "threat_level": ml_prediction.get("threat_level", "UNKNOWN"),
                    "features": result.get("features", {}),
                    "action_taken": ks_result.get("action_taken", "none")
                }
                self.callback(alert_data)
                self.stats['alerts_sent'] += 1
            except Exception as e:
                logger.error(f"[ORCHESTRATOR] Callback error: {e}")
    
    def analyze_process_now(self, pid: int) -> Optional[Dict[str, Any]]:
        """
        Manually trigger analysis of a specific process
        
        Args:
            pid: Process ID to analyze
            
        Returns:
            Analysis result or None
        """
        try:
            proc = psutil.Process(pid)
            process_name = proc.name()
            
            result = self.detector.analyze_process(pid, process_name)
            
            if result.get("valid", False):
                ml_prediction = result.get("ml_prediction", {})
                if ml_prediction.get("decision") in ["SUSPICIOUS", "RANSOMWARE"]:
                    self._handle_threat(result)
            
            return result
        except Exception as e:
            logger.error(f"[ORCHESTRATOR] Error analyzing PID {pid}: {e}")
            return None
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get orchestrator statistics"""
        return {
            **self.stats,
            'analyzed_pids': len(self.analyzed_pids),
            'active_pids_tracked': len(self.behavioral_analyzer.process_metrics),
            'detector_available': self.detector.is_available(),
            'running': self.running
        }
    
    def reset_statistics(self):
        """Reset statistics"""
        self.stats = {
            'events_received': 0,
            'features_extracted': 0,
            'ml_analyses': 0,
            'threats_detected': 0,
            'processes_killed': 0,
            'alerts_sent': 0
        }
        self.analyzed_pids.clear()
        self.last_analysis_time.clear()
        logger.info("[ORCHESTRATOR] Statistics reset")