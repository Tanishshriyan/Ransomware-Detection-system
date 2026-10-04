"""
backend/behavioral_analyzer.py - FIXED VERSION

PRODUCTION ML Feature Extractor - 85 Features
Comprehensive behavioral analysis with time-series tracking

FIXED ISSUES:
- Decay function now called periodically in cleanup()
- Proper memory management
- Fixed Dimension Mismatch (now provides 85 features)
"""

import time
import threading
import os
import math
from collections import defaultdict, deque
from typing import Dict, Any, Optional, Set, List, Tuple
from dataclasses import dataclass, field
import psutil
import logging
from ml_model.schema import MODEL_FEATURE_NAMES

logger = logging.getLogger("behavioral_analyzer")


@dataclass
class ProcessMetrics:
    """Time-series metrics for a single process"""
    cpu_history: deque = field(default_factory=lambda: deque(maxlen=20))
    memory_history: deque = field(default_factory=lambda: deque(maxlen=20))
    thread_history: deque = field(default_factory=lambda: deque(maxlen=20))
    network_history: deque = field(default_factory=lambda: deque(maxlen=20))
    
    # File operation tracking
    file_writes: int = 0
    file_reads: int = 0
    file_deletes: int = 0
    file_renames: int = 0
    file_modifications: int = 0
    
    # Timestamps for rate/burst detection
    write_timestamps: deque = field(default_factory=lambda: deque(maxlen=100))
    read_timestamps: deque = field(default_factory=lambda: deque(maxlen=100))
    delete_timestamps: deque = field(default_factory=lambda: deque(maxlen=100))
    rename_timestamps: deque = field(default_factory=lambda: deque(maxlen=100))
    modify_timestamps: deque = field(default_factory=lambda: deque(maxlen=100))
    
    # Entropy tracking
    entropy_values: deque = field(default_factory=lambda: deque(maxlen=100))
    
    # Extension tracking
    extensions_seen: Set[str] = field(default_factory=set)
    extension_changes: deque = field(default_factory=lambda: deque(maxlen=50))
    suspicious_extensions: Set[str] = field(default_factory=set)
    double_extensions: int = 0
    
    # Network tracking
    ports_seen: Set[int] = field(default_factory=set)
    suspicious_ports: Set[int] = field(default_factory=set)
    connection_intervals: deque = field(default_factory=lambda: deque(maxlen=20))
    last_connection_time: float = 0.0
    network_bytes_sent: int = 0
    network_bytes_recv: int = 0
    
    # Process context
    parent_name: Optional[str] = None
    parent_pid: Optional[int] = None
    cmdline: List[str] = field(default_factory=list)
    exe_path: Optional[str] = None
    
    # Advanced behavioral flags
    registry_modifications: int = 0
    shadow_copy_interactions: int = 0
    backup_deletions: int = 0
    privilege_escalations: int = 0
    process_injections: int = 0
    anti_analysis_indicators: int = 0
    persistence_mechanisms: int = 0
    
    # Timing
    first_seen: float = field(default_factory=time.time)
    last_seen: float = field(default_factory=time.time)
    create_time: float = 0.0
    
    # FIXED: Track last decay time
    last_decay_time: float = field(default_factory=time.time)


class BehavioralAnalyzer:
    """
    Production-grade feature extractor for 85-feature ML model
    Real-time behavioral analysis with comprehensive tracking
    
    FIXED: Memory leak prevention with periodic decay
    """
    
    WINDOW_SECONDS = 60  # 60-second analysis window
    DECAY_INTERVAL = 120  # Apply decay every 2 minutes
    MIN_ACTIVITY_EVENTS = 2  # Do not classify a process from resource metrics alone
    
    # Suspicious file extensions
    SUSPICIOUS_EXTENSIONS = {
        '.exe', '.dll', '.bat', '.cmd', '.ps1', '.vbs', '.js', '.jar',
        '.msi', '.scr', '.com', '.pif', '.hta', '.wsf', '.reg'
    }
    
    # Known safe extensions
    KNOWN_EXTENSIONS = {
        '.txt', '.doc', '.docx', '.pdf', '.jpg', '.jpeg', '.png', '.gif',
        '.mp3', '.mp4', '.avi', '.zip', '.rar', '.xlsx', '.pptx', '.csv'
    }
    
    # Suspicious ports
    SUSPICIOUS_PORTS = {22, 23, 135, 139, 445, 1433, 3306, 3389, 4444, 5555, 8080, 9999}
    
    # Suspicious parent processes
    SUSPICIOUS_PARENTS = {
        'powershell.exe', 'cmd.exe', 'wmic.exe', 'rundll32.exe',
        'mshta.exe', 'regsvr32.exe', 'wscript.exe', 'cscript.exe'
    }
    
    # Office applications
    OFFICE_APPS = {
        'winword.exe', 'excel.exe', 'powerpnt.exe', 'outlook.exe',
        'msaccess.exe', 'mspub.exe', 'visio.exe'
    }
    
    # Browsers
    BROWSERS = {
        'chrome.exe', 'firefox.exe', 'msedge.exe', 'iexplore.exe',
        'opera.exe', 'brave.exe', 'safari.exe'
    }
    
    # Script interpreters
    SCRIPT_INTERPRETERS = {
        'powershell.exe', 'python.exe', 'python3.exe', 'ruby.exe',
        'perl.exe', 'node.exe', 'cscript.exe', 'wscript.exe'
    }
    
    def __init__(self):
        self.total_events = 0
        self.process_metrics: Dict[int, ProcessMetrics] = {}
        self.lock = threading.Lock()
        logger.info("[ANALYZER] Production Behavioral Analyzer initialized (85 features)")
    
    def ingest_event(self, event: Dict[str, Any]) -> None:
        """Ingest file system or process event"""
        if not event.get("valid", False):
            return
        
        pid = event.get("pid")
        if pid is None or pid <= 0:
            logger.debug(f"[ANALYZER] Invalid PID: {pid}")
            return
        
        with self.lock:
            if pid not in self.process_metrics:
                self.process_metrics[pid] = ProcessMetrics()
            
            metrics = self.process_metrics[pid]
            now = time.time()
            metrics.last_seen = now
            self.total_events += 1
            
            event_type = event.get("event_type", "").upper()
            file_path = event.get("path", "")
            
            # Track file operations
            if event_type == "WRITE" or event_type == "CREATED":
                metrics.file_writes += 1
                metrics.write_timestamps.append(now)
                self._track_extension(metrics, file_path)
                
            elif event_type == "READ":
                metrics.file_reads += 1
                metrics.read_timestamps.append(now)
                
            elif event_type == "DELETE":
                metrics.file_deletes += 1
                metrics.delete_timestamps.append(now)
                self._detect_backup_deletion(metrics, file_path)
                
            elif event_type == "RENAME" or event_type == "MOVED":
                metrics.file_renames += 1
                metrics.rename_timestamps.append(now)
                old_path = event.get("old_path", "")
                self._track_extension_change(metrics, old_path, file_path)
                
            elif event_type == "MODIFIED":
                metrics.file_modifications += 1
                metrics.modify_timestamps.append(now)
            
            # Track entropy
            entropy = event.get("entropy")
            if isinstance(entropy, (int, float)) and entropy > 0:
                metrics.entropy_values.append(float(entropy))
            
            # Track advanced indicators from event metadata
            if event.get("registry_modified"):
                metrics.registry_modifications += 1
            if event.get("shadow_copy_interaction"):
                metrics.shadow_copy_interactions += 1
            if event.get("process_injection"):
                metrics.process_injections += 1
            if event.get("privilege_escalation"):
                metrics.privilege_escalations += 1
    
    def update_process_metrics(
        self, 
        pid: int, 
        cpu_percent: float = 0.0,
        memory_percent: float = 0.0,
        threads: int = 0,
        network_connections: int = 0
    ) -> None:
        """Update process CPU/memory/thread metrics"""
        with self.lock:
            if pid not in self.process_metrics:
                self.process_metrics[pid] = ProcessMetrics()
            
            metrics = self.process_metrics[pid]
            now = time.time()
            metrics.last_seen = now
            
            # Update histories
            metrics.cpu_history.append((now, float(cpu_percent)))
            metrics.memory_history.append((now, float(memory_percent)))
            metrics.thread_history.append((now, int(threads)))
            metrics.network_history.append((now, int(network_connections)))
    
    def update_process_context(
        self,
        pid: int,
        parent_name: Optional[str] = None,
        parent_pid: Optional[int] = None,
        exe_path: Optional[str] = None,
        cmdline: Optional[List[str]] = None
    ) -> None:
        """Update process context information"""
        with self.lock:
            if pid not in self.process_metrics:
                self.process_metrics[pid] = ProcessMetrics()
            
            metrics = self.process_metrics[pid]
            
            if parent_name:
                metrics.parent_name = parent_name.lower()
            if parent_pid:
                metrics.parent_pid = parent_pid
            if exe_path:
                metrics.exe_path = exe_path
                self._analyze_exe_path(metrics, exe_path)
            if cmdline:
                metrics.cmdline = cmdline
    
    def extract_features(self, pid: int) -> Optional[Dict[str, float]]:
        """
        Extract 85 features for ML model
        
        Returns:
            Dict with 85 features or None if insufficient data
        """
        with self.lock:
            if pid not in self.process_metrics:
                return None
            
            metrics = self.process_metrics[pid]
            now = time.time()
            uptime = max(0.1, now - metrics.first_seen)
            
            # Filter recent timestamps
            window_cutoff = now - self.WINDOW_SECONDS
            
            write_times = [t for t in metrics.write_timestamps if t > window_cutoff]
            read_times = [t for t in metrics.read_timestamps if t > window_cutoff]
            delete_times = [t for t in metrics.delete_timestamps if t > window_cutoff]
            rename_times = [t for t in metrics.rename_timestamps if t > window_cutoff]
            modify_times = [t for t in metrics.modify_timestamps if t > window_cutoff]

            # A process scan by itself is not evidence of ransomware.  The
            # previous implementation sent all-zero file/entropy vectors to
            # the model, which produced a moderate score for many ordinary
            # Windows services because that vector is outside the training
            # distribution.  Wait for real activity before making an ML claim.
            activity_events = (
                len(write_times)
                + len(read_times)
                + len(delete_times)
                + len(rename_times)
                + len(modify_times)
                + len(metrics.entropy_values)
            )
            if activity_events < self.MIN_ACTIVITY_EVENTS and not metrics.suspicious_ports:
                return None
            
            # CPU metrics
            cpu_values = [val for ts, val in metrics.cpu_history if ts > window_cutoff]
            cpu_mean = mean(cpu_values) if cpu_values else 0.0
            cpu_max = max(cpu_values) if cpu_values else 0.0
            cpu_min = min(cpu_values) if cpu_values else 0.0
            cpu_variance = variance(cpu_values) if len(cpu_values) > 1 else 0.0
            cpu_spike_count = sum(1 for v in cpu_values if v > 80.0)
            
            # Memory metrics
            mem_values = [val for ts, val in metrics.memory_history if ts > window_cutoff]
            mem_mean = mean(mem_values) if mem_values else 0.0
            mem_max = max(mem_values) if mem_values else 0.0
            mem_min = min(mem_values) if mem_values else 0.0
            mem_growth = (mem_max - mem_min) if (mem_max and mem_min) else 0.0
            mem_variance = variance(mem_values) if len(mem_values) > 1 else 0.0
            
            # Thread metrics
            thread_values = [val for ts, val in metrics.thread_history if ts > window_cutoff]
            threads_current = thread_values[-1] if thread_values else 0
            thread_spike_count = 0
            thread_variance = variance(thread_values) if len(thread_values) > 1 else 0.0
            
            # Entropy metrics
            entropy_vals = list(metrics.entropy_values)
            
            # Build 85-feature dictionary
            features = {
                # ============ CPU Metrics (5 features) ============
                "cpu_percent": float(cpu_mean),
                "cpu_percent_max": float(cpu_max),
                "cpu_percent_min": float(cpu_min),
                "cpu_sustained_count": float(cpu_spike_count),
                "cpu_variance": float(cpu_variance),
                
                # ============ Memory Metrics (5 features) ============
                "memory_percent": float(mem_mean),
                "memory_percent_max": float(mem_max),
                "memory_percent_min": float(mem_min),
                "memory_growth_rate": float(mem_growth),
                "memory_variance": float(mem_variance),
                
                # ============ Thread Metrics (3 features) ============
                "threads": float(threads_current),
                "thread_spike_count": float(thread_spike_count),
                "thread_variance": float(thread_variance),
                
                # ============ Process Timing (2 features) ============
                "uptime": float(uptime),
                "process_age_seconds": float(uptime),
                
                # ============ File Write Operations (6 features) ============
                "file_writes": float(len(write_times)),
                "file_write_rate": float(len(write_times) / self.WINDOW_SECONDS * 60.0),
                "file_write_burst_count": float(sum(1 for i in range(len(write_times)-1) 
                                                   if write_times[i+1] - write_times[i] < 0.5)),
                "file_write_variance": variance(write_times) if len(write_times) > 1 else 0.0,
                "sequential_write_count": float(metrics.file_writes),  # Simplified
                "random_write_count": 0.0,
                
                # ============ File Read Operations (4 features) ============
                "file_reads": float(len(read_times)),
                "file_read_rate": float(len(read_times) / self.WINDOW_SECONDS * 60.0),
                "file_read_write_ratio": float(len(read_times) / max(1, len(write_times))),
                "large_file_read_count": 0.0,  # Would need file size tracking
                
                # ============ File Delete Operations (4 features) ============
                "file_deletes": float(len(delete_times)),
                "file_delete_rate": float(len(delete_times) / self.WINDOW_SECONDS * 60.0),
                "file_delete_burst_count": float(sum(1 for i in range(len(delete_times)-1)
                                                    if delete_times[i+1] - delete_times[i] < 0.5)),
                "mass_delete_events": float(1 if len(delete_times) > 10 else 0),
                
                # ============ File Rename Operations (4 features) ============
                "file_renames": float(len(rename_times)),
                "file_rename_rate": float(len(rename_times) / self.WINDOW_SECONDS * 60.0),
                "extension_change_count": float(len(metrics.extension_changes)),
                "suspicious_rename_pattern": float(1 if len(metrics.extension_changes) > 5 else 0),
                
                # ============ File Modifications (3 features) ============
                "file_modifications": float(len(modify_times)),
                "modification_rate": float(len(modify_times) / self.WINDOW_SECONDS * 60.0),
                "modification_burst_count": float(sum(1 for i in range(len(modify_times)-1)
                                                     if modify_times[i+1] - modify_times[i] < 0.5)),
                
                # ============ Entropy Analysis (8 features) ============
                "entropy_mean": mean(entropy_vals) if entropy_vals else 0.0,
                "entropy_stddev": stddev(entropy_vals) if len(entropy_vals) > 1 else 0.0,
                "entropy_max": max(entropy_vals) if entropy_vals else 0.0,
                "entropy_min": min(entropy_vals) if entropy_vals else 0.0,
                "entropy_range": (max(entropy_vals) - min(entropy_vals)) if entropy_vals else 0.0,
                "entropy_variance": variance(entropy_vals) if len(entropy_vals) > 1 else 0.0,
                "entropy_change_rate": 0.0,  # Simplified
                "high_entropy_file_ratio": float(sum(1 for e in entropy_vals if e > 7.5) / max(1, len(entropy_vals))),
                
                # ============ File Operation Patterns (5 features) ============
                "rapid_file_ops_count": float(len(write_times) + len(delete_times) + len(rename_times)),
                "mass_file_change_events": float(1 if (len(write_times) + len(delete_times)) > 20 else 0),
                "read_write_delete_pattern": float(1 if (len(read_times) > 0 and len(write_times) > 0 and len(delete_times) > 0) else 0),
                "cascading_modification_pattern": float(1 if len(modify_times) > 10 else 0),
                "file_overwrite_count": float(metrics.file_modifications),
                
                # ============ Extension Analysis (4 features) ============
                "suspicious_extensions_count": float(len(metrics.suspicious_extensions)),
                "unknown_extension_count": float(len([e for e in metrics.extensions_seen 
                                                     if e not in self.KNOWN_EXTENSIONS and e not in self.SUSPICIOUS_EXTENSIONS])),
                "double_extension_count": float(metrics.double_extensions),
                "extension_entropy": self._calculate_extension_entropy(metrics.extensions_seen),
                
                # ============ Network Activity (6 features) ============
                "network_connections": float(metrics.network_history[-1][1] if metrics.network_history else 0),
                "network_connections_max": float(max([v for t, v in metrics.network_history], default=0)),
                "suspicious_port_count": float(len(metrics.suspicious_ports)),
                "c2_beacon_score": self._calculate_beacon_score(metrics.connection_intervals),
                "outbound_data_kb": float(metrics.network_bytes_sent / 1024.0),
                "data_exfiltration_score": self._calculate_exfiltration_score(metrics),
                
                # ============ Advanced Behavioral (8 features) ============
                "process_injection_attempts": float(metrics.process_injections),
                "registry_modification_count": float(metrics.registry_modifications),
                "shadow_copy_interaction": float(metrics.shadow_copy_interactions),
                "backup_deletion_attempts": float(metrics.backup_deletions),
                "privilege_escalation_attempts": float(metrics.privilege_escalations),
                "anti_analysis_indicators": float(metrics.anti_analysis_indicators),
                "persistence_mechanism_count": float(metrics.persistence_mechanisms),
                "lateral_movement_score": self._calculate_lateral_movement_score(metrics),
                
                # ============ Parent Process Context (4 features) ============
                "parent_suspicious": 1 if metrics.parent_name in self.SUSPICIOUS_PARENTS else 0,
                "parent_is_office": 1 if metrics.parent_name in self.OFFICE_APPS else 0,
                "parent_is_browser": 1 if metrics.parent_name in self.BROWSERS else 0,
                "spawned_by_script": 1 if metrics.parent_name in self.SCRIPT_INTERPRETERS else 0,
                
                # ============ Timing Patterns (4 features) ============
                "operation_time_variance": variance(write_times) if len(write_times) > 1 else 0.0,
                "inter_operation_delay_avg": float(sum(write_times[i+1] - write_times[i] 
                                                      for i in range(len(write_times)-1)) / max(1, len(write_times)-1)) if len(write_times) > 1 else 0.0,
                "burst_activity_score": float(min(1.0, len([t for t in write_times + delete_times + rename_times if now - t < 10]) / 30.0)),
                "idle_time_ratio": float(max(0.0, (now - metrics.last_seen) / max(1.0, uptime))) if uptime > 0 else 0.0,

                # ============ MISSING 10 FEATURES (Added for V3.0 Compliance) ============
                # These are required to match the scaler/model dimension (85)
                "io_read_bytes_rate": 0.0,
                "io_write_bytes_rate": 0.0,
                "page_faults_rate": 0.0,
                "context_switches_rate": 0.0,
                "num_handles": 0.0,
                "io_priority": 0.0,
                "working_set_size": 0.0,
                "private_bytes": 0.0,
                "directory_traversal_depth": 0.0,
                "unique_paths_touched": 0.0
            }
            
            return self._to_model_features(
                features=features,
                metrics=metrics,
                entropy_values=entropy_vals,
                write_times=write_times,
                read_times=read_times,
                delete_times=delete_times,
                rename_times=rename_times,
            )

    def _to_model_features(
        self,
        features: Dict[str, float],
        metrics: ProcessMetrics,
        entropy_values: List[float],
        write_times: List[float],
        read_times: List[float],
        delete_times: List[float],
        rename_times: List[float],
    ) -> Dict[str, float]:
        """Adapt live telemetry to the exact training schema.

        The live analyzer has richer operational names than the research
        dataset.  This explicit adapter makes every conversion visible and
        guarantees that the model receives the same ordered feature contract
        used during training.
        """

        operation_types = sum(
            int(bool(values))
            for values in (write_times, read_times, delete_times, rename_times)
        )
        entropy_mean = float(features.get("entropy_mean", 0.0))
        entropy_max = float(features.get("entropy_max", 0.0))
        entropy_min = float(features.get("entropy_min", 0.0))
        high_entropy_count = sum(1 for value in entropy_values if value > 7.5)
        low_entropy_count = sum(1 for value in entropy_values if value < 4.0)
        entropy_trend = (
            float(entropy_values[-1] - entropy_values[0])
            if len(entropy_values) > 1
            else 0.0
        )
        extension_count = len(metrics.extensions_seen)
        document_count = sum(
            1 for extension in metrics.extensions_seen if extension in self.KNOWN_EXTENSIONS
        )
        executable_count = sum(
            1
            for extension in metrics.extensions_seen
            if extension in self.SUSPICIOUS_EXTENSIONS
        )
        file_operation_total = len(write_times) + len(read_times) + len(delete_times) + len(rename_times)

        model_features = {
            # Process metrics
            "cpu_percent": features["cpu_percent"],
            "cpu_percent_max": features["cpu_percent_max"],
            "cpu_percent_min": features["cpu_percent_min"],
            "cpu_spike_count": features["cpu_sustained_count"],
            "cpu_sustained_count": features["cpu_sustained_count"],
            "memory_percent": features["memory_percent"],
            "memory_percent_max": features["memory_percent_max"],
            "memory_percent_growth": features["memory_growth_rate"],
            "threads": features["threads"],
            "thread_creation_rate": 0.0,
            "uptime": features["uptime"],
            "parent_risk": features["parent_suspicious"],
            "privilege_level": 0.0,
            "user_context": 0.0,
            "process_age": features["process_age_seconds"],
            # File operations
            "file_writes": features["file_writes"],
            "file_reads": features["file_reads"],
            "file_deletes": features["file_deletes"],
            "file_renames": features["file_renames"],
            "file_modifications": features["file_modifications"],
            "file_creates": features["file_writes"],
            "file_write_rate": features["file_write_rate"],
            "file_read_rate": features["file_read_rate"],
            "file_delete_rate": features["file_delete_rate"],
            "file_rename_rate": features["file_rename_rate"],
            "rapid_file_ops_count": features["rapid_file_ops_count"],
            "mass_file_change_events": features["mass_file_change_events"],
            "sequential_file_ops": min(1.0, features["rapid_file_ops_count"] / 100.0),
            "file_size_changes": features["file_modifications"],
            "large_file_writes": 0.0,
            "small_file_writes": 0.0,
            "file_operation_diversity": operation_types / 4.0,
            "file_access_pattern": float(features["read_write_delete_pattern"]),
            "file_overwrite_count": features["file_overwrite_count"],
            "unique_files_accessed": float(file_operation_total),
            # Entropy
            "entropy_mean": entropy_mean,
            "entropy_variance": features["entropy_variance"],
            "entropy_max": entropy_max,
            "entropy_min": entropy_min,
            "entropy_spike_count": float(high_entropy_count),
            "high_entropy_file_ratio": features["high_entropy_file_ratio"],
            "entropy_change_rate": abs(entropy_trend),
            "entropy_stddev": features["entropy_stddev"],
            "entropy_range": features["entropy_range"],
            "low_entropy_count": float(low_entropy_count),
            "median_entropy": entropy_mean,
            "entropy_trend": entropy_trend,
            # Extensions
            "extension_changes": float(len(metrics.extension_changes)),
            "suspicious_extensions_count": features["suspicious_extensions_count"],
            "unique_extensions": float(extension_count),
            "extension_diversity": features["extension_entropy"],
            "ransomware_extensions": features["suspicious_extensions_count"],
            "document_extensions": float(document_count),
            "executable_extensions": float(executable_count),
            "extension_change_rate": float(len(metrics.extension_changes) / self.WINDOW_SECONDS * 60.0),
            # Network
            "network_connections": features["network_connections"],
            "suspicious_port_connections": features["suspicious_port_count"],
            "outbound_data_kb": features["outbound_data_kb"],
            "inbound_data_kb": float(metrics.network_bytes_recv / 1024.0),
            "c2_beacon_pattern": features["c2_beacon_score"],
            "connection_frequency": features["network_connections"] / self.WINDOW_SECONDS * 60.0,
            "unique_ip_connections": features["network_connections_max"],
            "dns_lookups": 0.0,
            "http_connections": 0.0,
            "tls_connections": 0.0,
            # Registry and system behavior
            "registry_modifications": features["registry_modification_count"],
            "startup_key_changes": 0.0,
            "security_setting_changes": 0.0,
            "registry_deletes": 0.0,
            "registry_creates": 0.0,
            "persistence_mechanisms": features["persistence_mechanism_count"],
            "run_key_adds": 0.0,
            "service_installs": 0.0,
            # Advanced patterns
            "process_injection_attempts": features["process_injection_attempts"],
            "dll_injections": 0.0,
            "code_hollowing": 0.0,
            "shadow_copy_deletes": features["shadow_copy_interaction"],
            "backup_deletions": features["backup_deletion_attempts"],
            "volume_shadow_disables": features["shadow_copy_interaction"],
            "recovery_mode_disables": 0.0,
            # Behavioral patterns
            "read_write_delete_pattern": features["read_write_delete_pattern"],
            "encryption_signature": float(features["high_entropy_file_ratio"] >= 0.7),
            "mass_enumeration": float(features["mass_file_change_events"] > 0),
            "lateral_movement": features["lateral_movement_score"],
            "credential_access": 0.0,
        }

        return {name: float(model_features.get(name, 0.0)) for name in MODEL_FEATURE_NAMES}
    
    # Helper methods (same as before)
    def _track_extension(self, metrics: ProcessMetrics, file_path: str) -> None:
        """Track file extension usage"""
        if not file_path or '.' not in file_path:
            return
        
        ext = os.path.splitext(file_path)[1].lower()
        if ext:
            metrics.extensions_seen.add(ext)
            if ext in self.SUSPICIOUS_EXTENSIONS:
                metrics.suspicious_extensions.add(ext)
            
            basename = os.path.basename(file_path)
            if basename.count('.') >= 2:
                metrics.double_extensions += 1
    
    def _track_extension_change(self, metrics: ProcessMetrics, old_path: str, new_path: str) -> None:
        """Track file extension changes during rename"""
        if not old_path or not new_path:
            return
        
        old_ext = os.path.splitext(old_path)[1].lower()
        new_ext = os.path.splitext(new_path)[1].lower()
        
        if old_ext and new_ext and old_ext != new_ext:
            metrics.extension_changes.append((old_ext, new_ext, time.time()))
    
    def _detect_backup_deletion(self, metrics: ProcessMetrics, file_path: str) -> None:
        """Detect deletion of backup files"""
        if not file_path:
            return
        
        backup_indicators = ['.bak', '.backup', 'vssadmin', 'shadow', 'wbadmin']
        file_lower = file_path.lower()
        
        if any(indicator in file_lower for indicator in backup_indicators):
            metrics.backup_deletions += 1
    
    def _analyze_exe_path(self, metrics: ProcessMetrics, exe_path: str) -> None:
        """Analyze executable path for suspicious indicators"""
        if not exe_path:
            return
        
        path_lower = exe_path.lower()
        suspicious_paths = ['temp', 'appdata\\local\\temp', 'downloads', 'desktop', 'public']
        
        if any(path in path_lower for path in suspicious_paths):
            metrics.anti_analysis_indicators += 1
    
    def _calculate_extension_entropy(self, extensions: Set[str]) -> float:
        """Calculate Shannon entropy of file extensions"""
        if not extensions:
            return 0.0
        return float(min(1.0, len(extensions) / 10.0))
    
    def _calculate_beacon_score(self, intervals: deque) -> float:
        """Calculate C2 beacon score based on connection timing regularity"""
        if len(intervals) < 5:
            return 0.0
        
        interval_list = list(intervals)
        avg_interval = sum(interval_list) / len(interval_list)
        
        deviations = [abs(interval - avg_interval) for interval in interval_list]
        avg_deviation = sum(deviations) / len(deviations)
        
        if avg_interval > 0 and avg_deviation / avg_interval < 0.2:
            return 0.8
        elif avg_deviation / avg_interval < 0.4:
            return 0.5
        else:
            return 0.0
    
    def _calculate_exfiltration_score(self, metrics: ProcessMetrics) -> float:
        """Calculate data exfiltration risk score"""
        score = 0.0
        
        if metrics.network_bytes_sent > 10 * 1024 * 1024:
            score += 0.4
        
        if len(metrics.suspicious_ports) > 0:
            score += 0.3
        
        if len(metrics.network_history) > 0 and max([v for t, v in metrics.network_history], default=0) > 5:
            score += 0.3
        
        return min(1.0, score)
    
    def _calculate_lateral_movement_score(self, metrics: ProcessMetrics) -> float:
        """Calculate lateral movement risk score"""
        score = 0.0
        
        if 445 in metrics.ports_seen or 3389 in metrics.ports_seen:
            score += 0.5
        
        if metrics.parent_name in self.SUSPICIOUS_PARENTS and len(metrics.network_history) > 0:
            score += 0.3
        
        if metrics.process_injections > 0:
            score += 0.2
        
        return min(1.0, score)
    
    def _apply_decay(self, metrics: ProcessMetrics) -> None:
        """FIXED: Apply decay to counters to prevent unbounded growth"""
        decay_factor = 0.7
        
        metrics.file_writes = int(metrics.file_writes * decay_factor)
        metrics.file_reads = int(metrics.file_reads * decay_factor)
        metrics.file_deletes = int(metrics.file_deletes * decay_factor)
        metrics.file_renames = int(metrics.file_renames * decay_factor)
        metrics.file_modifications = int(metrics.file_modifications * decay_factor)
        
        # Update last decay time
        metrics.last_decay_time = time.time()
    
    def cleanup(self) -> int:
        """
        FIXED: Remove stale process metrics AND apply decay
        """
        now = time.time()
        with self.lock:
            stale_pids = []
            
            for pid, metrics in self.process_metrics.items():
                # Remove if stale
                if now - metrics.last_seen > self.WINDOW_SECONDS * 2:
                    stale_pids.append(pid)
                # Apply decay if needed
                elif now - metrics.last_decay_time > self.DECAY_INTERVAL:
                    self._apply_decay(metrics)
            
            for pid in stale_pids:
                del self.process_metrics[pid]
            
            if stale_pids:
                logger.debug(f"[ANALYZER] Cleaned up {len(stale_pids)} stale processes")
            
            return len(stale_pids)
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get analyzer statistics"""
        now = time.time()
        with self.lock:
            active_pids = len(self.process_metrics)
            valid_windows = sum(
                1 for metrics in self.process_metrics.values()
                if (now - metrics.last_seen) <= self.WINDOW_SECONDS
            )
            
            total_file_ops = sum(
                metrics.file_writes + metrics.file_reads + 
                metrics.file_deletes + metrics.file_renames
                for metrics in self.process_metrics.values()
            )
            
            return {
                "events_ingested": self.total_events,
                "active_pids": active_pids,
                "valid_feature_windows": valid_windows,
                "total_file_operations": total_file_ops,
                "window_seconds": self.WINDOW_SECONDS
            }
    
    def reset(self) -> None:
        """Reset all statistics"""
        with self.lock:
            self.total_events = 0
            self.process_metrics.clear()
            logger.info("[ANALYZER] Statistics reset")


# Helper functions
def mean(values: List[float]) -> float:
    """Calculate mean"""
    return sum(values) / len(values) if values else 0.0


def variance(values: List[float]) -> float:
    """Calculate variance"""
    if len(values) < 2:
        return 0.0
    m = mean(values)
    return sum((x - m) ** 2 for x in values) / len(values)


def stddev(values: List[float]) -> float:
    """Calculate standard deviation"""
    return math.sqrt(variance(values))
