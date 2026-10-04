"""
==============================================================================
RansomGuard - Advanced Threat Detection Engine v3.0
==============================================================================

Ransomware detection with behavioral analysis, machine learning
heuristics, and real-time monitoring.

Key Features:
- Process baseline establishment and deviation detection
- File system entropy analysis with statistical modeling
- Network behavior monitoring and C2 communication detection
- Memory scanning for encryption library signatures
- Multi-stage threat scoring with confidence intervals
- Behavior-based suspicious activity detection

Author: RansomGuard Security Team
License: MIT
==============================================================================
"""

import os
import sys
import time
import json
import psutil
import hashlib
import threading
import queue
import sqlite3
import tempfile
import platform
from datetime import datetime, timedelta
from collections import defaultdict, deque, Counter
from typing import Dict, List, Optional, Set, Tuple, Any, Callable
from pathlib import Path
from dataclasses import dataclass, field, asdict
import math
import re
from backend.behavioral_analyzer import BehavioralAnalyzer
from backend.detector import ThreatDetector
from backend.notification_manager import NotificationManager
from backend.threat_manager import ThreatManager
from utils.resource_path import app_root, runtime_path
import logging
logger = logging.getLogger(__name__)
from typing import Dict, List, Optional, Set, Tuple, Any, Callable, TYPE_CHECKING
if TYPE_CHECKING:
    from watchdog.observers import Observer as ObserverType
else:
    ObserverType = Any

try:
    from watchdog.observers import Observer
    from watchdog.events import FileSystemEventHandler, FileSystemEvent
    WATCHDOG_AVAILABLE = True
except ImportError:
    WATCHDOG_AVAILABLE = False
    logger.warning("[WATCHDOG] Not available - file monitoring disabled")


# ==============================================================================
# CONFIGURATION & CONSTANTS
# ==============================================================================

class ThreatConfig:
    """Centralized configuration for threat detection parameters"""
    
    # Process Monitoring
    BASELINE_COLLECTION_TIME = 120  # seconds to establish baseline
    PROCESS_SCAN_INTERVAL = 2.0  # seconds between process scans
    ANOMALY_THRESHOLD = 0.75  # deviation from baseline
    
    # CPU & Memory Thresholds
    CPU_SPIKE_THRESHOLD = 85.0
    MEMORY_SPIKE_THRESHOLD = 70.0
    SUSTAINED_HIGH_CPU_DURATION = 5  # seconds
    
    # File System Monitoring
    ENTROPY_THRESHOLD = 7.8  # Shannon entropy for encrypted files
    RAPID_FILE_OPERATIONS = 10  # operations per 10 seconds
    MASS_FILE_CHANGE_THRESHOLD = 5  # files changed in short period
    FILE_EXTENSION_CHANGE_THRESHOLD = 5  # suspicious renames
    
    # Network Monitoring
    SUSPICIOUS_PORT_CONNECTIONS = {22, 445, 3389, 4444, 5555, 8080, 9999}
    HIGH_NETWORK_UPLOAD_RATE = 10 * 1024 * 1024  # 10 MB/s
    C2_BEACON_PATTERN_THRESHOLD = 5  # regular intervals detected
    
    # Scoring - INCREASED THRESHOLDS TO REDUCE FALSE POSITIVES
    MIN_THREAT_SCORE = 75  # report events above this - INCREASED FROM 60
    CRITICAL_THREAT_SCORE = 85  # auto-kill at/above this - INCREASED FROM 60
    CONFIDENCE_THRESHOLD = 0.80  # minimum confidence for actions - INCREASED FROM 0.70


# Known System Processes (Windows, macOS, Linux)
SYSTEM_PROCESSES = {
    # Windows Core
    'system', 'system idle process', 'registry', 'smss.exe', 'csrss.exe',
    'wininit.exe', 'services.exe', 'lsass.exe', 'lsm.exe', 'svchost.exe',
    'winlogon.exe', 'dwm.exe', 'explorer.exe', 'taskmgr.exe', 'taskhost.exe',
    'taskhostw.exe', 'conhost.exe', 'fontdrvhost.exe', 'sihost.exe',
    'runtimebroker.exe', 'dllhost.exe', 'searchindexer.exe', 'spoolsv.exe',
    'wudfhost.exe', 'msdtc.exe', 'audiodg.exe', 'dashost.exe','chrome.exe',
    'powershell.exe', 'cmd.exe', 'notepad.exe', 'mspaint.exe', 'calc.exe',
    'winword.exe', 'excel.exe', 'powerpnt.exe', 'outlook.exe', 'teams.exe',
    'slack.exe', 'zoom.exe', 'discord.exe', 'spotify.exe', 'steam.exe',
    'epicgameslauncher.exe', 'uplay.exe', 'origin.exe', 'battlenet.exe',
    'code.exe', 'pycharm.exe', 'webstorm.exe', 'intellij.exe', 'eclipse.exe',
    'visualstudio.exe', 'devenv.exe', 'msbuild.exe', 'dotnet.exe', 'node.exe',
    'npm.cmd', 'yarn.cmd', 'git.exe', 'tortoiseproc.exe', 'svn.exe',
    'firefox.exe', 'msedge.exe', 'opera.exe', 'brave.exe', 'vivaldi.exe',
    'thunderbird.exe', 'foxitreader.exe', 'adobereader.exe', 'acrobat.exe',
    'photoshop.exe', 'illustrator.exe', 'premiere.exe', 'aftereffects.exe',
    'lightroom.exe', 'audacity.exe', 'vlc.exe', 'mpc-hc.exe', 'potplayer.exe',
    'winrar.exe', '7z.exe', 'peazip.exe', 'everything.exe', 'totalcommander.exe',
    'doublecmd.exe', 'far.exe', 'conemu.exe', 'hyper.exe', 'windowsterminal.exe',
    'wsl.exe', 'vmware.exe', 'virtualbox.exe', 'hyperv.exe', 'docker.exe',
    'kubectl.exe', 'minikube.exe', 'terraform.exe', 'aws.exe', 'az.exe',
    'gcloud.exe', 'kubectl.exe', 'helm.exe', 'istioctl.exe', 'argocd.exe',
    
    # Windows Defender & Security
    'msmpeng.exe', 'nissrv.exe', 'securityhealthservice.exe',
    'antimalware service executable', 'windows defender',
    'securitycenter.exe', 'wscsvc.exe', 'windefend.exe',
    
    # Windows Services
    'sppsvc.exe', 'wuauserv.exe', 'bits.exe', 'cryptsvc.exe',
    'dhcpsvc.exe', 'dnscache.exe', 'eventlog.exe', 'lanmanserver.exe',
    'lanmanworkstation.exe', 'netlogon.exe', 'ntds.exe', 'rpcss.exe',
    'samss.exe', 'sens.exe', 'termsvcs.exe', 'trustedinstaller.exe',
    'w32time.exe', 'winmgmt.exe', 'wlansvc.exe', 'wsearch.exe',
    
    # Development Tools
    'python', 'python3', 'python.exe', 'python3.exe', 'pip.exe', 'conda.exe',
    'jupyter.exe', 'ipython.exe', 'vscode.exe', 'atom.exe', 'sublime_text.exe',
    'notepad++.exe', 'vim.exe', 'emacs.exe', 'nano.exe', 'vi.exe',
    
    # Browsers and Web Tools
    'chrome', 'firefox', 'edge', 'opera', 'brave', 'vivaldi', 'safari',
    'webkitwebprocess.exe', 'webhelper.exe', 'browser_broker.exe',
    
    # Office Applications
    'winword', 'excel', 'powerpnt', 'outlook', 'onenote', 'access',
    'publisher', 'visio', 'project', 'lync', 'skype', 'teams',
    
    # Media Applications
    'vlc', 'mpc-hc', 'potplayer', 'wmplayer', 'groove', 'itunes',
    'spotify', 'audacity', 'obs', 'streamlabs', 'discord', 'slack',
    'zoom', 'webex', 'gotomeeting', 'skype', 'microsoftedgecp.exe',
    
    # System Utilities
    'taskmgr', 'resmon', 'perfmon', 'eventvwr', 'services', 'compmgmt',
    'devmgmt', 'diskmgmt', 'compmgmtlauncher.exe', 'sdclt.exe',
    'control.exe', 'rundll32.exe', 'regedit.exe', 'msconfig.exe',
    'msinfo32.exe', 'dxdiag.exe', 'cleanmgr.exe', 'defrag.exe',
    
    # macOS Core
    'kernel_task', 'launchd', 'syslogd', 'kextd', 'notifyd', 'securityd',
    'distnoted', 'cfprefsd', 'loginwindow', 'systemuiserver', 'finder',
    'dock', 'windowserver', 'coreaudiod', 'airplayuiagent',
    
    # Linux Core
    'systemd', 'init', 'kthreadd', 'ksoftirqd', 'kworker', 'kswapd',
    'khugepaged', 'bash', 'sh', 'dbus-daemon', 'networkmanager',
    'pulseaudio', 'gnome-shell', 'xorg', 'gdm', 'lightdm',
    
    # Common Services
    'python', 'python3', 'node', 'java', 'chrome', 'firefox', 'edge',
    'code', 'slack', 'teams', 'zoom', 'spotify', 'steam'
}

# Ransomware Indicators
RANSOMWARE_INDICATORS = {
    "keywords": {
        "high": [
            "ransom", "bitcoin", "btc", "payment", "wallet",
            "recover files", "files encrypted", "your files"
        ],
        "medium": [
            "decrypt", "decryptor", "restore", "cipher",
            "private key", "public key"
        ],
        "low": [
            "important", "attention", "warning", "instructions"
        ]
    },

    "extensions": {
        "high": [
            ".locky", ".wannacry", ".wcry", ".wncry",
            ".cryptolocker", ".cerber", ".petya", ".ryuk",
            ".maze", ".revil", ".conti", ".lockbit",
            ".blackcat", ".alphv", ".hive", ".darkside"
        ],
        "medium": [
            ".encrypted", ".locked", ".crypt", ".crypted",
            ".vault", ".ecc", ".exx", ".ezz", ".micro"
        ],
        "low": [
            ".xyz", ".zzz", ".aaa", ".abc", ".ccc", ".ttt"
        ]
    },

    "processes": [
        "wannacry", "petya", "notpetya", "ryuk",
        "maze", "revil", "sodinokibi", "conti",
        "lockbit", "blackcat", "alphv", "hive",
        "darkside", "blackmatter", "cl0p"
    ],

    "file_patterns": [
        r"README.*\.(txt|html)$",
        r"DECRYPT.*\.(txt|html)$",
        r"HOW.*TO.*DECRYPT",
        r"YOUR.*FILES.*ENCRYPTED",
        r"RECOVER.*FILES",
        r"RESTORE.*FILES",
        r".*-INSTRUCTION.*",
        r".*-README.*",
        r".*-DECRYPT.*",
        r".*-HELP.*"
    ]
}


# ==============================================================================
# DATA MODELS
# ==============================================================================

@dataclass
class ProcessSnapshot:
    """Snapshot of process state at a point in time"""
    pid: int
    name: str
    exe: Optional[str]
    cmdline: List[str]
    cpu_percent: float
    memory_percent: float
    num_threads: int
    create_time: float
    parent_pid: Optional[int]
    username: Optional[str]
    status: str
    connections: List[Tuple[str, int]] = field(default_factory=list)
    open_files: List[str] = field(default_factory=list)
    timestamp: float = field(default_factory=time.time)


@dataclass
class ProcessBaseline:
    """Established baseline behavior for a process"""
    name: str
    avg_cpu: float = 0.0
    avg_memory: float = 0.0
    avg_threads: int = 0
    typical_connections: Set[Tuple[str, int]] = field(default_factory=set)
    typical_files: Set[str] = field(default_factory=set)
    first_seen: float = field(default_factory=time.time)
    sample_count: int = 0
    is_system: bool = False
    is_trusted: bool = False


@dataclass
class ThreatEvent:
    """Structured threat event"""
    event_id: str
    timestamp: float
    event_type: str  # 'process', 'file', 'network', 'system'
    threat_level: str  # 'low', 'medium', 'high', 'critical'
    confidence: float  # 0.0 - 1.0
    suspicion_score: int  # 0-100
    
    # Process info
    process: str
    pid: Optional[int] = None
    
    # File info
    file_path: Optional[str] = None
    operation: Optional[str] = None
    
    # Additional context
    indicators: List[str] = field(default_factory=list)
    entropy: Optional[float] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization"""
        data = asdict(self)
        data['indicators'] = list(data['indicators'])
        return data


# ==============================================================================
# UTILITY FUNCTIONS
# ==============================================================================

def calculate_entropy(data: bytes) -> float:
    """Calculate Shannon entropy of data"""
    if not data:
        return 0.0
    
    counter = Counter(data)
    length = len(data)
    entropy = 0.0
    
    for count in counter.values():
        probability = count / length
        if probability > 0:
            entropy -= probability * math.log2(probability)
    
    return entropy


def calculate_file_hash(filepath: str, algorithm: str = 'sha256') -> Optional[str]:
    """Calculate cryptographic hash of file"""
    try:
        hash_obj = hashlib.new(algorithm)
        with open(filepath, 'rb') as f:
            for chunk in iter(lambda: f.read(65536), b''):
                hash_obj.update(chunk)
        return hash_obj.hexdigest()
    except Exception:
        return None


def is_ransomware_extension(filename: str) -> Tuple[bool, str]:
    """Check if filename has ransomware extension"""
    lower = filename.lower()
    
    # RANSOMWARE_INDICATORS['extensions'] is a dict: {high:[...], medium:[...], low:[...]}
    for ext_list in RANSOMWARE_INDICATORS.get('extensions', {}).values():
        for ext in ext_list:
            if lower.endswith(ext.lower()):
                return True, f"ransomware_ext:{ext}"
    
    # Check for double extensions (e.g., document.pdf.exe)
    parts = lower.split('.')
    if len(parts) >= 3:
        return True, "double_extension"
    
    return False, ""


def is_suspicious_filename(filename: str) -> Tuple[bool, List[str]]:
    """Analyze filename for suspicious patterns"""
    indicators = []
    lower = filename.lower()
    
    # Flatten nested dict structure  
    all_keywords = []
    for level_keywords in RANSOMWARE_INDICATORS['keywords'].values():
        all_keywords.extend(level_keywords)
    
    # Check keywords
    for keyword in all_keywords:
        if keyword in lower:
            indicators.append(f"keyword:{keyword}")
    
    # Check patterns
    for pattern in RANSOMWARE_INDICATORS['file_patterns']:
        if re.search(pattern, filename, re.IGNORECASE):
            indicators.append(f"pattern:{pattern[:20]}")
    
    # Check for ransom note patterns
    if any(x in lower for x in ['readme', 'decrypt', 'recover', 'how_to']):
        if any(lower.endswith(x) for x in ['.txt', '.html', '.hta']):
            indicators.append("ransom_note_pattern")
    
    return len(indicators) > 0, indicators


def is_system_process(process_name: str) -> bool:
    """Check if process is a known system process"""
    if not process_name:
        return False
    
    name_lower = process_name.lower()
    
    # Direct match
    if name_lower in SYSTEM_PROCESSES:
        return True
    
    # Remove .exe suffix and try again
    if name_lower.endswith('.exe'):
        base_name = name_lower[:-4]
        if base_name in SYSTEM_PROCESSES:
            return True
    
    # Check for Windows system paths
    if 'windows\\system32' in name_lower or 'windows\\syswow64' in name_lower:
        return True
    
    return False


def generate_event_id() -> str:
    """Generate unique event ID"""
    return f"{int(time.time() * 1000)}_{os.urandom(4).hex()}"


# ==============================================================================
# PROCESS INTELLIGENCE ENGINE
# ==============================================================================

class ProcessIntelligence:
    """Advanced process monitoring and anomaly detection"""
    
    def __init__(self):
        self.active_processes = {}
        self._active_processes: Dict[int, str] = {}

        self.baselines: Dict[str, ProcessBaseline] = {}
        self.process_history: Dict[int, List[ProcessSnapshot]] = defaultdict(list)
        self.new_processes: Set[int] = set()
        self.suspicious_processes: Dict[int, List[str]] = defaultdict(list)
        self.baseline_established = False
        self.baseline_start_time = time.time()
        
        # Statistics
        self.stats = {
            'total_processes_seen': 0,
            'new_processes': 0,
            'anomalous_processes': 0,
            'system_processes': 0,
            'third_party_processes': 0
        }
        
        print(" Process Intelligence Engine initialized")

    
    
    def capture_snapshot(self, proc: psutil.Process) -> Optional[ProcessSnapshot]:
        """Capture detailed process snapshot"""
        try:
            info = proc.as_dict([
                'pid', 'name', 'exe', 'cmdline', 'cpu_percent',
                'memory_percent', 'num_threads', 'create_time',
                'ppid', 'username', 'status'
            ])
            
            connections = []
            try:
                for conn in proc.connections():
                    if conn.raddr:
                        connections.append((conn.raddr.ip, conn.raddr.port))
            except (psutil.AccessDenied, psutil.NoSuchProcess):
                pass
            
            open_files = []
            try:
                for f in proc.open_files():
                    open_files.append(f.path)
            except (psutil.AccessDenied, psutil.NoSuchProcess):
                pass
            
            return ProcessSnapshot(
                pid=info['pid'],
                name=info['name'] or 'unknown',
                exe=info['exe'],
                cmdline=info['cmdline'] or [],
                cpu_percent=info['cpu_percent'] or 0.0,
                memory_percent=info['memory_percent'] or 0.0,
                num_threads=info['num_threads'] or 0,
                create_time=info['create_time'] or time.time(),
                parent_pid=info['ppid'],
                username=info['username'],
                status=info['status'] or 'unknown',
                connections=connections,
                open_files=open_files[:50]  # Limit to prevent memory issues
            )
        
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            return None
    
    def update_baseline(self, snapshot: ProcessSnapshot) -> None:
        """Update process baseline with new snapshot"""
        name = snapshot.name
        
        if name not in self.baselines:
            self.baselines[name] = ProcessBaseline(
                name=name,
                is_system=is_system_process(name),
                is_trusted=is_system_process(name)
            )
            self.stats['total_processes_seen'] += 1
        
        baseline = self.baselines[name]
        baseline.sample_count += 1
        
        # Running average
        n = baseline.sample_count
        baseline.avg_cpu = ((n - 1) * baseline.avg_cpu + snapshot.cpu_percent) / n
        baseline.avg_memory = ((n - 1) * baseline.avg_memory + snapshot.memory_percent) / n
        baseline.avg_threads = int(((n - 1) * baseline.avg_threads + snapshot.num_threads) / n)
        
        # Update typical patterns
        baseline.typical_connections.update(snapshot.connections)
        baseline.typical_files.update(snapshot.open_files[:10])  # Top 10 files
    
    def update_behavioral_analyzer(self, snapshot: ProcessSnapshot, behavioral_analyzer: Any) -> None:
        """Update behavioral analyzer with process metrics"""
        try:
            # Get network info
            network_count = len(snapshot.connections)
            ports = {conn[1] for conn in snapshot.connections if len(conn) > 1}
            
            # Get parent info
            parent_pid = snapshot.parent_pid
            parent_name = None
            if parent_pid:
                try:
                    parent_proc = psutil.Process(parent_pid)
                    parent_name = parent_proc.name()
                except Exception as e:
                    logger.debug(f"Failed to get parent process name for PID {parent_pid}: {e}")
            
            # Get network I/O
            bytes_sent = 0
            bytes_recv = 0
            try:
                proc = psutil.Process(snapshot.pid)
                io_counters = proc.io_counters()
                bytes_sent = io_counters.write_bytes
                bytes_recv = io_counters.read_bytes
            except Exception as e:
                logger.debug(f"Failed to get I/O counters for PID {snapshot.pid}: {e}")
            
            # Update behavioral analyzer
            behavioral_analyzer.update_process_metrics(
                pid=snapshot.pid,
                cpu=snapshot.cpu_percent,
                memory=snapshot.memory_percent,
                threads=snapshot.num_threads,
                network_connections=network_count,
                parent_pid=parent_pid,
                parent_name=parent_name,
                cmdline=snapshot.cmdline,
                exe_path=snapshot.exe,
                network_sent=bytes_sent,
                network_recv=bytes_recv
            )
            
            # Update network ports
            if ports:
                behavioral_analyzer.update_network_ports(snapshot.pid, ports)
                
        except Exception as e:
            logger.debug(f"Failed to update behavioral analyzer for PID {snapshot.pid}: {e}")
    
    def detect_anomalies(self, snapshot: ProcessSnapshot) -> Tuple[int, List[str], float]:
        """
        Detect anomalous behavior
        Returns: (suspicion_score, indicators, confidence)
        """
        indicators = []
        score = 0
        confidence = 0.0
        
        # Check if process is new
        if snapshot.pid not in self.process_history:
            self.new_processes.add(snapshot.pid)
            self.stats['new_processes'] += 1
            indicators.append("new_process")
            score += 5  # REDUCED FROM 10
        
        # Check if system or third-party
        is_sys = is_system_process(snapshot.name)
        if is_sys:
            self.stats['system_processes'] += 1
        else:
            self.stats['third_party_processes'] += 1
            # REDUCED: third-party processes get fewer points
            indicators.append("third_party_process")
            score += 2  # REDUCED FROM 5
        
        # Check for ransomware process names
        name_lower = snapshot.name.lower()
        for ransom_name in RANSOMWARE_INDICATORS['processes']:
            if ransom_name in name_lower:
                indicators.append(f"ransomware_name:{ransom_name}")
                score += 70
                confidence = 0.95
        
        # Check for suspicious keywords in process name
        for keyword in RANSOMWARE_INDICATORS['keywords']:
            if keyword in name_lower:
                indicators.append(f"suspicious_keyword:{keyword}")
                score += 15
        
        # Check against baseline if established
        if self.baseline_established and snapshot.name in self.baselines:
            baseline = self.baselines[snapshot.name]
            
            # CPU deviation
            if baseline.sample_count >= 1:
                cpu_deviation = abs(snapshot.cpu_percent - baseline.avg_cpu) / (baseline.avg_cpu + 1)
                if cpu_deviation > ThreatConfig.ANOMALY_THRESHOLD:
                    indicators.append(f"cpu_anomaly:{cpu_deviation:.2f}")
                    score += int(20 * min(cpu_deviation, 2.0))
                
                # Memory deviation
                mem_deviation = abs(snapshot.memory_percent - baseline.avg_memory) / (baseline.avg_memory + 1)
                if mem_deviation > ThreatConfig.ANOMALY_THRESHOLD:
                    indicators.append(f"memory_anomaly:{mem_deviation:.2f}")
                    score += int(15 * min(mem_deviation, 2.0))
                
                # Thread count spike
                if snapshot.num_threads > baseline.avg_threads * 2 and snapshot.num_threads > 50:
                    indicators.append("thread_spike")
                    score += 20
        
        # Extreme resource usage
        if snapshot.cpu_percent > ThreatConfig.CPU_SPIKE_THRESHOLD:
            indicators.append(f"high_cpu:{snapshot.cpu_percent:.1f}%")
            score += 15
        
        if snapshot.memory_percent > ThreatConfig.MEMORY_SPIKE_THRESHOLD:
            indicators.append(f"high_memory:{snapshot.memory_percent:.1f}%")
            score += 15
        
        # Suspicious network connections
        for ip, port in snapshot.connections:
            if port in ThreatConfig.SUSPICIOUS_PORT_CONNECTIONS:
                indicators.append(f"suspicious_port:{port}")
                score += 25
        
        # Check for unsigned or suspicious executable paths
        if snapshot.exe:
            exe_lower = snapshot.exe.lower()
            suspicious_paths = ['temp', 'appdata\\local\\temp', 'downloads', 'desktop']
            if any(path in exe_lower for path in suspicious_paths):
                indicators.append("suspicious_path")
                score += 10  # REDUCED FROM 20
        
        # Calculate confidence based on number of indicators and baseline data
        if baseline := self.baselines.get(snapshot.name):
            confidence = min(1.0, baseline.sample_count / 100)
        else:
            confidence = 0.3
        
        # Boost confidence for critical indicators
        if any('ransomware' in ind for ind in indicators):
            confidence = max(confidence, 0.9)
        
        self.process_history[snapshot.pid].append(snapshot)
        if len(self.process_history[snapshot.pid]) > 100:
            self.process_history[snapshot.pid] = self.process_history[snapshot.pid][-100:]
        
        return min(100, score), indicators, confidence
    
    def check_baseline_status(self) -> bool:
        """Check if baseline establishment period is complete"""
        elapsed = time.time() - self.baseline_start_time
        if not self.baseline_established and elapsed >= ThreatConfig.BASELINE_COLLECTION_TIME:
            self.baseline_established = True
            print(f"Process baseline established ({len(self.baselines)} unique processes)")
            return True
        return self.baseline_established
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get intelligence statistics"""
        return {
            **self.stats,
            'baselines_established': len(self.baselines),
            'baseline_ready': self.baseline_established,
            'processes_tracked': len(self.process_history),
            'new_processes_count': len(self.new_processes)
        }


# ==============================================================================
# FILE SYSTEM INTELLIGENCE
# ==============================================================================

class FileSystemIntelligence(FileSystemEventHandler if WATCHDOG_AVAILABLE else object):
    """Advanced file system monitoring and entropy analysis"""
    
    def __init__(self, callback: Optional[Callable[[ThreatEvent], None]] = None,
             behavioral_analyzer: Optional[Any] = None,
             controlled_folder_handler: Optional[Callable[[str, str, int, List[str]], None]] = None,
             protected_paths: Optional[List[str]] = None,
             pid_resolver: Optional[Callable[[str], int]] = None,
             blocked_pid_checker: Optional[Callable[[int, Optional[float]], bool]] = None,
             research_hook: Optional[Callable[[str, Any, Optional[Dict[str, Any]]], None]] = None):
        if WATCHDOG_AVAILABLE:
            super().__init__()
        
        self.callback = callback
        self.behavioral_analyzer = behavioral_analyzer
        self.controlled_folder_handler = controlled_folder_handler
        self.pid_resolver = pid_resolver
        self.blocked_pid_checker = blocked_pid_checker
        self.research_hook = research_hook
        self.protected_paths = [os.path.normcase(os.path.abspath(p)) for p in (protected_paths or [])]
        self.file_operations: deque = deque(maxlen=1000)
        self.file_entropy_cache: Dict[str, Tuple[float, float]] = {}  # path: (entropy, timestamp)
        self.extension_changes: List[Tuple[str, str, float]] = []  # (old, new, time)
        self.mass_operations: Dict[str, List[float]] = defaultdict(list)  # process: [timestamps]
        
        self.stats = {
            'total_events': 0,
            'high_entropy_files': 0,
            'suspicious_renames': 0,
            'mass_file_changes': 0,
            'ransomware_extensions_detected': 0
        }
        
        print(" File System Intelligence initialized")
    
    def analyze_file(self, filepath: str) -> Tuple[Optional[float], List[str]]:
        """Analyze file for suspicious characteristics"""
        indicators = []
        entropy = None

        # A move/rename notification can arrive after the source or
        # destination has disappeared.  Filename indicators remain valid in
        # that case, so evaluate them before the existence check.
        basename = os.path.basename(filepath)
        is_ransom, ext_indicator = is_ransomware_extension(basename)
        if is_ransom:
            indicators.append(ext_indicator)
            self.stats['ransomware_extensions_detected'] += 1
        is_susp, name_indicators = is_suspicious_filename(basename)
        if is_susp:
            indicators.extend(name_indicators)
        
        try:
            # Check if file exists
            if not os.path.exists(filepath):
                return None, indicators
            
            # Get file stats
            stat = os.stat(filepath)
            file_size = stat.st_size
            
            # Skip very large files (> 100MB) to avoid performance issues
            if file_size > 100 * 1024 * 1024:
                return None, indicators
            
            # Calculate entropy for files up to 1MB
            if file_size > 0 and file_size <= 0.1 * 1024 * 1024:
                with open(filepath, 'rb') as f:
                    # Read sample from beginning, middle, and end
                    samples = []
                    samples.append(f.read(min(8192, file_size)))
                    
                    if file_size > 16384:
                        f.seek(file_size // 2)
                        samples.append(f.read(8192))
                    
                    if file_size > 24576:
                        f.seek(-8192, 2)
                        samples.append(f.read(8192))
                    
                    # Calculate average entropy
                    entropies = [calculate_entropy(s) for s in samples if s]
                    entropy = sum(entropies) / len(entropies) if entropies else 0.0
                    
                    # Cache result
                    self.file_entropy_cache[filepath] = (entropy, time.time())
                    
                    if entropy > ThreatConfig.ENTROPY_THRESHOLD:
                        indicators.append(f"high_entropy:{entropy:.2f}")
                        self.stats['high_entropy_files'] += 1
            
        except Exception as e:
            pass
        
        return entropy, indicators
    
    def on_created(self, event: 'FileSystemEvent') -> None:
        """Handle file creation"""
        if event.is_directory:
            return
        print(f"[File-created] {os.path.basename(event.src_path)}")
        self._handle_event(event.src_path, 'created')
    
    def on_modified(self, event: 'FileSystemEvent') -> None:
        """Handle file modification"""
        if event.is_directory:
            return
        print(f"[File-modified] {os.path.basename(event.src_path)}")
        self._handle_event(event.src_path, 'modified')
    
    def on_deleted(self, event: 'FileSystemEvent') -> None:
        """Handle file deletion"""
        if event.is_directory:
            return
        print(f"[File-deleted] {os.path.basename(event.src_path)}")
        self._handle_event(event.src_path, 'deleted')
    
    def on_moved(self, event: 'FileSystemEvent') -> None:
        """Handle file move/rename"""
        if event.is_directory:
            return
        print(f"[File-moved] {os.path.basename(event.src_path)} -> {os.path.basename(event.dest_path)}")
        
        # Track extension changes
        old_ext = os.path.splitext(event.src_path)[1].lower()
        new_ext = os.path.splitext(event.dest_path)[1].lower()
        
        if old_ext != new_ext:
            self.extension_changes.append((old_ext, new_ext, time.time()))
            # Keep only recent changes
            cutoff = time.time() - 60
            self.extension_changes = [(o, n, t) for o, n, t in self.extension_changes if t > cutoff]
        
        self._handle_event(event.dest_path, 'moved', metadata={'old_path': event.src_path})
    
    def _handle_event(self, filepath: str, operation: str, metadata: Optional[Dict] = None) -> None:
        """Process file system event"""
        print(f"[ANALYSING] {operation.upper()} -> {os.path.basename(filepath)}")
        self.stats['total_events'] += 1

        # Prefer the monitor's registered external-process mapping. The
        # fallback open-file scan is expensive on Windows and blocks
        # watchdog's single event-dispatch thread long enough to lose the
        # burst of rename events produced by the demo.
        pid = 0
        if self.pid_resolver:
            try:
                pid = int(self.pid_resolver(filepath) or 0)
            except Exception:
                pid = 0
        if not pid or pid <= 0:
            pid = self._get_process_for_file_pid(filepath)
        process = int(pid or 0)
        if process <= 0:
            logger.debug("[FILE EVENT IGNORED] Missing PID op=%s path=%s", operation, filepath)
            return

        process_name = "unknown"
        process_create_time = None
        try:
            proc = psutil.Process(process)
            process_name = proc.name() or "unknown"
            process_create_time = float(proc.create_time())
        except Exception:
            process_name = "unknown"

        if self.blocked_pid_checker and self.blocked_pid_checker(process, process_create_time):
            logger.info("IGNORED EVENT (POST-BLOCK) pid=%s", process)
            return

        if not psutil.pid_exists(process):
            logger.debug("[FILE EVENT IGNORED] Dead PID pid=%s op=%s path=%s", process, operation, filepath)
            return

        if self.research_hook:
            try:
                self.research_hook("first_telemetry", {
                    "pid": process,
                    "event_type": operation,
                    "path": filepath,
                    "old_path": (metadata or {}).get("old_path"),
                }, None)
            except Exception:
                logger.debug("[RESEARCH] first telemetry hook failed", exc_info=True)

        # Analyze file only after a live PID is resolved.
        entropy, indicators = self.analyze_file(filepath) if operation != 'deleted' else (None, [])

        # Feed file telemetry into the same behavioral model used by the
        # process scanner. Without this bridge the ML path sees only process
        # snapshots and cannot learn that the registered process is performing
        # mass renames/deletes.
        if self.behavioral_analyzer:
            try:
                analyzer_event = {
                    "valid": True,
                    "pid": process,
                    "event_type": operation.upper(),
                    "path": filepath,
                    "entropy": entropy,
                }
                if metadata and metadata.get("old_path"):
                    analyzer_event["old_path"] = metadata["old_path"]
                self.behavioral_analyzer.ingest_event(analyzer_event)
                if self.research_hook:
                    self.research_hook("feature_generation", analyzer_event, None)
            except Exception:
                logger.debug("[ANALYZER] Failed to ingest file event", exc_info=True)

        # Controlled folder enforcement (highest priority signal).
        # If the file touched is inside a protected path, trigger immediate user-decision workflow.
        try:
            abs_path = os.path.normcase(os.path.abspath(filepath))
            protected_hit = any(
                abs_path == p or abs_path.startswith(p + os.sep)
                for p in self.protected_paths
            )
            if protected_hit and self.controlled_folder_handler:
                logger.info(
                    "[CONTROLLED-FOLDER] protected hit op=%s path=%s pid=%s protected_paths=%s",
                    operation,
                    abs_path,
                    int(process or 0),
                    self.protected_paths,
                )
                indicators_cf = ["controlled_folder_access", f"controlled_folder_op:{operation}"]
                if entropy is not None:
                    indicators_cf.append(f"entropy:{entropy:.2f}")
                self.controlled_folder_handler(filepath, operation, int(process or 0), indicators_cf)
        except Exception:
            logger.info("Controlled folder handler failed", exc_info=True)
        
        # Track operations by process (by PID)
        if process and process != 0:
            self.mass_operations[str(process)].append(time.time())
            # Check for mass file operations
            recent = [t for t in self.mass_operations[str(process)] if time.time() - t < 10]
            if len(recent) > ThreatConfig.RAPID_FILE_OPERATIONS:
                indicators.append(f"rapid_operations:{len(recent)}")
                self.stats['mass_file_changes'] += 1
        
        # Calculate suspicion score
        score = self._calculate_file_score(operation, entropy, indicators)

        # Determine threat level
        threat_level = self._determine_threat_level(score)
        confidence = self._calculate_confidence(indicators, entropy)
        
        # -------------------------------
        # SAFE EVENT CREATION & CALLBACK
        # -------------------------------
        event: Optional[ThreatEvent] = None

        if score >= ThreatConfig.MIN_THREAT_SCORE:
            event = ThreatEvent(
                event_id=generate_event_id(),
                timestamp=time.time(),
                event_type='file',
                threat_level=threat_level,
                confidence=confidence,
                suspicion_score=score,
                process=process_name,
                pid=process or None,
                file_path=filepath,
                operation=operation,
                indicators=indicators,
                entropy=entropy,
                metadata=metadata or {}
            )

        if event and self.callback:
            self.callback(event)

                        
        # Store for analysis
        self.file_operations.append({
            'timestamp': time.time(),
            'path': filepath,
            'operation': operation,
            'process': process,
            'score': score,
            'entropy': entropy
        })
    
    def _calculate_file_score(self, operation: str, entropy: Optional[float], indicators: List[str]) -> int:
        """Calculate file operation suspicion score"""
        score = 0
        
        # Base score by operation
        op_scores = {'created': 5, 'modified': 10, 'deleted': 15, 'moved': 8}
        score += op_scores.get(operation, 5)
        
        # Entropy score
        if entropy and entropy > ThreatConfig.ENTROPY_THRESHOLD:
            score += int((entropy - 7.0) * 15)
        
        # Indicator scoring
        for indicator in indicators:
            if indicator.startswith("ransomware_ext:"):
                score += 75
            elif indicator == "ransom_note_pattern":
                score += 40
            elif indicator.startswith("pattern:") and "decrypt" in indicator.lower():
                score += 30
            elif 'ransomware' in indicator:
                score += 60
            elif 'high_entropy' in indicator:
                score += 30
            elif 'suspicious' in indicator:
                score += 20
            elif 'rapid_operations' in indicator:
                score += 25
            elif 'keyword' in indicator:
                score += 15
            else:
                score += 10
        
        return min(100, score)
    
    def _determine_threat_level(self, score: int) -> str:
        """Determine threat level from score"""
        if score >= 85:
            return 'critical'
        elif score >= 60:
            return 'high'
        elif score >= 40:
            return 'medium'
        else:
            return 'low'
    
    def _calculate_confidence(self, indicators: List[str], entropy: Optional[float]) -> float:
        """Calculate detection confidence"""
        confidence = 0.5
        
        # More indicators = higher confidence
        confidence += min(0.3, len(indicators) * 0.05)
        
        # Entropy measurement adds confidence
        if entropy is not None:
            confidence += 0.2
        
        # Strong indicators boost confidence
        if any('ransomware' in ind for ind in indicators):
            confidence = 0.95
        
        return min(1.0, confidence)
    
    def _get_process_for_file_pid(self, filepath: str) -> int:
        """Best-effort: get PID of process accessing file path."""
        try:
            target = os.path.normcase(os.path.abspath(filepath))
            start = time.time()
            time_budget_s = 0.30  # best-effort attribution for controlled-folder enforcement
            for proc in psutil.process_iter(['name', 'pid']):
                if time.time() - start > time_budget_s:
                    break
                try:
                    for f in proc.open_files():
                        open_path = os.path.normcase(os.path.abspath(f.path))
                        if open_path == target:
                            return proc.info['pid']
                except (psutil.AccessDenied, psutil.NoSuchProcess):
                    continue
        except Exception:
            pass
        return 0  # Return 0 for unknown (behavioral_analyzer will filter it)
    def _is_shadow_copy_interaction(self, filepath: str) -> bool:
        """Detect if file operation involves shadow copies"""
        if not filepath:
            return False
        path_lower = filepath.lower()
        indicators = ['vssadmin', 'shadow', 'wbadmin', 'backup']
        return any(indicator in path_lower for indicator in indicators)

    
    def get_monitored_files_count(self) -> int:
        """
        Count total monitored paths.
        """
        monitored_paths = getattr(self, 'monitored_paths', []) or []
        return len(monitored_paths)



    def get_statistics(self) -> Dict[str, Any]:
        """Get file system statistics"""
        return {
            **self.stats,
            'cached_entropy_entries': len(self.file_entropy_cache),
            'recent_operations': len(self.file_operations),
            'extension_changes_tracked': len(self.extension_changes),
            'files_monitored': self.get_monitored_files_count()
        }


# ==============================================================================
# NETWORK INTELLIGENCE
# ==============================================================================

class NetworkIntelligence:
    """Network behavior monitoring and C2 detection"""
    
    def __init__(self):
        self.connection_history: Dict[int, List[Tuple[str, int, float]]] = defaultdict(list)
        self.upload_rates: Dict[int, deque] = defaultdict(lambda: deque(maxlen=60))
        self.beacon_patterns: Dict[int, List[float]] = defaultdict(list)
        self.previous_net_io = psutil.net_io_counters()
        self.last_check = time.time()
        
        self.stats = {
            'total_connections': 0,
            'suspicious_connections': 0,
            'high_upload_detected': 0,
            'c2_patterns_detected': 0
        }
        
        print(" Network Intelligence initialized")
    
    def analyze_connections(self, pid: int, connections: List[Tuple[str, int]]) -> Tuple[int, List[str]]:
        """Analyze network connections for suspicious activity"""
        score = 0
        indicators = []
        
        for ip, port in connections:
            self.connection_history[pid].append((ip, port, time.time()))
            self.stats['total_connections'] += 1
            
            # Check for suspicious ports
            if port in ThreatConfig.SUSPICIOUS_PORT_CONNECTIONS:
                indicators.append(f"suspicious_port:{port}")
                score += 20
                self.stats['suspicious_connections'] += 1
            
            # Check for connections to known malicious IPs (simplified)
            if self._is_suspicious_ip(ip):
                indicators.append(f"suspicious_ip:{ip}")
                score += 30
        
        # Check for beacon patterns (regular periodic connections)
        if self._detect_beacon_pattern(pid):
            indicators.append("c2_beacon_pattern")
            score += 40
            self.stats['c2_patterns_detected'] += 1
        
        return score, indicators
    
    def check_upload_rate(self) -> Tuple[int, List[str]]:
        """Check for abnormal upload rates"""
        score = 0
        indicators = []
        
        try:
            current_net_io = psutil.net_io_counters()
            elapsed = time.time() - self.last_check
            
            if elapsed > 0:
                bytes_sent = current_net_io.bytes_sent - self.previous_net_io.bytes_sent
                upload_rate = bytes_sent / elapsed
                
                if upload_rate > ThreatConfig.HIGH_NETWORK_UPLOAD_RATE:
                    mb_per_sec = upload_rate / (1024 * 1024)
                    indicators.append(f"high_upload:{mb_per_sec:.2f}MB/s")
                    score += 25
                    self.stats['high_upload_detected'] += 1
            
            self.previous_net_io = current_net_io
            self.last_check = time.time()
            
        except Exception:
            pass
        
        return score, indicators
    
    def _is_suspicious_ip(self, ip: str) -> bool:
        """Check if IP is suspicious (simplified heuristic)"""
        # In production, this would check against threat intelligence feeds
        # For now, basic checks for private/local addresses being less suspicious
        if ip.startswith('127.') or ip.startswith('192.168.') or ip.startswith('10.'):
            return False
        return False  # Conservative default
    
    def _detect_beacon_pattern(self, pid: int) -> bool:
        """Detect regular periodic connection patterns (C2 beacons)"""
        history = self.connection_history.get(pid, [])
        
        if len(history) < 5:
            return False
        
        # Get recent connections
        recent = history[-10:]
        timestamps = [t for _, _, t in recent]
        
        if len(timestamps) < 5:
            return False
        
        # Calculate intervals between connections
        intervals = [timestamps[i+1] - timestamps[i] for i in range(len(timestamps)-1)]
        
        if not intervals:
            return False
        
        # Check if intervals are roughly similar (beacon pattern)
        avg_interval = sum(intervals) / len(intervals)
        variance = sum((x - avg_interval) ** 2 for x in intervals) / len(intervals)
        std_dev = math.sqrt(variance)
        
        # If intervals are very consistent, might be a beacon
        if std_dev < avg_interval * 0.2 and avg_interval > 5:  # Regular pattern with >5s intervals
            return True
        
        return False
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get network statistics"""
        return {
            **self.stats,
            'processes_with_connections': len(self.connection_history)
        }


# ==============================================================================
# MAIN SYSTEM MONITOR
# ==============================================================================

class SystemMonitor:
    """
    Main monitoring orchestrator - Advanced Version 3.0
    Coordinates all intelligence modules and threat detection
    """
    
    def __init__(
        self,
        callback: Optional[Callable[[Dict[str, Any]], None]] = None,
        threat_manager: Optional[ThreatManager] = None,
        analyzer: Optional[BehavioralAnalyzer] = None,
        detector: Optional[ThreatDetector] = None,
        research_hook: Optional[Callable[[str, Any, Optional[Dict[str, Any]]], None]] = None,
    ):
        # Reuse the application-level analyzer and detector when provided so
        # the monitor, scheduler, and dashboard report one consistent stream
        # of features and predictions.
        self.analyzer = analyzer or BehavioralAnalyzer()
        self.ml_detector = detector or ThreatDetector()
        self.callback = callback
        self.threat_manager = threat_manager
        self.monitoring = False
        self._running = False

        self.monitoring_thread: Optional[threading.Thread] = None
        self.event_queue: queue.Queue = queue.Queue()
        self.notification_manager = NotificationManager(
            websocket_callback=self._send_websocket_alert
        )

        # Controlled folder feature (Windows Defender-like)
        self.controlled_folder_enabled = False
        self.controlled_folder_paths: List[str] = []
        self.controlled_folder_allowlist: Set[str] = set()
        self.controlled_folder_auto_suspend = True

        # Recent alerts cache to prevent notification spam (PID -> last_alert_time)
        self.recent_controlled_folder_alerts: Dict[int, float] = {}
        self.alert_cooldown_seconds = 30  # Don't spam alerts for same PID within 30 seconds

        self._load_controlled_folder_config()
        
        # KillSwitch configured for automatic containment
        from backend.killswitch import KillSwitch
        from utils.config import config as yaml_config

        threshold = int(yaml_config.get("killswitch.threat_threshold", ThreatConfig.CRITICAL_THREAT_SCORE))
        self.killswitch = KillSwitch(
            enable_auto_kill=True,
            threat_threshold=threshold
        )
        self.auto_action_cooldown_seconds = 20
        self._recent_auto_actions: Dict[int, float] = {}
        self.registered_external_processes: Dict[int, Dict[str, Any]] = {}
        self.housekeeping_interval_seconds = 30.0
        self.last_housekeeping_time = 0.0
        self.restart_count = 0

        # Intelligence modules
        self.process_intel = ProcessIntelligence()
        self.file_intel = FileSystemIntelligence(
            callback=self.handle_event,
            behavioral_analyzer=self.analyzer,
            controlled_folder_handler=self._handle_controlled_folder_access,
            protected_paths=self.controlled_folder_paths,
            pid_resolver=self._resolve_pid_for_file,
            blocked_pid_checker=self._is_blocked_pid,
            research_hook=research_hook,
        )

        self.network_intel = NetworkIntelligence()
        
        # File system observers
        self.file_observers: List[Observer] = []
        
        #Thread lock safety
        self._lock = threading.Lock()
        self._active_processes: Dict[int, str] = {}
        
        # Threat tracking
        self.active_threats: Dict[int, ThreatEvent] = {}
        self.threat_history: deque = deque(maxlen=1000)
        self.recent_events: Dict[Tuple[int, str, str], float] = {}
        self.recent_events_lock = threading.Lock()
        self.recent_event_ttl_seconds = 2.0
        
        # Statistics
        self.stats = {
            'uptime_start': time.time(),
            'total_events': 0,
            'high_risk_events': 0,
            'processes_killed': 0,
            'monitoring_active': False
        }
        
        print("\n" + "="*70)
        print("  RANSOMGUARD ADVANCED THREAT DETECTION ENGINE v3.0")
        print("="*70)
        print(" System Monitor initialized successfully")
        print("="*70 + "\n")

    def _project_root(self) -> Path:
        return app_root()

    def _resolve_paths(self, paths: List[str]) -> List[str]:
        root = self._project_root()
        resolved = []
        for p in paths:
            if not p:
                continue
            try:
                pp = Path(p)
                if not pp.is_absolute():
                    pp = (root / pp).resolve()
                resolved.append(str(pp))
            except Exception:
                resolved.append(p)
        return resolved

    def _load_controlled_folder_config(self) -> None:
        """
        Best-effort load from config.yaml.
        If config is absent/invalid, feature stays disabled.
        """
        try:
            from utils.config import config as yaml_config

            self.controlled_folder_enabled = bool(
                yaml_config.get("controlled_folders.enabled", False)
            )
            self.controlled_folder_auto_suspend = bool(
                yaml_config.get("controlled_folders.auto_suspend", True)
            )
            raw_paths = yaml_config.get("controlled_folders.paths", []) or []
            if not raw_paths:
                raw_paths = self._default_controlled_folder_paths()
            self.controlled_folder_paths = self._resolve_paths(list(raw_paths))
            allow = yaml_config.get("controlled_folders.allowlist_processes", []) or []
            if not allow:
                allow = list(SYSTEM_PROCESSES)
            self.controlled_folder_allowlist = {str(x).lower() for x in allow if x}
            logger.info(
                "[CONTROLLED-FOLDER] enabled=%s auto_suspend=%s paths=%s allowlist=%s",
                self.controlled_folder_enabled,
                self.controlled_folder_auto_suspend,
                self.controlled_folder_paths,
                sorted(self.controlled_folder_allowlist),
            )
        except Exception:
            logger.debug("Controlled folder config not loaded", exc_info=True)

    def _default_controlled_folder_paths(self) -> List[str]:
        """Cross-machine defaults for controlled folders."""
        candidates: List[str] = []
        home = Path.home()
        for folder in ("Documents", "Desktop", "Downloads", "Pictures"):
            path = home / folder
            if path.exists():
                candidates.append(str(path))
        return candidates

    def register_external_process(
        self,
        pid: int,
        process_name: Optional[str] = None,
        exe_path: Optional[str] = None,
        target_paths: Optional[List[str]] = None,
    ) -> None:
        if pid <= 0:
            return
        normalized_targets = []
        for path in target_paths or []:
            try:
                normalized_targets.append(os.path.normcase(os.path.abspath(str(path))))
            except Exception:
                continue
        self.registered_external_processes[int(pid)] = {
            "pid": int(pid),
            "process_name": process_name or "unknown",
            "exe_path": exe_path or "",
            "target_paths": normalized_targets,
            "registered_at": time.time(),
        }

    def get_registered_external_processes(self) -> List[Dict[str, Any]]:
        rows: List[Dict[str, Any]] = []
        stale: List[int] = []
        for pid, info in self.registered_external_processes.items():
            alive = psutil.pid_exists(pid)
            row = dict(info)
            row["alive"] = bool(alive)
            rows.append(row)
            if not alive:
                stale.append(pid)
        for pid in stale:
            self.registered_external_processes.pop(pid, None)
        rows.sort(key=lambda x: x.get("registered_at", 0), reverse=True)
        return rows

    def _resolve_registered_external_pid(self) -> int:
        active = [p for p in self.get_registered_external_processes() if p.get("alive")]
        if not active:
            return 0
        return int(active[0]["pid"])

    def _resolve_pid_for_file(self, _filepath: str) -> int:
        filepath = os.path.normcase(os.path.abspath(str(_filepath or "")))
        candidates = []
        for pid, info in list(self.registered_external_processes.items()):
            if not psutil.pid_exists(pid):
                continue
            for target in info.get("target_paths", []):
                if filepath == target or filepath.startswith(target + os.sep):
                    candidates.append(pid)
                    break

        if len(candidates) == 1:
            return int(candidates[0])
        return 0

    def _resolve_process_name(self, pid: int, fallback: str = "unknown") -> str:
        pid = int(pid or 0)
        if pid <= 0:
            return fallback or "unknown"

        info = self.registered_external_processes.get(pid)
        if info:
            registered_name = str(info.get("process_name", "") or "").strip()
            if registered_name and registered_name.lower() != "unknown":
                return registered_name

        try:
            proc = psutil.Process(pid)
            name = (proc.name() or "").strip()
            if name:
                return name
        except Exception:
            pass

        fallback_name = str(fallback or "").strip()
        if fallback_name and fallback_name.lower() != "unknown" and not fallback_name.isdigit():
            return fallback_name
        return "unknown"

    def _is_live_pid(self, pid: int) -> bool:
        pid = int(pid or 0)
        if pid <= 0 or pid == os.getpid():
            return False
        try:
            return psutil.pid_exists(pid)
        except Exception:
            return False

    def _get_process_create_time(self, pid: int) -> Optional[float]:
        try:
            return float(psutil.Process(int(pid)).create_time())
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess, ValueError, TypeError):
            return None

    def _is_blocked_pid(self, pid: int, process_create_time: Optional[float] = None) -> bool:
        if not self.threat_manager:
            return False
        return self.threat_manager.is_blocked(pid, process_create_time=process_create_time)

    def _make_recent_event_key(self, pid: int, file_path: str, event_type: str) -> Tuple[int, str, str]:
        normalized_path = str(file_path or "").strip()
        if normalized_path:
            try:
                normalized_path = os.path.normcase(os.path.abspath(normalized_path))
            except Exception:
                normalized_path = normalized_path.lower()
        normalized_type = str(event_type or "unknown").strip().lower() or "unknown"
        return (int(pid), normalized_path, normalized_type)

    def _is_duplicate_event(self, pid: int, file_path: str, event_type: str) -> bool:
        now = time.time()
        key = self._make_recent_event_key(pid, file_path, event_type)

        with self.recent_events_lock:
            cutoff = now - self.recent_event_ttl_seconds
            stale_keys = [cached_key for cached_key, ts in self.recent_events.items() if ts < cutoff]
            for stale_key in stale_keys:
                self.recent_events.pop(stale_key, None)

            last_seen = self.recent_events.get(key)
            if last_seen is not None and (now - last_seen) <= self.recent_event_ttl_seconds:
                logger.info(
                    "DUPLICATE EVENT SKIPPED: pid=%s file=%s event_type=%s",
                    pid,
                    file_path,
                    event_type,
                )
                return True

            self.recent_events[key] = now
            return False

    def _handle_controlled_folder_access(
        self,
        filepath: str,
        operation: str,
        pid: int,
        indicators: List[str],
    ) -> None:
        """
        Enforce controlled folder policy:
        - If an untrusted process touches a protected path and score >= threshold,
          terminate immediately, then notify dashboard/OS.
        """
        if not self.controlled_folder_enabled:
            return

        # Deterministic PID resolution for dashboard-started external processes.
        if not pid or pid <= 0:
            pid = self._resolve_registered_external_pid()
        if not pid or pid <= 0:
            logger.debug("[CONTROLLED-FOLDER] Skipping event: no resolvable external PID")
            return

        process_name = "unknown"
        if pid:
            try:
                proc = psutil.Process(pid)
                process_name = proc.name() or "unknown"
            except Exception:
                pass
        if process_name.lower() == "unknown":
            logger.debug("[CONTROLLED-FOLDER] Skipping event: unresolved process metadata for PID %s", pid)
            return

        # Check if process is already blocked/terminated
        if process_name.lower() in self.killswitch.blocked_processes:
            logger.debug(f"[CONTROLLED-FOLDER] Skipping alert for already blocked process: {process_name}")
            return

        # Check for recent alerts to prevent spam
        now = time.time()
        last_alert_time = self.recent_controlled_folder_alerts.get(pid, 0)
        if now - last_alert_time < self.alert_cooldown_seconds:
            logger.debug(f"[CONTROLLED-FOLDER] Skipping duplicate alert for PID {pid} (cooldown active)")
            return

        pname = process_name.lower()
        if pname in self.controlled_folder_allowlist:
            return

        # Update recent alerts cache
        self.recent_controlled_folder_alerts[pid] = now

        score = max(int(self.killswitch.threat_threshold), 85)
        combined_indicators = list(indicators) + [f"file_path:{filepath}", f"operation:{operation}"]

        threat_event = ThreatEvent(
            event_id=generate_event_id(),
            timestamp=time.time(),
            event_type='file',
            threat_level='critical',
            confidence=1.0,
            suspicion_score=score,
            process=process_name,
            pid=int(pid or 0),
            file_path=filepath,
            operation=operation,
            indicators=combined_indicators,
            metadata={"pipeline_phase": "phase_2_scored", "source": "controlled_folder"},
        )
        self.handle_event(threat_event)

    def get_controlled_folder_config(self) -> Dict[str, Any]:
        return {
            "enabled": self.controlled_folder_enabled,
            "auto_suspend": self.controlled_folder_auto_suspend,
            "paths": list(self.controlled_folder_paths),
            "allowlist_processes": sorted(self.controlled_folder_allowlist),
        }

    def set_controlled_folder_config(
        self,
        *,
        enabled: Optional[bool] = None,
        auto_suspend: Optional[bool] = None,
        paths: Optional[List[str]] = None,
        allowlist_processes: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        old_paths: Set[str] = set(
            os.path.normcase(os.path.abspath(p)) for p in self.controlled_folder_paths
        )
        if enabled is not None:
            self.controlled_folder_enabled = bool(enabled)
        if auto_suspend is not None:
            self.controlled_folder_auto_suspend = bool(auto_suspend)
        if paths is not None:
            self.controlled_folder_paths = self._resolve_paths(list(paths))
            try:
                self.file_intel.protected_paths = [
                    os.path.normcase(os.path.abspath(p)) for p in self.controlled_folder_paths
                ]
            except Exception:
                pass
            # Add new paths to live file observers without restart.
            if self.monitoring:
                new_paths: List[str] = []
                for p in self.controlled_folder_paths:
                    norm = os.path.normcase(os.path.abspath(p))
                    if norm not in old_paths:
                        new_paths.append(p)
                if new_paths:
                    self._start_file_monitoring(new_paths)
        if allowlist_processes is not None:
            self.controlled_folder_allowlist = {
                str(x).lower() for x in allowlist_processes if x
            }
        return self.get_controlled_folder_config()

    def start_process_scanner(self, interval=2.0):
            self._running = True

            def _loop():
                while self._running:
                    try:
                        self._scan_processes()
                    except Exception as e:
                        logger.exception("Process scan failed: %s", e)
                    time.sleep(interval)

            t = threading.Thread(target=_loop, daemon=True)
            t.start()


    def get_active_processes(self):
        """
        Returns iterable of (pid, process_name).
        Authoritative source for MLScheduler.
        """
        return list(self._active_processes.items())

    
    def start_monitoring(self, watch_paths: Optional[List[str]] = None) -> bool:
        """Start comprehensive monitoring"""
        if self.monitoring:
            thread_alive = bool(self.monitoring_thread and self.monitoring_thread.is_alive())
            if watch_paths:
                self._start_file_monitoring(watch_paths)
            if thread_alive:
                print("  Monitoring already active")
                return True

            logger.warning("[MONITOR] Monitoring flag was set but worker thread was not alive; restarting")
            self.monitoring = False
            self.stats['monitoring_active'] = False
            self.restart_count += 1
        
        print("\n Starting comprehensive threat monitoring...")
        print("-" * 70)
        
        self.monitoring = True
        self.stats['monitoring_active'] = True
        
        # Start main monitoring thread
        self.monitoring_thread = threading.Thread(
            target=self._monitoring_loop,
            name="RansomGuard-MainMonitor",
            daemon=True
        )
        self.monitoring_thread.start()
        print("Process monitoring active")
        
        # Start file system monitoring
        if WATCHDOG_AVAILABLE:
            paths = watch_paths or self._get_default_watch_paths()
            self._start_file_monitoring(paths)
        else:
            print("  File system monitoring unavailable (watchdog not installed)")
        
        print("-" * 70)
        print(f" All systems operational | Baseline: {ThreatConfig.BASELINE_COLLECTION_TIME}s")
        print("="*70 + "\n")
        
        return True

    def is_healthy(self) -> bool:
        return bool(self.monitoring and self.monitoring_thread and self.monitoring_thread.is_alive())

    def ensure_running(self) -> bool:
        """Restart the worker if monitoring was marked active but the thread died."""
        if self.is_healthy():
            return True
        logger.warning("[MONITOR] Health check failed; attempting restart")
        return self.start_monitoring()

    def _perform_housekeeping(self) -> None:
        """Trim stale monitor state so long-running demos stay responsive."""
        now = time.time()
        if (now - self.last_housekeeping_time) < self.housekeeping_interval_seconds:
            return

        self.last_housekeeping_time = now

        try:
            cleaned = self.analyzer.cleanup()
            if cleaned:
                logger.info("[MONITOR] Analyzer cleanup removed %s stale process windows", cleaned)
        except Exception:
            logger.exception("[MONITOR] Analyzer cleanup failed")

        try:
            stale_pids = [
                pid for pid in list(self.registered_external_processes)
                if not psutil.pid_exists(pid)
            ]
            for pid in stale_pids:
                self.registered_external_processes.pop(pid, None)
        except Exception:
            logger.debug("[MONITOR] External process cleanup failed", exc_info=True)

        try:
            cutoff = now - 30
            self.recent_controlled_folder_alerts = {
                pid: ts
                for pid, ts in self.recent_controlled_folder_alerts.items()
                if ts >= cutoff
            }
        except Exception:
            logger.debug("[MONITOR] Controlled-folder cleanup failed", exc_info=True)

        try:
            if self.threat_manager:
                self.threat_manager.cleanup_stale(ttl_seconds=300)
        except Exception:
            logger.debug("[MONITOR] Threat-manager cleanup failed", exc_info=True)

        try:
            dedup_cutoff = now - self.recent_event_ttl_seconds
            with self.recent_events_lock:
                stale_keys = [key for key, ts in self.recent_events.items() if ts < dedup_cutoff]
                for stale_key in stale_keys:
                    self.recent_events.pop(stale_key, None)
        except Exception:
            logger.debug("[MONITOR] Dedup cache cleanup failed", exc_info=True)
    
    def stop_monitoring(self) -> None:
        """Stop all monitoring activities"""
        print("\n Shutting down monitoring systems...")
        print("-" * 70)
        
        self.monitoring = False
        self.stats['monitoring_active'] = False
        
        # Stop file observers
        for observer in self.file_observers:
            try:
                observer.stop()
                observer.join(timeout=3)
            except Exception as e:
                print(f"[WARNING]  Error stopping observer: {e}")
        
        self.file_observers.clear()
        
        # Wait for monitoring thread
        if self.monitoring_thread and self.monitoring_thread.is_alive():
            self.monitoring_thread.join(timeout=5)
        
        # Print final statistics
        uptime = int(time.time() - self.stats['uptime_start'])
        actual_threats = sum(1 for event in self.threat_history if event.suspicion_score >= self.killswitch.threat_threshold)
        print(f"\n Final Statistics:")
        print(f"   Ã¢â‚¬Â¢ Uptime: {uptime // 60}m {uptime % 60}s")
        print(f"   Ã¢â‚¬Â¢ Total events: {self.stats['total_events']}")
        print(f"   Ã¢â‚¬Â¢ High-risk events: {self.stats['high_risk_events']}")
        print(f"   Ã¢â‚¬Â¢ Threats detected: {actual_threats}")
        print(f"   Ã¢â‚¬Â¢ Processes analyzed: {self.process_intel.stats['total_processes_seen']}")
        print(f"   Ã¢â‚¬Â¢ File events: {self.file_intel.stats['total_events']}")
        print("-" * 70)
        print(" Monitoring stopped\n")
    
    def _monitoring_loop(self) -> None:
        """Main monitoring loop - scans processes and system state"""
        print(" Main monitoring loop started\n")
        
        last_process_scan = 0
        last_network_check = 0
        
        while self.monitoring:
            try:
                current_time = time.time()
                
                # Process scanning
                if current_time - last_process_scan >= ThreatConfig.PROCESS_SCAN_INTERVAL:
                    self._scan_processes()
                    last_process_scan = current_time
                
                # Network checking
                if current_time - last_network_check >= 5.0:
                    self._check_network()
                    last_network_check = current_time
                
                # Check baseline status
                self.process_intel.check_baseline_status()
                self._perform_housekeeping()
                
                time.sleep(0.5)  # Small sleep to prevent CPU spinning
                
            except Exception as e:
                print(f"  Error in monitoring loop: {e}")
                time.sleep(2)
    
    def _scan_processes(self) -> None:
            self._active_processes.clear()
            logger.debug("[MONITOR] scanning processes")

            """Scan all running processes for threats"""
            try:
                for proc in psutil.process_iter():
                    try:
                        # 1Ã¯Â¸ÂÃ¢Æ’Â£ Capture snapshot
                        snapshot = self.process_intel.capture_snapshot(proc)

                        if not snapshot:
                            continue

                        # Register active process ONLY after validation
                        self._active_processes[snapshot.pid] = snapshot.name

                        if snapshot:
                            # Register active process (single source of truth)
                            with self._lock:
                                self._active_processes[snapshot.pid] = snapshot.name
                            
                            # Update behavioral analyzer with process metrics
                            self.process_intel.update_behavioral_analyzer(
                                snapshot, 
                                self.analyzer
                            )

                        # 2Ã¯Â¸ÂÃ¢Æ’Â£ Update baseline
                        self.process_intel.update_baseline(snapshot)

                        # 3Ã¯Â¸ÂÃ¢Æ’Â£ Heuristic detection
                        score, indicators, confidence = self.process_intel.detect_anomalies(snapshot)

                        # 4Ã¯Â¸ÂÃ¢Æ’Â£ Network heuristic
                        if snapshot.connections:
                            net_score, net_indicators = self.network_intel.analyze_connections(
                                snapshot.pid, snapshot.connections
                            )
                            score += net_score
                            indicators.extend(net_indicators)

                        # ================================
                        # [CRITICAL] REAL ML INTEGRATION
                        # ================================
                        
                        # 5Ã¯Â¸ÂÃ¢Æ’Â£ Build event for analyzer
                        event = {
                            "valid": True,
                            "type": "process_event",
                            # This is a process snapshot, not a file write.  The
                            # previous value inflated file-write features once
                            # per process scan and caused false ML signals.
                            "event_type": "PROCESS_SNAPSHOT",
                            "pid": snapshot.pid,
                            "process_name": snapshot.name,
                            "cpu_percent": snapshot.cpu_percent,
                            "memory_percent": snapshot.memory_percent,
                            "threads": snapshot.num_threads,
                        }
                        
                        # Ingest into behavioral analyzer
                        self.analyzer.ingest_event(event)
                        
                        # 6. ML feature extraction and model decision
                        raw_features = self.analyzer.extract_features(snapshot.pid)
                        analysis = self.ml_detector.prepare_analysis(raw_features) if raw_features else None
                        prob = 0.0
                        ml_result = None
                        decision = "UNKNOWN"
                        if analysis and analysis.get("valid"):
                            ml_result = self.ml_detector.analyze_features(analysis)
                            if ml_result:
                                decision = ml_result.get("decision", "UNKNOWN")
                                prob = ml_result.get("probability", 0.0) or 0.0
                                if decision in ["SUSPICIOUS", "RANSOMWARE", "KILL"]:
                                    print(
                                        f"[ ML ALERT] PID={snapshot.pid:5d} {snapshot.name:25s} "
                                        f"-> {decision:12s} (confidence={prob:.2f})"
                                    )

                        # Only ML-confirmed ransomware should trigger immediate containment.
                        if ml_result and decision in ["RANSOMWARE", "KILL"] and prob >= 0.85:
                            system_whitelist = {
                                "system", "registry", "svchost.exe", "csrss.exe", "dwm.exe",
                                "explorer.exe", "lsass.exe", "services.exe", "winlogon.exe",
                                "wininit.exe", "smss.exe", "fontdrvhost.exe", "conhost.exe",
                                "runtimebroker.exe", "taskmgr.exe", "searchindexer.exe",
                                "msmpeng.exe", "securityhealthservice.exe", "audiodg.exe",
                                "spoolsv.exe", "dllhost.exe", "chrome.exe", "msedge.exe",
                                "firefox.exe", "python.exe", "code.exe",
                            }
                            if snapshot.name.lower() not in system_whitelist:
                                indicators.append(f"ml_ransomware_detected:{prob:.2f}")
                                score = max(score, int(prob * 100))
                                self._report_ml_threat(snapshot, score, indicators, prob)
                                continue

                        # Heuristic high-score events are logged/reported.
                        if score >= ThreatConfig.MIN_THREAT_SCORE:
                            print(f"[ HEURISTIC ALERT] {snapshot.name} (Score: {score})")
                            self._report_process_threat(snapshot, score, indicators, confidence)

                    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                        continue

            except Exception as e:
                print(f" Error scanning processes: {e}")
                import traceback
                traceback.print_exc()

    
    def _check_network(self) -> None:
        """Check network activity for suspicious patterns"""
        try:
            score, indicators = self.network_intel.check_upload_rate()
            
            if score >= ThreatConfig.MIN_THREAT_SCORE:
                event = ThreatEvent(
                    event_id=generate_event_id(),
                    timestamp=time.time(),
                    event_type='network',
                    threat_level='medium' if score < 70 else 'high',
                    confidence=0.7,
                    suspicion_score=score,
                    process='NETWORK_IO',
                    file_path='Network Activity',
                    operation='high_upload',
                    indicators=indicators
                )
                self.handle_event(event)
                
        except Exception as e:
            print(f"  Error checking network: {e}")

    def list_active_processes(self):
         return list(self._active_processes.items())

    
    def _report_process_threat(
        self, 
        snapshot: ProcessSnapshot, 
        score: int, 
        indicators: List[str], 
        confidence: float
    ) -> None:
        """Report a process-based threat"""
        threat_level = 'low'
        if score >= 85:
            threat_level = 'critical'
        elif score >= self.killswitch.threat_threshold:
            threat_level = 'high'
        elif score >= 40:
            threat_level = 'medium'
        
        event = ThreatEvent(
            event_id=generate_event_id(),
            timestamp=snapshot.timestamp,
            event_type='process',
            threat_level=threat_level,
            confidence=confidence,
            suspicion_score=min(100, score),
            process=snapshot.name,
            pid=snapshot.pid,
            file_path=f"Process: {snapshot.name} (PID: {snapshot.pid})",
            operation='running',
            indicators=indicators,
            metadata={
                'pipeline_phase': 'phase_2_scored',
                'pipeline_model': '3-phase',
                'source': 'heuristic_process',
                'cpu_percent': snapshot.cpu_percent,
                'memory_percent': snapshot.memory_percent,
                'num_threads': snapshot.num_threads,
                'username': snapshot.username,
                'exe': snapshot.exe
            }
        )
        
        self.handle_event(event)

    def _report_ml_threat(
        self,
        snapshot: ProcessSnapshot,
        score: int,
        indicators: List[str],
        ml_confidence: float
    ) -> None:
        """Report ML-confirmed ransomware and enforce immediate termination."""
        bounded_score = max(int(score), int(self.killswitch.threat_threshold))
        event = ThreatEvent(
            event_id=generate_event_id(),
            timestamp=time.time(),
            event_type='process',
            threat_level='critical',
            confidence=max(ml_confidence, 0.9),
            suspicion_score=min(100, bounded_score),
            process=snapshot.name,
            pid=snapshot.pid,
            file_path=f"Process: {snapshot.name} (PID: {snapshot.pid})",
            operation='running',
            indicators=indicators,
            metadata={
                "pipeline_phase": "phase_2_scored",
                "pipeline_model": "3-phase",
                "source": "ml_confirmed",
                "ml_confidence": ml_confidence,
            },
        )
        self.handle_event(event)

    def _auto_terminate_and_notify(
        self,
        *,
        process_name: str,
        pid: int,
        score: int,
        indicators: List[str],
        source: str,
        exe_path: str = "unknown",
    ) -> Dict[str, Any]:
        """
        Three-phase response pipeline:
        1) detect threat event
        2) score and classify risk
        3) terminate immediately when score >= threshold, then notify
        """
        now = time.time()
        if pid and (now - self._recent_auto_actions.get(pid, 0)) < self.auto_action_cooldown_seconds:
            return {
                "success": False,
                "action": "throttled",
                "reason": "cooldown",
                "pid": pid,
                "process": process_name,
                "score": score,
                "source": source,
            }

        action = "monitor_only"
        success = False
        reason = "below_threshold"

        if score >= int(self.killswitch.threat_threshold):
            action = "terminated"
            reason = "threshold_reached"
            if pid and process_name and process_name.lower() != "unknown":
                success = self.killswitch.kill_process_tree(process_name, pid)
            else:
                success = False
                reason = "missing_pid_or_process"
            if pid:
                self._recent_auto_actions[pid] = now
            if success:
                self.stats["processes_killed"] += 1

        result = {
            "success": success,
            "action": action if success or action != "terminated" else "termination_failed",
            "reason": reason,
            "pid": pid,
            "process": process_name,
            "score": score,
            "threshold": int(self.killswitch.threat_threshold),
            "source": source,
            "exe_path": exe_path,
            "timestamp": now,
            "pipeline": {
                "phase_1": "detect",
                "phase_2": "score",
                "phase_3": "terminate_and_notify",
            },
            "indicators": list(indicators or []),
        }

        if success:
            title = "Threat blocked"
            line1 = f"{process_name} (PID {pid}) terminated"
        else:
            title = "Threat action required"
            line1 = f"{process_name} (PID {pid}) could not be terminated"

        try:
            self.notification_manager.send_info_notification(
                title=title,
                line1=line1,
                line2=f"Score {score} | Source {source}",
            )
        except Exception:
            logger.debug("Post-termination toast failed", exc_info=True)

        self._send_websocket_alert({"type": "protection_action", "data": result})
        return result

    def _handle_user_decision(self, alert_id: str, decision: str) -> None:
        """Execute user decision from notification"""
        alert = self.notification_manager.pending_alerts.get(alert_id)
        if not alert:
            logger.warning(f"Alert {alert_id} not found")
            return
        
        print(f"\n{'='*70}")
        print(f"[[USER] USER DECISION] {decision} for {alert.process_name} (PID {alert.pid})")
        print(f"{'='*70}\n")
        
        result = {"success": True}
        
        if decision == "KILL":
            # Simplified kill (kill_and_delete not in killswitch)
            success = self.killswitch.kill_process_tree(alert.process_name, alert.pid)
            self.killswitch.suspended_processes.pop(alert.pid, None)
            block_result = None
            if success and self.threat_manager:
                block_result = self.threat_manager.mark_blocked(
                    pid=alert.pid,
                    process_name=alert.process_name,
                    score=int(self.killswitch.threat_threshold),
                    operation="user_kill",
                )
                summary = block_result.get("summary", {})
                self._send_websocket_alert({
                    "type": "protection_action",
                    "data": {
                        "success": True,
                        "action": "terminated",
                        "reason": "manual_kill",
                        "pid": alert.pid,
                        "process": alert.process_name,
                        "status": "BLOCKED",
                        "score": int(self.killswitch.threat_threshold),
                        "active_threats": int(summary.get("active_threats", 0)),
                        "blocked_threats": int(summary.get("blocked_threats", 0)),
                        "total_threats": int(summary.get("total_threats", 0)),
                        "timestamp": time.time(),
                    },
                })
            result = {"success": success, "message": "Kill successful" if success else "Kill failed"}
            print(f"[ KILL RESULT] {result['message']}")
        
        elif decision == "QUARANTINE":
            # Quarantine mode
            self.killswitch.enable_quarantine_mode()
            success = self.killswitch.kill_process_tree(alert.process_name, alert.pid)
            self.killswitch.suspended_processes.pop(alert.pid, None)
            block_result = None
            if success and self.threat_manager:
                block_result = self.threat_manager.mark_blocked(
                    pid=alert.pid,
                    process_name=alert.process_name,
                    score=int(self.killswitch.threat_threshold),
                    operation="user_quarantine",
                )
                summary = block_result.get("summary", {})
                self._send_websocket_alert({
                    "type": "protection_action",
                    "data": {
                        "success": True,
                        "action": "terminated",
                        "reason": "manual_quarantine",
                        "pid": alert.pid,
                        "process": alert.process_name,
                        "status": "BLOCKED",
                        "score": int(self.killswitch.threat_threshold),
                        "active_threats": int(summary.get("active_threats", 0)),
                        "blocked_threats": int(summary.get("blocked_threats", 0)),
                        "total_threats": int(summary.get("total_threats", 0)),
                        "timestamp": time.time(),
                    },
                })
            result = {"success": success, "message": "Quarantine successful" if success else "Quarantine failed"}
            print(f"[ QUARANTINE RESULT] {result['message']}")
        
        elif decision == "WHITELIST":
            # Whitelist = unblock process
            self.killswitch.unblock_process(alert.process_name)
            self.killswitch.resume_process(alert.pid)
            result = {"success": True, "message": f"{alert.process_name} whitelisted"}
            print(f"[ WHITELIST RESULT] {result['message']}")
        
        elif decision == "IGNORE":
            # Ignore = resume process
            self.killswitch.resume_process(alert.pid)
            result = {"success": True, "message": "Threat ignored"}
            print(f"[IGNORED] IGNORE RESULT] {result['message']}")
        
        # Send result back to web dashboard
        self._send_websocket_alert({
            "type": "decision_result",
            "alert_id": alert_id,
            "decision": decision,
            "result": result
        })

    def _send_websocket_alert(self, message: dict) -> None:
        """Send alert to web dashboard via WebSocket"""
        if self.callback:
            self.callback(message)

    
    def handle_event(self, event: ThreatEvent) -> None:
        """Centralized PID-first event pipeline."""
        if not event:
            return

        pid = int(event.pid or 0)
        if pid <= 0:
            return

        if self._is_blocked_pid(pid, self._get_process_create_time(pid)):
            logger.info("IGNORED EVENT (POST-BLOCK) pid=%s", pid)
            return

        event.metadata = event.metadata or {}
        dedup_event_type = str(event.operation or event.event_type or "unknown")
        logger.info(
            "EVENT RECEIVED: pid=%s event_type=%s file=%s",
            pid,
            dedup_event_type,
            event.file_path or "",
        )

        if not self._is_live_pid(pid):
            logger.debug("[EVENT IGNORED] Invalid or dead PID pid=%s type=%s", pid, dedup_event_type)
            return

        if self._is_duplicate_event(pid, event.file_path or "", dedup_event_type):
            return

        process_name = self._resolve_process_name(pid, event.process)
        event.process = process_name
        self.stats['total_events'] += 1
        if event.suspicion_score >= self.killswitch.threat_threshold:
            self.stats['high_risk_events'] += 1

        event_dict = event.to_dict()
        event_dict.setdefault("metadata", {})
        event_dict["metadata"].setdefault("pipeline_phase", "phase_2_scored")
        event_dict["metadata"].setdefault("pipeline_model", "3-phase")

        registry_result = None
        if self.file_intel.research_hook:
            try:
                # Decision timestamp is taken before ThreatManager can block
                # the PID, so it cannot collapse into containment time.
                self.file_intel.research_hook("decision", event, None)
            except Exception:
                logger.debug("[RESEARCH] decision hook failed", exc_info=True)
        if self.threat_manager:
            registry_result = self.threat_manager.process_event(pid, event_dict)

        if self.file_intel.research_hook:
            try:
                if registry_result and registry_result.get("block_attempted"):
                    self.file_intel.research_hook("containment", event, registry_result)
            except Exception:
                logger.debug("[RESEARCH] telemetry hook failed", exc_info=True)

        if registry_result and not registry_result.get("tracked"):
            return

        summary = registry_result.get("summary") if registry_result else (
            self.threat_manager.get_summary() if self.threat_manager else {"active_threats": 0, "blocked_threats": 0, "total_threats": 0, "threats": []}
        )
        threat_snapshot = registry_result.get("threat") if registry_result else None
        threat_status = str((threat_snapshot or {}).get("status") or "")

        event.metadata["threat"] = threat_snapshot or {}
        event.metadata["threat_counts"] = {
            "active_threats": int(summary.get("active_threats", 0)),
            "blocked_threats": int(summary.get("blocked_threats", 0)),
            "total_threats": int(summary.get("total_threats", 0)),
        }
        event.metadata["threat_status"] = threat_status

        if registry_result:
            if registry_result.get("created"):
                event.metadata["threat_registry_action"] = "created"
            elif registry_result.get("block_attempted"):
                event.metadata["threat_registry_action"] = "blocked"
            else:
                event.metadata["threat_registry_action"] = "updated"

        if threat_status in {"DETECTED", "ANALYZING"}:
            self.active_threats[pid] = event
        else:
            self.active_threats.pop(pid, None)

        self.threat_history.append(event)

        cutoff = time.time() - 300
        self.active_threats = {
            tracked_pid: tracked_event
            for tracked_pid, tracked_event in self.active_threats.items()
            if tracked_event.timestamp > cutoff
        }

        if registry_result and registry_result.get("block_attempted"):
            kill_success = bool(registry_result.get("kill_success"))
            if kill_success:
                self.stats["processes_killed"] += 1

            try:
                self.notification_manager.send_info_notification(
                    title="Threat blocked" if kill_success else "Threat action required",
                    line1=(
                        f"{process_name} (PID {pid}) terminated"
                        if kill_success
                        else f"{process_name} (PID {pid}) could not be terminated"
                    ),
                    line2=(
                        f"Score {int(event.suspicion_score or 0)} | "
                        f"Source {event.metadata.get('source', event.event_type)}"
                    ),
                )
            except Exception:
                logger.debug("[TOAST] Automatic protection notification failed", exc_info=True)

            logger.warning(
                "[AUTO-CONTAINMENT] %s pid=%s process=%s score=%s threshold=%s active=%s blocked=%s",
                "SUCCESS" if kill_success else "FAILED",
                pid,
                process_name,
                int(event.suspicion_score or 0),
                int(self.threat_manager.block_threshold if self.threat_manager else self.killswitch.threat_threshold),
                int(summary.get("active_threats", 0)),
                int(summary.get("blocked_threats", 0)),
            )

            action_payload = {
                "success": kill_success,
                "action": "terminated" if kill_success else "termination_failed",
                "reason": "threshold_reached",
                "pid": pid,
                "process": process_name,
                "status": "BLOCKED",
                "score": int(event.suspicion_score or 0),
                "threshold": int(self.threat_manager.block_threshold if self.threat_manager else self.killswitch.threat_threshold),
                "source": event.metadata.get("source", event.event_type),
                "timestamp": time.time(),
                "indicators": list(event.indicators or []),
                "active_threats": int(summary.get("active_threats", 0)),
                "blocked_threats": int(summary.get("blocked_threats", 0)),
                "total_threats": int(summary.get("total_threats", 0)),
            }
            self._send_websocket_alert({"type": "protection_action", "data": action_payload})

        if self.callback:
            callback_event = event.to_dict()
            callback_event.setdefault("metadata", {})
            callback_event["metadata"].update(event.metadata)
            self.callback(callback_event)

        if event.threat_level == 'critical':
            print(f" CRITICAL THREAT: {event.process} | Score: {event.suspicion_score} | Indicators: {event.indicators[:3]}")

    def _handle_threat_event(self, event: ThreatEvent) -> None:
        self.handle_event(event)
    
    def _get_default_watch_paths(self) -> List[str]:
        """Get default directories to monitor"""
        paths = []
        
        if platform.system() == 'Windows':
            user_profile = os.environ.get('USERPROFILE', '')
            if user_profile:
                for folder in ['Desktop', 'Documents', 'Downloads', 'Pictures', 'Videos', 'Music']:
                    path = os.path.join(user_profile, folder)
                    if os.path.isdir(path):
                        paths.append(path)
        else:
            home = os.path.expanduser('~')
            for folder in ['Desktop', 'Documents', 'Downloads', 'Pictures', 'Videos', 'Music']:
                path = os.path.join(home, folder)
                if os.path.isdir(path):
                    paths.append(path)
        
        # Add demo directory for testing
        demo_dir = runtime_path("data/test_monitoring/demo_ransomware")
        paths.append(demo_dir)
        
        return paths
    
    def _start_file_monitoring(self, paths: List[str]) -> None:
        """Start file system monitoring on specified paths"""
        if not paths:
            print("  No paths provided for file monitoring")
            return
        
        print(f"\n Starting file system monitoring:")
        # Store paths for file counting
        if not hasattr(self.file_intel, "monitored_paths"):
            self.file_intel.monitored_paths = []

        existing = {
            os.path.normcase(os.path.abspath(p)) for p in self.file_intel.monitored_paths
        }
        for path in paths:
            if not os.path.exists(path):
                print(f"    Path not found: {path}")
                continue

            norm_path = os.path.normcase(os.path.abspath(path))
            if norm_path in existing:
                continue
            
            try:
                observer = Observer()
                observer.schedule(self.file_intel, path, recursive=True)
                observer.start()
                self.file_observers.append(observer)
                self.file_intel.monitored_paths.append(path)
                existing.add(norm_path)
                print(f" Monitoring: {path}")
            except Exception as e:
                print(f" Failed to monitor {path}: {e}")
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get comprehensive statistics"""
        uptime = time.time() - self.stats['uptime_start']
        threat_summary = self.threat_manager.get_summary(include_closed=True) if self.threat_manager else {
            "active_threats": 0,
            "blocked_threats": 0,
            "total_threats": 0,
            "threats": [],
        }
        
        return {
            'uptime_seconds': int(uptime),
            'monitoring_active': self.monitoring,
            'total_events': self.stats['total_events'],
            'high_risk_events': self.stats['high_risk_events'],
            'processes_killed': self.stats['processes_killed'],
            'active_threats_count': int(threat_summary.get('active_threats', 0)),
            'blocked_threats_count': int(threat_summary.get('blocked_threats', 0)),
            'total_threats': int(threat_summary.get('total_threats', 0)),
            'threats': list(threat_summary.get('threats', [])),
            'process_intelligence': self.process_intel.get_statistics(),
            'file_intelligence': self.file_intel.get_statistics(),
            'network_intelligence': self.network_intel.get_statistics(),
            'monitor': {
                'baseline_established': self.process_intel.baseline_established,
                'file_observers': len(self.file_observers),
                'file_stats': self.file_intel.get_statistics(),
                'thread_alive': bool(self.monitoring_thread and self.monitoring_thread.is_alive()),
                'restart_count': self.restart_count,
            },
            'killswitch': {
                'enabled': self.killswitch.enabled,
                'threat_threshold': self.killswitch.threat_threshold,
                'auto_terminate': True
            }
        }
    
    def get_recent_events(self, limit: int = 100) -> List[Dict[str, Any]]:
        """Get recent threat events"""
        events = list(self.threat_history)[-limit:]
        return [event.to_dict() for event in reversed(events)]
