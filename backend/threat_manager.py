import logging
import os
import threading
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, Optional

import psutil

logger = logging.getLogger("threat_manager")


class ThreatStatus(str, Enum):
    DETECTED = "DETECTED"
    ANALYZING = "ANALYZING"
    BLOCKED = "BLOCKED"
    CLOSED = "CLOSED"


ACTIVE_STATUSES = {ThreatStatus.DETECTED, ThreatStatus.ANALYZING}


@dataclass
class ThreatRecord:
    pid: int
    process_name: str
    status: ThreatStatus
    score: int
    files_affected: int
    first_seen: float
    last_seen: float
    process_create_time: Optional[float] = None
    last_file_path: str = ""
    last_event_type: str = ""
    last_operation: str = ""
    events_seen: int = 0
    was_blocked: bool = False
    block_successful: bool = False
    _file_paths: set[str] = field(default_factory=set)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "pid": self.pid,
            "process_name": self.process_name,
            "status": self.status.value,
            "score": self.score,
            "files_affected": self.files_affected,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "process_create_time": self.process_create_time,
            "last_file_path": self.last_file_path,
            "last_event_type": self.last_event_type,
            "last_operation": self.last_operation,
            "events_seen": self.events_seen,
            "was_blocked": self.was_blocked,
            "block_successful": self.block_successful,
        }

    def to_api_dict(self) -> Dict[str, Any]:
        if self.status in ACTIVE_STATUSES:
            ui_status = "ACTIVE"
        elif self.status == ThreatStatus.BLOCKED:
            ui_status = "BLOCKED"
        else:
            ui_status = self.status.value

        return {
            "pid": self.pid,
            "status": ui_status,
            "score": self.score,
            "files_affected": self.files_affected,
            "process_name": self.process_name,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "last_file_path": self.last_file_path,
            "last_event_type": self.last_event_type,
            "last_operation": self.last_operation,
            "was_blocked": self.was_blocked,
        }


class ThreatManager:
    """
    Thread-safe PID-first threat registry.

    One live PID maps to one threat record. All public counts are derived directly
    from the registry on demand so API responses never rely on external cached
    counters.
    """

    def __init__(self, block_threshold: int = 70, blocked_retention_seconds: float = 8.0):
        self.block_threshold = int(block_threshold)
        self.blocked_retention_seconds = max(float(blocked_retention_seconds), 0.0)
        self._lock = threading.Lock()
        self._threats: Dict[int, ThreatRecord] = {}
        self._close_timers: Dict[int, threading.Timer] = {}
        # Exact-PID exemptions are used only by the controlled, benign demo
        # process. They never apply to arbitrary processes by name.
        self._lab_exempt_pids: set[int] = set()

    def exempt_pid(self, pid: int) -> None:
        """Keep a registered lab process observable without terminating it."""
        normalized_pid = int(pid or 0)
        if normalized_pid > 0:
            with self._lock:
                self._lab_exempt_pids.add(normalized_pid)

    def remove_pid_exemption(self, pid: int) -> None:
        with self._lock:
            self._lab_exempt_pids.discard(int(pid or 0))

    def process_event(self, pid: int, event: Dict[str, Any]) -> Dict[str, Any]:
        """
        Create or update a threat for a live PID, and block it once when the score
        reaches the configured threshold.
        """
        normalized_pid = int(pid or 0)
        if normalized_pid <= 0:
            return self._build_result(tracked=False, block_attempted=False, block_success=False)

        if normalized_pid == os.getpid():
            logger.warning("Ignoring self PID in threat manager: pid=%s", normalized_pid)
            return self._build_result(tracked=False, block_attempted=False, block_success=False)

        if not psutil.pid_exists(normalized_pid):
            return self._build_result(tracked=False, block_attempted=False, block_success=False)

        event = dict(event or {})
        timestamp = float(event.get("timestamp") or time.time())
        score = int(event.get("suspicion_score") or 0)
        file_path = str(event.get("file_path") or "").strip()
        operation = str(event.get("operation") or "").strip()
        event_type = str(event.get("event_type") or event.get("type") or operation or "unknown").strip() or "unknown"
        entropy = float(event.get("entropy") or 0.0)
        file_ext = os.path.splitext(file_path)[1].lower()
        process_name = self._resolve_process_name(normalized_pid, str(event.get("process") or "unknown"))
        process_create_time = self._get_process_create_time(normalized_pid)
        block_reasons = []
        if score >= self.block_threshold:
            block_reasons.append(f"score>={self.block_threshold}")
        if entropy > 7.5:
            block_reasons.append(f"entropy>{7.5}")
        if file_ext in {".lockbit", ".encrypted", ".crypt"}:
            block_reasons.append(f"ext={file_ext}")

        should_block = False
        created = False
        block_history_count = None
        block_history_count = None
        with self._lock:
            lab_exempt = normalized_pid in self._lab_exempt_pids
            record = self._threats.get(normalized_pid)
            if record is None or self._should_start_new_incident(record, process_name, process_create_time):
                record = ThreatRecord(
                    pid=normalized_pid,
                    process_name=process_name,
                    status=ThreatStatus.DETECTED,
                    score=score,
                    files_affected=0,
                    first_seen=timestamp,
                    last_seen=timestamp,
                    process_create_time=process_create_time,
                )
                self._threats[normalized_pid] = record
                created = True
                logger.warning("NEW THREAT CREATED: pid=%s process=%s score=%s", normalized_pid, process_name, score)
            else:
                logger.info(
                    "THREAT UPDATED: pid=%s process=%s previous_score=%s incoming_score=%s",
                    normalized_pid,
                    record.process_name,
                    record.score,
                    score,
                )

            record.process_name = process_name
            record.process_create_time = process_create_time or record.process_create_time
            record.score = max(record.score, score)
            record.last_seen = timestamp
            record.last_event_type = event_type
            record.last_operation = operation or record.last_operation
            record.events_seen += 1
            if file_path:
                record.last_file_path = file_path
                if file_path not in record._file_paths:
                    record._file_paths.add(file_path)
                    record.files_affected += 1

            if record.status in ACTIVE_STATUSES and record.events_seen > 1:
                record.status = ThreatStatus.ANALYZING

            if record.status != ThreatStatus.BLOCKED:
                self._cancel_close_timer_locked(normalized_pid)

            if block_reasons and not lab_exempt:
                if record.status == ThreatStatus.BLOCKED:
                    logger.info("PROCESS ALREADY BLOCKED: pid=%s", normalized_pid)
                else:
                    record.status = ThreatStatus.BLOCKED
                    should_block = True
            elif block_reasons and lab_exempt:
                logger.info(
                    "LAB DEMO EXEMPTION: recording threat without termination pid=%s",
                    normalized_pid,
                )

            threat_snapshot = record.to_dict()
            summary = self._build_summary_locked()

        block_success = False
        if should_block:
            logger.warning(
                "BLOCK TRIGGERED pid=%s reason=%s score=%s",
                normalized_pid,
                ",".join(block_reasons) or "threshold",
                record.score if 'record' in locals() and record is not None else score,
            )
            block_success = self.block_process(normalized_pid)
            with self._lock:
                record = self._threats.get(normalized_pid)
                if record is not None:
                    if not block_success and psutil.pid_exists(normalized_pid):
                        record.status = ThreatStatus.ANALYZING if record.events_seen > 1 else ThreatStatus.DETECTED
                        self._cancel_close_timer_locked(normalized_pid)
                    elif block_success and not record.was_blocked:
                        record.was_blocked = True
                        block_history_count = self._count_block_history_locked()
                    record.block_successful = block_success
                    record.last_seen = time.time()
                    threat_snapshot = record.to_dict()
                    summary = self._build_summary_locked()
            if block_success:
                logger.critical("BLOCK SUCCESS pid=%s", normalized_pid)
                logger.critical("PROCESS BLOCKED pid=%s", normalized_pid)
                logger.critical("THREAT BLOCKED pid=%s", normalized_pid)
                if block_history_count is not None:
                    logger.info("BLOCK HISTORY COUNT updated: %s", block_history_count)
                self._schedule_blocked_close(normalized_pid, threat_snapshot.get("process_create_time") if threat_snapshot else None)
            else:
                logger.error("PROCESS BLOCK FAILED: pid=%s", normalized_pid)

        return {
            "tracked": True,
            "created": created,
            "block_attempted": should_block,
            "blocked": should_block and block_success,
            "kill_success": block_success,
            "threat": threat_snapshot,
            "summary": summary,
        }

    def mark_blocked(
        self,
        *,
        pid: int,
        process_name: str,
        score: int = 0,
        timestamp: Optional[float] = None,
        file_path: str = "",
        operation: str = "",
    ) -> Dict[str, Any]:
        normalized_pid = int(pid or 0)
        if normalized_pid <= 0:
            return self._build_result(tracked=False, block_attempted=False, block_success=False)

        ts = float(timestamp or time.time())
        normalized_name = self._resolve_process_name(normalized_pid, process_name)
        bounded_score = max(int(score or 0), self.block_threshold)
        process_create_time = self._get_process_create_time(normalized_pid)
        created = False

        with self._lock:
            record = self._threats.get(normalized_pid)
            if record is None or self._should_start_new_incident(record, normalized_name, process_create_time):
                record = ThreatRecord(
                    pid=normalized_pid,
                    process_name=normalized_name,
                    status=ThreatStatus.BLOCKED,
                    score=bounded_score,
                    files_affected=0,
                    first_seen=ts,
                    last_seen=ts,
                    process_create_time=process_create_time,
                    was_blocked=True,
                    block_successful=True,
                )
                self._threats[normalized_pid] = record
                created = True
                block_history_count = self._count_block_history_locked()
                logger.warning("NEW THREAT CREATED: pid=%s process=%s score=%s", normalized_pid, normalized_name, bounded_score)
            else:
                if record.status == ThreatStatus.BLOCKED:
                    logger.info("PROCESS ALREADY BLOCKED: pid=%s", normalized_pid)
                else:
                    logger.critical("PROCESS BLOCKED pid=%s", normalized_pid)
                record.status = ThreatStatus.BLOCKED
                record.score = max(record.score, bounded_score)
                record.last_seen = ts
                record.process_name = normalized_name
                record.process_create_time = process_create_time or record.process_create_time
                if not record.was_blocked:
                    record.was_blocked = True
                    block_history_count = self._count_block_history_locked()

            record.block_successful = True
            record.events_seen += 1
            record.last_event_type = operation or record.last_event_type or "manual"
            record.last_operation = operation or record.last_operation
            if file_path:
                record.last_file_path = file_path
                if file_path not in record._file_paths:
                    record._file_paths.add(file_path)
                    record.files_affected += 1
            summary = self._build_summary_locked()
            threat_snapshot = record.to_dict()

        if created:
            logger.critical("PROCESS BLOCKED pid=%s", normalized_pid)
        if block_history_count is not None:
            logger.critical("THREAT BLOCKED pid=%s", normalized_pid)
            logger.info("BLOCK HISTORY COUNT updated: %s", block_history_count)
        self._schedule_blocked_close(normalized_pid, threat_snapshot.get("process_create_time") if threat_snapshot else None)

        return {
            "tracked": True,
            "created": created,
            "block_attempted": False,
            "blocked": True,
            "kill_success": True,
            "threat": threat_snapshot,
            "summary": summary,
        }

    def mark_closed(
        self,
        pid: int,
        *,
        allow_blocked: bool = False,
        expected_create_time: Optional[float] = None,
    ) -> bool:
        normalized_pid = int(pid or 0)
        if normalized_pid <= 0:
            return False

        with self._lock:
            record = self._threats.get(normalized_pid)
            if not record:
                return False
            if (
                expected_create_time is not None
                and record.process_create_time is not None
                and abs(record.process_create_time - expected_create_time) > 0.001
            ):
                return False
            if record.status == ThreatStatus.BLOCKED and not allow_blocked:
                return False
            if record.status == ThreatStatus.CLOSED:
                self._cancel_close_timer_locked(normalized_pid)
                return False
            record.status = ThreatStatus.CLOSED
            record.last_seen = time.time()
            process_name = record.process_name
            was_blocked = record.was_blocked
            self._cancel_close_timer_locked(normalized_pid)

        if was_blocked:
            logger.info("THREAT CLOSED pid=%s process=%s (history preserved)", normalized_pid, process_name)
        else:
            logger.info("THREAT CLOSED pid=%s process=%s", normalized_pid, process_name)
        return True

    def is_blocked(self, pid: int, process_create_time: Optional[float] = None) -> bool:
        normalized_pid = int(pid or 0)
        if normalized_pid <= 0:
            return False

        with self._lock:
            record = self._threats.get(normalized_pid)
            if not record or record.status != ThreatStatus.BLOCKED:
                return False
            if (
                process_create_time is not None
                and record.process_create_time is not None
                and abs(record.process_create_time - process_create_time) > 0.001
            ):
                return False
            return True

    def cleanup_stale(self, ttl_seconds: int = 300) -> int:
        now = time.time()
        closed = 0
        with self._lock:
            for record in self._threats.values():
                if record.status == ThreatStatus.BLOCKED:
                    continue
                if (now - record.last_seen) < ttl_seconds:
                    continue
                if psutil.pid_exists(record.pid):
                    continue
                if record.status != ThreatStatus.CLOSED:
                    record.status = ThreatStatus.CLOSED
                    record.last_seen = now
                    self._cancel_close_timer_locked(record.pid)
                    closed += 1
                    if record.was_blocked:
                        logger.info("THREAT CLOSED pid=%s process=%s (history preserved)", record.pid, record.process_name)
                    else:
                        logger.info("THREAT CLOSED pid=%s process=%s", record.pid, record.process_name)
        return closed

    def get_counts(self) -> Dict[str, int]:
        summary = self.get_summary()
        return {
            "active_threats": int(summary["active_threats"]),
            "blocked_threats": int(summary["blocked_threats"]),
            "total_threats": int(summary["total_threats"]),
        }

    def get_threat(self, pid: int) -> Optional[Dict[str, Any]]:
        normalized_pid = int(pid or 0)
        if normalized_pid <= 0:
            return None
        with self._lock:
            record = self._threats.get(normalized_pid)
            return record.to_api_dict() if record else None

    def get_summary(self, include_closed: bool = False) -> Dict[str, Any]:
        with self._lock:
            return self._build_summary_locked(include_closed=include_closed)

    def get_registry_snapshot(self) -> Dict[int, Dict[str, Any]]:
        with self._lock:
            return {pid: record.to_dict() for pid, record in self._threats.items()}

    def _build_summary_locked(self, include_closed: bool = False) -> Dict[str, Any]:
        active = 0
        blocked = self._count_block_history_locked()
        threats = []

        for record in self._threats.values():
            if record.status in ACTIVE_STATUSES:
                active += 1
                threats.append(record.to_api_dict())
            elif record.status == ThreatStatus.BLOCKED:
                threats.append(record.to_api_dict())
            elif include_closed:
                threats.append(record.to_api_dict())

        threats.sort(
            key=lambda item: (
                self._status_sort_order(item.get("status")),
                -int(item.get("score") or 0),
                -(float(item.get("first_seen") or 0.0)),
                -int(item.get("pid") or 0),
            )
        )
        return {
            "active_threats": active,
            "blocked_threats": blocked,
            "total_threats": len(self._threats),
            "threats": threats,
        }

    def _build_result(self, *, tracked: bool, block_attempted: bool, block_success: bool) -> Dict[str, Any]:
        return {
            "tracked": tracked,
            "created": False,
            "block_attempted": block_attempted,
            "blocked": block_success,
            "kill_success": block_success,
            "threat": None,
            "summary": self.get_summary(),
        }

    def _should_start_new_incident(
        self,
        record: ThreatRecord,
        process_name: str,
        process_create_time: Optional[float],
    ) -> bool:
        if record.status not in {ThreatStatus.BLOCKED, ThreatStatus.CLOSED}:
            return False

        if process_create_time is None:
            return False

        if record.process_create_time is None:
            return True

        if abs(record.process_create_time - process_create_time) > 0.001:
            return True

        if process_name and record.process_name.lower() != process_name.lower():
            return True

        return False

    def _resolve_process_name(self, pid: int, fallback: str = "unknown") -> str:
        fallback = str(fallback or "").strip() or "unknown"
        try:
            proc = psutil.Process(pid)
            name = (proc.name() or "").strip()
            if name:
                return name
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            pass
        return fallback

    def _get_process_create_time(self, pid: int) -> Optional[float]:
        try:
            return float(psutil.Process(pid).create_time())
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess, ValueError):
            return None

    def block_process(self, pid: int) -> bool:
        return self._kill_process(pid)

    def _schedule_blocked_close(self, pid: int, process_create_time: Optional[float]) -> None:
        if self.blocked_retention_seconds <= 0:
            self.mark_closed(pid, allow_blocked=True, expected_create_time=process_create_time)
            return

        timer = threading.Timer(
            self.blocked_retention_seconds,
            self._auto_close_blocked_threat,
            args=(int(pid), process_create_time),
        )
        timer.daemon = True

        with self._lock:
            self._cancel_close_timer_locked(pid)
            self._close_timers[int(pid)] = timer

        timer.start()

    def _auto_close_blocked_threat(self, pid: int, expected_create_time: Optional[float]) -> None:
        self.mark_closed(pid, allow_blocked=True, expected_create_time=expected_create_time)

    def _cancel_close_timer_locked(self, pid: int) -> None:
        timer = self._close_timers.pop(int(pid), None)
        if timer is not None:
            timer.cancel()

    def _count_block_history_locked(self) -> int:
        return sum(1 for record in self._threats.values() if record.was_blocked)

    def _status_sort_order(self, status: Optional[str]) -> int:
        normalized = str(status or "").upper()
        if normalized == "ACTIVE":
            return 0
        if normalized == "BLOCKED":
            return 1
        if normalized == "CLOSED":
            return 2
        return 3

    def _kill_process(self, pid: int) -> bool:
        if pid <= 0 or pid == os.getpid():
            return False

        proc: Optional[psutil.Process] = None
        try:
            proc = psutil.Process(pid)
            proc.terminate()
            proc.wait(timeout=3)
            return True
        except psutil.NoSuchProcess:
            return True
        except (psutil.TimeoutExpired, psutil.AccessDenied, OSError):
            pass
        except Exception:
            logger.exception("Unexpected terminate failure for pid=%s", pid)

        try:
            if proc is None:
                proc = psutil.Process(pid)
            proc.kill()
            proc.wait(timeout=3)
            return True
        except psutil.NoSuchProcess:
            return True
        except Exception:
            logger.exception("Force kill failed for pid=%s", pid)
            return not psutil.pid_exists(pid)
