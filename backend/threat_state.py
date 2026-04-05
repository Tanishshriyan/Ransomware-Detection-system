# backend/threat_state.py
from collections import deque
from dataclasses import dataclass
from enum import Enum
from threading import Lock
from typing import Dict, Iterable, Optional
import time


@dataclass
class ProcessEvent:
    pid: int
    name: str
    score: float
    risk: str




class ThreatState(Enum):
    NORMAL = "NORMAL"
    EVALUATING = "EVALUATING"
    SUSPENDED = "SUSPENDED"
    TERMINATED = "TERMINATED"
    WHITELISTED = "WHITELISTED"


class ProcessState:
    def __init__(self, pid: int):
        self.pid = pid
        self.state = ThreatState.NORMAL
        self.last_transition = time.time()
        self.last_ml_score = None
        self.suspend_time = None


class ThreatStateMachine:
    def __init__(self):
        self._states: Dict[int, ProcessState] = {}
        self._lock = Lock()

    def _get_unlocked(self, pid: int) -> ProcessState:
        if pid not in self._states:
            self._states[pid] = ProcessState(pid)
        return self._states[pid]

    def get(self, pid: int) -> ProcessState:
        with self._lock:
            return self._get_unlocked(pid)

    def transition(self, pid: int, new_state: ThreatState) -> bool:
        with self._lock:
            ps = self._get_unlocked(pid)
            current = ps.state

            allowed = {
                ThreatState.NORMAL: {ThreatState.EVALUATING},
                ThreatState.EVALUATING: {
                    ThreatState.NORMAL,
                    ThreatState.SUSPENDED,
                    ThreatState.TERMINATED,
                    ThreatState.EVALUATING,
                },
                ThreatState.SUSPENDED: {
                    ThreatState.NORMAL,
                    ThreatState.TERMINATED,
                },
            }

            if current in {ThreatState.TERMINATED, ThreatState.WHITELISTED}:
                return False

            if new_state not in allowed.get(current, set()):
                return False

            ps.state = new_state
            ps.last_transition = time.time()

            if new_state == ThreatState.SUSPENDED:
                ps.suspend_time = ps.last_transition
            elif new_state == ThreatState.NORMAL:
                ps.suspend_time = None

            return True

    def can_evaluate(self, pid: int) -> bool:
        with self._lock:
            state = self._get_unlocked(pid).state
            return state in {ThreatState.NORMAL, ThreatState.EVALUATING}

    def is_suspended(self, pid: int) -> bool:
        with self._lock:
            return self._get_unlocked(pid).state == ThreatState.SUSPENDED

    def mark_ml_score(self, pid: int, score: float):
        with self._lock:
            ps = self._get_unlocked(pid)
            ps.last_ml_score = score

    def get_state(self, pid: int) -> ThreatState:
        with self._lock:
            return self._get_unlocked(pid).state

    def cleanup(
        self,
        active_pids: Optional[Iterable[int]] = None,
        *,
        ttl_seconds: int = 600,
    ) -> int:
        """Prune stale process state so long-running sessions stay lightweight."""
        active = set(active_pids or [])
        now = time.time()
        removed = []

        with self._lock:
            for pid, ps in list(self._states.items()):
                if pid in active:
                    continue
                if ps.state in {ThreatState.SUSPENDED, ThreatState.EVALUATING}:
                    continue
                if (now - ps.last_transition) >= ttl_seconds:
                    removed.append(pid)

            for pid in removed:
                self._states.pop(pid, None)

        return len(removed)

    def tracked_count(self) -> int:
        with self._lock:
            return len(self._states)

class EventBuffer:
    def __init__(self, max_size=5000):
        self._events = deque(maxlen=max_size)
        self._lock = Lock()

    def add(self, event: dict):
        with self._lock:
            self._events.append(event)

    def snapshot(self):
        with self._lock:
            return list(self._events)

EVENT_BUFFER = EventBuffer()
