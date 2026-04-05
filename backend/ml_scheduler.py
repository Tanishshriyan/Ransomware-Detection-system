# backend/ml_scheduler.py
import asyncio
import logging
import time

from backend.threat_state import ThreatState

logger = logging.getLogger("ml_scheduler")


class MLScheduler:
    def __init__(
        self,
        state_machine,
        analyzer,
        detector,
        whitelist,
        list_active_processes,
        dashboard_broadcast,
        maintenance_callback=None,
        interval_seconds=2.0,
    ):
        self.state_machine = state_machine
        self.analyzer = analyzer
        self.detector = detector
        self.whitelist = whitelist
        self.list_active_processes = list_active_processes
        self.dashboard_broadcast = dashboard_broadcast
        self.maintenance_callback = maintenance_callback
        self.interval = interval_seconds
        self._running = False

    @staticmethod
    def decide_transition(probability: float) -> ThreatState:
        """Map ML probability to target threat state."""
        if probability >= 0.85:
            return ThreatState.TERMINATED
        if probability >= 0.70:
            return ThreatState.SUSPENDED
        return ThreatState.NORMAL

    def _evaluate_pid(self, pid: int, process_name: str):
        # Fast pre-checks
        if pid <= 0:
            return False, False
        if self.whitelist.is_whitelisted(process_name):
            return False, False
        if not self.state_machine.can_evaluate(pid):
            return False, False

        # Atomic transition into EVALUATING
        if not self.state_machine.transition(pid, ThreatState.EVALUATING):
            return False, False

        try:
            analysis = self.analyzer.extract_features(pid)
            if not analysis or not analysis.get("valid"):
                self.state_machine.transition(pid, ThreatState.NORMAL)
                return True, False

            result = self.detector.analyze_features(analysis)
            prob = result.get("probability")
            if prob is None:
                self.state_machine.transition(pid, ThreatState.NORMAL)
                return True, False

            self.state_machine.mark_ml_score(pid, prob)
            requested = self.decide_transition(prob)
            self.state_machine.transition(pid, requested)

            if requested in {ThreatState.SUSPENDED, ThreatState.TERMINATED}:
                logger.info("[ML] pid=%s score=%.3f decision=%s", pid, prob, requested.value)

            # Dashboard telemetry (best effort)
            try:
                asyncio.create_task(
                    self.dashboard_broadcast(
                        {
                            "type": "telemetry",
                            "data": {
                                "pid": pid,
                                "process_name": process_name,
                                "ml_score": prob,
                                "state": self.state_machine.get_state(pid).value,
                                "timestamp": time.time(),
                            },
                        }
                    )
                )
            except RuntimeError:
                logger.debug("[ML] Telemetry broadcast skipped (no event loop)")
            return True, requested in {ThreatState.SUSPENDED, ThreatState.TERMINATED}

        except Exception as e:
            logger.exception("[ML] evaluation error for pid=%s: %s", pid, e)

            # Fail closed: suspend on analysis errors.
            self.state_machine.transition(pid, ThreatState.SUSPENDED)

            try:
                asyncio.create_task(
                    self.dashboard_broadcast(
                        {
                            "type": "ml_error",
                            "data": {
                                "pid": pid,
                                "process_name": process_name,
                                "error": str(e),
                                "action": "suspended_for_review",
                                "timestamp": time.time(),
                            },
                        }
                    )
                )
            except RuntimeError:
                logger.debug("[ML] Cannot broadcast error - no event loop")
            return True, True

    async def run(self):
        logger.info("[ML-SCHEDULER] started (interval=%.1fs)", self.interval)
        self._running = True

        while self._running:
            start = time.time()
            evaluated = 0
            elevated = 0
            active_pids = []
            try:
                for pid, process_name in list(self.list_active_processes()):
                    active_pids.append(pid)
                    did_eval, did_elevate = self._evaluate_pid(pid, process_name)
                    if did_eval:
                        evaluated += 1
                    if did_elevate:
                        elevated += 1
                if self.maintenance_callback:
                    self.maintenance_callback(active_pids)
            except Exception:
                logger.exception("[ML-SCHEDULER] cycle error")
            logger.debug("[ML] cycle complete evaluated=%d elevated=%d", evaluated, elevated)

            elapsed = time.time() - start
            await asyncio.sleep(max(0.0, self.interval - elapsed))

    def stop(self):
        self._running = False
        logger.info("[ML-SCHEDULER] stopping")
