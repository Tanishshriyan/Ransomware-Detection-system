# backend/policy_enforcer.py
import logging
import time
from typing import Optional

from backend.threat_state import ThreatState, ThreatStateMachine
from backend.killswitch import KillSwitch

logger = logging.getLogger("policy_enforcer")


class PolicyEnforcer:
    def __init__(
        self,
        state_machine: ThreatStateMachine,
        killswitch: KillSwitch,
        suspend_timeout_seconds: int = 30,
    ):
        self.state_machine = state_machine
        self.killswitch = killswitch
        self.suspend_timeout = suspend_timeout_seconds
    def enforce(self, pid: int, process_name: Optional[str] = None):
        """
        Enforce OS-level actions based on the current state of the process.
        This method is idempotent and safe to call repeatedly.
        """
        ps = self.state_machine.get(pid)
        state = ps.state

        if state == ThreatState.SUSPENDED:
            self._enforce_suspend(pid)

        elif state == ThreatState.TERMINATED:
            self._enforce_kill(pid, process_name)

        # NORMAL, EVALUATING, WHITELISTED → no OS action
    def _enforce_suspend(self, pid: int):
        # Already suspended?
        if pid in self.killswitch.suspended_processes:
            return

        success = self.killswitch.suspend_process(pid)
        if not success:
            logger.error("[POLICY] Failed to suspend pid=%s, reverting to NORMAL", pid)
            self.state_machine.transition(pid, ThreatState.NORMAL)
            return

        logger.warning("[POLICY] Process suspended pid=%s", pid)

    def _enforce_kill(self, pid: int, process_name: Optional[str]) -> bool:
            if not process_name:
                logger.error("[POLICY] Cannot kill pid=%s: process_name missing", pid)
                # Revert to SUSPENDED for manual intervention
                self.state_machine.transition(pid, ThreatState.SUSPENDED)
                return False

            success = self.killswitch.kill_process_tree(process_name, pid)
            if not success:
                logger.critical("[POLICY] Kill failed pid=%s (%s) - reverting to SUSPENDED", pid, process_name)
                # Revert to SUSPENDED - requires manual kill
                self.state_machine.transition(pid, ThreatState.SUSPENDED)
                return False

            logger.critical("[POLICY] Process terminated pid=%s (%s)", pid, process_name)
            return True
    def enforce_timeouts(self):
        """
        Enforce suspension timeouts.
        Any process suspended beyond the timeout is terminated.
        """
        now = time.time()

        for pid, ps in list(self.state_machine._states.items()):
            if ps.state != ThreatState.SUSPENDED:
                continue

            if not ps.suspend_time:
                continue

            elapsed = now - ps.suspend_time
            if elapsed >= self.suspend_timeout:
                logger.critical(
                    "[POLICY] Suspension timeout exceeded pid=%s (%.1fs), terminating",
                    pid, elapsed
                )
                self.state_machine.transition(pid, ThreatState.TERMINATED)
