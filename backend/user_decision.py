# backend/user_decision.py
from enum import Enum
import logging
from typing import Optional

from backend.threat_state import ThreatState, ThreatStateMachine
from backend.policy_enforcer import PolicyEnforcer

logger = logging.getLogger("user_decision")


class UserDecision(Enum):
    ALLOW = "ALLOW"
    REMOVE = "REMOVE"
    TRUST = "TRUST"
class WhitelistStore:
    def __init__(self):
        self._by_name = set()

    def is_whitelisted(self, process_name: str) -> bool:
        return process_name.lower() in self._by_name

    def add(self, process_name: str):
        self._by_name.add(process_name.lower())
class UserDecisionHandler:
    def __init__(
        self,
        state_machine: ThreatStateMachine,
        policy_enforcer: PolicyEnforcer,
        whitelist: WhitelistStore,
    ):
        self.state_machine = state_machine
        self.policy_enforcer = policy_enforcer
        self.whitelist = whitelist
    def apply_decision(
        self,
        pid: int,
        process_name: str,
        decision: UserDecision,
    ) -> bool:
        ps = self.state_machine.get(pid)

        # Decisions are valid ONLY for suspended processes
        if ps.state != ThreatState.SUSPENDED:
            logger.warning(
                "[USER] Decision ignored pid=%s state=%s",
                pid, ps.state.value
            )
            return False
        if decision == UserDecision.ALLOW:
            ok = self.state_machine.transition(pid, ThreatState.NORMAL)
            if not ok:
                return False

            self.policy_enforcer.enforce(pid, process_name)
            logger.info("[USER] ALLOW pid=%s (%s)", pid, process_name)
            return True
        if decision == UserDecision.REMOVE:
            ok = self.state_machine.transition(pid, ThreatState.TERMINATED)
            if not ok:
                return False

            self.policy_enforcer.enforce(pid, process_name)
            logger.critical("[USER] REMOVE pid=%s (%s)", pid, process_name)
            return True
        if decision == UserDecision.TRUST:
            self.whitelist.add(process_name)

            ok = self.state_machine.transition(pid, ThreatState.WHITELISTED)
            if not ok:
                return False

            # Resume execution
            self.policy_enforcer.enforce(pid, process_name)
            logger.info("[USER] TRUST pid=%s (%s)", pid, process_name)
            return True
        logger.error("[USER] Invalid decision pid=%s decision=%s", pid, decision)
        return False
        