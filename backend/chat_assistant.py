"""
RansomGuard AI Chat Assistant.

Uses Gemini when available and configured, with a deterministic local
fallback so the dashboard chat remains functional offline.
"""

from datetime import datetime
from typing import Dict, List

try:
    import google.generativeai as genai
except Exception:  # pragma: no cover - optional dependency
    genai = None


class RansomGuardChatbot:
    def __init__(self, api_key: str, db_path: str = "data/ransomguard.db"):
        """Initialize chatbot with optional Gemini support."""
        self.api_key = (api_key or "").strip()
        self.client = None
        self.db_path = db_path
        self.system_prompt = self.build_system_prompt()
        self.conversation_history: List[Dict[str, str]] = []
        self.provider = "local-fallback"
        self.model_name = self._resolve_model_name()
        self.api_key_error = None

        if genai and self.api_key:
            try:
                genai.configure(api_key=self.api_key)
                self.client = genai.GenerativeModel(self.model_name)
                self.provider = self.model_name
                print("[OK] RansomGuard Chatbot: Google Gemini API configured successfully")
            except Exception as e:
                self.api_key_error = str(e)
                self.client = None
                self.provider = "local-fallback"
                print(f"! RansomGuard Chatbot: Failed to initialize Gemini API: {e}")
        elif not self.api_key:
            self.api_key_error = (
                "API key not set. Configure integrations.gemini.api_key, "
                "GEMINI_API_KEY, or RG_GEMINI_API_KEY."
            )
            print(f"! RansomGuard Chatbot: {self.api_key_error}")
        elif not genai:
            self.api_key_error = (
                "google.generativeai library not available. "
                "Install: pip install google-generativeai"
            )
            print(f"! RansomGuard Chatbot: {self.api_key_error}")

    def _resolve_model_name(self) -> str:
        preferred_models = [
            "gemini-2.5-flash",
            "gemini-flash-latest",
            "gemini-2.0-flash",
            "gemini-pro-latest",
        ]

        if not genai or not self.api_key:
            return preferred_models[0]

        try:
            genai.configure(api_key=self.api_key)
            available = {
                str(model.name).split("/", 1)[-1]
                for model in genai.list_models()
                if "generateContent" in (getattr(model, "supported_generation_methods", []) or [])
            }
            for candidate in preferred_models:
                if candidate in available:
                    return candidate
        except Exception:
            pass

        return preferred_models[0]

    def build_system_prompt(self) -> str:
        return (
            "You are RansomGuard AI, an intelligent assistant with expertise in cybersecurity, "
            "ransomware detection, malware behavior analysis, and prevention. You can help with "
            "security analysis, answer general questions, provide information about the RansomGuard "
            "project, discuss technical topics, and assist with various subjects. You have access to "
            "current system monitoring data and can provide context about security threats when relevant."
        )

    async def get_system_context(self) -> str:
        """
        Pull monitoring context from database.
        """
        import json
        import aiosqlite

        try:
            async with aiosqlite.connect(self.db_path) as db:
                cutoff = float(datetime.now().timestamp()) - 3600.0
                table_info = await db.execute("PRAGMA table_info(events)")
                event_columns = {row[1] for row in await table_info.fetchall()}

                threat_count = 0
                active_processes = set()

                if {"ts", "event_json"}.issubset(event_columns):
                    cursor = await db.execute(
                        "SELECT process, event_json FROM events WHERE ts >= ?",
                        (cutoff,),
                    )
                    rows = await cursor.fetchall()

                    for process_name, payload in rows:
                        if process_name:
                            active_processes.add(str(process_name).strip().lower())

                        try:
                            event = json.loads(payload) if payload else {}
                        except Exception:
                            event = {}

                        score = int(event.get("suspicion_score") or 0)
                        threat_level = str(event.get("threat_level") or "").lower()
                        if score >= 60 or threat_level in {"high", "critical"}:
                            threat_count += 1
                else:
                    cursor = await db.execute(
                        "SELECT process, suspicion_score FROM events WHERE timestamp >= ?",
                        (cutoff,),
                    )
                    rows = await cursor.fetchall()

                    for process_name, suspicion_score in rows:
                        if process_name:
                            active_processes.add(str(process_name).strip().lower())
                        if int(suspicion_score or 0) >= 60:
                            threat_count += 1

                return (
                    f"threats_last_hour={threat_count}\n"
                    f"active_processes={len(active_processes)}\n"
                    f"ml_model=LightGBM"
                )

        except Exception as e:
            return f"context_unavailable: {str(e)}"

    async def chat(self, user_message: str, include_context: bool = True) -> Dict:
        """
        Send message to Gemini API or local fallback.
        """
        messages = [self.system_prompt]
        context = ""

        if include_context:
            context = await self.get_system_context()
            messages.append(f"System Context:\n{context}")

        for msg in self.conversation_history[-10:]:
            messages.append(f"{msg['role']}: {msg['content']}")

        messages.append(f"user: {user_message}")
        prompt = "\n".join(messages)

        try:
            if self.client is None:
                raise RuntimeError("cloud_model_unavailable")

            response = self.client.generate_content(prompt)
            assistant_message = self._extract_response_text(response)
            model_name = self.provider
        except Exception as e:
            assistant_message = self._generate_local_response(user_message, context)
            model_name = "local-fallback"
            error_text = str(e)

            self.conversation_history.append({"role": "user", "content": user_message})
            self.conversation_history.append(
                {"role": "assistant", "content": assistant_message}
            )

            return {
                "success": True,
                "response": assistant_message,
                "timestamp": datetime.now().isoformat(),
                "model": model_name,
                "fallback": True,
                "warning": error_text if "error_text" in locals() else self.api_key_error,
            }

        self.conversation_history.append({"role": "user", "content": user_message})
        self.conversation_history.append(
            {"role": "assistant", "content": assistant_message}
        )

        return {
            "success": True,
            "response": assistant_message,
            "timestamp": datetime.now().isoformat(),
            "model": model_name,
            "fallback": False,
        }

    def _extract_response_text(self, response) -> str:
        if hasattr(response, "text") and response.text:
            return response.text

        if hasattr(response, "candidates") and response.candidates:
            candidate = response.candidates[0]
            content = getattr(candidate, "content", None)
            parts = getattr(content, "parts", None) or []
            text_parts = [part.text for part in parts if hasattr(part, "text") and part.text]
            if text_parts:
                return "".join(text_parts)

        return str(response)

    def _generate_local_response(self, user_message: str, context: str) -> str:
        message = (user_message or "").strip()
        lower = message.lower()

        context_map: Dict[str, str] = {}
        for line in context.splitlines():
            if "=" in line:
                key, value = line.split("=", 1)
                context_map[key.strip()] = value.strip()

        threats = context_map.get("threats_last_hour", "unknown")
        active_processes = context_map.get("active_processes", "unknown")
        context_summary = self._build_context_summary(threats, active_processes)

        if any(term in lower for term in ["current threats", "status", "active threats", "local context"]):
            return (
                f"{context_summary} "
                "Use the activity feed and protection-action logs to inspect recent behavior."
            )

        if any(term in lower for term in ["what is ransomware", "define ransomware", "explain ransomware"]):
            return (
                "Ransomware is malware that blocks access to files or systems, usually by encrypting data, and then demands payment for recovery. "
                "Modern ransomware often spreads through phishing, exposed remote access, malicious downloads, or abused credentials. "
                "Before encryption, it commonly performs rapid file discovery, mass renames, ransom-note drops, and unusually heavy disk activity. "
                f"{context_summary}"
            )

        if any(term in lower for term in ["prevent", "protection", "avoid ransomware", "defend"]):
            return (
                "Good ransomware prevention combines offline backups, patching, least-privilege access, MFA, email filtering, endpoint monitoring, and user training. "
                "You should also restrict script execution, monitor mass file changes, and isolate suspicious hosts quickly when high-risk behavior appears."
            )

        if any(term in lower for term in ["symptom", "sign", "indicator", "behavior"]):
            return (
                "Common ransomware indicators include rapid file creation or rename bursts, suspicious extensions such as `.lockbit`, ransom-note filenames, entropy spikes, "
                "unexpected delete activity, and one process touching many user files in a short period. "
                "Those are the same behaviors the dashboard is designed to surface."
            )

        if any(term in lower for term in ["ml", "score", "confidence", "detection score"]):
            return (
                "RansomGuard scores behavior, not signatures alone. Higher scores usually come from rapid file churn, suspicious extensions, ransom-note patterns, entropy spikes, "
                "and correlated process behavior. As a working rule, a score of 60 or higher is high risk and triggers automatic termination."
            )

        if any(term in lower for term in ["safe test", "safe ransomware test", "testing", "demo", "simulate", "test lab"]):
            return (
                "Demo simulation is disabled in this build. Detection is based on live host processes and real file-system behavior only."
            )

        if any(term in lower for term in ["help", "what can you do", "capabilities", "who are you"]):
            return (
                "I can answer general ransomware and cybersecurity questions, explain local dashboard context, interpret risk scores, describe suspicious behaviors, "
                "and explain the live 3-phase protection pipeline."
            )

        api_status = ""
        if not self.api_key or self.api_key_error:
            api_status = (
                "\n\nNOTE: Google Gemini API is not configured. To enable AI responses, "
                "set `integrations.gemini.api_key`, `GEMINI_API_KEY`, or `RG_GEMINI_API_KEY`. "
                "Currently running in local fallback mode."
            )

        return (
            "I can help with cybersecurity questions, ransomware analysis, general knowledge, and technical topics. "
            f"{context_summary} "
            "Ask me anything - from security best practices to general questions about the RansomGuard system or other topics."
            f"{api_status}"
        )

    def _build_context_summary(self, threats: str, active_processes: str) -> str:
        threat_text = (
            f"The current local context shows {threats} high or critical alerts in the last hour"
            if threats != "unknown"
            else "The current local alert count is unavailable"
        )
        process_text = (
            f"and {active_processes} active processes observed."
            if active_processes != "unknown"
            else "and the active process count is unavailable."
        )
        return f"{threat_text} {process_text}"

    async def explain_threat(self, pid: int, features: Dict) -> str:
        """
        Generate explanation for suspicious process.
        """
        feature_summary = "\n".join([f"{k}: {v}" for k, v in features.items()])

        prompt = f"""
A process (PID {pid}) was flagged as suspicious.

Behavioral features:

{feature_summary}

Explain why this could indicate ransomware activity and what defensive action should be taken.
"""

        result = await self.chat(prompt, include_context=False)
        return result.get("response", "Unable to generate explanation")

    def reset_conversation(self):
        """Reset chat history."""
        self.conversation_history = []
