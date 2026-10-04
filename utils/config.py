"""
Configuration Management System.

Loads YAML configuration, supports legacy key aliases, and applies
environment variable overrides for deployment-safe runtime control.
"""

import os
import sys
from copy import deepcopy
from pathlib import Path
from typing import Any, Dict

from utils.resource_path import runtime_or_resource_path, runtime_path

try:
    import yaml
except ModuleNotFoundError as e:
    print(f"[CRITICAL] PyYAML module not found: {e}")
    print("[CRITICAL] Configuration system will not work properly without PyYAML")
    yaml = None


class Config:
    """
    Configuration manager for RansomGuard.
    Loads settings from YAML file and provides easy access.
    """

    LEGACY_KEY_ALIASES = {
        "performance.max_events": "performance.max_events_in_memory",
        "alerts.max_per_minute": "alerts.max_alerts_per_minute",
        "alerts.threshold": "alerts.alert_on_score",
        "ml.model_path": "ml_model.model_path",
        "ml.scaler_path": "ml_model.scaler_path",
    }

    ENV_KEY_MAP = {
        "RG_SERVER_HOST": "server.host",
        "RG_SERVER_PORT": "server.port",
        "RG_DB_PATH": "database.path",
        "RG_KILLSWITCH_ENABLED": "killswitch.enabled",
        "RG_KILLSWITCH_THRESHOLD": "killswitch.threat_threshold",
        "RG_API_KEY": "security.api_key",
        "GEMINI_API_KEY": "integrations.gemini.api_key",
        "RG_GEMINI_API_KEY": "integrations.gemini.api_key",
    }

    def __init__(self, config_path: str = "config.yaml"):
        self.config_path = self._resolve_config_path(config_path)
        self.config_data: Dict[str, Any] = {}
        self.load()

    def _resolve_config_path(self, config_path: str) -> str:
        raw_path = Path(config_path)
        if raw_path.is_absolute():
            return str(raw_path)

        if getattr(sys, "frozen", False):
            return runtime_or_resource_path(str(raw_path))

        return runtime_path(str(raw_path))

    def load(self):
        """Load configuration from YAML file."""
        if not os.path.exists(self.config_path):
            print(f"[WARN] Config file not found: {self.config_path}")
            print("[INFO] Creating default configuration...")
            self._create_default_config()
            if not os.path.exists(self.config_path):
                self.config_data = {}
                self._apply_env_overrides()
                return

        if yaml is None:
            print("[WARN] PyYAML is not installed; using defaults and environment overrides only")
            self.config_data = {}
            self._apply_env_overrides()
            return

        try:
            with open(self.config_path, "r", encoding="utf-8") as f:
                self.config_data = yaml.safe_load(f) or {}
            self._apply_env_overrides()
            print(f"[OK] Configuration loaded from {self.config_path}")
        except Exception as e:
            print(f"[CRITICAL] Error loading config file: {e}")
            print(f"[CRITICAL] Using defaults and environment overrides only")
            import traceback
            traceback.print_exc()
            self.config_data = {}
            self._apply_env_overrides()

    def get(self, key_path: str, default: Any = None) -> Any:
        """
        Get configuration value using dot notation.
        Supports a narrow legacy-key alias list to keep older modules working.
        """
        value = self._get_raw(key_path)
        if value is not None:
            return value

        alias = self.LEGACY_KEY_ALIASES.get(key_path)
        if alias:
            value = self._get_raw(alias)
            if value is not None:
                return value

        return default

    def set(self, key_path: str, value: Any):
        """Set configuration value using dot notation."""
        keys = key_path.split(".")
        data = self.config_data

        for key in keys[:-1]:
            if key not in data or not isinstance(data[key], dict):
                data[key] = {}
            data = data[key]

        data[keys[-1]] = value

    def _get_raw(self, key_path: str) -> Any:
        keys = key_path.split(".")
        value: Any = self.config_data
        try:
            for key in keys:
                value = value[key]
            return value
        except (KeyError, TypeError):
            return None

    def _apply_env_overrides(self):
        for env_name, key_path in self.ENV_KEY_MAP.items():
            raw = os.getenv(env_name)
            if raw is None or raw == "":
                continue
            self.set(key_path, self._coerce_env_value(raw))

    def _coerce_env_value(self, value: str) -> Any:
        raw = value.strip()
        lowered = raw.lower()
        if lowered in {"true", "false"}:
            return lowered == "true"
        try:
            if "." in raw:
                return float(raw)
            return int(raw)
        except ValueError:
            return raw

    def save(self):
        """Save current configuration to YAML file."""
        if yaml is None:
            print("[ERROR] Cannot save configuration because PyYAML is not installed")
            return
        try:
            with open(self.config_path, "w", encoding="utf-8") as f:
                yaml.dump(self.config_data, f, default_flow_style=False, sort_keys=False)
            print(f"[OK] Configuration saved to {self.config_path}")
        except Exception as e:
            print(f"[ERROR] Error saving config: {e}")

    def reload(self):
        """Reload configuration from file."""
        self.load()

    def _create_default_config(self):
        """Create default configuration file if it doesn't exist."""
        pass

    @property
    def server_host(self) -> str:
        return self.get("server.host", "127.0.0.1")

    @property
    def server_port(self) -> int:
        return self.get("server.port", 8000)

    @property
    def killswitch_enabled(self) -> bool:
        return self.get("killswitch.enabled", True)

    @property
    def killswitch_threshold(self) -> int:
        return self.get("killswitch.threat_threshold", 60)

    @property
    def monitoring_paths(self) -> list:
        return self.get("monitoring.watch_paths", ["data/test_monitoring"])

    @property
    def protected_processes(self) -> list:
        return self.get("killswitch.protected_processes", [])

    @property
    def suspicious_extensions(self) -> list:
        return self.get("behavioral_analysis.suspicious_extensions", [])

    def get_all(self) -> Dict[str, Any]:
        """Get entire configuration dictionary."""
        return deepcopy(self.config_data)

    def validate(self) -> bool:
        required_keys = [
            "system.name",
            "system.version",
            "server.host",
            "server.port",
        ]

        for key in required_keys:
            if self.get(key) is None:
                print(f"[ERROR] Missing required config key: {key}")
                return False

        print("[OK] Configuration validated successfully")
        return True


config = Config()
