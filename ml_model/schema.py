"""Canonical feature schema shared by training and live inference."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any, Final


MODEL_FEATURE_NAMES: Final[tuple[str, ...]] = (
    # Process metrics (15)
    "cpu_percent", "cpu_percent_max", "cpu_percent_min", "cpu_spike_count",
    "cpu_sustained_count", "memory_percent", "memory_percent_max",
    "memory_percent_growth", "threads", "thread_creation_rate", "uptime",
    "parent_risk", "privilege_level", "user_context", "process_age",
    # File operations (20)
    "file_writes", "file_reads", "file_deletes", "file_renames",
    "file_modifications", "file_creates", "file_write_rate", "file_read_rate",
    "file_delete_rate", "file_rename_rate", "rapid_file_ops_count",
    "mass_file_change_events", "sequential_file_ops", "file_size_changes",
    "large_file_writes", "small_file_writes", "file_operation_diversity",
    "file_access_pattern", "file_overwrite_count", "unique_files_accessed",
    # Entropy analysis (12)
    "entropy_mean", "entropy_variance", "entropy_max", "entropy_min",
    "entropy_spike_count", "high_entropy_file_ratio", "entropy_change_rate",
    "entropy_stddev", "entropy_range", "low_entropy_count", "median_entropy",
    "entropy_trend",
    # Extension tracking (8)
    "extension_changes", "suspicious_extensions_count", "unique_extensions",
    "extension_diversity", "ransomware_extensions", "document_extensions",
    "executable_extensions", "extension_change_rate",
    # Network activity (10)
    "network_connections", "suspicious_port_connections", "outbound_data_kb",
    "inbound_data_kb", "c2_beacon_pattern", "connection_frequency",
    "unique_ip_connections", "dns_lookups", "http_connections", "tls_connections",
    # Registry operations (8)
    "registry_modifications", "startup_key_changes", "security_setting_changes",
    "registry_deletes", "registry_creates", "persistence_mechanisms",
    "run_key_adds", "service_installs",
    # Advanced patterns (7)
    "process_injection_attempts", "dll_injections", "code_hollowing",
    "shadow_copy_deletes", "backup_deletions", "volume_shadow_disables",
    "recovery_mode_disables",
    # Behavioral patterns (5)
    "read_write_delete_pattern", "encryption_signature", "mass_enumeration",
    "lateral_movement", "credential_access",
)

LABEL_COLUMN: Final[str] = "malware_label"
SCHEMA_VERSION: Final[str] = "ransomguard-85-v1"

# These aliases are only for adapting older telemetry producers. They are
# never used as a second model schema: all returned mappings are ordered by
# MODEL_FEATURE_NAMES and missing fields are explicit zero-valued observations.
LEGACY_FEATURE_ALIASES: Final[dict[str, str]] = {
    "memory_growth_rate": "memory_percent_growth",
    "process_age_seconds": "process_age",
    "file_create_rate": "file_write_rate",
    "file_write_burst_count": "rapid_file_ops_count",
    "file_read_write_ratio": "file_access_pattern",
    "file_delete_burst_count": "mass_file_change_events",
    "file_rename_burst_count": "rapid_file_ops_count",
    "extension_change_count": "extension_changes",
    "suspicious_rename_pattern": "suspicious_extensions_count",
    "modification_rate": "file_write_rate",
    "modification_burst_count": "rapid_file_ops_count",
    "extension_entropy": "extension_diversity",
    "unknown_extension_count": "unique_extensions",
    "double_extension_count": "extension_diversity",
    "network_connections_max": "unique_ip_connections",
    "suspicious_port_count": "suspicious_port_connections",
    "c2_beacon_score": "c2_beacon_pattern",
    "data_exfiltration_score": "outbound_data_kb",
    "registry_modification_count": "registry_modifications",
    "registry_writes": "registry_modifications",
    "shadow_copy_interaction": "shadow_copy_deletes",
    "backup_deletion_attempts": "backup_deletions",
    "privilege_escalation_attempts": "privilege_level",
    "persistence_mechanism_count": "persistence_mechanisms",
    "lateral_movement_score": "lateral_movement",
    "parent_suspicious": "parent_risk",
    "cpu_variance": "cpu_spike_count",
    "memory_variance": "memory_percent_growth",
    "thread_spike_count": "thread_creation_rate",
    "thread_variance": "thread_creation_rate",
    "sequential_write_count": "sequential_file_ops",
    "random_write_count": "file_access_pattern",
    "large_file_read_count": "large_file_writes",
    "mass_delete_events": "mass_file_change_events",
    "cascading_modification_pattern": "mass_file_change_events",
    "anti_analysis_indicators": "encryption_signature",
    "autorun_modifications": "startup_key_changes",
    "boot_config_changes": "recovery_mode_disables",
    "service_installations": "service_installs",
    "volume_shadow_disables": "volume_shadow_disables",
}


class SchemaContractError(ValueError):
    """Raised when a producer or artifact violates the canonical schema."""


def validate_feature_columns(
    columns: Sequence[str],
    *,
    label_column: str | None = LABEL_COLUMN,
    require_order: bool = True,
) -> None:
    """Fail loudly when feature names, count, or order differ."""

    observed = list(columns)
    expected = list(MODEL_FEATURE_NAMES)
    if label_column is not None:
        if not observed or observed[-1] != label_column:
            raise SchemaContractError(
                f"Label column must be the final column {label_column!r}; "
                f"got {observed[-1] if observed else None!r}"
            )
        observed = observed[:-1]

    if len(observed) != len(expected):
        raise SchemaContractError(
            f"Feature count mismatch for {SCHEMA_VERSION}: "
            f"expected {len(expected)}, got {len(observed)}"
        )
    if len(set(observed)) != len(observed):
        raise SchemaContractError("Feature schema contains duplicate names")
    if require_order and observed != expected:
        first_difference = next(
            (index for index, (actual, wanted) in enumerate(zip(observed, expected)) if actual != wanted),
            min(len(observed), len(expected)),
        )
        raise SchemaContractError(
            f"Feature order mismatch at index {first_difference}: "
            f"expected {expected[first_difference] if first_difference < len(expected) else None!r}, "
            f"got {observed[first_difference] if first_difference < len(observed) else None!r}"
        )


def canonicalize_features(
    features: Mapping[str, Any],
    *,
    fill_value: float = 0.0,
    strict: bool = False,
) -> dict[str, float]:
    """Return one ordered 85-feature mapping from live or legacy telemetry."""

    source = dict(features)
    output: dict[str, float] = {}
    for name in MODEL_FEATURE_NAMES:
        value = source.get(name, fill_value)
        if name not in source:
            for legacy_name, canonical_name in LEGACY_FEATURE_ALIASES.items():
                if canonical_name == name and legacy_name in source:
                    value = source[legacy_name]
                    break
        try:
            output[name] = float(value)
        except (TypeError, ValueError):
            if strict:
                raise SchemaContractError(f"Feature {name!r} is not numeric: {value!r}")
            output[name] = float(fill_value)

    if strict:
        missing = [name for name in MODEL_FEATURE_NAMES if name not in source]
        if missing:
            raise SchemaContractError(f"Missing canonical features: {missing[:10]}")
    return output


def validate_schema() -> None:
    if len(MODEL_FEATURE_NAMES) != 85:
        raise RuntimeError(
            f"RansomGuard model schema must contain 85 features, got {len(MODEL_FEATURE_NAMES)}"
        )
    if len(set(MODEL_FEATURE_NAMES)) != len(MODEL_FEATURE_NAMES):
        raise RuntimeError("RansomGuard model schema contains duplicate feature names")
    validate_feature_columns((*MODEL_FEATURE_NAMES, LABEL_COLUMN))


validate_schema()
