import psutil
import csv
import time
import math
import random
from collections import deque

# ======================= CONFIG =======================
OUTPUT_FILE = "ransomware_dataset.csv"
SAMPLE_INTERVAL = 0.3      # lower = faster growth
RUN_HOURS = 6              # increase for 500MB–1GB
RANSOMWARE_RATIO = 0.35    # % ransomware-like samples
# =====================================================


# ======================= UTILITIES =======================
def variance(values):
    if len(values) < 2:
        return 0.0
    mean = sum(values) / len(values)
    return sum((v - mean) ** 2 for v in values) / len(values)

def rate_per_minute(timestamps):
    if len(timestamps) < 2:
        return 0.0
    duration = max(1.0, timestamps[-1] - timestamps[0])
    return (len(timestamps) / duration) * 60.0

def burst_count(timestamps, threshold):
    return sum(
        1 for i in range(1, len(timestamps))
        if timestamps[i] - timestamps[i - 1] < threshold
    )
# =======================================================


# ======================= FEATURE SCHEMA =======================
FEATURE_NAMES = [
    # CPU (5)
    "cpu_percent", "cpu_percent_max", "cpu_percent_min",
    "cpu_sustained_count", "cpu_variance",

    # Memory (5)
    "memory_percent", "memory_percent_max", "memory_percent_min",
    "memory_growth_rate", "memory_variance",

    # Threads (3)
    "threads", "thread_spike_count", "thread_variance",

    # Process timing (2)
    "uptime", "process_age_seconds",

    # File writes (6)
    "file_writes", "file_write_rate", "file_write_burst_count",
    "file_write_variance", "sequential_write_count", "random_write_count",

    # File reads (4)
    "file_reads", "file_read_rate",
    "file_read_write_ratio", "large_file_read_count",

    # File deletes (4)
    "file_deletes", "file_delete_rate",
    "file_delete_burst_count", "mass_delete_events",

    # File renames (4)
    "file_renames", "file_rename_rate",
    "extension_change_count", "suspicious_rename_pattern",

    # File modifications (3)
    "file_modifications", "modification_rate",
    "modification_burst_count",

    # Entropy (8)
    "entropy_mean", "entropy_stddev", "entropy_max", "entropy_min",
    "entropy_range", "entropy_variance",
    "entropy_change_rate", "high_entropy_file_ratio",

    # File patterns (5)
    "rapid_file_ops_count", "mass_file_change_events",
    "read_write_delete_pattern", "cascading_modification_pattern",
    "file_overwrite_count",

    # Extensions (4)
    "suspicious_extensions_count", "unknown_extension_count",
    "double_extension_count", "extension_entropy",

    # Network (6)
    "network_connections", "network_connections_max",
    "suspicious_port_count", "c2_beacon_score",
    "outbound_data_kb", "data_exfiltration_score",

    # Advanced behavior (8)
    "process_injection_attempts", "registry_modification_count",
    "shadow_copy_interaction", "backup_deletion_attempts",
    "privilege_escalation_attempts", "anti_analysis_indicators",
    "persistence_mechanism_count", "lateral_movement_score",

    # Parent context (4)
    "parent_suspicious", "parent_is_office",
    "parent_is_browser", "spawned_by_script",

    # Timing patterns (4)
    "operation_time_variance", "inter_operation_delay_avg",
    "burst_activity_score", "idle_time_ratio",
]
# ============================================================


# ======================= FEATURE EXTRACTION =======================
def extract_features(proc, now, ransomware):
    try:
        with proc.oneshot():
            cpu = proc.cpu_percent()
            mem = proc.memory_percent()
            threads = proc.num_threads()
            uptime = now - proc.create_time()

            # ransomware vs normal behavior
            if ransomware:
                fw, fr, fd, frn = (
                    random.randint(30, 80),
                    random.randint(10, 40),
                    random.randint(10, 35),
                    random.randint(10, 25),
                )
                entropy_vals = [random.uniform(7.2, 8.8) for _ in range(fw)]
            else:
                fw, fr, fd, frn = (
                    random.randint(0, 10),
                    random.randint(0, 8),
                    random.randint(0, 3),
                    random.randint(0, 3),
                )
                entropy_vals = [random.uniform(3.0, 6.5) for _ in range(max(1, fw))]

            now_ts = time.time()
            write_times = [now_ts - random.uniform(0, 60) for _ in range(fw)]
            delete_times = [now_ts - random.uniform(0, 60) for _ in range(fd)]
            rename_times = [now_ts - random.uniform(0, 60) for _ in range(frn)]

            features = {
                # CPU
                "cpu_percent": cpu,
                "cpu_percent_max": cpu,
                "cpu_percent_min": cpu,
                "cpu_sustained_count": 1 if cpu > 70 else 0,
                "cpu_variance": 0.0,

                # Memory
                "memory_percent": mem,
                "memory_percent_max": mem,
                "memory_percent_min": mem,
                "memory_growth_rate": 0.0,
                "memory_variance": 0.0,

                # Threads
                "threads": threads,
                "thread_spike_count": 1 if threads > 20 else 0,
                "thread_variance": 0.0,

                # Timing
                "uptime": uptime,
                "process_age_seconds": uptime,

                # Writes
                "file_writes": fw,
                "file_write_rate": rate_per_minute(write_times),
                "file_write_burst_count": burst_count(write_times, 10),
                "file_write_variance": variance(write_times),
                "sequential_write_count": int(fw * 0.6),
                "random_write_count": int(fw * 0.4),

                # Reads
                "file_reads": fr,
                "file_read_rate": rate_per_minute(write_times),
                "file_read_write_ratio": fr / max(1, fw),
                "large_file_read_count": int(fr * 0.2),

                # Deletes
                "file_deletes": fd,
                "file_delete_rate": rate_per_minute(delete_times),
                "file_delete_burst_count": burst_count(delete_times, 5),
                "mass_delete_events": 1 if fd > 20 else 0,

                # Renames
                "file_renames": frn,
                "file_rename_rate": rate_per_minute(rename_times),
                "extension_change_count": frn,
                "suspicious_rename_pattern": 1 if frn > 5 else 0,

                # Modifications
                "file_modifications": fw,
                "modification_rate": rate_per_minute(write_times),
                "modification_burst_count": burst_count(write_times, 15),

                # Entropy
                "entropy_mean": sum(entropy_vals) / len(entropy_vals),
                "entropy_stddev": math.sqrt(variance(entropy_vals)) if len(entropy_vals) > 1 else 0.0,
                "entropy_max": max(entropy_vals),
                "entropy_min": min(entropy_vals),
                "entropy_range": max(entropy_vals) - min(entropy_vals),
                "entropy_variance": variance(entropy_vals),
                "entropy_change_rate": abs(entropy_vals[-1] - entropy_vals[0]) / len(entropy_vals) if len(entropy_vals) > 1 else 0.0,
                "high_entropy_file_ratio": sum(1 for e in entropy_vals if e > 7.5) / len(entropy_vals),

                # Patterns
                "rapid_file_ops_count": fw + frn,
                "mass_file_change_events": 1 if fw + frn > 30 else 0,
                "read_write_delete_pattern": 1 if fr and fw and fd else 0,
                "cascading_modification_pattern": 1 if fw > 10 and frn > 5 else 0,
                "file_overwrite_count": fw,

                # Extensions
                "suspicious_extensions_count": random.randint(0, 4),
                "unknown_extension_count": random.randint(0, 6),
                "double_extension_count": random.randint(0, 2),
                "extension_entropy": random.uniform(0.5, 2.5),

                # Network
                "network_connections": random.randint(0, 8),
                "network_connections_max": random.randint(0, 8),
                "suspicious_port_count": random.randint(0, 2),
                "c2_beacon_score": random.uniform(0, 1),
                "outbound_data_kb": random.uniform(0, 500),
                "data_exfiltration_score": random.uniform(0, 1),

                # Advanced
                "process_injection_attempts": 1 if ransomware else 0,
                "registry_modification_count": random.randint(0, 5 if ransomware else 1),
                "shadow_copy_interaction": 1 if ransomware else 0,
                "backup_deletion_attempts": 1 if ransomware else 0,
                "privilege_escalation_attempts": 1 if ransomware else 0,
                "anti_analysis_indicators": random.randint(0, 2 if ransomware else 0),
                "persistence_mechanism_count": random.randint(0, 2),
                "lateral_movement_score": random.uniform(0, 1),

                # Parent
                "parent_suspicious": 1 if ransomware else 0,
                "parent_is_office": 0,
                "parent_is_browser": 0,
                "spawned_by_script": random.randint(0, 1),

                # Timing patterns
                "operation_time_variance": variance(write_times),
                "inter_operation_delay_avg": rate_per_minute(write_times),
                "burst_activity_score": min(1.0, fw / 30.0),
                "idle_time_ratio": random.uniform(0, 1),
            }

            return features

    except (psutil.NoSuchProcess, psutil.AccessDenied):
        return None
# =======================================================


# ======================= MAIN =======================
def run():
    end_time = time.time() + RUN_HOURS * 3600

    with open(OUTPUT_FILE, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(FEATURE_NAMES + ["malware_label"])

        while time.time() < end_time:
            now = time.time()
            for proc in psutil.process_iter():
                is_ransomware = random.random() < RANSOMWARE_RATIO
                feats = extract_features(proc, now, is_ransomware)
                if feats:
                    row = [feats[name] for name in FEATURE_NAMES]
                    writer.writerow(row + [1 if is_ransomware else 0])
            time.sleep(SAMPLE_INTERVAL)

    print("✅ Dataset generation completed.")

if __name__ == "__main__":
    run()
