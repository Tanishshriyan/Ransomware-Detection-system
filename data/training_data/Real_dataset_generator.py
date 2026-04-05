"""
Enterprise Ransomware Dataset Generator - 85 Features
Matches train_model.py v3.0 schema exactly
Generates 1-2GB production datasets with all required features

Author: RansomGuard Team  
Version: 3.1
"""

import os
import sys
import random
import numpy as np
import pandas as pd
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Tuple
import argparse

# 85 FEATURES - Exact match to train_model.py v3.0
FEATURE_COLUMNS = [
    # Process Metrics (15 features)
    'cpu_percent', 'cpu_percent_max', 'cpu_percent_min', 'cpu_sustained_count',
    'memory_percent', 'memory_percent_max', 'memory_percent_growth',
    'threads', 'thread_creation_rate', 'uptime', 'cpu_spike_count',
    'parent_risk', 'privilege_level', 'user_context', 'process_age',
    
    # File Operations (22 features)
    'file_writes', 'file_reads', 'file_deletes', 'file_renames', 'file_creates',
    'file_modifications', 'file_write_rate', 'file_read_rate', 'file_rename_rate',
    'file_delete_rate', 'sequential_file_ops', 'file_size_changes',
    'large_file_writes', 'small_file_writes', 'file_operation_diversity',
    'file_access_pattern', 'file_overwrite_count', 'unique_files_accessed',
    'extension_changes', 'rapid_file_ops_count', 'mass_file_change_events',
    'file_create_rate',
    
    # Entropy Features (12 features)
    'entropy_mean', 'entropy_max', 'entropy_min', 'entropy_variance',
    'entropy_change_rate', 'entropy_stddev', 'entropy_range',
    'entropy_spike_count', 'low_entropy_count', 'median_entropy',
    'entropy_trend', 'high_entropy_file_ratio',
    
    # Network Features (14 features)
    'network_connections', 'outbound_data_kb', 'inbound_data_kb',
    'suspicious_port_connections', 'c2_beacon_pattern', 'connection_frequency',
    'unique_ip_connections', 'dns_lookups', 'dns_queries',
    'http_connections', 'tls_connections', 'data_exfil_rate',
    'external_ip_contacts', 'suspicious_ports',
    
    # Registry & System (10 features)
    'registry_writes', 'registry_deletes', 'registry_modifications',
    'registry_creates', 'startup_key_changes', 'security_setting_changes',
    'autorun_modifications', 'persistence_mechanisms', 'run_key_adds',
    'boot_config_changes',
    
    # Process Behavior (12 features)
    'process_injection_attempts', 'dll_injections', 'code_hollowing',
    'service_installs', 'service_installations', 'driver_loads',
    'scheduled_task_creates', 'privilege_escalation_attempts',
    'token_manipulation', 'cmd_shell_spawns', 'powershell_suspicious_calls',
    'script_execution_count',
    
    # Ransomware Patterns (10 features)
    'read_write_delete_pattern', 'suspicious_extensions_count',
    'shadow_copy_deletes', 'backup_deletions', 'volume_shadow_disables',
    'recovery_mode_disables', 'encryption_signature', 'mass_enumeration',
    'lateral_movement', 'credential_access'
]

LABEL_COLUMN = 'malware_label'


class BehavioralProfile:
    """Behavioral profile for process simulation"""
    def __init__(self, name: str, is_malicious: bool, weight: float):
        self.name = name
        self.is_malicious = is_malicious
        self.weight = weight
        self.ranges = {}
    
    def set_ranges(self, **kwargs):
        self.ranges = kwargs
        return self


# BENIGN PROFILES
BENIGN_PROFILES = [
    BehavioralProfile("idle_background", False, 0.20).set_ranges(
        cpu_percent=(1, 15), memory_percent=(5, 25), threads=(1, 8),
        file_writes=(0, 50), file_reads=(0, 100), entropy_mean=(3.5, 6.0)
    ),
    BehavioralProfile("web_browser", False, 0.20).set_ranges(
        cpu_percent=(15, 50), memory_percent=(25, 65), threads=(12, 40),
        file_writes=(100, 800), file_reads=(200, 1500), entropy_mean=(5.5, 7.0),
        network_connections=(8, 30)
    ),
    BehavioralProfile("ide_development", False, 0.15).set_ranges(
        cpu_percent=(30, 70), memory_percent=(35, 75), threads=(15, 50),
        file_writes=(200, 3000), file_reads=(500, 6000), entropy_mean=(4.5, 6.8)
    ),
    BehavioralProfile("media_editor", False, 0.12).set_ranges(
        cpu_percent=(40, 85), memory_percent=(30, 70), threads=(10, 30),
        file_writes=(500, 5000), file_reads=(1000, 10000), entropy_mean=(6.0, 7.4)
    ),
    BehavioralProfile("office_suite", False, 0.18).set_ranges(
        cpu_percent=(10, 45), memory_percent=(15, 55), threads=(5, 20),
        file_writes=(50, 1000), file_reads=(100, 2000), entropy_mean=(4.0, 6.5)
    ),
    BehavioralProfile("system_service", False, 0.15).set_ranges(
        cpu_percent=(5, 35), memory_percent=(10, 40), threads=(3, 15),
        file_writes=(20, 300), file_reads=(50, 800), entropy_mean=(4.5, 6.8)
    )
]

# RANSOMWARE PROFILES
RANSOMWARE_PROFILES = [
    BehavioralProfile("crypto_locker", True, 0.30).set_ranges(
        cpu_percent=(70, 100), memory_percent=(50, 85), threads=(20, 50),
        file_writes=(10000, 60000), file_reads=(15000, 80000),
        file_deletes=(1000, 10000), file_renames=(2000, 50000),
        extension_changes=(1500, 40000), entropy_mean=(7.7, 7.999),
        network_connections=(10, 40)
    ),
    BehavioralProfile("screen_locker", True, 0.15).set_ranges(
        cpu_percent=(40, 80), memory_percent=(30, 70), threads=(8, 25),
        file_writes=(50, 800), file_reads=(100, 1500), entropy_mean=(5.0, 7.2),
        registry_writes=(100, 500)
    ),
    BehavioralProfile("wiper_malware", True, 0.15).set_ranges(
        cpu_percent=(75, 100), memory_percent=(55, 90), threads=(25, 60),
        file_writes=(5000, 40000), file_reads=(8000, 50000),
        file_deletes=(5000, 30000), entropy_mean=(6.5, 7.8),
        shadow_copy_deletes=(5, 15)
    ),
    BehavioralProfile("stealth_encryptor", True, 0.20).set_ranges(
        cpu_percent=(30, 65), memory_percent=(25, 60), threads=(10, 30),
        file_writes=(1000, 8000), file_reads=(2000, 12000),
        file_renames=(500, 5000), extension_changes=(300, 4000),
        entropy_mean=(7.6, 7.95)
    ),
    BehavioralProfile("double_extortion", True, 0.20).set_ranges(
        cpu_percent=(60, 95), memory_percent=(45, 80), threads=(15, 45),
        file_writes=(8000, 50000), file_reads=(12000, 70000),
        file_deletes=(800, 8000), file_renames=(1500, 40000),
        entropy_mean=(7.75, 7.999), outbound_data_kb=(20000, 150000),
        network_connections=(20, 60)
    )
]


def safe_value(val, min_val=0, max_val=None):
    """Ensure value is within bounds"""
    val = max(min_val, val)
    if max_val is not None:
        val = min(max_val, val)
    return val


def generate_feature_value(base_range: Tuple[float, float], noise: float = 0.15) -> float:
    """Generate realistic value with noise"""
    min_val, max_val = base_range
    base = random.uniform(min_val, max_val)
    noise_factor = 1.0 + random.uniform(-noise, noise)
    return max(0, base * noise_factor)


def generate_sample(profile: BehavioralProfile) -> Dict[str, float]:
    """Generate single sample matching exact 85-feature schema"""
    sample = {}
    is_malicious = profile.is_malicious
    
    # Process Metrics (15 features)
    cpu_base = generate_feature_value(profile.ranges.get('cpu_percent', (10, 50)))
    sample['cpu_percent'] = cpu_base
    sample['cpu_percent_max'] = min(100, cpu_base + random.uniform(5, 25))
    sample['cpu_percent_min'] = max(0, cpu_base - random.uniform(3, 15))
    sample['cpu_sustained_count'] = int(generate_feature_value((0, 5 if not is_malicious else 30)))
    
    mem_base = generate_feature_value(profile.ranges.get('memory_percent', (10, 50)))
    sample['memory_percent'] = mem_base
    sample['memory_percent_max'] = min(100, mem_base + random.uniform(5, 20))
    sample['memory_percent_growth'] = generate_feature_value((0.9, 1.3 if not is_malicious else 2.5))
    
    sample['threads'] = int(generate_feature_value(profile.ranges.get('threads', (5, 20))))
    sample['thread_creation_rate'] = generate_feature_value((0, 2 if not is_malicious else 10))
    sample['uptime'] = generate_feature_value((10, 50000))
    sample['cpu_spike_count'] = int(generate_feature_value((0, 10 if not is_malicious else 50)))
    sample['parent_risk'] = int(generate_feature_value((0, 2 if not is_malicious else 8)))
    sample['privilege_level'] = random.choice([0, 1, 2, 3])
    sample['user_context'] = random.choice([0, 1, 2])
    sample['process_age'] = sample['uptime'] * random.uniform(0.8, 1.0)
    
    # File Operations (22 features)
    uptime_minutes = max(1, sample['uptime'] / 60)
    
    file_writes = generate_feature_value(profile.ranges.get('file_writes', (10, 500)))
    file_reads = generate_feature_value(profile.ranges.get('file_reads', (20, 1000)))
    file_deletes = generate_feature_value(profile.ranges.get('file_deletes', (0, 50)))
    file_renames = generate_feature_value(profile.ranges.get('file_renames', (0, 30)))
    
    sample['file_writes'] = file_writes
    sample['file_reads'] = file_reads
    sample['file_deletes'] = file_deletes
    sample['file_renames'] = file_renames
    sample['file_creates'] = file_writes * random.uniform(0.7, 1.0)
    sample['file_modifications'] = file_writes * random.uniform(0.6, 1.2)
    
    sample['file_write_rate'] = file_writes / uptime_minutes
    sample['file_read_rate'] = file_reads / uptime_minutes
    sample['file_rename_rate'] = file_renames / uptime_minutes
    sample['file_delete_rate'] = file_deletes / uptime_minutes
    sample['file_create_rate'] = sample['file_creates'] / uptime_minutes
    
    sample['sequential_file_ops'] = int(generate_feature_value((0, 10 if not is_malicious else 100)))
    sample['file_size_changes'] = generate_feature_value((0, 1000 if not is_malicious else 10000))
    sample['large_file_writes'] = int(file_writes * random.uniform(0.05, 0.3))
    sample['small_file_writes'] = int(file_writes * random.uniform(0.4, 0.8))
    sample['file_operation_diversity'] = generate_feature_value((0.3, 0.8))
    sample['file_access_pattern'] = int(generate_feature_value((0, 5 if not is_malicious else 9)))
    sample['file_overwrite_count'] = int(generate_feature_value((0, 50 if not is_malicious else 500)))
    sample['unique_files_accessed'] = int(generate_feature_value((10, 500 if not is_malicious else 5000)))
    
    sample['extension_changes'] = generate_feature_value(profile.ranges.get('extension_changes', (0, 10)))
    sample['rapid_file_ops_count'] = int(generate_feature_value((0, 5 if not is_malicious else 50)))
    sample['mass_file_change_events'] = int(generate_feature_value((0, 3 if not is_malicious else 35)))
    
    # Entropy Features (12 features)
    entropy_mean = generate_feature_value(profile.ranges.get('entropy_mean', (4.0, 6.5)), noise=0.08)
    sample['entropy_mean'] = entropy_mean
    sample['entropy_max'] = min(8.0, entropy_mean + random.uniform(0.2, 1.5))
    sample['entropy_min'] = max(0, entropy_mean - random.uniform(0.5, 2.0))
    sample['entropy_range'] = sample['entropy_max'] - sample['entropy_min']
    sample['entropy_variance'] = (sample['entropy_range'] ** 2) / 4
    sample['entropy_stddev'] = sample['entropy_range'] / 2
    sample['median_entropy'] = entropy_mean * random.uniform(0.95, 1.05)
    
    sample['entropy_change_rate'] = generate_feature_value((0, 1 if not is_malicious else 5))
    sample['entropy_spike_count'] = int(generate_feature_value((0, 3 if not is_malicious else 30)))
    sample['low_entropy_count'] = int(generate_feature_value((5, 100 if not is_malicious else 20)))
    sample['entropy_trend'] = generate_feature_value((0.5, 1.5 if not is_malicious else 3.0))
    sample['high_entropy_file_ratio'] = generate_feature_value((0.05, 0.25 if not is_malicious else 0.95))
    
    # Network Features (14 features)
    net_conns = int(generate_feature_value(profile.ranges.get('network_connections', (0, 10))))
    sample['network_connections'] = net_conns
    sample['outbound_data_kb'] = generate_feature_value(profile.ranges.get('outbound_data_kb', (0, 1000)))
    sample['inbound_data_kb'] = generate_feature_value((0, 500 if not is_malicious else 3000))
    sample['data_exfil_rate'] = sample['outbound_data_kb'] / max(1, uptime_minutes)
    
    sample['suspicious_port_connections'] = int(generate_feature_value((0, 1 if not is_malicious else 10)))
    sample['suspicious_ports'] = sample['suspicious_port_connections']
    sample['c2_beacon_pattern'] = generate_feature_value((0, 1 if not is_malicious else 8))
    sample['connection_frequency'] = net_conns / max(1, uptime_minutes)
    sample['unique_ip_connections'] = int(net_conns * random.uniform(0.5, 1.0))
    sample['external_ip_contacts'] = sample['unique_ip_connections']
    
    sample['dns_lookups'] = int(generate_feature_value((0, 30 if not is_malicious else 150)))
    sample['dns_queries'] = sample['dns_lookups']
    sample['http_connections'] = int(net_conns * random.uniform(0.3, 0.7))
    sample['tls_connections'] = int(net_conns * random.uniform(0.2, 0.6))
    
    # Registry & System (10 features)
    reg_writes = int(generate_feature_value(profile.ranges.get('registry_writes', (5, 100))))
    sample['registry_writes'] = reg_writes
    sample['registry_deletes'] = int(generate_feature_value((0, 10 if not is_malicious else 100)))
    sample['registry_modifications'] = int(reg_writes * random.uniform(0.7, 1.2))
    sample['registry_creates'] = int(reg_writes * random.uniform(0.3, 0.7))
    
    sample['startup_key_changes'] = int(generate_feature_value((0, 1 if not is_malicious else 5)))
    sample['security_setting_changes'] = int(generate_feature_value((0, 0 if not is_malicious else 4)))
    sample['autorun_modifications'] = int(generate_feature_value((0, 1 if not is_malicious else 5)))
    sample['persistence_mechanisms'] = int(generate_feature_value((0, 1 if not is_malicious else 6)))
    sample['run_key_adds'] = int(generate_feature_value((0, 0 if not is_malicious else 4)))
    sample['boot_config_changes'] = int(generate_feature_value((0, 0 if not is_malicious else 3)))
    
    # Process Behavior (12 features)
    sample['process_injection_attempts'] = int(generate_feature_value((0, 1 if not is_malicious else 10)))
    sample['dll_injections'] = int(generate_feature_value((0, 1 if not is_malicious else 8)))
    sample['code_hollowing'] = int(generate_feature_value((0, 0 if not is_malicious else 4)))
    
    service_inst = int(generate_feature_value((0, 1 if not is_malicious else 5)))
    sample['service_installs'] = service_inst
    sample['service_installations'] = service_inst
    
    sample['driver_loads'] = int(generate_feature_value((0, 2 if not is_malicious else 6)))
    sample['scheduled_task_creates'] = int(generate_feature_value((0, 1 if not is_malicious else 6)))
    sample['privilege_escalation_attempts'] = int(generate_feature_value((0, 0 if not is_malicious else 5)))
    sample['token_manipulation'] = int(generate_feature_value((0, 0 if not is_malicious else 4)))
    sample['cmd_shell_spawns'] = int(generate_feature_value((0, 2 if not is_malicious else 12)))
    sample['powershell_suspicious_calls'] = int(generate_feature_value((0, 1 if not is_malicious else 20)))
    sample['script_execution_count'] = int(generate_feature_value((0, 3 if not is_malicious else 25)))
    
    # Ransomware Patterns (10 features)
    sample['read_write_delete_pattern'] = generate_feature_value((0, 2 if not is_malicious else 9))
    sample['suspicious_extensions_count'] = int(generate_feature_value((0, 3 if not is_malicious else 60)))
    sample['shadow_copy_deletes'] = int(generate_feature_value(profile.ranges.get('shadow_copy_deletes', (0, 0 if not is_malicious else 10))))
    sample['backup_deletions'] = int(generate_feature_value((0, 0 if not is_malicious else 15)))
    sample['volume_shadow_disables'] = int(generate_feature_value((0, 0 if not is_malicious else 5)))
    sample['recovery_mode_disables'] = int(generate_feature_value((0, 0 if not is_malicious else 3)))
    sample['encryption_signature'] = generate_feature_value((0, 1 if not is_malicious else 9))
    sample['mass_enumeration'] = generate_feature_value((0.1, 2 if not is_malicious else 8))
    sample['lateral_movement'] = int(generate_feature_value((0, 0 if not is_malicious else 5)))
    sample['credential_access'] = int(generate_feature_value((0, 0 if not is_malicious else 6)))
    
    # Label
    sample[LABEL_COLUMN] = 1 if is_malicious else 0
    
    return sample


def generate_dataset(num_samples: int, output_path: str, benign_ratio: float = 0.55):
    """Generate complete 85-feature dataset"""
    
    print(f"\n{'='*70}")
    print(f"🚀 RANSOMGUARD DATASET GENERATOR v3.1 (85 Features)")
    print(f"{'='*70}")
    print(f"Target samples: {num_samples:,}")
    print(f"Benign ratio: {benign_ratio:.1%}")
    print(f"Malicious ratio: {1-benign_ratio:.1%}")
    print(f"Total features: {len(FEATURE_COLUMNS)}")
    print(f"Output: {output_path}")
    
    num_benign = int(num_samples * benign_ratio)
    num_malicious = num_samples - num_benign
    
    print(f"\n📊 Generating {num_benign:,} benign + {num_malicious:,} malicious samples...")
    
    samples = []
    batch_size = 10000
    
    # Generate benign
    print("\n✓ Generating benign samples...")
    for i in range(num_benign):
        profile = random.choices(BENIGN_PROFILES, weights=[p.weight for p in BENIGN_PROFILES])[0]
        samples.append(generate_sample(profile))
        
        if (i + 1) % batch_size == 0:
            print(f"  Progress: {i+1:,}/{num_benign:,} ({100*(i+1)/num_benign:.1f}%)")
    
    # Generate malicious
    print("\n🦠 Generating ransomware samples...")
    for i in range(num_malicious):
        profile = random.choices(RANSOMWARE_PROFILES, weights=[p.weight for p in RANSOMWARE_PROFILES])[0]
        samples.append(generate_sample(profile))
        
        if (i + 1) % batch_size == 0:
            print(f"  Progress: {i+1:,}/{num_malicious:,} ({100*(i+1)/num_malicious:.1f}%)")
    
    # Create DataFrame
    print("\n📦 Creating DataFrame...")
    df = pd.DataFrame(samples)
    
    # Shuffle
    print("🔀 Shuffling dataset...")
    df = df.sample(frac=1, random_state=42).reset_index(drop=True)
    
    # Save
    print(f"\n💾 Saving to {output_path}...")
    output_dir = os.path.dirname(output_path)
    if output_dir:
        os.makedirs(output_dir, exist_ok=True)
    
    df.to_csv(output_path, index=False)
    
    file_size_mb = os.path.getsize(output_path) / (1024 * 1024)
    
    print(f"\n{'='*70}")
    print(f"✅ DATASET GENERATION COMPLETE!")
    print(f"{'='*70}")
    print(f"Total samples: {len(df):,}")
    print(f"Benign: {(df[LABEL_COLUMN]==0).sum():,} ({100*(df[LABEL_COLUMN]==0).sum()/len(df):.1f}%)")
    print(f"Malicious: {(df[LABEL_COLUMN]==1).sum():,} ({100*(df[LABEL_COLUMN]==1).sum()/len(df):.1f}%)")
    print(f"Features: {len(FEATURE_COLUMNS)}")
    print(f"File size: {file_size_mb:.2f} MB")
    
    print(f"\n📊 Sample Statistics:")
    print(f"Entropy mean (benign): {df[df[LABEL_COLUMN]==0]['entropy_mean'].mean():.3f}")
    print(f"Entropy mean (malicious): {df[df[LABEL_COLUMN]==1]['entropy_mean'].mean():.3f}")
    print(f"File deletes (benign): {df[df[LABEL_COLUMN]==0]['file_deletes'].mean():.1f}")
    print(f"File deletes (malicious): {df[df[LABEL_COLUMN]==1]['file_deletes'].mean():.1f}")
    
    return df


def main():
    parser = argparse.ArgumentParser(description='Generate 85-feature ransomware dataset')
    parser.add_argument('--samples', type=int, default=1000000,
                       help='Number of samples (default: 1M)')
    parser.add_argument('--output', type=str, default='data/training_data/ransomware_dataset.csv',
                       help='Output path')
    parser.add_argument('--benign-ratio', type=float, default=0.55,
                       help='Benign ratio (default: 0.55)')
    
    args = parser.parse_args()
    
    estimated_size_mb = args.samples * 0.00065  # ~650 bytes per sample with 85 features
    print(f"\nEstimated file size: ~{estimated_size_mb:.0f} MB")
    
    if estimated_size_mb > 500:
        confirm = input(f"\nThis will generate a ~{estimated_size_mb:.0f}MB file. Continue? (yes/no): ")
        if confirm.lower() != 'yes':
            print("Cancelled.")
            return
    
    generate_dataset(args.samples, args.output, args.benign_ratio)
    
    print(f"\n🚀 Ready for training!")
    print(f"Next: python ml_model/train_model.py")


if __name__ == "__main__":
    main()
