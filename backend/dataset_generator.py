"""
Ransomware Detection Dataset Generator v3.0
Generates synthetic 85-feature behavioral datasets for ML training

Author: RansomGuard Team
License: MIT
"""

import numpy as np
import pandas as pd
from pathlib import Path
from datetime import datetime
import sys

# ===========================================================================
# CONFIGURATION
# ===========================================================================

class DatasetConfig:
    """Dataset generation configuration"""
    
    # Output settings
    PROJECT_ROOT = Path(__file__).parent
    OUTPUT_DIR = PROJECT_ROOT / "data" / "training_data"
    
    # Dataset parameters
    DEFAULT_SAMPLES = 10000  # Total samples to generate
    MALICIOUS_RATIO = 0.3    # 30% malicious samples
    
    # Feature names (85 features matching train_model.py)
    FEATURE_NAMES = [
        # Process Metrics (15 features)
        "cpu_percent", "cpu_percent_max", "cpu_percent_min", "cpu_spike_count", 
        "cpu_sustained_count", "memory_percent", "memory_percent_max", 
        "memory_percent_growth", "threads", "thread_creation_rate", 
        "uptime", "parent_risk", "privilege_level", "user_context", "process_age",
        
        # File Operations (20 features)
        "file_writes", "file_reads", "file_deletes", "file_renames", 
        "file_modifications", "file_creates", "file_write_rate", "file_read_rate",
        "file_delete_rate", "file_rename_rate", "rapid_file_ops_count", 
        "mass_file_change_events", "sequential_file_ops", "file_size_changes",
        "large_file_writes", "small_file_writes", "file_operation_diversity",
        "file_access_pattern", "file_overwrite_count", "unique_files_accessed",
        
        # Entropy Analysis (12 features)
        "entropy_mean", "entropy_variance", "entropy_max", "entropy_min",
        "entropy_spike_count", "high_entropy_file_ratio", "entropy_change_rate",
        "entropy_stddev", "entropy_range", "low_entropy_count", 
        "median_entropy", "entropy_trend",
        
        # Extension Tracking (8 features)
        "extension_changes", "suspicious_extensions_count", 
        "unique_extensions", "extension_diversity", "ransomware_extensions",
        "document_extensions", "executable_extensions", "extension_change_rate",
        
        # Network Activity (10 features)
        "network_connections", "suspicious_port_connections", 
        "outbound_data_kb", "inbound_data_kb", "c2_beacon_pattern",
        "connection_frequency", "unique_ip_connections", "dns_lookups",
        "http_connections", "tls_connections",
        
        # Registry Operations (8 features)
        "registry_modifications", "startup_key_changes", 
        "security_setting_changes", "registry_deletes", "registry_creates",
        "persistence_mechanisms", "run_key_adds", "service_installs",
        
        # Advanced Patterns (7 features)
        "process_injection_attempts", "dll_injections", "code_hollowing",
        "shadow_copy_deletes", "backup_deletions", "volume_shadow_disables",
        "recovery_mode_disables",
        
        # Behavioral Patterns (5 features)
        "read_write_delete_pattern", "encryption_signature", 
        "mass_enumeration", "lateral_movement", "credential_access"
    ]
    
    LABEL_COLUMN = "malware_label"


# ===========================================================================
# BENIGN BEHAVIOR GENERATOR
# ===========================================================================

class BenignBehaviorGenerator:
    """Generates realistic benign process behavior"""
    
    @staticmethod
    def generate(n_samples: int) -> pd.DataFrame:
        """Generate benign behavior samples"""
        
        data = {}
        
        # Process Metrics (15) - Normal office/web browsing behavior
        data['cpu_percent'] = np.random.uniform(2, 25, n_samples)
        data['cpu_percent_max'] = data['cpu_percent'] + np.random.uniform(5, 20, n_samples)
        data['cpu_percent_min'] = data['cpu_percent'] - np.random.uniform(1, 5, n_samples)
        data['cpu_percent_min'] = np.clip(data['cpu_percent_min'], 0, None)
        data['cpu_spike_count'] = np.random.poisson(2, n_samples)
        data['cpu_sustained_count'] = np.random.poisson(1, n_samples)
        
        data['memory_percent'] = np.random.uniform(5, 30, n_samples)
        data['memory_percent_max'] = data['memory_percent'] + np.random.uniform(3, 15, n_samples)
        data['memory_percent_growth'] = np.random.uniform(0.8, 1.2, n_samples)
        
        data['threads'] = np.random.randint(2, 12, n_samples)
        data['thread_creation_rate'] = np.random.uniform(0, 2, n_samples)
        data['uptime'] = np.random.uniform(10, 3600, n_samples)
        data['parent_risk'] = np.random.uniform(0, 0.3, n_samples)
        data['privilege_level'] = np.random.choice([0, 1], n_samples, p=[0.8, 0.2])
        data['user_context'] = np.random.choice([0, 1], n_samples, p=[0.9, 0.1])
        data['process_age'] = np.random.uniform(0.1, 1.0, n_samples)
        
        # File Operations (20) - Normal file activity
        data['file_writes'] = np.random.poisson(10, n_samples)
        data['file_reads'] = np.random.poisson(20, n_samples)
        data['file_deletes'] = np.random.poisson(2, n_samples)
        data['file_renames'] = np.random.poisson(1, n_samples)
        data['file_modifications'] = np.random.poisson(8, n_samples)
        data['file_creates'] = np.random.poisson(5, n_samples)
        
        data['file_write_rate'] = np.random.uniform(0.5, 5, n_samples)
        data['file_read_rate'] = np.random.uniform(1, 10, n_samples)
        data['file_delete_rate'] = np.random.uniform(0, 1, n_samples)
        data['file_rename_rate'] = np.random.uniform(0, 0.5, n_samples)
        
        data['rapid_file_ops_count'] = np.random.poisson(1, n_samples)
        data['mass_file_change_events'] = 0  # Rare in benign
        data['sequential_file_ops'] = np.random.uniform(0, 0.3, n_samples)
        data['file_size_changes'] = np.random.poisson(5, n_samples)
        data['large_file_writes'] = np.random.poisson(2, n_samples)
        data['small_file_writes'] = np.random.poisson(8, n_samples)
        data['file_operation_diversity'] = np.random.uniform(0.4, 0.8, n_samples)
        data['file_access_pattern'] = np.random.uniform(0.3, 0.7, n_samples)
        data['file_overwrite_count'] = np.random.poisson(1, n_samples)
        data['unique_files_accessed'] = np.random.randint(5, 30, n_samples)
        
        # Entropy Analysis (12) - Normal file entropy
        data['entropy_mean'] = np.random.uniform(4.5, 6.0, n_samples)
        data['entropy_variance'] = np.random.uniform(0.2, 1.0, n_samples)
        data['entropy_max'] = np.random.uniform(6.0, 7.0, n_samples)
        data['entropy_min'] = np.random.uniform(2.0, 4.0, n_samples)
        data['entropy_spike_count'] = np.random.poisson(1, n_samples)
        data['high_entropy_file_ratio'] = np.random.uniform(0.05, 0.2, n_samples)
        data['entropy_change_rate'] = np.random.uniform(0, 0.3, n_samples)
        data['entropy_stddev'] = np.random.uniform(0.3, 1.2, n_samples)
        data['entropy_range'] = data['entropy_max'] - data['entropy_min']
        data['low_entropy_count'] = np.random.poisson(3, n_samples)
        data['median_entropy'] = np.random.uniform(4.5, 5.8, n_samples)
        data['entropy_trend'] = np.random.uniform(-0.1, 0.1, n_samples)
        
        # Extension Tracking (8) - Normal extensions
        data['extension_changes'] = np.random.poisson(1, n_samples)
        data['suspicious_extensions_count'] = 0  # None for benign
        data['unique_extensions'] = np.random.randint(2, 8, n_samples)
        data['extension_diversity'] = np.random.uniform(0.3, 0.7, n_samples)
        data['ransomware_extensions'] = 0  # None for benign
        data['document_extensions'] = np.random.randint(1, 10, n_samples)
        data['executable_extensions'] = np.random.randint(0, 2, n_samples)
        data['extension_change_rate'] = np.random.uniform(0, 0.2, n_samples)
        
        # Network Activity (10) - Normal browsing
        data['network_connections'] = np.random.randint(5, 30, n_samples)
        data['suspicious_port_connections'] = np.random.choice([0, 1], n_samples, p=[0.95, 0.05])
        data['outbound_data_kb'] = np.random.uniform(10, 500, n_samples)
        data['inbound_data_kb'] = np.random.uniform(50, 1000, n_samples)
        data['c2_beacon_pattern'] = 0  # None for benign
        data['connection_frequency'] = np.random.uniform(0.1, 2, n_samples)
        data['unique_ip_connections'] = np.random.randint(3, 15, n_samples)
        data['dns_lookups'] = np.random.randint(5, 50, n_samples)
        data['http_connections'] = np.random.randint(3, 25, n_samples)
        data['tls_connections'] = np.random.randint(2, 20, n_samples)
        
        # Registry Operations (8) - Minimal registry changes
        data['registry_modifications'] = np.random.poisson(1, n_samples)
        data['startup_key_changes'] = 0  # Rare for benign
        data['security_setting_changes'] = 0
        data['registry_deletes'] = 0
        data['registry_creates'] = np.random.poisson(1, n_samples)
        data['persistence_mechanisms'] = 0
        data['run_key_adds'] = 0
        data['service_installs'] = 0
        
        # Advanced Patterns (7) - None for benign
        data['process_injection_attempts'] = 0
        data['dll_injections'] = 0
        data['code_hollowing'] = 0
        data['shadow_copy_deletes'] = 0
        data['backup_deletions'] = 0
        data['volume_shadow_disables'] = 0
        data['recovery_mode_disables'] = 0
        
        # Behavioral Patterns (5) - Normal behavior
        data['read_write_delete_pattern'] = np.random.uniform(0, 0.2, n_samples)
        data['encryption_signature'] = 0
        data['mass_enumeration'] = 0
        data['lateral_movement'] = 0
        data['credential_access'] = 0
        
        # Label
        data['malware_label'] = 0
        
        return pd.DataFrame(data)


# ===========================================================================
# RANSOMWARE BEHAVIOR GENERATOR
# ===========================================================================

class RansomwareBehaviorGenerator:
    """Generates realistic ransomware behavior patterns"""
    
    @staticmethod
    def generate(n_samples: int) -> pd.DataFrame:
        """Generate ransomware behavior samples"""
        
        data = {}
        
        # Process Metrics (15) - High resource usage
        data['cpu_percent'] = np.random.uniform(40, 95, n_samples)
        data['cpu_percent_max'] = np.clip(data['cpu_percent'] + np.random.uniform(5, 30, n_samples), 0, 100)
        data['cpu_percent_min'] = data['cpu_percent'] - np.random.uniform(5, 20, n_samples)
        data['cpu_percent_min'] = np.clip(data['cpu_percent_min'], 0, None)
        data['cpu_spike_count'] = np.random.poisson(8, n_samples)
        data['cpu_sustained_count'] = np.random.poisson(5, n_samples)
        
        data['memory_percent'] = np.random.uniform(30, 70, n_samples)
        data['memory_percent_max'] = np.clip(data['memory_percent'] + np.random.uniform(10, 30, n_samples), 0, 100)
        data['memory_percent_growth'] = np.random.uniform(1.3, 2.5, n_samples)
        
        data['threads'] = np.random.randint(8, 32, n_samples)
        data['thread_creation_rate'] = np.random.uniform(2, 10, n_samples)
        data['uptime'] = np.random.uniform(5, 600, n_samples)
        data['parent_risk'] = np.random.uniform(0.5, 1.0, n_samples)
        data['privilege_level'] = np.random.choice([0, 1, 2], n_samples, p=[0.2, 0.3, 0.5])
        data['user_context'] = np.random.choice([0, 1, 2], n_samples, p=[0.3, 0.4, 0.3])
        data['process_age'] = np.random.uniform(0.01, 0.3, n_samples)
        
        # File Operations (20) - MASSIVE file activity
        data['file_writes'] = np.random.poisson(500, n_samples)
        data['file_reads'] = np.random.poisson(800, n_samples)
        data['file_deletes'] = np.random.poisson(200, n_samples)
        data['file_renames'] = np.random.poisson(400, n_samples)
        data['file_modifications'] = np.random.poisson(600, n_samples)
        data['file_creates'] = np.random.poisson(450, n_samples)
        
        data['file_write_rate'] = np.random.uniform(20, 100, n_samples)
        data['file_read_rate'] = np.random.uniform(30, 150, n_samples)
        data['file_delete_rate'] = np.random.uniform(10, 50, n_samples)
        data['file_rename_rate'] = np.random.uniform(15, 80, n_samples)
        
        data['rapid_file_ops_count'] = np.random.poisson(15, n_samples)
        data['mass_file_change_events'] = np.random.poisson(8, n_samples)
        data['sequential_file_ops'] = np.random.uniform(0.7, 0.95, n_samples)
        data['file_size_changes'] = np.random.poisson(300, n_samples)
        data['large_file_writes'] = np.random.poisson(50, n_samples)
        data['small_file_writes'] = np.random.poisson(400, n_samples)
        data['file_operation_diversity'] = np.random.uniform(0.8, 1.0, n_samples)
        data['file_access_pattern'] = np.random.uniform(0.8, 1.0, n_samples)
        data['file_overwrite_count'] = np.random.poisson(150, n_samples)
        data['unique_files_accessed'] = np.random.randint(100, 5000, n_samples)
        
        # Entropy Analysis (12) - HIGH entropy (encryption)
        data['entropy_mean'] = np.random.uniform(7.2, 7.95, n_samples)
        data['entropy_variance'] = np.random.uniform(0.1, 0.5, n_samples)
        data['entropy_max'] = np.random.uniform(7.8, 8.0, n_samples)
        data['entropy_min'] = np.random.uniform(6.5, 7.5, n_samples)
        data['entropy_spike_count'] = np.random.poisson(10, n_samples)
        data['high_entropy_file_ratio'] = np.random.uniform(0.7, 0.95, n_samples)
        data['entropy_change_rate'] = np.random.uniform(0.5, 1.5, n_samples)
        data['entropy_stddev'] = np.random.uniform(0.2, 0.8, n_samples)
        data['entropy_range'] = data['entropy_max'] - data['entropy_min']
        data['low_entropy_count'] = np.random.poisson(1, n_samples)
        data['median_entropy'] = np.random.uniform(7.3, 7.9, n_samples)
        data['entropy_trend'] = np.random.uniform(0.3, 1.0, n_samples)
        
        # Extension Tracking (8) - Ransomware extensions
        data['extension_changes'] = np.random.poisson(100, n_samples)
        data['suspicious_extensions_count'] = np.random.randint(50, 500, n_samples)
        data['unique_extensions'] = np.random.randint(5, 20, n_samples)
        data['extension_diversity'] = np.random.uniform(0.2, 0.5, n_samples)
        data['ransomware_extensions'] = np.random.randint(50, 400, n_samples)
        data['document_extensions'] = np.random.randint(20, 200, n_samples)
        data['executable_extensions'] = np.random.randint(0, 5, n_samples)
        data['extension_change_rate'] = np.random.uniform(0.6, 1.0, n_samples)
        
        # Network Activity (10) - C2 communication
        data['network_connections'] = np.random.randint(10, 100, n_samples)
        data['suspicious_port_connections'] = np.random.randint(3, 20, n_samples)
        data['outbound_data_kb'] = np.random.uniform(500, 5000, n_samples)
        data['inbound_data_kb'] = np.random.uniform(100, 2000, n_samples)
        data['c2_beacon_pattern'] = np.random.choice([0, 1], n_samples, p=[0.3, 0.7])
        data['connection_frequency'] = np.random.uniform(2, 10, n_samples)
        data['unique_ip_connections'] = np.random.randint(5, 30, n_samples)
        data['dns_lookups'] = np.random.randint(10, 100, n_samples)
        data['http_connections'] = np.random.randint(5, 50, n_samples)
        data['tls_connections'] = np.random.randint(3, 30, n_samples)
        
        # Registry Operations (8) - Persistence mechanisms
        data['registry_modifications'] = np.random.poisson(15, n_samples)
        data['startup_key_changes'] = np.random.poisson(3, n_samples)
        data['security_setting_changes'] = np.random.poisson(5, n_samples)
        data['registry_deletes'] = np.random.poisson(8, n_samples)
        data['registry_creates'] = np.random.poisson(10, n_samples)
        data['persistence_mechanisms'] = np.random.poisson(4, n_samples)
        data['run_key_adds'] = np.random.poisson(2, n_samples)
        data['service_installs'] = np.random.poisson(2, n_samples)
        
        # Advanced Patterns (7) - Evasion techniques
        data['process_injection_attempts'] = np.random.poisson(3, n_samples)
        data['dll_injections'] = np.random.poisson(2, n_samples)
        data['code_hollowing'] = np.random.choice([0, 1, 2], n_samples, p=[0.5, 0.3, 0.2])
        data['shadow_copy_deletes'] = np.random.choice([0, 1, 2, 3], n_samples, p=[0.3, 0.3, 0.2, 0.2])
        data['backup_deletions'] = np.random.poisson(5, n_samples)
        data['volume_shadow_disables'] = np.random.choice([0, 1], n_samples, p=[0.4, 0.6])
        data['recovery_mode_disables'] = np.random.choice([0, 1], n_samples, p=[0.5, 0.5])
        
        # Behavioral Patterns (5) - Strong signatures
        data['read_write_delete_pattern'] = np.random.uniform(0.7, 1.0, n_samples)
        data['encryption_signature'] = np.random.choice([0, 1], n_samples, p=[0.2, 0.8])
        data['mass_enumeration'] = np.random.choice([0, 1], n_samples, p=[0.3, 0.7])
        data['lateral_movement'] = np.random.choice([0, 1], n_samples, p=[0.6, 0.4])
        data['credential_access'] = np.random.choice([0, 1], n_samples, p=[0.5, 0.5])
        
        # Label
        data['malware_label'] = 1
        
        return pd.DataFrame(data)


# ===========================================================================
# MAIN GENERATOR
# ===========================================================================

class DatasetGenerator:
    """Main dataset generator orchestrator"""
    
    def __init__(self, total_samples: int = None, malicious_ratio: float = None):
        self.total_samples = total_samples or DatasetConfig.DEFAULT_SAMPLES
        self.malicious_ratio = malicious_ratio or DatasetConfig.MALICIOUS_RATIO
        
        self.n_malicious = int(self.total_samples * self.malicious_ratio)
        self.n_benign = self.total_samples - self.n_malicious
        
        print(f"\n{'='*70}")
        print(f"📊 RANSOMWARE DATASET GENERATOR v3.0")
        print(f"{'='*70}")
        print(f"Total samples: {self.total_samples:,}")
        print(f"  Benign: {self.n_benign:,} ({(1-self.malicious_ratio)*100:.1f}%)")
        print(f"  Malicious: {self.n_malicious:,} ({self.malicious_ratio*100:.1f}%)")
        print(f"Features: {len(DatasetConfig.FEATURE_NAMES)}")
        print(f"{'='*70}\n")
    
    def generate(self) -> pd.DataFrame:
        """Generate complete dataset"""
        
        print("🔧 Generating benign samples...")
        benign_df = BenignBehaviorGenerator.generate(self.n_benign)
        print(f"✅ Generated {len(benign_df):,} benign samples")
        
        print("\n🦠 Generating ransomware samples...")
        malicious_df = RansomwareBehaviorGenerator.generate(self.n_malicious)
        print(f"✅ Generated {len(malicious_df):,} malicious samples")
        
        print("\n🔀 Combining and shuffling dataset...")
        combined_df = pd.concat([benign_df, malicious_df], ignore_index=True)
        combined_df = combined_df.sample(frac=1, random_state=42).reset_index(drop=True)
        
        # Validate
        assert len(combined_df) == self.total_samples
        assert len(combined_df.columns) == len(DatasetConfig.FEATURE_NAMES) + 1  # +1 for label
        assert set(combined_df[DatasetConfig.LABEL_COLUMN].unique()) == {0, 1}
        
        print(f"✅ Dataset ready: {len(combined_df):,} samples")
        
        return combined_df
    
    def save(self, df: pd.DataFrame) -> Path:
        """Save dataset to CSV"""
        
        # Create output directory
        DatasetConfig.OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
        
        # Generate filename
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"ransomware_dataset_{self.total_samples}samples_{timestamp}.csv"
        filepath = DatasetConfig.OUTPUT_DIR / filename
        
        print(f"\n💾 Saving dataset...")
        df.to_csv(filepath, index=False)
        
        file_size_mb = filepath.stat().st_size / (1024 * 1024)
        
        print(f"✅ Dataset saved!")
        print(f"   File: {filename}")
        print(f"   Path: {filepath}")
        print(f"   Size: {file_size_mb:.2f} MB")
        
        return filepath
    
    def show_statistics(self, df: pd.DataFrame):
        """Display dataset statistics"""
        
        print(f"\n{'='*70}")
        print(f"📈 DATASET STATISTICS")
        print(f"{'='*70}")
        
        # Basic stats
        print(f"\nShape: {df.shape[0]:,} samples × {df.shape[1]} features")
        print(f"\nClass Distribution:")
        print(f"  Benign:    {(df['malware_label']==0).sum():,} ({(df['malware_label']==0).sum()/len(df)*100:.1f}%)")
        print(f"  Malicious: {(df['malware_label']==1).sum():,} ({(df['malware_label']==1).sum()/len(df)*100:.1f}%)")
        
        # Feature statistics
        print(f"\nFeature Statistics (sample):")
        print(f"{'Feature':<35} {'Benign Mean':<15} {'Malicious Mean':<15} {'Difference'}")
        print(f"{'-'*80}")
        
        key_features = [
            'cpu_percent', 'memory_percent', 'file_writes', 'file_deletes',
            'entropy_mean', 'high_entropy_file_ratio', 'ransomware_extensions',
            'shadow_copy_deletes', 'encryption_signature'
        ]
        
        for feature in key_features:
            benign_mean = df[df['malware_label']==0][feature].mean()
            malicious_mean = df[df['malware_label']==1][feature].mean()
            diff = malicious_mean - benign_mean
            
            print(f"{feature:<35} {benign_mean:<15.2f} {malicious_mean:<15.2f} {diff:+.2f}")
        
        print(f"\n{'='*70}")


# ===========================================================================
# MAIN EXECUTION
# ===========================================================================

def main():
    """Main execution"""
    
    # Parse arguments
    total_samples = DatasetConfig.DEFAULT_SAMPLES
    malicious_ratio = DatasetConfig.MALICIOUS_RATIO
    
    if len(sys.argv) > 1:
        try:
            total_samples = int(sys.argv[1])
        except ValueError:
            print(f"❌ Invalid sample count: {sys.argv[1]}")
            sys.exit(1)
    
    if len(sys.argv) > 2:
        try:
            malicious_ratio = float(sys.argv[2])
            if not 0 < malicious_ratio < 1:
                raise ValueError
        except ValueError:
            print(f"❌ Invalid malicious ratio: {sys.argv[2]}")
            print(f"   Must be between 0 and 1 (e.g., 0.3 for 30%)")
            sys.exit(1)
    
    # Generate dataset
    try:
        generator = DatasetGenerator(total_samples, malicious_ratio)
        df = generator.generate()
        generator.show_statistics(df)
        filepath = generator.save(df)
        
        print(f"\n{'='*70}")
        print(f"🎉 GENERATION COMPLETE!")
        print(f"{'='*70}")
        print(f"✅ Dataset: {filepath.name}")
        print(f"✅ Samples: {len(df):,}")
        print(f"✅ Features: {len(DatasetConfig.FEATURE_NAMES)}")
        print(f"\n🚀 Next step:")
        print(f"   python train_model.py {filepath}")
        print(f"{'='*70}\n")
        
    except Exception as e:
        print(f"\n❌ Generation failed: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] in ['-h', '--help']:
        print(f"""
Ransomware Detection Dataset Generator v3.0

Usage:
    python dataset_generator.py [total_samples] [malicious_ratio]

Arguments:
    total_samples     Total number of samples to generate (default: 10000)
    malicious_ratio   Ratio of malicious samples 0-1 (default: 0.3 = 30%)

Examples:
    python dataset_generator.py                  # Generate 10,000 samples (30% malicious)
    python dataset_generator.py 50000            # Generate 50,000 samples (30% malicious)
    python dataset_generator.py 20000 0.4        # Generate 20,000 samples (40% malicious)

Output:
    Generates CSV file in: data/training_data/
    Format: ransomware_dataset_<samples>samples_<timestamp>.csv
        """)
        sys.exit(0)
    
    main()