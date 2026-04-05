"""
Universal LightGBM Ransomware Detection Model Trainer v3.0
Handles 85-feature datasets with proper underscore naming
Enhanced for production-grade ransomware detection

Author: RansomGuard Team
License: MIT
"""

import os
import sys
import json
import numpy as np
import pandas as pd
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Tuple, Optional
import warnings
warnings.filterwarnings('ignore')

# ===========================================================================
# DEPENDENCY CHECKS
# ===========================================================================

def check_dependencies():
    """Verify all required libraries are installed"""
    missing = []
    
    try:
        import lightgbm as lgb
    except ImportError:
        missing.append("lightgbm")
    
    try:
        import joblib
    except ImportError:
        missing.append("joblib")
    
    try:
        from sklearn.model_selection import train_test_split
    except ImportError:
        missing.append("scikit-learn")
    
    if missing:
        print(f"\n❌ Missing required packages: {', '.join(missing)}")
        print(f"\nInstall with:")
        print(f"   pip install {' '.join(missing)}")
        sys.exit(1)

# Run dependency check
check_dependencies()

# Safe imports after check
import joblib
import lightgbm as lgb
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    confusion_matrix, classification_report, roc_auc_score, roc_curve
)

# ===========================================================================
# CONFIGURATION
# ===========================================================================

class Config:
    """Training configuration"""
    
    # Paths
    PROJECT_ROOT = Path(__file__).parent.parent if Path(__file__).parent.name == "ml_model" else Path(__file__).parent
    DATASET_DIR = PROJECT_ROOT / "data" / "training_data"
    MODEL_DIR = PROJECT_ROOT / "ml_model" / "models"
    LOGS_DIR = PROJECT_ROOT / "ml_model" / "logs"
    
    # Model parameters
    MODEL_VERSION = "3.0"  # v3.0 for 85-feature model (won't overwrite v2.0)
    TEST_SIZE = 0.2
    RANDOM_STATE = 42
    CROSS_VAL_FOLDS = 5
    
    # LightGBM hyperparameters (optimized for 85-feature ransomware detection)
    LGBM_PARAMS = {
        'objective': 'binary',
        'metric': 'binary_logloss',
        'boosting_type': 'gbdt',
        'num_leaves': 63,  # Increased for 85 features
        'learning_rate': 0.03,  # Slightly lower for better convergence
        'feature_fraction': 0.85,
        'bagging_fraction': 0.8,
        'bagging_freq': 5,
        'max_depth': 8,  # Deeper trees for complex patterns
        'min_child_samples': 20,
        'reg_alpha': 0.1,
        'reg_lambda': 0.1,
        'n_estimators': 1000,  # More estimators for 85 features
        'early_stopping_rounds': 100,
        'verbose': -1,
        'random_state': RANDOM_STATE,
        'n_jobs': -1,
        'class_weight': 'balanced'
    }
    
    # Expected feature names (85 features) - WITH UNDERSCORES
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
    EXPECTED_FEATURE_COUNT = 85
    
    # Validate feature count at startup
    @classmethod
    def validate_config(cls):
        """Validate configuration is correct"""
        actual_count = len(cls.FEATURE_NAMES)
        if actual_count != cls.EXPECTED_FEATURE_COUNT:
            raise ValueError(
                f"Feature count mismatch! Expected {cls.EXPECTED_FEATURE_COUNT}, "
                f"got {actual_count}. Check FEATURE_NAMES list."
            )
        
        # Check for duplicates
        duplicates = [name for name in cls.FEATURE_NAMES if cls.FEATURE_NAMES.count(name) > 1]
        if duplicates:
            raise ValueError(f"Duplicate feature names found: {set(duplicates)}")
        
        print(f"✅ Config validated: {cls.EXPECTED_FEATURE_COUNT} features")


# Validate config on import
Config.validate_config()


# ===========================================================================
# UTILITY FUNCTIONS
# ===========================================================================

def setup_directories():
    """Create necessary directories"""
    Config.DATASET_DIR.mkdir(parents=True, exist_ok=True)
    Config.MODEL_DIR.mkdir(parents=True, exist_ok=True)
    Config.LOGS_DIR.mkdir(parents=True, exist_ok=True)


def find_latest_dataset() -> Optional[Path]:
    """Find the most recent dataset in the datasets directory"""
    if not Config.DATASET_DIR.exists():
        return None
    
    csv_files = list(Config.DATASET_DIR.glob("*.csv"))
    if not csv_files:
        return None
    
    # Sort by modification time, return most recent
    latest = max(csv_files, key=lambda p: p.stat().st_mtime)
    return latest


def validate_dataset_schema(df: pd.DataFrame) -> Tuple[bool, List[str]]:
    """Validate dataset has correct schema"""
    
    expected_cols = Config.FEATURE_NAMES + [Config.LABEL_COLUMN]
    missing = [col for col in expected_cols if col not in df.columns]
    extra = [col for col in df.columns if col not in expected_cols]
    
    issues = []
    
    if missing:
        issues.append(f"Missing {len(missing)} columns: {missing[:5]}{'...' if len(missing) > 5 else ''}")
    
    if extra:
        issues.append(f"Extra {len(extra)} columns (will be ignored): {extra[:5]}{'...' if len(extra) > 5 else ''}")
    
    # Check label column
    if Config.LABEL_COLUMN not in df.columns:
        issues.append(f"CRITICAL: Label column '{Config.LABEL_COLUMN}' not found!")
        return False, issues
    
    # Verify label values
    unique_labels = df[Config.LABEL_COLUMN].unique()
    if not set(unique_labels).issubset({0, 1, 0.0, 1.0}):
        issues.append(f"CRITICAL: Invalid label values: {unique_labels}. Expected only 0 and 1.")
        return False, issues
    
    # Check for empty dataset
    if len(df) == 0:
        issues.append("CRITICAL: Dataset is empty!")
        return False, issues
    
    # If only missing columns issue, we can fill them
    if missing and not any("CRITICAL" in issue for issue in issues):
        return True, issues
    
    return len(issues) == 0 or (len(issues) == 1 and "Extra" in issues[0]), issues


def fill_missing_features(df: pd.DataFrame) -> pd.DataFrame:
    """Fill missing features with safe default values"""
    
    missing = [col for col in Config.FEATURE_NAMES if col not in df.columns]
    
    if missing:
        print(f"\n⚠️  Missing {len(missing)} features - filling with safe defaults:")
        
        for feature in missing:
            # Determine appropriate default based on feature name
            if 'entropy' in feature:
                if 'mean' in feature or 'median' in feature:
                    default = 5.0  # Normal file entropy
                elif 'max' in feature:
                    default = 6.5
                elif 'min' in feature:
                    default = 3.0
                elif 'ratio' in feature:
                    default = 0.1
                elif 'count' in feature:
                    default = 0
                else:
                    default = 0.5
            elif 'percent' in feature:
                if 'max' in feature:
                    default = 20.0
                elif 'min' in feature:
                    default = 0.0
                elif 'growth' in feature:
                    default = 1.0
                else:
                    default = 10.0
            elif 'ratio' in feature or 'diversity' in feature:
                default = 0.5
            elif 'count' in feature or 'events' in feature or 'attempts' in feature:
                default = 0
            elif 'rate' in feature:
                default = 0.0
            elif feature == 'threads':
                default = 4
            elif feature == 'uptime':
                default = 300.0
            elif feature == 'process_age':
                default = 0.1
            elif 'kb' in feature:
                default = 100.0
            else:
                default = 0
            
            df[feature] = default
            print(f"   '{feature}' = {default}")
    
    return df


def handle_infinite_and_nan(df: pd.DataFrame) -> pd.DataFrame:
    """Replace infinite and NaN values"""
    
    # Replace infinity
    df = df.replace([np.inf, -np.inf], np.nan)
    
    # Count NaNs before filling
    nan_counts = df[Config.FEATURE_NAMES].isna().sum()
    total_nans = nan_counts.sum()
    
    if total_nans > 0:
        print(f"\n🧹 Handling {total_nans} missing values...")
        
        # Fill numeric columns with median
        for col in Config.FEATURE_NAMES:
            if df[col].isna().any():
                median_val = df[col].median()
                if pd.isna(median_val):  # If all NaN, use 0
                    median_val = 0
                df[col] = df[col].fillna(median_val)
                if nan_counts[col] > 0:
                    print(f"   '{col}': {nan_counts[col]} values filled with {median_val:.2f}")
    
    return df


def remove_duplicates(df: pd.DataFrame) -> pd.DataFrame:
    """Remove duplicate rows"""
    before = len(df)
    df = df.drop_duplicates(subset=Config.FEATURE_NAMES)
    after = len(df)
    
    if before > after:
        print(f"\n🗑️  Removed {before - after:,} duplicate samples")
    
    return df


# ===========================================================================
# TRAINING CLASS
# ===========================================================================

class RansomwareTrainer:
    """Enhanced trainer for 85-feature ransomware detection"""
    
    def __init__(self):
        self.model = None
        self.scaler = StandardScaler()
        self.feature_names = Config.FEATURE_NAMES
        self.model_version = Config.MODEL_VERSION
        self.training_metrics = {}
        
        print(f"\n🤖 RansomwareTrainer v{self.model_version} initialized")
        print(f"   Features: {len(self.feature_names)}")
    
    def load_and_prepare_data(self, csv_path: str) -> Tuple[pd.DataFrame, pd.Series]:
        """Load and prepare dataset"""
        
        print(f"\n{'='*70}")
        print(f"📂 LOADING DATASET")
        print(f"{'='*70}")
        print(f"📁 File: {csv_path}")
        
        if not os.path.exists(csv_path):
            raise FileNotFoundError(f"❌ Dataset not found: {csv_path}")
        
        # Load dataset
        try:
            df = pd.read_csv(csv_path)
        except Exception as e:
            raise ValueError(f"❌ Failed to load CSV: {e}")
        
        original_size = len(df)
        print(f"✅ Loaded {len(df):,} samples with {len(df.columns)} columns")
        
        # Validate schema
        print(f"\n{'='*70}")
        print(f"🔍 SCHEMA VALIDATION")
        print(f"{'='*70}")
        
        is_valid, issues = validate_dataset_schema(df)
        
        if issues:
            print(f"⚠️  Schema issues detected:")
            for issue in issues:
                print(f"   - {issue}")
        
        if not is_valid:
            raise ValueError(f"❌ Dataset schema validation failed! Check issues above.")
        
        print(f"✅ Schema validation passed")
        
        # Fill missing features
        df = fill_missing_features(df)
        
        # Handle missing values and infinities
        print(f"\n{'='*70}")
        print(f"🧹 DATA CLEANING")
        print(f"{'='*70}")
        df = handle_infinite_and_nan(df)
        
        # Remove duplicates
        df = remove_duplicates(df)
        
        # Select final columns in correct order
        X = df[self.feature_names]
        y = df[Config.LABEL_COLUMN].astype(int)  # Ensure integer labels
        
        # Final validation
        if len(X) < 100:
            raise ValueError(f" Dataset too small! Need at least 100 samples, got {len(X)}")
        
        if len(X.columns) != Config.EXPECTED_FEATURE_COUNT:
            raise ValueError(
                f" Feature count mismatch! Expected {Config.EXPECTED_FEATURE_COUNT}, "
                f"got {len(X.columns)}"
            )
        
        # Final stats
        print(f"\n{'='*70}")
        print(f" DATA PREPARATION COMPLETE")
        print(f"{'='*70}")
        print(f"Final dataset: {len(df):,} samples")
        print(f"Features: {len(self.feature_names)}")
        print(f"Class distribution:")
        print(f"   Benign: {(y==0).sum():,} ({(y==0).sum()/len(y)*100:.1f}%)")
        print(f"   Malicious: {(y==1).sum():,} ({(y==1).sum()/len(y)*100:.1f}%)")
        
        # Check class balance
        minority_ratio = min((y==0).sum(), (y==1).sum()) / len(y)
        if minority_ratio < 0.1:
            print(f"\n⚠️  WARNING: Highly imbalanced dataset (minority class: {minority_ratio*100:.1f}%)")
        
        return X, y
    
    def train(self, X: pd.DataFrame, y: pd.Series) -> Dict:
        """Train the LightGBM model"""
        
        print(f"\n{'='*70}")
        print(f"🤖 MODEL TRAINING")
        print(f"{'='*70}")
        
        # Split data
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, 
            test_size=Config.TEST_SIZE, 
            random_state=Config.RANDOM_STATE, 
            stratify=y
        )
        
        print(f"Training set: {len(X_train):,} samples")
        print(f"   Benign: {(y_train==0).sum():,}")
        print(f"   Malicious: {(y_train==1).sum():,}")
        print(f"Test set: {len(X_test):,} samples")
        print(f"   Benign: {(y_test==0).sum():,}")
        print(f"   Malicious: {(y_test==1).sum():,}")
        
        # Scale features
        print(f"\n📊 Scaling features...")
        X_train_scaled = self.scaler.fit_transform(X_train)
        X_test_scaled = self.scaler.transform(X_test)
        
        # Train LightGBM
        print(f"\n🚀 Training LightGBM model...")
        print(f"   Model version: v{self.model_version}")
        print(f"   Features: {len(self.feature_names)}")
        print(f"   Estimators: {Config.LGBM_PARAMS['n_estimators']}")
        print(f"   Max depth: {Config.LGBM_PARAMS['max_depth']}")
        print(f"   Learning rate: {Config.LGBM_PARAMS['learning_rate']}")
        
        train_start = datetime.now()
        
        self.model = lgb.LGBMClassifier(**Config.LGBM_PARAMS)
        self.model.fit(
            X_train_scaled, y_train,
            eval_set=[(X_test_scaled, y_test)],
            eval_metric='logloss'
        )
        
        train_time = (datetime.now() - train_start).total_seconds()
        print(f"\n Training completed in {train_time:.1f}s")
        
        # Predictions
        print(f"\n Evaluating model...")
        y_pred = self.model.predict(X_test_scaled)
        y_pred_proba = self.model.predict_proba(X_test_scaled)[:, 1]
        
        # Calculate metrics
        metrics = {
            'accuracy': accuracy_score(y_test, y_pred),
            'precision': precision_score(y_test, y_pred, zero_division=0),
            'recall': recall_score(y_test, y_pred, zero_division=0),
            'f1_score': f1_score(y_test, y_pred, zero_division=0),
            'roc_auc': roc_auc_score(y_test, y_pred_proba),
            'confusion_matrix': confusion_matrix(y_test, y_pred).tolist(),
            'samples_train': len(X_train),
            'samples_test': len(X_test),
            'train_time_seconds': train_time,
            'features_count': len(self.feature_names),
            'model_version': self.model_version
        }
        
        self.training_metrics = metrics
        
        # Display results
        print(f"\n{'='*70}")
        print(f" TRAINING RESULTS")
        print(f"{'='*70}")
        print(f"Accuracy:  {metrics['accuracy']*100:.2f}%")
        print(f"Precision: {metrics['precision']*100:.2f}%")
        print(f"Recall:    {metrics['recall']*100:.2f}%")
        print(f"F1 Score:  {metrics['f1_score']*100:.2f}%")
        print(f"ROC AUC:   {metrics['roc_auc']:.4f}")
        
        # Confusion Matrix
        print(f"\n Confusion Matrix:")
        cm = metrics['confusion_matrix']
        print(f"                Predicted")
        print(f"              Benign  Malicious")
        print(f"Actual Benign   {cm[0][0]:5d}     {cm[0][1]:5d}")
        print(f"     Malicious  {cm[1][0]:5d}     {cm[1][1]:5d}")
        
        # Calculate additional metrics
        tn, fp, fn, tp = cm[0][0], cm[0][1], cm[1][0], cm[1][1]
        false_positive_rate = fp / (fp + tn) * 100 if (fp + tn) > 0 else 0
        false_negative_rate = fn / (fn + tp) * 100 if (fn + tp) > 0 else 0
        
        print(f"\n🎯 Error Analysis:")
        print(f"False Positive Rate: {false_positive_rate:.2f}% ({fp} benign flagged as malicious)")
        print(f"False Negative Rate: {false_negative_rate:.2f}% ({fn} malicious missed)")
        
        if false_positive_rate > 5:
            print(f"  High false positive rate - consider adjusting threshold")
        if false_negative_rate > 10:
            print(f"  High false negative rate - critical threats may be missed")
        
        # Feature importance
        print(f"\n🔝 Top 15 Most Important Features:")
        importances = self.model.feature_importances_
        feature_importance = sorted(
            zip(self.feature_names, importances), 
            key=lambda x: x[1], 
            reverse=True
        )
        
        for i, (feature, importance) in enumerate(feature_importance[:15], 1):
            bar_length = int(importance / max(importances) * 30)
            bar = '█' * bar_length
            print(f"   {i:2d}. {feature:35s} {bar} {importance:8.1f}")
        
        return metrics
    
    def save_model(self) -> Tuple[Path, Path]:
        """Save trained model and scaler"""
        
        print(f"\n{'='*70}")
        print(f"💾 SAVING MODEL")
        print(f"{'='*70}")
        
        model_path = Config.MODEL_DIR / f"lightgbm_model_v{self.model_version}.pkl"
        scaler_path = Config.MODEL_DIR / f"lightgbm_scaler_v{self.model_version}.pkl"
        metrics_path = Config.LOGS_DIR / f"training_metrics_v{self.model_version}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        
        # Check if model already exists
        if model_path.exists():
            backup_path = Config.MODEL_DIR / f"lightgbm_model_v{self.model_version}_backup_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pkl"
            print(f"⚠️  Model v{self.model_version} already exists - creating backup")
            model_path.rename(backup_path)
        
        # Save model and scaler
        try:
            joblib.dump(self.model, model_path)
            joblib.dump(self.scaler, scaler_path)
        except Exception as e:
            raise IOError(f"❌ Failed to save model: {e}")
        
        # Save metrics with feature names
        metrics_with_features = {
            **self.training_metrics,
            'feature_names': self.feature_names,
            'model_version': self.model_version,
            'timestamp': datetime.now().isoformat(),
            'config': {
                'test_size': Config.TEST_SIZE,
                'random_state': Config.RANDOM_STATE,
                'lgbm_params': Config.LGBM_PARAMS
            }
        }
        
        with open(metrics_path, 'w') as f:
            json.dump(metrics_with_features, f, indent=2)
        
        print(f"✅ Model saved: {model_path.name}")
        print(f"   Size: {model_path.stat().st_size / 1024:.1f} KB")
        print(f"✅ Scaler saved: {scaler_path.name}")
        print(f"   Size: {scaler_path.stat().st_size / 1024:.1f} KB")
        print(f"✅ Metrics saved: {metrics_path.name}")
        
        return model_path, scaler_path


# ===========================================================================
# MAIN EXECUTION
# ===========================================================================

def main():
    """Main execution function"""
    
    print(f"\n{'='*70}")
    print(f"🤖 RANSOMGUARD ML TRAINER v{Config.MODEL_VERSION}")
    print(f"{'='*70}")
    print(f"Enterprise 85-feature ransomware detection system")
    print(f"{'='*70}\n")
    
    # Setup
    setup_directories()
    
    # Find dataset
    if len(sys.argv) > 1:
        dataset_path = Path(sys.argv[1])
    else:
        print(f"🔍 Searching for latest dataset in {Config.DATASET_DIR}...")
        dataset_path = find_latest_dataset()
    
    if dataset_path is None or not dataset_path.exists():
        print(f"\n❌ No dataset found!")
        print(f"\nUsage: python train_model.py [path/to/dataset.csv]")
        print(f"Or place dataset in: {Config.DATASET_DIR}")
        print(f"\n💡 Generate dataset first:")
        print(f"   python dataset_generator.py")
        sys.exit(1)
    
    print(f"📁 Using dataset: {dataset_path.name}")
    print(f"   Path: {dataset_path}")
    print(f"   Size: {dataset_path.stat().st_size / (1024*1024):.1f} MB\n")
    
    # Train
    try:
        trainer = RansomwareTrainer()
        X, y = trainer.load_and_prepare_data(str(dataset_path))
        metrics = trainer.train(X, y)
        model_path, scaler_path = trainer.save_model()
        
        # Final summary
        print(f"\n{'='*70}")
        print(f"🎉 TRAINING COMPLETE!")
        print(f"{'='*70}")
        print(f"✅ Model: {model_path.name}")
        print(f"✅ Version: v{Config.MODEL_VERSION}")
        print(f"✅ Test Accuracy: {metrics['accuracy']*100:.2f}%")
        print(f"✅ F1 Score: {metrics['f1_score']*100:.2f}%")
        print(f"✅ ROC AUC: {metrics['roc_auc']:.4f}")
        print(f"\n🚀 Next steps:")
        print(f"   1. Update detector.py to use v{Config.MODEL_VERSION}")
        print(f"   2. Update behavioral_analyzer.py for 85 features")
        print(f"   3. Test detection: python backend/main.py")
        print(f"{'='*70}\n")
        
    except Exception as e:
        print(f"\n❌ Training failed: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
