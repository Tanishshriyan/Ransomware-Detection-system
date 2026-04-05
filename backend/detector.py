"""
backend/detector.py - FIXED VERSION

STRICT ML-BASED Threat Detector with proper behavioral analyzer integration
Connects monitor events → behavioral analyzer → ML prediction → threat decision
"""

import time
from utils.resource_path import resource_path
import os
import joblib
import numpy as np
from typing import Dict, Any, Optional
import warnings
import logging

warnings.filterwarnings('ignore', category=UserWarning, module='sklearn')

logger = logging.getLogger("detector")

class ThreatDetector:
    """
    FIXED: Now properly integrated with BehavioralAnalyzer
    
    Flow:
    1. Receives events from monitor
    2. Passes to behavioral_analyzer for feature extraction
    3. Runs ML prediction on features
    4. Returns comprehensive threat assessment
    """
    
    # Feature order must match training data (85 features)
    FEATURE_ORDER = [
        # CPU Metrics (5 features)
        "cpu_percent", "cpu_percent_max", "cpu_percent_min", 
        "cpu_sustained_count", "cpu_variance",
        
        # Memory Metrics (5 features)
        "memory_percent", "memory_percent_max", "memory_percent_min",
        "memory_growth_rate", "memory_variance",
        
        # Thread Metrics (3 features)
        "threads", "thread_spike_count", "thread_variance",
        
        # Process Timing (2 features)
        "uptime", "process_age_seconds",
        
        # File Write Operations (6 features)
        "file_writes", "file_write_rate", "file_write_burst_count",
        "file_write_variance", "sequential_write_count", "random_write_count",
        
        # File Read Operations (4 features)
        "file_reads", "file_read_rate", "file_read_write_ratio",
        "large_file_read_count",
        
        # File Delete Operations (4 features)
        "file_deletes", "file_delete_rate", "file_delete_burst_count",
        "mass_delete_events",
        
        # File Rename Operations (4 features)
        "file_renames", "file_rename_rate", "extension_change_count",
        "suspicious_rename_pattern",
        
        # File Modifications (3 features)
        "file_modifications", "modification_rate", "modification_burst_count",
        
        # Entropy Analysis (8 features)
        "entropy_mean", "entropy_stddev", "entropy_max", "entropy_min",
        "entropy_range", "entropy_variance", "entropy_change_rate",
        "high_entropy_file_ratio",
        
        # File Operation Patterns (5 features)
        "rapid_file_ops_count", "mass_file_change_events",
        "read_write_delete_pattern", "cascading_modification_pattern",
        "file_overwrite_count",
        
        # Extension Analysis (4 features)
        "suspicious_extensions_count", "unknown_extension_count",
        "double_extension_count", "extension_entropy",
        
        # Network Activity (6 features)
        "network_connections", "network_connections_max", 
        "suspicious_port_count", "c2_beacon_score",
        "outbound_data_kb", "data_exfiltration_score",
        
        # Advanced Behavioral (8 features)
        "process_injection_attempts", "registry_modification_count",
        "shadow_copy_interaction", "backup_deletion_attempts",
        "privilege_escalation_attempts", "anti_analysis_indicators",
        "persistence_mechanism_count", "lateral_movement_score",
        
        # Parent Process Context (4 features)
        "parent_suspicious", "parent_is_office", "parent_is_browser",
        "spawned_by_script",
        
        # Timing Patterns (4 features)
        "operation_time_variance", "inter_operation_delay_avg",
        "burst_activity_score", "idle_time_ratio",

        # --- NEW: MISSING 10 FEATURES (System Resources & IO) ---
        # Added to satisfy the 85-feature requirement of the Scaler
        "io_read_bytes_rate", "io_write_bytes_rate",
        "page_faults_rate", "context_switches_rate",
        "num_handles", "io_priority",
        "working_set_size", "private_bytes",
        "directory_traversal_depth", "unique_paths_touched"
    ]

    
    def __init__(self, behavioral_analyzer=None, config=None):
        """
        Initialize ThreatDetector with ML model and behavioral analyzer
        
        Args:
            behavioral_analyzer: BehavioralAnalyzer instance for feature extraction
            config: Configuration object (optional)
        """
        self.config = config
        self.model = None
        self.scaler = None
        self.model_loaded = False
        self.model_version = "3.0"
        self.load_error = None
        
        # FIXED: Store behavioral analyzer reference
        self.behavioral_analyzer = behavioral_analyzer
        
        # Statistics
        self.stats = {
            'total_analyses': 0,
            'safe_detections': 0,
            'suspicious_detections': 0,
            'ransomware_detections': 0,
            'errors': 0,
            'model_unavailable': 0,
            'features_extracted': 0,
            'ml_predictions': 0
        }
        
        # Determine model paths
        if config and hasattr(config, 'get'):
            model_path = config.get('ml.model_path', self._default_model_path())
            scaler_path = config.get('ml.scaler_path', self._default_scaler_path())
        else:
            model_path = self._default_model_path()
            scaler_path = self._default_scaler_path()
        
        # Load model
        self._load_model(model_path, scaler_path)
        
    def _default_model_path(self) -> str:
        """Get default model path relative to project root"""
        current_dir = os.path.dirname(os.path.abspath(__file__))
        project_root = os.path.dirname(current_dir)
        return resource_path("ml_model/models/lightgbm_model_v3.0.pkl")
    
    def _default_scaler_path(self) -> str:
        """Get default scaler path relative to project root"""
        current_dir = os.path.dirname(os.path.abspath(__file__))
        project_root = os.path.dirname(current_dir)
        return resource_path("ml_model/models/lightgbm_scaler_v3.0.pkl")
    
    def _load_model(self, model_path: str, scaler_path: str) -> None:
        """Load ML model and scaler"""
        try:
            if not os.path.exists(model_path):
                raise FileNotFoundError(f"Model file not found: {model_path}")
            if not os.path.exists(scaler_path):
                raise FileNotFoundError(f"Scaler file not found: {scaler_path}")
            
            self.model = joblib.load(model_path)
            self.scaler = joblib.load(scaler_path)
            self.model_loaded = True
            logger.info(f"[DETECTOR] ML model loaded: {model_path}")
            logger.info(f"[DETECTOR] Scaler loaded: {scaler_path}")
        except Exception as e:
            self.load_error = str(e)
            self.model_loaded = False
            logger.error(f"[DETECTOR] Failed to load ML model: {e}")
    
    def analyze_process(self, pid: int, process_name: str = None) -> Dict[str, Any]:
        """
        FIXED: Analyze a process using behavioral analyzer + ML
        
        Args:
            pid: Process ID to analyze
            process_name: Optional process name for logging
            
        Returns:
            Complete threat assessment with ML prediction
        """
        result = {
            "pid": pid,
            "process": process_name or f"PID_{pid}",
            "timestamp": time.time(),
            "ml_prediction": None,
            "features": None,
            "valid": False,
            "error": None
        }
        
        # Check if behavioral analyzer available
        if self.behavioral_analyzer is None:
            result["error"] = "No behavioral analyzer configured"
            result["ml_prediction"] = {
                "decision": "UNAVAILABLE",
                "probability": None,
                "threat_level": None,
                "reason": "no_behavioral_analyzer"
            }
            return result
        
        # Extract features using behavioral analyzer
        try:
            features = self.behavioral_analyzer.extract_features(pid)
            
            if not features:
                result["error"] = "No features available for PID"
                result["ml_prediction"] = {
                    "decision": "UNAVAILABLE",
                    "probability": None,
                    "threat_level": None,
                    "reason": "no_features"
                }
                return result
            
            result["features"] = features
            self.stats['features_extracted'] += 1
            
            # Validate features
            analysis = self._validate_features(features)
            
            # Run ML prediction
            ml_result = self.analyze_features(analysis)
            result["ml_prediction"] = ml_result
            result["valid"] = analysis.get("valid", False)
            
            # Add metadata for killswitch
            result["metadata"] = {
                "detection_source": "ML_PRIMARY" if self.model_loaded else "HEURISTIC",
                "ml_confidence": ml_result.get("probability", 0.0) if ml_result.get("probability") is not None else 0.0,
                "feature_count": len(features)
            }
            
            # Set detection_mode based on ML result
            if ml_result.get("decision") == "RANSOMWARE":
                result["detection_mode"] = "ML_CONFIRMED"
            elif ml_result.get("decision") == "SUSPICIOUS":
                result["detection_mode"] = "SCORE_BASED"
            else:
                result["detection_mode"] = "LOW_RISK"
            
            # Set suspicion score for killswitch (CRASH FIX HERE)
            probability = ml_result.get("probability")
            if probability is not None:
                result["suspicion_score"] = int(probability * 100)
            else:
                result["suspicion_score"] = 0
            
            return result
            
        except Exception as e:
            logger.exception(f"[DETECTOR] Error analyzing PID {pid}: {e}")
            result["error"] = str(e)
            result["ml_prediction"] = {
                "decision": "ERROR",
                "probability": None,
                "threat_level": None,
                "reason": f"analysis_error: {str(e)}"
            }
            # Fallback score to prevent downstream errors
            result["suspicion_score"] = 0
            return result
    
    def _validate_features(self, features: Dict) -> Dict:
        """Validate feature dictionary has all required features"""
        missing = []
        for feature_name in self.FEATURE_ORDER:
            if feature_name not in features:
                missing.append(feature_name)
        
        if missing:
            return {
                "valid": False,
                "reason": f"Missing {len(missing)} features: {missing[:5]}...",
                "features": features
            }
        
        return {
            "valid": True,
            "features": features,
            "feature_count": len(features)
        }
    
    def analyze_features(self, analysis: Dict) -> Dict:
        """
        Perform ML inference on extracted features
        
        Args:
            analysis: Feature analysis dict with 'valid', 'features', 'reason' keys
            
        Returns:
            Detection result dict with decision, probability, threat_level
        """
        self.stats['total_analyses'] += 1
        
        result = {
            "timestamp": time.time(),
            "status": "OK",
            "decision": "UNDETERMINED",
            "probability": None,
            "threat_level": None,
            "reason": None,
        }
        
        # Model availability check
        if not self.model_loaded:
            result.update({
                "status": "DEGRADED",
                "decision": "UNAVAILABLE",
                "reason": f"ML model not loaded: {self.load_error}"
            })
            self.stats['model_unavailable'] += 1
            return result
        
        # Input validation
        if not analysis.get("valid", False):
            result.update({
                "status": "INVALID",
                "decision": "UNAVAILABLE",
                "reason": analysis.get("reason", "Invalid feature set")
            })
            self.stats['errors'] += 1
            return result
        
        features = analysis.get("features")
        if not isinstance(features, dict):
            result.update({
                "status": "INVALID",
                "decision": "UNAVAILABLE",
                "reason": "Features missing or malformed"
            })
            self.stats['errors'] += 1
            return result
        
        # Feature extraction and prediction
        try:
            feature_vector = []
            for key in self.FEATURE_ORDER:
                if key not in features:
                    raise KeyError(f"Missing feature: {key}")
                feature_vector.append(float(features[key]))
            
            # Use cached method if available
            if hasattr(self, '_use_dataframe'):
                probability = self._predict_cached(feature_vector, features)
            else:
                probability = self._predict_auto_detect(feature_vector, features)
            
            result["probability"] = probability
            self.stats['ml_predictions'] += 1
            
        except Exception as e:
            result.update({
                "status": "ERROR",
                "decision": "UNAVAILABLE",
                "reason": f"Prediction error: {str(e)}"
            })
            self.stats['errors'] += 1
            logger.error(f"[DETECTOR] Prediction error: {e}")
            return result
        
        # Decision policy
        if probability < 0.30:
            result["decision"] = "SAFE"
            result["threat_level"] = "NONE"
            self.stats['safe_detections'] += 1
        elif probability < 0.60:
            result["decision"] = "SUSPICIOUS"
            result["threat_level"] = "MEDIUM"
            self.stats['suspicious_detections'] += 1
        else:
            result["decision"] = "RANSOMWARE"
            result["threat_level"] = "HIGH"
            self.stats['ransomware_detections'] += 1
        
        logger.debug(f"[DETECTOR] Result: {result['decision']} (p={probability:.3f})")
        logger.info(
            f"[ML] decision={result['decision']} "
            f"probability={probability:.3f} "
            f"threat={result['threat_level']}"
        )

        return result
    
    def _predict_auto_detect(self, feature_vector, features):
        """Auto-detect correct format and cache for future use"""
        import pandas as pd
        
        # Try DataFrame first
        try:
            feature_dict = {key: [float(features[key])] for key in self.FEATURE_ORDER}
            X = pd.DataFrame(feature_dict)
            X_scaled = self.scaler.transform(X)
            probability = float(self.model.predict_proba(X_scaled)[0][1])
            
            self._use_dataframe = True
            logger.debug("[DETECTOR] Using DataFrame format (cached)")
            return probability
        
        except Exception as e:
            logger.debug(f"[DETECTOR] DataFrame failed ({e}), trying numpy")
            X = np.array(feature_vector).reshape(1, -1)
            X_scaled = self.scaler.transform(X)
            probability = float(self.model.predict_proba(X_scaled)[0][1])
            
            self._use_dataframe = False
            logger.debug("[DETECTOR] Using numpy format (cached)")
            return probability
    
    def _predict_cached(self, feature_vector, features):
        """Use cached prediction method"""
        if self._use_dataframe:
            import pandas as pd
            feature_dict = {key: [float(features[key])] for key in self.FEATURE_ORDER}
            X = pd.DataFrame(feature_dict)
        else:
            X = np.array(feature_vector).reshape(1, -1)
        
        X_scaled = self.scaler.transform(X)
        return float(self.model.predict_proba(X_scaled)[0][1])
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get detector statistics"""
        return {
            'model_loaded': self.model_loaded,
            'model_version': self.model_version,
            'load_error': self.load_error,
            **self.stats,
            'detection_rate': {
                'safe': self.stats['safe_detections'],
                'suspicious': self.stats['suspicious_detections'],
                'ransomware': self.stats['ransomware_detections']
            }
        }
    
    def is_available(self) -> bool:
        """Check if detector is available for use"""
        return self.model_loaded and self.behavioral_analyzer is not None