import time
from collections import defaultdict, deque
from typing import Dict, Any, List, Set
import joblib
import os

from ml_model.schema import LABEL_COLUMN, MODEL_FEATURE_NAMES, canonicalize_features

WINDOW_SECONDS_DEFAULT = 60

# ------------------ Feature Extractor ------------------
class FeatureExtractor:
    def __init__(self, window_seconds: int = WINDOW_SECONDS_DEFAULT):
        self.window = window_seconds
        self.process_stats = defaultdict(lambda: {
            "file_writes": deque(),
            "file_renames": deque(),
            "entropy_samples": deque(),
            "extensions": set(),
            "start_time": time.time(),
            "last_cpu": 0.0,
            "last_mem": 0.0,
            "last_threads": 0,
            "network_conn": 0,
            "parent": None,
        })

    def update_process_activity(self, pid: int, event_type: str, event_data: dict):
        now = time.time()
        st = self.process_stats[pid]

        et = (event_type or "").lower()
        if et in ("file_write", "write", "modified", "created"):
            st["file_writes"].append(now)
        if et in ("file_rename", "rename", "moved"):
            st["file_renames"].append(now)
        if "entropy" in event_data and event_data["entropy"] is not None:
            st["entropy_samples"].append((now, float(event_data["entropy"])))
        if "path" in event_data and event_data["path"]:
            p = event_data["path"]
            if "." in p:
                st["extensions"].add(p.split(".")[-1].lower())
        if "parent" in event_data and event_data["parent"] is not None:
            st["parent"] = event_data["parent"]

        self._prune(pid)

    def update_process_metrics(self, pid: int, cpu: float, memory: float, threads: int, network_connections: int = 0):
        st = self.process_stats[pid]
        st["last_cpu"] = float(cpu)
        st["last_mem"] = float(memory)
        st["last_threads"] = int(threads)
        st["network_conn"] = int(network_connections)

    def _prune(self, pid: int):
        now = time.time()
        cutoff = now - self.window
        st = self.process_stats[pid]
        while st["file_writes"] and st["file_writes"][0] < cutoff:
            st["file_writes"].popleft()
        while st["file_renames"] and st["file_renames"][0] < cutoff:
            st["file_renames"].popleft()
        while st["entropy_samples"] and st["entropy_samples"][0][0] < cutoff:
            st["entropy_samples"].popleft()

    def extract_features(self, pid: int, window_seconds: int = None) -> Dict[str, Any]:
        if window_seconds is None:
            window_seconds = self.window
        if pid not in self.process_stats:
            return self._get_default_features()

        self.window = window_seconds
        self._prune(pid)
        st = self.process_stats[pid]
        now = time.time()
        uptime = max(0.0, now - st.get("start_time", now))

        writes = list(st["file_writes"])
        renames = list(st["file_renames"])
        entropy_samples = [v for _, v in st["entropy_samples"]]

        file_writes = len(writes)
        file_renames = len(renames)
        write_rate = (file_writes / max(1.0, window_seconds)) * 60.0
        rename_write_ratio = file_renames / (file_writes + 1e-6)
        entropy_mean = float(sum(entropy_samples) / len(entropy_samples)) if entropy_samples else 0.0
        entropy_std = float(np_std(entropy_samples)) if entropy_samples else 0.0
        entropy_spike = False
        if entropy_samples:
            last = entropy_samples[-1]
            if len(entropy_samples) >= 2 and (last - entropy_mean) > 1.2:
                entropy_spike = True

        features = {
            "cpu_percent": float(st["last_cpu"]),
            "memory_percent": float(st["last_mem"]),
            "file_writes": int(file_writes),
            "file_renames": int(file_renames),
            "entropy_mean": float(entropy_mean),
            "entropy_std": float(entropy_std),
            "write_rate": float(write_rate),
            "rename_write_ratio": float(rename_write_ratio),
            "unique_extensions": int(len(st["extensions"])),
            "threads": int(st["last_threads"]),
            "network_connections": int(st["network_conn"]),
            "uptime": float(uptime),
            "parent_risk": int(1 if (st.get("parent") and st.get("parent") in ("powershell.exe", "cmd.exe", "wmic.exe")) else 0),
            "entropy_spike": bool(entropy_spike),
        }
        return features

    def _get_default_features(self):
        return {k: 0.0 if isinstance(k, float) else 0 for k in [
            "cpu_percent", "memory_percent", "file_writes", "file_renames",
            "entropy_mean", "entropy_std", "write_rate", "rename_write_ratio",
            "unique_extensions", "threads", "network_connections", "uptime", "parent_risk", "entropy_spike"]}

    def cleanup_old_processes(self, active_pids: Set[int], max_age_seconds: int = 600):
        now = time.time()
        remove = []
        for pid, st in list(self.process_stats.items()):
            if pid not in active_pids and (now - st.get("start_time", now)) > max_age_seconds:
                remove.append(pid)
        for pid in remove:
            del self.process_stats[pid]

    def get_stats_summary(self) -> Dict[str, Any]:
        total_writes = sum(len(st["file_writes"]) for st in self.process_stats.values())
        total_renames = sum(len(st["file_renames"]) for st in self.process_stats.values())
        return {"tracked_processes": len(self.process_stats), "total_file_writes": total_writes, "total_file_renames": total_renames}

# Small helper
def np_std(arr: List[float]) -> float:
    if not arr:
        return 0.0
    mean = sum(arr) / len(arr)
    var = sum((x - mean) ** 2 for x in arr) / len(arr)
    return var ** 0.5

# ------------------ ML Model Wrapper ------------------
class RansomwareMLModel:
    def __init__(self, model_dir="ml_model/models"):
        self.model = None
        self.scaler = None
        self.model_dir = model_dir
        self.feature_columns = list(MODEL_FEATURE_NAMES)
        os.makedirs(self.model_dir, exist_ok=True)

    def train(self, train_csv_path="data/training_data/ransomware_dataset.csv", model_type="lightgbm"):
        import lightgbm as lgb
        import pandas as pd
        import xgboost as xgb
        from sklearn.preprocessing import StandardScaler
        from sklearn.model_selection import train_test_split
        from sklearn.metrics import classification_report

        df = pd.read_csv(train_csv_path)
        from ml_model.schema import validate_feature_columns
        validate_feature_columns(list(df.columns), label_column=LABEL_COLUMN, require_order=True)
        X = df.loc[:, list(MODEL_FEATURE_NAMES)].values.astype(float)
        y = df[LABEL_COLUMN].astype(int).values

        # Scale
        self.scaler = StandardScaler()
        X_scaled = self.scaler.fit_transform(X)

        X_train, X_test, y_train, y_test = train_test_split(
            X_scaled, y, test_size=0.2, random_state=42, stratify=y
        )

        # Train model
        if model_type.lower() == "lightgbm":
            self.model = lgb.LGBMClassifier(
                n_estimators=500,
                max_depth=12,
                learning_rate=0.05,
                class_weight="balanced",
                n_jobs=-1,
                random_state=42
            )
        elif model_type.lower() == "xgboost":
            self.model = xgb.XGBClassifier(
                n_estimators=500,
                max_depth=12,
                learning_rate=0.05,
                scale_pos_weight=(len(y_train[y_train==0])/len(y_train[y_train==1])),
                n_jobs=-1,
                use_label_encoder=False,
                eval_metric="logloss",
                random_state=42
            )
        else:
            raise ValueError("Unknown model type")

        print(f"🔬 Training {model_type}...")
        self.model.fit(X_train, y_train)

        y_pred = self.model.predict(X_test)
        print("\n📊 Model Performance:")
        print(classification_report(y_test, y_pred, target_names=["Benign", "Ransomware"]))

        # Save
        joblib.dump(self.model, os.path.join(self.model_dir, "model.pkl"))
        joblib.dump(self.scaler, os.path.join(self.model_dir, "scaler.pkl"))
        print(f"✅ Model & scaler saved in {self.model_dir}")

    def load_model(self):
        model_path = os.path.join(self.model_dir, "model.pkl")
        scaler_path = os.path.join(self.model_dir, "scaler.pkl")
        if os.path.exists(model_path) and os.path.exists(scaler_path):
            self.model = joblib.load(model_path)
            self.scaler = joblib.load(scaler_path)
            print("✅ ML model loaded successfully")
            return True
        print("❌ No trained model found")
        return False

    def predict(self, features: Dict[str, Any]):
        import numpy as np
        if not self.model or not self.scaler:
            return {"is_ransomware": False, "confidence": 0, "probability": 0.0, "model_status": "not_loaded"}
        try:
            ordered = canonicalize_features(features)
            X = np.array([[ordered[col] for col in self.feature_columns]])
            X_scaled = self.scaler.transform(X)
            pred = self.model.predict(X_scaled)[0]
            proba = self.model.predict_proba(X_scaled)[0] if hasattr(self.model, "predict_proba") else [1-pred, pred]
            malware_prob = proba[1] if len(proba) > 1 else 0.0
            return {
                "is_ransomware": bool(pred == 1),
                "confidence": int(round(malware_prob * 100)),
                "probability": float(malware_prob),
                "model_status": "active"
            }
        except Exception as e:
            print(f"❌ Prediction error: {e}")
            return {"is_ransomware": False, "confidence": 0, "probability": 0.0, "model_status": "error"}
