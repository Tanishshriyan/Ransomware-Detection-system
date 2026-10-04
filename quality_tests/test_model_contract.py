import csv
import os
import tempfile
import unittest
from pathlib import Path

from backend.behavioral_analyzer import BehavioralAnalyzer
from backend.detector import ThreatDetector
from backend.monitor import FileSystemIntelligence
from ml_model.schema import MODEL_FEATURE_NAMES


PROJECT_ROOT = Path(__file__).resolve().parents[1]


class ModelContractTests(unittest.TestCase):
    def test_training_csv_matches_canonical_feature_set(self):
        dataset = PROJECT_ROOT / "data" / "training_data" / "ransomware_dataset.csv"
        with dataset.open("r", encoding="utf-8", newline="") as handle:
            columns = next(csv.reader(handle))

        self.assertEqual(set(columns[:-1]), set(MODEL_FEATURE_NAMES))
        self.assertEqual(len(columns[:-1]), len(MODEL_FEATURE_NAMES))
        self.assertEqual(columns[-1], "malware_label")

    def test_live_analyzer_returns_training_order(self):
        analyzer = BehavioralAnalyzer()
        analyzer.update_process_metrics(12345, cpu_percent=10.0, memory_percent=20.0, threads=4)
        analyzer.ingest_event(
            {
                "valid": True,
                "pid": 12345,
                "event_type": "WRITE",
                "path": "example.txt",
                "entropy": 5.2,
            }
        )

        features = analyzer.extract_features(12345)
        self.assertIsNotNone(features)
        self.assertEqual(list(features), list(MODEL_FEATURE_NAMES))
        self.assertEqual(len(features), 85)

    def test_detector_accepts_live_features(self):
        analyzer = BehavioralAnalyzer()
        analyzer.update_process_metrics(12346, cpu_percent=10.0, memory_percent=20.0, threads=4)
        analyzer.ingest_event(
            {
                "valid": True,
                "pid": 12346,
                "event_type": "WRITE",
                "path": "example.txt",
                "entropy": 5.2,
            }
        )
        features = analyzer.extract_features(12346)

        detector = ThreatDetector()
        analysis = detector.prepare_analysis(features)
        self.assertTrue(analysis["valid"])
        result = detector.analyze_features(analysis)
        self.assertEqual(result["status"], "OK")
        self.assertGreaterEqual(result["probability"], 0.0)
        self.assertLessEqual(result["probability"], 1.0)

    def test_rename_extension_is_detected_even_if_file_is_gone(self):
        intelligence = FileSystemIntelligence()
        _, indicators = intelligence.analyze_file("C:/lab/example.lockbit")
        self.assertIn("ransomware_ext:.lockbit", indicators)

    def test_registered_pid_path_skips_slow_open_file_scan(self):
        analyzer = BehavioralAnalyzer()
        events = []
        intelligence = FileSystemIntelligence(
            callback=events.append,
            behavioral_analyzer=analyzer,
            pid_resolver=lambda _path: os.getpid(),
        )
        intelligence._get_process_for_file_pid = lambda _path: self.fail(
            "registered PID should be used before the open-file scan"
        )

        with tempfile.TemporaryDirectory() as tmpdir:
            target = Path(tmpdir) / "sample.lockbit"
            target.write_bytes(os.urandom(2048))
            intelligence._handle_event(
                str(target),
                "moved",
                metadata={"old_path": str(Path(tmpdir) / "sample.txt")},
            )

        self.assertEqual(len(events), 1)
        self.assertEqual(events[0].pid, os.getpid())
        self.assertGreaterEqual(events[0].suspicion_score, 75)
        self.assertEqual(analyzer.total_events, 1)


if __name__ == "__main__":
    unittest.main()
