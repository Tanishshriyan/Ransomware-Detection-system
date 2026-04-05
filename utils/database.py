"""
Async SQLite logger for events, predictions, and alerts.
Uses aiosqlite when available; otherwise uses sqlite3 synchronous mode.

Schema:
- events (id, timestamp, pid, process, event_json)
- predictions (id, timestamp, pid, process, features_json, prediction_json)
- alerts (id, timestamp, pid, process, alert_json)
- model_metadata (id, key, value_json)
"""

import os
import json
import time
import sqlite3
from pathlib import Path
from typing import Optional, List, Dict, Any

from utils.resource_path import resolve_runtime_path

try:
    import aiosqlite
    ASYNC_DB = True
except Exception:
    ASYNC_DB = False

DB_PATH_DEFAULT = "data/ransomguard.db"

CREATE_EVENTS = """
CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp REAL,
    pid INTEGER,
    process TEXT,
    event_json TEXT
);
"""

CREATE_PREDICTIONS = """
CREATE TABLE IF NOT EXISTS predictions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp REAL,
    pid INTEGER,
    process TEXT,
    features_json TEXT,
    prediction_json TEXT
);
"""

CREATE_ALERTS = """
CREATE TABLE IF NOT EXISTS alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp REAL,
    pid INTEGER,
    process TEXT,
    alert_json TEXT
);
"""

CREATE_META = """
CREATE TABLE IF NOT EXISTS model_metadata (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    key TEXT UNIQUE,
    value_json TEXT
);
"""

class Database:
    def __init__(self, db_path: str = DB_PATH_DEFAULT):
        self.db_path = resolve_runtime_path(db_path)
        self._conn = None
        Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)

    # ---------------- Async API using aiosqlite -----------------------------
    async def init_db(self):
        if ASYNC_DB:
            self._conn = await aiosqlite.connect(self.db_path)
            await self._conn.execute(CREATE_EVENTS)
            await self._conn.execute(CREATE_PREDICTIONS)
            await self._conn.execute(CREATE_ALERTS)
            await self._conn.execute(CREATE_META)
            await self._ensure_events_columns_async()
            await self._conn.commit()
        else:
            # synchronous sqlite3 mode
            self._conn = sqlite3.connect(self.db_path, check_same_thread=False)
            cur = self._conn.cursor()
            cur.execute(CREATE_EVENTS)
            cur.execute(CREATE_PREDICTIONS)
            cur.execute(CREATE_ALERTS)
            cur.execute(CREATE_META)
            self._ensure_events_columns_sync()
            self._conn.commit()

    async def _ensure_events_columns_async(self):
        """Backfill legacy `events` table columns for old project DBs."""
        required = {
            "timestamp": "REAL",
            "pid": "INTEGER",
            "process": "TEXT",
            "event_json": "TEXT",
        }
        cur = await self._conn.execute("PRAGMA table_info(events)")
        rows = await cur.fetchall()
        existing = {str(r[1]).lower() for r in rows}

        for col, col_type in required.items():
            if col.lower() not in existing:
                await self._conn.execute(f"ALTER TABLE events ADD COLUMN {col} {col_type}")

    def _ensure_events_columns_sync(self):
        required = {
            "timestamp": "REAL",
            "pid": "INTEGER",
            "process": "TEXT",
            "event_json": "TEXT",
        }
        cur = self._conn.cursor()
        cur.execute("PRAGMA table_info(events)")
        rows = cur.fetchall()
        existing = {str(r[1]).lower() for r in rows}

        for col, col_type in required.items():
            if col.lower() not in existing:
                cur.execute(f"ALTER TABLE events ADD COLUMN {col} {col_type}")

    async def close(self):
        if not self._conn:
            return
        if ASYNC_DB:
            await self._conn.close()
        else:
            self._conn.close()

    async def log_event(self, event: Dict[str, Any]):
        ts = time.time()
        pid = int(event.get("pid") or 0)
        process = event.get("process") or ""
        payload = json.dumps(event, default=str)
        if ASYNC_DB:
            await self._conn.execute("INSERT INTO events (timestamp, pid, process, event_json) VALUES (?, ?, ?, ?)", (ts, pid, process, payload))
            await self._conn.commit()
        else:
            cur = self._conn.cursor()
            cur.execute("INSERT INTO events (timestamp, pid, process, event_json) VALUES (?, ?, ?, ?)", (ts, pid, process, payload))
            self._conn.commit()

    async def log_prediction(self, pid: int, process: str, features: Dict[str, Any], prediction: Dict[str, Any]):
        ts = time.time()
        fs = json.dumps(features, default=str)
        pred = json.dumps(prediction, default=str)
        if ASYNC_DB:
            await self._conn.execute("INSERT INTO predictions (timestamp, pid, process, features_json, prediction_json) VALUES (?, ?, ?, ?, ?)", (ts, pid, process, fs, pred))
            await self._conn.commit()
        else:
            cur = self._conn.cursor()
            cur.execute("INSERT INTO predictions (timestamp, pid, process, features_json, prediction_json) VALUES (?, ?, ?, ?, ?)", (ts, pid, process, fs, pred))
            self._conn.commit()

    async def log_alert(self, pid: int, process: str, alert: Dict[str, Any]):
        ts = time.time()
        payload = json.dumps(alert, default=str)
        if ASYNC_DB:
            await self._conn.execute("INSERT INTO alerts (timestamp, pid, process, alert_json) VALUES (?, ?, ?, ?)", (ts, pid, process, payload))
            await self._conn.commit()
        else:
            cur = self._conn.cursor()
            cur.execute("INSERT INTO alerts (timestamp, pid, process, alert_json) VALUES (?, ?, ?, ?)", (ts, pid, process, payload))
            self._conn.commit()

    async def save_model_metadata(self, key: str, value: Dict[str, Any]):
        v = json.dumps(value, default=str)
        if ASYNC_DB:
            await self._conn.execute("INSERT OR REPLACE INTO model_metadata (key, value_json) VALUES (?, ?)", (key, v))
            await self._conn.commit()
        else:
            cur = self._conn.cursor()
            cur.execute("INSERT OR REPLACE INTO model_metadata (key, value_json) VALUES (?, ?)", (key, v))
            self._conn.commit()

    async def get_recent_logs(self, limit: int = 50):
        if ASYNC_DB:
            cur = await self._conn.execute("SELECT id, timestamp, pid, process, event_json FROM events ORDER BY id DESC LIMIT ?", (limit,))
            rows = await cur.fetchall()
        else:
            cur = self._conn.cursor()
            cur.execute("SELECT id, timestamp, pid, process, event_json FROM events ORDER BY id DESC LIMIT ?", (limit,))
            rows = cur.fetchall()
        result = []
        for r in rows:
            result.append({
                "id": r[0],
                "timestamp": r[1],
                "pid": r[2],
                "process": r[3],
                "event": json.loads(r[4]) if r[4] else {}
            })
        return result
