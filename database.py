"""
database.py
Handles all SQLite storage for the IDS: connection setup, schema creation,
and helper functions for inserting and querying detected events.
"""

import sqlite3
from datetime import datetime
from contextlib import contextmanager

DB_PATH = "ids_events.db"


@contextmanager
def get_connection():
    """Context manager so every caller gets a fresh connection and it
    always closes cleanly, even if an exception is raised mid-query."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


def init_db():
    """Create the events table if it doesn't already exist."""
    with get_connection() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                event_type TEXT NOT NULL,
                source_ip TEXT,
                target_ip TEXT,
                target_port INTEGER,
                severity TEXT NOT NULL,
                description TEXT
            )
        """)
        conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_events_timestamp
            ON events(timestamp)
        """)
        conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_events_source_ip
            ON events(source_ip)
        """)


def log_event(event_type, source_ip, target_ip=None, target_port=None,
              severity="medium", description=""):
    """Insert one detected event into the database."""
    with get_connection() as conn:
        conn.execute("""
            INSERT INTO events
                (timestamp, event_type, source_ip, target_ip, target_port,
                 severity, description)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (
            datetime.now().isoformat(timespec="seconds"),
            event_type,
            source_ip,
            target_ip,
            target_port,
            severity,
            description,
        ))


def get_recent_events(limit=100):
    with get_connection() as conn:
        rows = conn.execute("""
            SELECT * FROM events
            ORDER BY id DESC
            LIMIT ?
        """, (limit,)).fetchall()
        return [dict(r) for r in rows]


def get_event_counts_by_type():
    """Used for the dashboard's summary chart."""
    with get_connection() as conn:
        rows = conn.execute("""
            SELECT event_type, COUNT(*) as count
            FROM events
            GROUP BY event_type
        """).fetchall()
        return {r["event_type"]: r["count"] for r in rows}


def get_events_over_time(bucket_minutes=1, limit_buckets=30):
    """Rough time-bucketed count of events, used for the 'attacks over
    time' chart on the dashboard."""
    with get_connection() as conn:
        rows = conn.execute("""
            SELECT timestamp FROM events
            ORDER BY id DESC
            LIMIT 1000
        """).fetchall()

    from collections import Counter
    buckets = Counter()
    for r in rows:
        ts = datetime.fromisoformat(r["timestamp"])
        bucket_key = ts.replace(second=0, microsecond=0)
        minute = (bucket_key.minute // bucket_minutes) * bucket_minutes
        bucket_key = bucket_key.replace(minute=minute)
        buckets[bucket_key.strftime("%H:%M")] += 1

    sorted_items = sorted(buckets.items())[-limit_buckets:]
    return sorted_items


def clear_events():
    """Useful for demos/testing so old data doesn't clutter the dashboard."""
    with get_connection() as conn:
        conn.execute("DELETE FROM events")