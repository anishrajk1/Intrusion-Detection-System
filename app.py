"""
app.py
Flask dashboard for the IDS. Shows live alerts, event counts by type, and
an "attacks over time" chart. Also starts packet capture automatically
when run with sufficient privileges.
"""

import sys
import json

from flask import Flask, render_template, jsonify

import database
from detector import DetectionEngine

app = Flask(__name__)
engine = DetectionEngine()

database.init_db()

capture = None
if "--no-capture" not in sys.argv:
    try:
        from capture import PacketCapture
        capture = PacketCapture(engine)
        capture.start()
        print("Live packet capture started.")
    except Exception as e:
        print(f"Could not start live capture ({e}). "
              f"Dashboard will still work -- use simulator.py to generate demo traffic.")


@app.route("/")
def dashboard():
    return render_template("dashboard.html")


@app.route("/api/events")
def api_events():
    events = database.get_recent_events(limit=100)
    return jsonify(events)


@app.route("/api/stats")
def api_stats():
    counts = database.get_event_counts_by_type()
    timeline = database.get_events_over_time()
    packet_count = capture.packet_count if capture else None
    return jsonify({
        "counts_by_type": counts,
        "timeline": timeline,
        "packets_captured": packet_count,
    })


@app.route("/api/clear", methods=["POST"])
def api_clear():
    database.clear_events()
    return jsonify({"status": "cleared"})


if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000)