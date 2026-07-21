# Intrusion Detection System (IDS)

Real-time network intrusion detection: captures live traffic, detects
common attack patterns (port scans, brute-force attempts, sensitive-port
access), and displays alerts on a live web dashboard.

## Description

Most beginner security projects (port scanners, password crackers) test
one skill in isolation. This project pulls together networking, stateful
pattern-detection logic, a database, and a live dashboard into one working
system — closer to what an actual SOC monitoring tool looks like.

It works by sniffing live TCP traffic with Scapy, running that traffic
through three independent detectors (port scan, brute force, sensitive
port access), logging any matches to SQLite, and displaying them in
real time on a Flask-powered dashboard with live charts.

## Getting Started

### Dependencies

* Python 3.10+
* Flask and Scapy (see `requirements.txt`)
* Linux or macOS recommended for live packet capture (root/sudo required).
  Windows works too, but needs [Npcap](https://npcap.com/) installed first.
* No special dependencies needed if you only run the dashboard with
  simulated traffic (`--no-capture` mode) — that works on any OS, no
  admin/root needed.

### Installing

* Download or clone all files, keeping the folder structure intact:
  ```
  ids/
  ├── app.py
  ├── capture.py
  ├── config.py
  ├── database.py
  ├── detector.py
  ├── simulator.py
  ├── requirements.txt
  └── templates/
      └── dashboard.html
  ```
* No modifications needed to files/folders — install dependencies and run.

### Executing program

**Option A — Dashboard with simulated traffic (no admin/root needed):**

* Install dependencies:
  ```bash
  pip install -r requirements.txt
  ```
* Start the dashboard:
  ```bash
  python3 app.py --no-capture
  ```
* Open `http://localhost:5000` in your browser.
* In a second terminal, generate demo traffic:
  ```bash
  python3 simulator.py normal
  python3 simulator.py portscan
  python3 simulator.py bruteforce
  ```
* Watch alerts appear on the dashboard in real time.

**Option B — Live packet capture (requires root/admin):**

* Linux/macOS:
  ```bash
  sudo python3 app.py
  ```
* Windows: install Npcap, then run as Administrator.

## Help

* If `capture.py` fails to start, it's almost always a permissions issue —
  run with `sudo` (Linux/macOS) or as Administrator (Windows), or just use
  `--no-capture` mode with the simulator instead.
* If the dashboard shows no data, confirm the Flask server is actually
  running and check you're hitting `http://localhost:5000`, not `127.0.0.1`
  with a different port.
* To reset all logged events without restarting the server:
  ```bash
  curl -X POST http://localhost:5000/api/clear
  ```

## Authors

* Your Name
  [@your_github_handle](https://github.com/your_github_handle)

## Version History

* 0.1
  * Initial release: packet capture, three detectors, SQLite logging, live dashboard

## License

This project is licensed under the MIT License - see the LICENSE.md file for details

## Acknowledgments

* [Scapy documentation](https://scapy.readthedocs.io/)
* [OWASP](https://owasp.org/) for threat pattern reference
* [PurpleBooth README template](https://gist.github.com/PurpleBooth)

---

## How It Works (technical deep dive)

```
 Live Traffic (Scapy)  --->  Detection Engine  --->  SQLite  --->  Flask Dashboard
  or simulator.py             (3 detectors)          (events.db)   (live charts)
```

1. **Capture** — `capture.py` sniffs live TCP traffic using Scapy and pulls
   out source IP, destination IP, and destination port for every packet.
2. **Detect** — `detector.py` runs three independent, stateful detectors
   against a sliding time window of recent activity:
   - **Port scan detector** — flags a source IP that touches an unusually
     high number of distinct ports on one target within a short window
     (the signature of an Nmap-style scan).
   - **Brute force detector** — flags a source IP that repeatedly hits the
     *same* port on one target (the signature of a login-guessing attack
     against SSH, RDP, etc).
   - **Sensitive port detector** — flags first contact with high-value
     ports (SSH, RDP, Telnet, databases) even before a pattern emerges.
3. **Store** — every detection is logged to SQLite with a timestamp,
   severity, and human-readable description.
4. **Visualize** — `app.py` serves a live dashboard (auto-refreshing every
   2s) showing alert counts, a severity breakdown chart, an events-over-time
   chart, and a live alert feed table.

Both statistical detectors use a **sliding window + threshold** approach:
every observed connection is timestamped and stored per source; entries
older than the configured window get dropped on each new packet, so memory
stays bounded. If enough qualifying events land inside the window, an alert
fires — with a cooldown so one ongoing attack doesn't spam duplicate
alerts. All thresholds live in `config.py`, kept separate from detection
logic.

## Interview Talking Points

- **Why a sliding window instead of a fixed counter?** A fixed counter
  never resets and eventually flags everyone; a sliding window only counts
  *recent* activity, matching how real attacks look — bursty, not spread
  evenly over hours.
- **How did you reduce false positives?** The alert cooldown, plus
  requiring a minimum number of *distinct* ports (not just packets) for
  the scan detector, cuts down noise from normal retries.
- **Why Scapy?** Raw access to packet layers without hand-parsing IP/TCP
  headers, and it's widely used in real-world security tooling.