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

* If `capture.py` fails to start, it's almost always a permissions issue,
  run with `sudo` (Linux/macOS) or as Administrator (Windows), or just use
  `--no-capture` mode with the simulator instead.
* If the dashboard shows no data, confirm the Flask server is actually
  running and check you're hitting `http://localhost:5000`, not `127.0.0.1`
  with a different port.
* To reset all logged events without restarting the server:
  ```bash
  curl -X POST http://localhost:5000/api/clear
  ```

## Author

* Anish Rajkumar
  [@anishrajk1](https://github.com/anishrajk1)

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

# Intrusion-Detection-System

A lightweight network intrusion detection system in Python that detects port scans, brute-force attempts, and sensitive port access in real time, with a live Flask dashboard.
