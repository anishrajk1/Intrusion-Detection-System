"""
detector.py
The detection engine. This is where raw packet data turns into security
events. Each detector tracks state over a sliding time window so it can
recognize patterns (like a scan or a brute force attempt) that no single
packet reveals on its own.

Detection logic implemented:
  1. Port scan detection   - many distinct ports hit by one source, fast
  2. SYN flood / brute force - many connection attempts to one port, fast
  3. Suspicious connection  - traffic to known-sensitive ports (e.g. 23, 3389)

All thresholds are configurable in config.py so you can tune false-positive
rates without touching detection logic.
"""

import time
from collections import defaultdict, deque

import config
from database import log_event


class PortScanDetector:
    """
    Flags a source IP as scanning if it contacts more than
    PORT_SCAN_THRESHOLD distinct ports on the same target within
    PORT_SCAN_WINDOW seconds. This mirrors how a real Nmap SYN scan looks
    on the wire: a burst of connections to many ports in a short window.
    """

    def __init__(self):
        #source_ip -> deque of timestamp, target_ip, port
        self.activity = defaultdict(deque)
        self.already_flagged = {}

    def process(self, src_ip, dst_ip, dst_port, timestamp):
        window = self.activity[src_ip]
        window.append((timestamp, dst_ip, dst_port))

        #drop entries older than the detection window
        cutoff = timestamp - config.PORT_SCAN_WINDOW
        while window and window[0][0] < cutoff:
            window.popleft()

        #count distinct ports touched on the SAME target within the window
        ports_per_target = defaultdict(set)
        for ts, dip, port in window:
            ports_per_target[dip].add(port)

        for target, ports in ports_per_target.items():
            if len(ports) >= config.PORT_SCAN_THRESHOLD:
                key = (src_ip, target)
                last_flag = self.already_flagged.get(key, 0)
                if timestamp - last_flag > config.ALERT_COOLDOWN:
                    self.already_flagged[key] = timestamp
                    log_event(
                        event_type="port_scan",
                        source_ip=src_ip,
                        target_ip=target,
                        target_port=None,
                        severity="high",
                        description=(
                            f"{src_ip} probed {len(ports)} distinct ports on "
                            f"{target} within {config.PORT_SCAN_WINDOW}s "
                            f"(threshold: {config.PORT_SCAN_THRESHOLD})"
                        ),
                    )
                    return True
        return False


class BruteForceDetector:
    """
    Flags repeated connection attempts from one source to the SAME port
    on the same target -- the signature of a brute-force login attempt
    (e.g. hammering SSH port 22 or an HTTP login form).
    """

    def __init__(self):
        #source_ip, target_ip, port -> deque of timestamps
        self.activity = defaultdict(deque)
        self.already_flagged = {}

    def process(self, src_ip, dst_ip, dst_port, timestamp):
        key = (src_ip, dst_ip, dst_port)
        window = self.activity[key]
        window.append(timestamp)

        cutoff = timestamp - config.BRUTE_FORCE_WINDOW
        while window and window[0] < cutoff:
            window.popleft()

        if len(window) >= config.BRUTE_FORCE_THRESHOLD:
            last_flag = self.already_flagged.get(key, 0)
            if timestamp - last_flag > config.ALERT_COOLDOWN:
                self.already_flagged[key] = timestamp
                log_event(
                    event_type="brute_force",
                    source_ip=src_ip,
                    target_ip=dst_ip,
                    target_port=dst_port,
                    severity="high",
                    description=(
                        f"{src_ip} made {len(window)} connection attempts to "
                        f"{dst_ip}:{dst_port} within {config.BRUTE_FORCE_WINDOW}s "
                        f"(threshold: {config.BRUTE_FORCE_THRESHOLD})"
                    ),
                )
                return True
        return False


class SensitivePortDetector:
    """
    Lightweight rule: flag any connection attempt to a port on the
    'sensitive' watchlist (Telnet, RDP, SMB, etc). Cheap to compute and
    catches things the statistical detectors above might miss on a first
    contact, since those need repeated activity to trigger.
    """

    def __init__(self):
        self.already_flagged = {}

    def process(self, src_ip, dst_ip, dst_port, timestamp):
        if dst_port in config.SENSITIVE_PORTS:
            key = (src_ip, dst_ip, dst_port)
            last_flag = self.already_flagged.get(key, 0)
            if timestamp - last_flag > config.ALERT_COOLDOWN:
                self.already_flagged[key] = timestamp
                log_event(
                    event_type="sensitive_port_access",
                    source_ip=src_ip,
                    target_ip=dst_ip,
                    target_port=dst_port,
                    severity="medium",
                    description=(
                        f"{src_ip} connected to sensitive port {dst_port} "
                        f"({config.SENSITIVE_PORTS[dst_port]}) on {dst_ip}"
                    ),
                )
                return True
        return False


class DetectionEngine:
    """Runs every configured detector against each observed packet."""

    def __init__(self):
        self.port_scan = PortScanDetector()
        self.brute_force = BruteForceDetector()
        self.sensitive_port = SensitivePortDetector()

    def analyze(self, src_ip, dst_ip, dst_port, timestamp=None):
        timestamp = timestamp or time.time()
        self.port_scan.process(src_ip, dst_ip, dst_port, timestamp)
        self.brute_force.process(src_ip, dst_ip, dst_port, timestamp)
        self.sensitive_port.process(src_ip, dst_ip, dst_port, timestamp)