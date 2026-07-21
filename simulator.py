"""
simulator.py
Generates synthetic traffic events and feeds them through the same
DetectionEngine used by live capture. This exists so you (or anyone
reviewing your project) can see the IDS detect attacks WITHOUT needing
root/admin privileges for raw packet capture -- ideal for demos,
screenshots, and interviews.
"""

import sys
import time
import random

from database import init_db
from detector import DetectionEngine

COMMON_PORTS = [80, 443, 53, 123]
SAMPLE_IPS = ["10.0.0.5", "10.0.0.12", "192.168.1.20"]


def simulate_normal_traffic(engine, duration=15):
    print(f"Simulating {duration}s of normal background traffic...")
    end = time.time() + duration
    while time.time() < end:
        src = random.choice(SAMPLE_IPS)
        dst = "10.0.0.1"
        port = random.choice(COMMON_PORTS)
        engine.analyze(src, dst, port)
        time.sleep(random.uniform(0.3, 1.0))
    print("Done.")


def simulate_port_scan(engine, attacker_ip="203.0.113.50", target_ip="10.0.0.1"):
    print(f"Simulating port scan from {attacker_ip} -> {target_ip} ...")
    ports = list(range(20, 40))  # 20 distinct ports, fast
    for port in ports:
        engine.analyze(attacker_ip, target_ip, port)
        time.sleep(0.1)
    print("Port scan simulation complete. Check the dashboard for an alert.")


def simulate_brute_force(engine, attacker_ip="203.0.113.77", target_ip="10.0.0.1", port=22):
    print(f"Simulating brute force from {attacker_ip} -> {target_ip}:{port} ...")
    for attempt in range(10):
        engine.analyze(attacker_ip, target_ip, port)
        time.sleep(0.3)
    print("Brute force simulation complete. Check the dashboard for an alert.")


if __name__ == "__main__":
    init_db()
    engine = DetectionEngine()

    mode = sys.argv[1] if len(sys.argv) > 1 else "normal"

    if mode == "normal":
        simulate_normal_traffic(engine)
    elif mode == "portscan":
        simulate_port_scan(engine)
    elif mode == "bruteforce":
        simulate_brute_force(engine)
    else:
        print("Usage: python3 simulator.py [normal|portscan|bruteforce]")