"""
capture.py
Live packet capture using Scapy. Pulls IP/TCP layer info off each packet
and hands it to the detection engine. Runs in its own thread so it doesn't
block the Flask dashboard.

Note: raw packet capture requires elevated privileges.
  - Linux/Mac: run with sudo
  - Windows: install Npcap and run as Administrator
"""

import threading
from scapy.all import sniff, IP, TCP

import config
from detector import DetectionEngine


class PacketCapture:
    def __init__(self, engine: DetectionEngine):
        self.engine = engine
        self.packet_count = 0
        self._thread = None
        self._stop_event = threading.Event()

    def _handle_packet(self, packet):
        if packet.haslayer(IP) and packet.haslayer(TCP):
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            dst_port = packet[TCP].dport
            self.engine.analyze(src_ip, dst_ip, dst_port)
            self.packet_count += 1

    def _run(self):
        sniff(
            iface=config.NETWORK_INTERFACE,
            filter=config.CAPTURE_FILTER,
            prn=self._handle_packet,
            stop_filter=lambda p: self._stop_event.is_set(),
            store=False,
        )

    def start(self):
        """Start sniffing in a background thread."""
        if self._thread and self._thread.is_alive():
            return  # already running
        self._stop_event.clear()
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def stop(self):
        self._stop_event.set()


if __name__ == "__main__":
    from database import init_db

    init_db()
    engine = DetectionEngine()
    cap = PacketCapture(engine)
    print("Starting capture... Ctrl+C to stop.")
    try:
        cap.start()
        while True:
            pass
    except KeyboardInterrupt:
        cap.stop()
        print(f"\nStopped. Captured {cap.packet_count} packets.")