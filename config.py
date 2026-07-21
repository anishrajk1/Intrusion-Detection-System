"""
config.py
All tunable detection thresholds live here so you can adjust sensitivity
without digging through detection logic. Lower thresholds = more alerts
(and more false positives). Higher = fewer alerts, but you might miss
slow/stealthy attacks.
"""

#Port scan detection
#Flag a source if it touches this many distinct ports on one target
#within PORT_SCAN_WINDOW seconds.
PORT_SCAN_THRESHOLD = 8
PORT_SCAN_WINDOW = 5  # seconds

#Brute force detection
#Flag a source if it makes this many connection attempts to the SAME
#port on one target within BRUTE_FORCE_WINDOW seconds.
BRUTE_FORCE_THRESHOLD = 6
BRUTE_FORCE_WINDOW = 10  # seconds

#Alert cooldown
#Once a (source, target) pair is flagged, wait this long before flagging
#it again, so one ongoing attack doesn't flood the dashboard with duplicate alerts.
ALERT_COOLDOWN = 30  # seconds

#Sensitive ports watchlist
#Commonly abused / high-value target ports worth flagging on first contact.
SENSITIVE_PORTS = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    445: "SMB",
    3389: "RDP",
    3306: "MySQL",
    5432: "PostgreSQL",
    6379: "Redis",
}

#Capture settings
NETWORK_INTERFACE = None
CAPTURE_FILTER = "tcp"