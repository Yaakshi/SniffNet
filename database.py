import sqlite3
import json

# Initialize DB
conn = sqlite3.connect("traffic.db", check_same_thread=False)
cur = conn.cursor()

# Create table if not exists
cur.execute("""
CREATE TABLE IF NOT EXISTS packets (
    id TEXT PRIMARY KEY,
    timestamp TEXT,
    proto TEXT,
    ip_src TEXT,
    ip_dst TEXT,
    mac_src TEXT,
    mac_dst TEXT,
    ttl INTEGER,
    sport INTEGER,
    dport INTEGER,
    flags TEXT,
    payload_len INTEGER,
    layer_stack TEXT,
    details TEXT
)
""")
conn.commit()

def log_packet(data):
    cur.execute("""
        INSERT INTO packets (
            id, timestamp, proto, ip_src, ip_dst, mac_src, mac_dst,
            ttl, sport, dport, flags, payload_len, layer_stack, details
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        data["id"],
        data["timestamp"],
        data["proto"],
        data["ip_src"],
        data["ip_dst"],
        data["mac_src"],
        data["mac_dst"],
        data["ttl"],
        data["sport"],
        data["dport"],
        str(data["flags"]),
        data["payload_len"],
        json.dumps(data["layer_stack"]),
        json.dumps(data["details"])
    ))
    conn.commit()
