import time
import re
from collections import defaultdict, deque
from alert import trigger_alert

# Time-window activity history
packet_history = defaultdict(lambda: deque(maxlen=200))
syn_tracker = defaultdict(list)
icmp_tracker = defaultdict(list)
port_tracker = defaultdict(set)
dns_tracker = defaultdict(list)
arp_cache = defaultdict(set)

# Thresholds
THRESHOLDS = {
    "port_scan_ports": 20,
    "syn_flood_syns": 50,
    "packet_rate": 100,
    "max_payload_size": 1500,
    "icmp_flood": 30,
    "large_payload": 2000,
    "arp_spoof_threshold": 2
}

def analyze_packet(data):
    now = time.time()
    src = data.get("ip_src")
    dst = data.get("ip_dst")
    proto = data.get("proto")
    flags = data.get("flags", 0)
    dport = data.get("dport")
    ttl = data.get("ttl")
    payload_len = int(data.get("payload_len", 0))
    mac_src = data.get("mac_src")
    qname = data.get("details", {}).get("dns_query")
    icmp_type = data.get("details", {}).get("icmp_type")
    
    alerts = []

    # Save history for time-window based analysis
    if src:
        entry = (now, dport, str(flags), payload_len)
        packet_history[src].append(entry)

        recent = [p for p in packet_history[src] if now - p[0] <= 10]
        recent_5s = [p for p in recent if now - p[0] <= 5]

        # 1. Port Scan
        unique_ports = set(p[1] for p in recent if p[1])
        if len(unique_ports) > THRESHOLDS["port_scan_ports"]:
            alerts.append(f"Port scan from {src}: {len(unique_ports)} ports in 10s")

        # 2. SYN Flood
        syn_count = sum(1 for p in recent_5s if 'S' in p[2] and 'A' not in p[2])
        if syn_count > THRESHOLDS["syn_flood_syns"]:
            alerts.append(f"SYN flood from {src}: {syn_count} SYNs in 5s")

        # 3. Packet Rate Spike
        if len(recent_5s) > THRESHOLDS["packet_rate"]:
            alerts.append(f"Traffic spike from {src}: {len(recent_5s)} packets in 5s")

        # 4. Large Payloads
        if any(p for p in recent if p[3] > THRESHOLDS["max_payload_size"]):
            alerts.append(f"Large payloads from {src}")

    # 5. ICMP Flood
    if proto == "ICMP" and icmp_type == 8:
        icmp_tracker[src].append(now)
        icmp_tracker[src] = [t for t in icmp_tracker[src] if now - t < 10]
        if len(icmp_tracker[src]) > THRESHOLDS["icmp_flood"]:
            alerts.append(f"ICMP Echo flood from {src}")
        # Limit memory
        icmp_tracker[src] = icmp_tracker[src][-100:]

    # 6. DNS Tunneling
    if proto == "DNS" and qname:
        if len(qname) > 50 or re.match(r"^[A-Za-z0-9]{30,}", qname.replace('.', '')):
            alerts.append(f"DNS tunneling attempt from {src}: {qname}")
        dns_tracker[src].append(qname)
        if len(set(dns_tracker[src][-10:])) > 7:
            alerts.append(f"Fast-flux/DGA from {src}: {len(set(dns_tracker[src][-10:]))} unique queries")
        # Limit memory
        dns_tracker[src] = dns_tracker[src][-20:]

    # 7. ARP Spoofing
    if mac_src and src:
        arp_cache[src].add(mac_src)
        if len(arp_cache[src]) > THRESHOLDS["arp_spoof_threshold"]:
            alerts.append(f"ARP spoofing: {src} has {len(arp_cache[src])} MACs")

    # # 8. TCP Flag Scans (Xmas/NULL)
    # if proto == "TCP":
    #     flag_value = int(flags) if str(flags).isdigit() else 0
    #     if flag_value == 0:
    #         alerts.append(f"NULL scan from {src}")
    #     elif flag_value == 41:  # FIN + PSH + URG (Xmas scan)
    #         alerts.append(f"Xmas scan from {src}")

    # # 9. Low TTL
    # if ttl is not None and ttl < 10:
    #     alerts.append(f"Low TTL from {src}: TTL={ttl}")

    # 10. Reserved IP
    if src and (src.startswith("127.") or src.startswith("0.")):
        alerts.append(f"Reserved IP source: {src}")

    # Log and Trigger Alerts
    for alert in alerts:
        trigger_alert(alert)

        # Optional: Write to log file
        with open("logs/anomaly_events.log", "a") as f:
            f.write(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] {alert}\n")

    return alerts
