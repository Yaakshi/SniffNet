from scapy.all import sniff, Raw
from scapy.layers.l2 import Ether, ARP
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.inet6 import IPv6
from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.layers.http import HTTPRequest, HTTPResponse
from scapy.packet import Packet
from datetime import datetime
from queue import Queue
import uuid

from database import log_packet
from analyzer import analyze_packet

packet_queue = Queue()

# Mapping protocol numbers to names for IPv4 and IPv6
PROTO_MAP = {
    1: "ICMP",
    6: "TCP",
    17: "UDP"
}

def get_layer_name(pkt):
    return pkt.name if isinstance(pkt, Packet) else str(pkt.__class__.__name__)

def extract_fields(packet):
    data = {
        "id": str(uuid.uuid4()),
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "proto": "Unknown",
        "ip_src": None,
        "ip_dst": None,
        "mac_src": None,
        "mac_dst": None,
        "ttl": None,
        "sport": None,
        "dport": None,
        "flags": None,
        "payload_len": len(packet[Raw].load) if Raw in packet else 0,
        "layer_stack": [],
        "details": {}
    }

    # MAC Layer
    if Ether in packet:
        eth = packet[Ether]
        data["mac_src"] = eth.src
        data["mac_dst"] = eth.dst
        data["layer_stack"].append("Ethernet")

    # ARP
    if ARP in packet:
        arp = packet[ARP]
        data["proto"] = "ARP"
        data["ip_src"] = arp.psrc
        data["ip_dst"] = arp.pdst
        data["layer_stack"].append("ARP")

    # IPv4
    elif IP in packet:
        ip = packet[IP]
        data["proto"] = PROTO_MAP.get(ip.proto, str(ip.proto))
        data["ip_src"] = ip.src
        data["ip_dst"] = ip.dst
        data["ttl"] = ip.ttl
        data["layer_stack"].append("IPv4")

    # IPv6
    elif IPv6 in packet:
        ipv6 = packet[IPv6]
        data["proto"] = PROTO_MAP.get(ipv6.nh, str(ipv6.nh))
        data["ip_src"] = ipv6.src
        data["ip_dst"] = ipv6.dst
        data["ttl"] = ipv6.hlim
        data["layer_stack"].append("IPv6")

    # TCP
    if TCP in packet:
        tcp = packet[TCP]
        data["proto"] = "TCP"
        data["sport"] = tcp.sport
        data["dport"] = tcp.dport
        data["flags"] = tcp.flags
        data["layer_stack"].append("TCP")

    # UDP
    elif UDP in packet:
        udp = packet[UDP]
        data["proto"] = "UDP"
        data["sport"] = udp.sport
        data["dport"] = udp.dport
        data["layer_stack"].append("UDP")

    # ICMP
    if ICMP in packet:
        icmp = packet[ICMP]
        data["proto"] = "ICMP"
        data["details"]["icmp_type"] = icmp.type
        data["layer_stack"].append("ICMP")

    # DNS
    if DNS in packet:
        dns = packet[DNS]
        data["proto"] = "DNS"
        if dns.qr == 0 and DNSQR in dns:
            data["details"]["dns_query"] = dns[DNSQR].qname.decode(errors="ignore")
        elif dns.qr == 1 and DNSRR in dns:
            data["details"]["dns_answer"] = str(dns[DNSRR].rdata)
        data["layer_stack"].append("DNS")

    # HTTP
    if HTTPRequest in packet:
        http = packet[HTTPRequest]
        data["proto"] = "HTTP"
        data["details"]["http_host"] = http.Host.decode(errors="ignore")
        data["details"]["http_path"] = http.Path.decode(errors="ignore")
        data["layer_stack"].append("HTTP (Request)")
    elif HTTPResponse in packet:
        data["proto"] = "HTTP"
        data["layer_stack"].append("HTTP (Response)")

    return data

def process_packet(packet):
    data = extract_fields(packet)

    # Print basic info
    print(f"[{data['timestamp']}] {data['proto']} | {data['ip_src']} → {data['ip_dst']} | Port: {data.get('dport')} | Len: {data['payload_len']}")

    # Log to SQLite
    log_packet(data)

    # analyze the packets
    analyze_packet(data)
    
    # Enqueue for GUI/analysis
    packet_queue.put(data)

def start_sniffing():
    print("[*] Sniffing started... (Press Ctrl+C to stop)")
    sniff(prn=process_packet, store=False)
