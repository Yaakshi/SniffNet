# SniffNet: Network Packet Sniffer with Real-Time Anomaly Detection

## Introduction

This Windows-based project provides a real-time network packet sniffer with anomaly detection and an intuitive GUI. Its purpose: monitor traffic, identify suspicious behaviors, and alert users instantly. Designed for scalability and practicality, it offers logging, live data visualization, and robust cybersecurity monitoring.

## Abstract

Network intrusion detection is crucial in identifying abnormal traffic patterns and potential attacks. Built with Python and Scapy, this system actively captures and analyses real-time traffic to identify potential attacks. All data and anomalies are logged to SQLite for forensic analysis. A Tkinter GUI with Matplotlib provides live visualization and instant alerts. It serves as both a learning tool and a lightweight defensive mechanism.

## Tools Used

1. ``` Visual Studio Code``` - Code Editor
2. ```Python 3.13.5``` – Core programming language
3. ```Npcap``` – Windows Packet capture driver
4. ```Scapy``` – Packet sniffing and parsing
5. ```SQLite3``` – Local database to store packet logs
6. ```Matplotlib``` – Graphical traffic plots
7. ```Tkinter``` – GUI for live traffic visualization and alerting
8. ```Collections/Regex``` – Efficient anomaly tracking
9. ```time, re, threading``` – Real-time analysis & concurrency

## Steps Involved in Building the Project

### Step 1 - Environment Setup

1.	Install Python and ensure it's added to the system PATH.
2.	Install required Python packages: scapy, matplotlib, sqlite3, and tkinter.
3.	On Windows, install Npcap in WinPcap API-compatible Mode with raw 802.11 traffic support.
4.	Run VS Code as Administrator to allow Scapy to capture packets with elevated permissions.

### Step 2 - Packet Sniffer - ```sniffer.py```

1.	Capture live packets using Scapy.
2.	Extract key info: IP, protocol, ports, flags, length, TTL, etc.
3.	Support detailed analysis of all layers: Ethernet, ARP, IP, TCP, UDP, ICMP, DNS, HTTP.
4.	Map protocol numbers (e.g., 6 → TCP, 17 → UDP) for clarity.
5.	Use a packet_queue to feed data into the analyzer and GUI.
6.	Assign a unique packet ID to each packet for GUI tracking.


### Step 3 - Database Logging - ```database.py```

1.	Connect to SQLite and create packets table if not exists.
2.	Insert packet data received from sniffer.py.
3.	Fields include: id (UUID), IP, ports, protocol, flags, TTL, payload length, timestamp, etc.
4.	Store layer_stack and details as JSON strings for flexibility.
5.	Use check_same_thread=False to allow shared DB access across threads (Sniffer + GUI).

### Step 4 - Anomaly Detection - ```analyzer.py```

1.	Analyze live packet data per IP using time-windowed tracking.
2.	Detect multiple attacks.
3.	Trigger alerts via alert.py.

### Detection Types and Descriptions

| **Detection Type**     | **Description**                                                                 |
|------------------------|---------------------------------------------------------------------------------|
| ```Port Scanning```      | Tracks unique destination ports within a short time window.                    |
| ```SYN Flooding```       | Detects high number of SYN packets without corresponding ACKs within 5 seconds.|
| ```Packet Rate Spike```  | Flags traffic bursts with over 100 packets in 5 seconds.                       |
| ```Large Payload```      | Detects packets with unusually large payload sizes.                            |
| ```ICMP Echo Flood```    | Monitors excessive ICMP type 8 (Echo Request) packets.                         |
| ```DNS Tunnelling```     | Identifies suspicious DNS queries based on length, patterns, and entropy.      |
| ```Fast Flux / DGA```    | Detects many unique DNS queries in a short period, indicating DGA behavior.    |
| ```ARP Spoofing```       | Flags when a single IP address maps to multiple MAC addresses.                 |
| ```TCP Flag Scans```     | Detects Xmas (FIN, PSH, URG) and NULL flag scans.                              |
| ```Low TTL Detection```  | Flags packets with TTL values less than 10, indicating evasion techniques.     |
| ```Reserved IP Use```    | Detects traffic using local, non-routable, or spoofed IP addresses.            |

### Step 5 - Alert Handling - ```alert.py```

1.	Print alerts to the console with color coding
2.	Log alerts to a timestamped file
3.	Alerts are triggered by analyzer.py in real-time

### Step 6 - GUI Dashboard - ```gui.py```

1.	Shows real-time traffic graph (packets/sec)
2.	Displays live alerts via a shared Queue from alert.py
3.	Lists live packet stats
4.	Includes:
      - Non-blocking GUI (Tkinter + threading)
      - Export to CSV button
      - Clear Alerts button
  
### Step 7 - Test Script - ```attacksim.py```

1.	Simulate real network anomalies (port scan, SYN flood, ICMP flood)

### Step 8 - Export to CSV - ```exporter.py```

1.	Export all captured packet data from the SQLite database
2.	Can be triggered from the GUI's “Export CSV” button
