# CodeAlpha_NetworkSniffer

**CodeAlpha Cyber Security Internship — Task 1: Basic Network Sniffer**

## 📋 Overview
This project is a simple, educational network packet sniffer written in Python
using the [Scapy](https://scapy.net/) library. It captures live traffic on a
chosen network interface and prints out key details for each packet:

- Source and destination IP addresses
- Protocol (TCP / UDP / ICMP / Other)
- Source and destination ports (for TCP/UDP)
- A short printable preview of the packet payload

## ⚠️ Legal & Ethical Notice
This tool must only be used on networks you own or have explicit written
permission to monitor (e.g. your own home network, or a lab/virtual machine
you control). Capturing network traffic without authorization is illegal in
most countries. This project is for educational purposes as part of a
cybersecurity internship.

## 🛠 Requirements
- Python 3.8+
- [Scapy](https://scapy.net/) (`pip install scapy`)
- Administrator / root privileges (needed to open a raw socket)
- On Windows: [Npcap](https://npcap.com/) must be installed

## 📦 Installation
```bash
git clone https://github.com/<your-username>/CodeAlpha_NetworkSniffer.git
cd CodeAlpha_NetworkSniffer
pip install -r requirements.txt
```

## ▶️ Usage
Run with elevated privileges:

```bash
# Sniff all traffic on all interfaces (stop with Ctrl+C)
sudo python3 sniffer.py

# Sniff on a specific interface
sudo python3 sniffer.py -i eth0

# Stop automatically after 50 packets
sudo python3 sniffer.py -c 50

# Apply a custom BPF filter (e.g. only HTTP traffic)
sudo python3 sniffer.py -f "tcp port 80"
```

On Windows, run your terminal/PowerShell **as Administrator** and drop `sudo`
from the commands above.

## 🖥 Example Output
```
======================================================================
 Basic Network Sniffer - CodeAlpha Cyber Security Internship
======================================================================
 Interface : all
 Filter    : ip
 Count     : infinite (Ctrl+C to stop)
======================================================================
----------------------------------------------------------------------
[14:32:10] TCP Packet
  192.168.1.5:52344  ->  142.250.190.14:443
  Payload: ......................
----------------------------------------------------------------------
[14:32:11] UDP Packet
  192.168.1.5:5353  ->  224.0.0.251:5353
```

## 📚 What I Learned
- How packets are structured at the IP, TCP, UDP, and ICMP layers
- How to use Scapy to capture and parse live traffic
- The basics of BPF (Berkeley Packet Filter) syntax for filtering traffic
- Why raw socket access requires elevated privileges
- Ethical and legal considerations around network monitoring tools

## 👤 Author
Submitted as part of the **CodeAlpha Cyber Security Internship**, Task 1.
