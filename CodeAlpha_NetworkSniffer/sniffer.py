"""
CodeAlpha Cyber Security Internship - Task 1
Basic Network Sniffer

Description:
    A simple, educational packet sniffer built with Scapy.
    It captures live network traffic on a chosen interface and displays
    key details for each packet: source/destination IP, protocol,
    ports (for TCP/UDP), and a preview of the raw payload.

    IMPORTANT: This tool is for learning purposes on networks you own
    or have explicit permission to monitor (e.g., your own home network
    or a lab/VM environment). Capturing traffic on networks without
    authorization is illegal in most jurisdictions.

Requirements:
    pip install scapy
    (On Linux/Mac you typically need to run this script with sudo/root
     privileges to open a raw socket. On Windows, install Npcap first
     and run as Administrator.)

Usage:
    sudo python3 sniffer.py                 # sniff all traffic
    sudo python3 sniffer.py -i eth0         # sniff on a specific interface
    sudo python3 sniffer.py -c 50           # stop after 50 packets
    sudo python3 sniffer.py -f "tcp port 80"  # apply a BPF filter
"""

import argparse
from datetime import datetime

from scapy.all import sniff, IP, TCP, UDP, ICMP, Raw


def get_protocol_name(packet):
    """Return a human-readable protocol name for the packet."""
    if packet.haslayer(TCP):
        return "TCP"
    elif packet.haslayer(UDP):
        return "UDP"
    elif packet.haslayer(ICMP):
        return "ICMP"
    else:
        return "OTHER"


def format_payload(packet, max_len=60):
    """Extract a short, printable preview of the payload, if any."""
    if packet.haslayer(Raw):
        raw_bytes = bytes(packet[Raw].load)
        # Replace non-printable bytes so the terminal doesn't break
        printable = "".join(
            chr(b) if 32 <= b <= 126 else "." for b in raw_bytes
        )
        return printable[:max_len]
    return ""


def process_packet(packet):
    """Callback executed by Scapy for every captured packet."""
    if not packet.haslayer(IP):
        return  # skip non-IP traffic (e.g., ARP) to keep output clean

    timestamp = datetime.now().strftime("%H:%M:%S")
    src_ip = packet[IP].src
    dst_ip = packet[IP].dst
    proto = get_protocol_name(packet)

    src_port = dst_port = None
    if packet.haslayer(TCP):
        src_port = packet[TCP].sport
        dst_port = packet[TCP].dport
    elif packet.haslayer(UDP):
        src_port = packet[UDP].sport
        dst_port = packet[UDP].dport

    print("-" * 70)
    print(f"[{timestamp}] {proto} Packet")
    if src_port and dst_port:
        print(f"  {src_ip}:{src_port}  ->  {dst_ip}:{dst_port}")
    else:
        print(f"  {src_ip}  ->  {dst_ip}")

    payload_preview = format_payload(packet)
    if payload_preview:
        print(f"  Payload: {payload_preview}")


def main():
    parser = argparse.ArgumentParser(description="Basic Network Sniffer (CodeAlpha Task 1)")
    parser.add_argument("-i", "--iface", default=None,
                         help="Network interface to sniff on (default: all interfaces)")
    parser.add_argument("-c", "--count", type=int, default=0,
                         help="Number of packets to capture (default: 0 = infinite, stop with Ctrl+C)")
    parser.add_argument("-f", "--filter", default="ip",
                         help='BPF filter string, e.g. "tcp port 80" (default: "ip")')
    args = parser.parse_args()

    print("=" * 70)
    print(" Basic Network Sniffer - CodeAlpha Cyber Security Internship")
    print("=" * 70)
    print(f" Interface : {args.iface or 'all'}")
    print(f" Filter    : {args.filter}")
    print(f" Count     : {'infinite (Ctrl+C to stop)' if args.count == 0 else args.count}")
    print("=" * 70)

    try:
        sniff(
            iface=args.iface,
            filter=args.filter,
            prn=process_packet,
            store=False,
            count=args.count if args.count > 0 else 0,
        )
    except PermissionError:
        print("\n[ERROR] Permission denied. Try running with sudo/administrator privileges.")
    except KeyboardInterrupt:
        print("\n[INFO] Sniffing stopped by user.")


if __name__ == "__main__":
    main()
