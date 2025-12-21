#!/usr/bin/env python3
"""
Network responders for sniffdet integration testing.

These responders simulate vulnerable hosts that respond to sniffdet's
detection probes. They run as separate processes and communicate via
raw sockets to properly test the full detection path.

Requires: CAP_NET_RAW capability or root privileges.
"""

import socket
import struct
import random
import fcntl
import sys
import signal
import os

ETH_P_IP = 0x0800
ETH_P_ARP = 0x0806
IPPROTO_ICMP = 1
IPPROTO_TCP = 6
ICMP_ECHO_REQUEST = 8
ICMP_ECHO_REPLY = 0
ARP_REQUEST = 1
ARP_REPLY = 2


def get_mac(ifname):
    """Get MAC address of an interface."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    info = fcntl.ioctl(s.fileno(), 0x8927, struct.pack('256s', ifname[:15].encode()))
    s.close()
    return info[18:24]


def checksum(data):
    """Calculate IP/ICMP checksum."""
    if len(data) % 2:
        data += b'\x00'
    s = sum(struct.unpack('!%dH' % (len(data) // 2), data))
    s = (s >> 16) + (s & 0xffff)
    s += s >> 16
    return ~s & 0xffff


class ICMPResponder:
    """
    Responds to ALL ICMP echo requests regardless of destination MAC.

    This simulates a host in promiscuous mode that has a vulnerable
    network stack responding to packets not addressed to it.
    """

    def __init__(self, iface='veth1'):
        self.iface = iface
        self.running = False

    def start(self):
        """Start responding to ICMP requests."""
        recv_sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_IP))
        recv_sock.bind((self.iface, 0))

        send_sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_IP))
        send_sock.bind((self.iface, 0))

        recv_sock.settimeout(0.5)
        self.running = True

        while self.running:
            try:
                packet, addr = recv_sock.recvfrom(65535)
            except socket.timeout:
                continue

            # Parse ethernet header
            eth_dst = packet[0:6]
            eth_src = packet[6:12]
            eth_type = struct.unpack('!H', packet[12:14])[0]

            if eth_type != ETH_P_IP:
                continue

            # Parse IP header
            ip_start = 14
            ip_header = packet[ip_start:ip_start+20]
            iph = struct.unpack('!BBHHHBBH4s4s', ip_header)
            ip_header_len = (iph[0] & 0x0F) * 4
            protocol = iph[6]
            src_ip = iph[8]
            dst_ip = iph[9]

            if protocol != IPPROTO_ICMP:
                continue

            # Parse ICMP
            icmp_start = ip_start + ip_header_len
            icmp_type = packet[icmp_start]

            if icmp_type != ICMP_ECHO_REQUEST:
                continue

            # Build reply
            reply_eth = eth_src + eth_dst + struct.pack('!H', ETH_P_IP)

            # Swap src/dst IP
            new_ip = packet[ip_start:ip_start+12] + dst_ip + src_ip
            ip_csum = checksum(new_ip[:10] + b'\x00\x00' + new_ip[12:])
            new_ip = new_ip[:10] + struct.pack('!H', ip_csum) + new_ip[12:]

            # Change ICMP type to reply
            icmp_data = packet[icmp_start:]
            new_icmp = bytes([ICMP_ECHO_REPLY]) + icmp_data[1:2] + b'\x00\x00' + icmp_data[4:]
            icmp_csum = checksum(new_icmp)
            new_icmp = bytes([ICMP_ECHO_REPLY]) + icmp_data[1:2] + struct.pack('!H', icmp_csum) + icmp_data[4:]

            reply = reply_eth + new_ip + new_icmp
            send_sock.send(reply)

        recv_sock.close()
        send_sock.close()

    def stop(self):
        self.running = False


class ARPResponder:
    """
    Responds to ALL ARP requests regardless of destination MAC.

    Simulates a host that responds to ARP requests even when the
    request was sent to a bogus MAC address.
    """

    def __init__(self, iface='veth1', my_ip='10.0.0.2'):
        self.iface = iface
        self.my_ip = socket.inet_aton(my_ip)
        self.running = False

    def start(self):
        """Start responding to ARP requests."""
        sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ARP))
        sock.bind((self.iface, 0))
        sock.settimeout(0.5)

        my_mac = get_mac(self.iface)
        self.running = True

        while self.running:
            try:
                packet, addr = sock.recvfrom(65535)
            except socket.timeout:
                continue

            eth_type = struct.unpack('!H', packet[12:14])[0]
            if eth_type != ETH_P_ARP:
                continue

            arp_start = 14
            arp_op = struct.unpack('!H', packet[arp_start+6:arp_start+8])[0]

            if arp_op != ARP_REQUEST:
                continue

            sender_mac = packet[arp_start+8:arp_start+14]
            sender_ip = packet[arp_start+14:arp_start+18]

            # Build ARP reply
            eth = sender_mac + my_mac + struct.pack('!H', ETH_P_ARP)
            arp = struct.pack('!HHBBH', 1, 0x0800, 6, 4, ARP_REPLY)
            arp += my_mac + self.my_ip + sender_mac + sender_ip

            sock.send(eth + arp)

        sock.close()

    def stop(self):
        self.running = False


class DNSResponder:
    """
    Generates DNS PTR queries for destination IPs of observed TCP packets.

    Simulates a network monitoring tool that automatically resolves
    IPs it sees in promiscuous mode.
    """

    def __init__(self, iface='veth1', my_ip='10.0.0.2'):
        self.iface = iface
        self.my_ip = socket.inet_aton(my_ip)
        self.running = False
        self.seen_ips = set()

    def _build_dns_ptr_query(self, ip_addr):
        """Build a DNS PTR query for reverse lookup."""
        txn_id = random.randint(0, 65535)
        flags = 0x0100
        header = struct.pack('!HHHHHH', txn_id, flags, 1, 0, 0, 0)

        octets = ip_addr.split('.')
        reversed_octets = octets[::-1]
        qname_parts = reversed_octets + ['in-addr', 'arpa']

        qname = b''
        for part in qname_parts:
            qname += bytes([len(part)]) + part.encode()
        qname += b'\x00'

        question = qname + struct.pack('!HH', 12, 1)
        return header + question

    def start(self):
        """Start watching for TCP and generating DNS queries."""
        recv_sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_IP))
        recv_sock.bind((self.iface, 0))

        send_sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_IP))
        send_sock.bind((self.iface, 0))

        recv_sock.settimeout(0.5)
        my_mac = get_mac(self.iface)
        dns_server_ip = socket.inet_aton('8.8.8.8')

        self.running = True

        while self.running:
            try:
                packet, addr = recv_sock.recvfrom(65535)
            except socket.timeout:
                continue

            eth_type = struct.unpack('!H', packet[12:14])[0]
            if eth_type != ETH_P_IP:
                continue

            ip_start = 14
            iph = struct.unpack('!BBHHHBBH4s4s', packet[ip_start:ip_start+20])
            protocol = iph[6]
            dst_ip = socket.inet_ntoa(iph[9])

            if protocol != IPPROTO_TCP:
                continue

            if dst_ip in self.seen_ips or dst_ip == '10.0.0.2':
                continue

            self.seen_ips.add(dst_ip)

            # Build and send DNS PTR query
            dns_query = self._build_dns_ptr_query(dst_ip)

            src_port = random.randint(1024, 65535)
            udp_len = 8 + len(dns_query)
            udp_header = struct.pack('!HHHH', src_port, 53, udp_len, 0)

            ip_total_len = 20 + udp_len
            ip_id = random.randint(0, 65535)
            ip_h = struct.pack('!BBHHHBBH4s4s',
                0x45, 0, ip_total_len, ip_id, 0, 64, 17, 0,
                self.my_ip, dns_server_ip)
            ip_csum = checksum(ip_h)
            ip_h = struct.pack('!BBHHHBBH4s4s',
                0x45, 0, ip_total_len, ip_id, 0, 64, 17, ip_csum,
                self.my_ip, dns_server_ip)

            dst_mac = b'\xff\xff\xff\xff\xff\xff'
            eth = dst_mac + my_mac + struct.pack('!H', ETH_P_IP)

            send_sock.send(eth + ip_h + udp_header + dns_query)

        recv_sock.close()
        send_sock.close()

    def stop(self):
        self.running = False


def run_responder(responder_type, iface='veth1'):
    """Run a responder until SIGTERM/SIGINT."""
    responders = {
        'icmp': ICMPResponder,
        'arp': ARPResponder,
        'dns': DNSResponder,
    }

    if responder_type not in responders:
        print(f"Unknown responder type: {responder_type}", file=sys.stderr)
        sys.exit(1)

    responder = responders[responder_type](iface)

    def handler(signum, frame):
        responder.stop()

    signal.signal(signal.SIGTERM, handler)
    signal.signal(signal.SIGINT, handler)

    print(f"Starting {responder_type} responder on {iface}...", flush=True)
    responder.start()
    print(f"{responder_type} responder stopped.", flush=True)


if __name__ == '__main__':
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <icmp|arp|dns> [interface]")
        sys.exit(1)

    iface = sys.argv[2] if len(sys.argv) > 2 else 'veth1'
    run_responder(sys.argv[1], iface)
