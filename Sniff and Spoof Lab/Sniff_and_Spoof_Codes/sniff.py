# -*- coding: utf-8 -*-
from scapy.all import * 

interface = "enp0s3"

def print_packet(packet):
    ip_layer = packet.getlayer(IP)
    print("[!] New Packet: {src} -> {dst}".format(src=ip_layer.src, dst=ip_layer.dst))

print("[*] Start sniffing...")
sniff(filter='tcp and dst 192.168.95.101/4', prn=print_packet)
print("[*] Stop sniffing")