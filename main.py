#!/usr/bin/env python

import scapy.all as scapy

def scan(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_bradcast = broadcast/arp_request
    answered_list = scapy.srp(arp_request_bradcast, timeout=1, verbose=False)[0]

    print("IP\t\t\t\tMAC Address")
    print("--------------------------------------------------------------")
    for element in answered_list:
        print(element[1].psrc + "\t\t\t" + element[1].hwsrc)
    # scapy.ls is used to list out the options of a scapy attribute
    # scapy.ls(scapy.Ether())


scan("192.168.174.2/24")