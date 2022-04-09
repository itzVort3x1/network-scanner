#!/usr/bin/env python

import scapy.all as scapy
import optparse


def get_arguments():
    parser = optparse.OptionParser()
    parser.add_option("-t", "--target", dest="target", help="Network Target to scan")
    (options, arguments) = parser.parse_args()
    if not options.target:
        parser.error("[-] Please specify a target to scan for, use --help for more info")
    else:
        return options


def scan(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]

    client_list = []
    for element in answered_list:
        client_dict = {"ip": element[1].psrc, "mac": element[1].hwsrc}
        client_list.append(client_dict)
        # print(element[1].psrc + "\t\t\t" + element[1].hwsrc)
    return client_list
    # scapy.ls is used to list out the options of a scapy attribute
    # scapy.ls(scapy.Ether())


def print_result(results_list):
    print("IP\t\t\t\tMAC Address")
    print("--------------------------------------------------------------")
    for element in results_list:
        print(element["ip"] + "\t\t\t" + element["mac"])


values = get_arguments()
scan_result = scan(values.target)
print_result(scan_result)