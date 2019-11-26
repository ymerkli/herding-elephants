#!/usr/bin/env python
import sys
import socket
import random
import time
from threading import Thread, Event
from scapy.all import *


def get_if():
    ifs=get_if_list()
    iface=None # "h1-eth0"
    for i in get_if_list():
        if "eth0" in i:
            iface=i
            break;
    if not iface:
        print "Cannot find eth0 interface"
        exit(1)
    return iface

def send_packet(iface, ether_dst, random_ports):

    raw_input("Press the return key to send a packet:")
    print "Sending on interface %s\n" % (iface)
    pkt =  Ether(src=get_if_hwaddr(iface), dst=ether_dst)
    pkt = pkt /IP(src='10.0.0.1', dst='10.0.0.2', tos=0)
    if random_ports:
        pkt = pkt /TCP(dport=random.randint(5000,60000), sport=random.randint(49152,65535))
    else:
        pkt = pkt /TCP(dport=50001, sport=50000)
    sendp(pkt, iface=iface, verbose=False)

def main():

    ether_dst = sys.argv[1]
    random_ports = False
    if len(sys.argv) > 2:
        if sys.argv[2] == '-r':
            random_ports = True

    iface = get_if()

    while True:
        send_packet(iface, ether_dst, random_ports)
        time.sleep(0.1)


if __name__ == '__main__':
    main()
