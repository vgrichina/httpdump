#!/usr/bin/env python

import argparse
import http_parse

import pcap

parser = argparse.ArgumentParser(description='Dump HTTP requests/responses')
parser.add_argument('--read', '-r', dest='pcapFile',
                   help='parse .pcap file from tcpdump')
parser.add_argument('--capture', '-c', dest='pcapFilter',
                   help='capture packets with given filter')
parser.add_argument('--interface', '-i', dest='interface',
                   help='capture on given interface')
args = parser.parse_args()

if args.pcapFile:
    http_parse.display_pcap_file(args.pcapFile)
else:
    pc = pcap.pcap(name=args.interface)
    pc.setfilter(args.pcapFilter)
    print 'listening on %s: %s' % (pc.name, pc.filter)

    http_parse.display(http_parse.parse_pcap(pc))

