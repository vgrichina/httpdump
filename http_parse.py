#!/usr/bin/env python
# Turns a pcap file with http gzip compressed data into plain text, making it
# easier to follow.

import dpkt

def tcp_flags(flags):
    ret = ''
    if flags & dpkt.tcp.TH_FIN:
        ret = ret + 'F'
    if flags & dpkt.tcp.TH_SYN:
        ret = ret + 'S'
    if flags & dpkt.tcp.TH_RST:
        ret = ret + 'R'
    if flags & dpkt.tcp.TH_PUSH:
        ret = ret + 'P'
    if flags & dpkt.tcp.TH_ACK:
        ret = ret + 'A'
    if flags & dpkt.tcp.TH_URG:
        ret = ret + 'U'
    if flags & dpkt.tcp.TH_ECE:
        ret = ret + 'E'
    if flags & dpkt.tcp.TH_CWR:
        ret = ret + 'C'

    return ret

def parse_http_stream(stream):
    while len(stream) > 0:
        if stream[:4] == 'HTTP':
            http = dpkt.http.Response(stream)
            print http.status
        else:
            http = dpkt.http.Request(stream)
            print http.method, http.uri
        stream = stream[len(http):]

def parse_pcap_file(filename):
    # Open the pcap file
    f = open(filename, 'rb')
    pcap = dpkt.pcap.Reader(f)

    # I need to reassmble the TCP flows before decoding the HTTP
    conn = dict() # Connections with current buffer
    for ts, buf in pcap:
        eth = dpkt.ethernet.Ethernet(buf)
        if eth.type != dpkt.ethernet.ETH_TYPE_IP:
            continue

        ip = eth.data
        if ip.p != dpkt.ip.IP_PROTO_TCP:
            continue

        tcp = ip.data

        tupl = (ip.src, ip.dst, tcp.sport, tcp.dport)
        #print tupl, tcp_flags(tcp.flags)

        # Ensure these are in order! TODO change to a defaultdict
        if tupl in conn:
            conn[ tupl ] = conn[ tupl ] + tcp.data
        else:
            conn[ tupl ] = tcp.data

        # TODO Check if it is a FIN, if so end the connection

        # Try and parse what we have
        try:
            stream = conn[ tupl ]
            if stream[:4] == 'HTTP':
                http = dpkt.http.Response(stream)
                #print http.status
            else:
                http = dpkt.http.Request(stream)
                #print http.method, http.uri

            print http
            print

            # If we reached this part an exception hasn't been thrown
            stream = stream[len(http):]
            if len(stream) == 0:
                del conn[ tupl ]
            else:
                conn[ tupl ] = stream
        except dpkt.UnpackError:
            pass

    f.close()

if __name__ == '__main__':
    import sys
    if len(sys.argv) <= 1:
        print "%s " % sys.argv[0]
        sys.exit(2)

    parse_pcap_file(sys.argv[1])
