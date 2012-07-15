#!/usr/bin/env python
# Turns a pcap file with http gzip compressed data into plain text, making it
# easier to follow.

import dpkt
import gzip
from StringIO import StringIO

# Can be used for debugging
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


def parse_pcap_file(filename):
    # Open the pcap file
    f = open(filename, 'rb')
    pcap = dpkt.pcap.Reader(f)

    parse_pcap(pcap)

def parse_pcap(pcap):
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

        addr_tuple = (ip.src, ip.dst, tcp.sport, tcp.dport)
        #print addr_tuple, tcp_flags(tcp.flags)

        # Ensure these are in order! TODO change to a defaultdict
        if addr_tuple in conn:
            conn[ addr_tuple ] = conn[ addr_tuple ] + tcp.data
        else:
            conn[ addr_tuple ] = tcp.data

        # Check if it is a FIN, if so end the connection
        if tcp.flags & dpkt.tcp.TH_FIN:
            del conn[ addr_tuple ]
        else:
            # Try and parse what we have
            try:
                stream = conn[ addr_tuple ]
                if stream[:4] == 'HTTP':
                    http = dpkt.http.Response(stream)
                    #print http.status
                else:
                    http = dpkt.http.Request(stream)
                    #print http.method, http.uri

                if "content-encoding" in http.headers and http.headers["content-encoding"] == "gzip":
                    buf = StringIO(http.body)
                    f = gzip.GzipFile(fileobj=buf)
                    http.body = f.read()

                yield addr_tuple, http

                # If we reached this part an exception hasn't been thrown
                stream = stream[len(http):]
                conn[ addr_tuple ] = stream
            except dpkt.UnpackError:
                pass

    f.close()

def ip_to_str(ip):
    return ".".join([str(ord(c)) for c in ip])

def display(pcap):
    for addr_tuple, http in pcap:
        (src, dst, srcPort, dstPort) = addr_tuple
        print "== src: %s:%d dst: %s:%d" % (ip_to_str(src), srcPort, ip_to_str(dst), dstPort)
        print http

def display_pcap_file(fileName):
    display(parse_pcap_file(fileName))

if __name__ == '__main__':
    import sys
    if len(sys.argv) <= 1:
        print "%s " % sys.argv[0]
        sys.exit(2)

    display_pcap_file(sys.argv[1])
