import os
from scapy.all import rdpcap

file_in = "../tftp/in"
file_out = "../tftp/out"

pkts = rdpcap(file_in)

list = []

for pkt in pkts:
    timestamp = pkt.time 
    srcIP,srcPort = pkt.sprintf("%IP.src%"), pkt.sprintf("%TCP.sport%")
    dstIP,dstPort = pkt.sprintf("%IP.dst%"), pkt.sprintf("%TCP.dport%")
    ipLength, protocol = pkt.sprintf("%IP.len%"),pkt.sprintf("%IP.proto%")
    list = [timestamp, srcIP, srcPort, dstIP, dstPort, ipLength, protocol]
    #print(timestamp, srcIP, srcPort, dstIP, dstPort, ipLength, protocol, flags)
    print(list)




