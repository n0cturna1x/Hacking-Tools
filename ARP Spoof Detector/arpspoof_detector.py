'''
ARP Spoof Detector
'''

# Imports ARP and sniff modules from Scapy library
from scapy.all import ARP, sniff

# MAC <-> IP mappings
ARP_TABLE = {}

#'lfilter' parameter for sniff() function. Applied to each packet to determine if further action may be done.
# Accepts ARP packets with Operation field equals 1 (request) or 2 (reply)
def arp_filter(pkt):
    return ARP in pkt and pkt[ARP].op in (1, 2)

# ARP payload function to apply to each packet in sniff() function.
# Operation
# Hardware Source (Sender's MAC address)
# Protocol Source (Sender's IP address)
# Hardware Destination (Target's MAC address)
# Protocol Destination (Target's IP address)
def prn_callback(pkt):
    op = pkt[ARP].op 
    hwsrc = pkt[ARP].hwsrc  
    psrc = pkt[ARP].psrc  
    hwdst = pkt[ARP].hwdst  
    pdst = pkt[ARP].pdst  

    # Print the operation
    # Request (who-has)
    # Reply (is-at)
    if op == 1:  
        print(f"Who has {pdst} asks {psrc} ({hwsrc})")
    elif op == 2:  
        print(f"{psrc} is at {hwsrc}")

    # Detect ARP spoofing attack
    # Prints sender's MAC and IP
    # Saves MAC <-> IP mapping
    if ARP_TABLE.get(hwsrc) is not None and ARP_TABLE[hwsrc] != psrc:
        print(f"ATTACK DETECTED: {hwsrc}, formerly known as {ARP_TABLE[hwsrc]}, is trying to become {psrc}")
    else:
        ARP_TABLE[hwsrc] = psrc

# Processes data from packet capture.
sniff(offline='capture.pcap', prn=prn_callback, lfilter=arp_filter, store=0)