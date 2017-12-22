#!/usr/local/bin/python
from scapy.all import *


##### Phase 1 #####

# capturing TWO 1st pk from UE and ePDG
packet1=sniff(iface="eth0", filter="udp and port 500", count=2, prn=lambda x: x.summary)

# forwarding 1st request pk from ue to swan server
data1 = ""		
tlayer =packet1[0].getlayer("UDP")	
if packet1[0].getlayer("Raw"):	
   data1 += str(tlayer.payload)
f = open("raw_data1.dat", 'w')
f.write(data1)
f.close()

wrpcap("data2.pcap", packet1[1])

send(IP(dst="192.168.84.128")/UDP()/ISAKMP(data1))




