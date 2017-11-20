#!/usr/bin/python

import pyshark

cap = pyshark.FileCapture('../data/wifi-calling-android-t-mobile.pcapng')

# print dir(cap[1282].frame_info.protocols)
# if hasattr(cap[1282], 'isakmp'):
#     print dir(cap[1282].isakmp)

print "[+] Initiator SPI \t %s " % (cap[1282].isakmp.ispi)
print "[+] Key Exchange Data %s " % (cap[1282].isakmp.key_exchange_data)
print "[+] Nonce %s " % (cap[1282].isakmp.nonce)
# for index in range(0, 9248):
# 	protocols = cap[index].frame_info.protocols.showname_value
# 	data = protocols.split(":")
# 	if "isakmp" in data:
# 		print index
# 		break