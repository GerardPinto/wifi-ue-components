#!/usr/bin/python

import pyshark

cap = pyshark.FileCapture('../data/wifi-calling-android-t-mobile.pcapng')
print cap[0]