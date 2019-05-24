#!/usr/bin/env python3

from scapy.all import *
import sys
import settings
import monitor_ble
import classes

"""Gets and prints the spreadsheet's header columns
@type file_loc: str
@param file_loc: The file location of the spreadsheet
"""

def main(argv):

	settings.init()

	packets = rdpcap(argv[1])
	startCaptureTime = packets[0].time

	start = time.time()
	
	for packet in packets:

		if monitor_ble.monitor(packet) == "Not good":
			print("Not good")
			break
		
		


if '__main__' == __name__:
	main(sys.argv)
