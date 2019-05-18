#!/usr/bin/env python
############################# IMPORT #################################
from netifaces import AF_INET, AF_INET6, AF_LINK, AF_PACKET, AF_BRIDGE
import netifaces as ni
import time
import sys
import socket
import os
import re
import time
import logging
import subprocess 
import argparse
############################ CLASS COLORS ############################
class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

############################ MONITORING LOGIC ###########################
def startMonitoring(ipAddress, my_ip, interface):
	print(bcolors.HEADER + "\nGET THE MAC ADDRRESS DURING THE LEARNING PHASE"+bcolors.ENDC)
	print(bcolors.BOLD + "\nINITIALIZING..." + bcolors.ENDC)
	print(bcolors.BOLD + "REMOVING "+ipAddress+" FROM THE ARP TABLE" + bcolors.ENDC) 
	os.system("arp -d " + ipAddress)
	print(bcolors.BOLD + "OK.")

	print(bcolors.BOLD + "\nOBTAINING MAC ADDRESS"+ bcolors.ENDC)
	ping(ipAddress)

	mac = getMAC(ipAddress)

	print(bcolors.BOLD +"MAC ADDRESS FOUND: "+mac+""+bcolors.BOLD) 
		
	valid = False
	while valid != True:
		print(bcolors.BOLD+"IS "+mac+" THE CORRECT MAC ADDRESS FOR "+ipAddress+" (y/n)?"+bcolors.ENDC) 
		answer = str(input("> "))
		if answer == "N" or answer == "n":
			print(bcolors.FAIL+"IF THIS IS NOT THE CORRECT MAC THE YOU HAVE ALREADY BEEN POISENED."+bcolors.ENDC)
			print(bcolors.FAIL+"YOU MUST START THIS SCRIPT IN A SAFE STATE"+bcolors.ENDC)
			sys.exit()
		elif answer == "Y" or answer == "y":
			print(bcolors.OKGREEN+"OK.\n"+bcolors.ENDC)
			print(bcolors.HEADER +"MONITORING YOUR ARP TABLE...\n"+bcolors.ENDC)
			goodMac = mac
			valid = True
	monitor = True
	while monitor == True:
		mac = getMAC(ipAddress)
		if mac != goodMac:
			print("\a")
			print(bcolors.WARNING+"ARP POISONED"+bcolors.WARNING)
			break
		time.sleep(2)
############################ FUNCTION #########################
def getMyIp(interface):
	return ni.ifaddresses(interface)[AF_INET][0]['addr']
	
def ping(ip):
	# return == 1: OK.
	# return == 0: Failed.
	p = os.system("ping -c 1 " + ip)
	if p == 0:
		return 1
	else:
		return 
def getMAC(ip):
	p = subprocess.Popen("arp -a | grep  '(" + ip + ")' |  awk  '{print $4}'", shell=True, stdout=subprocess.PIPE)
	output = p.communicate()[0].rstrip()
	return output.decode("utf-8")
############################ MAIN #############################
def main(argv):
	
	parser = argparse.ArgumentParser(description='ARP poisoning detection')
	parser.add_argument("-a", "--address", dest="ip_addr", help="IP address to monitor.", required=True)
	parser.add_argument("-f", "--interface", dest="interface", help="Interface to defend.",	required=True)

	args = parser.parse_args()
	my_ip = getMyIp(args.interface)
	
	if args.ip_addr == my_ip:
		print(bcolors.FAIL + "ERROR : Cannot monitor your own IP address --  try using the default gateway's IP." + bcolors.ENDC)
	
	res = ping(args.ip_addr)
	if res == 0:
		print(bcolors.FAIL+"Address unreachable"+ bcolors.ENDC)
		sys.exit()

	startMonitoring(args.ip_addr, my_ip, args.interface)

if __name__ == "__main__":
	main(sys.argv)
