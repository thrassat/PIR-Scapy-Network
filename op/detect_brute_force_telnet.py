#! /usr/bin/python3
#NE PAS OUBLIER SUDO AVANT !
from scapy.all import *
import sys
from interruptingcow import timeout 
import time
count_telnet = 0
learned_telnet_telnet = 0

	try:
		interface = input("[*] Enter Desired Interface: ")
	except KeyboardInterrupt:
		print("[*] User Requested Shutdown...")
		print("[*] Exiting...")
		sys.exit(1)
	
	temps = input("Temps d'apprentissage (en secondes) : ")
	nport = input("Numéro de port utilisé : ")				
	def scan(pkt):
		global learned_telnet_telnet
		if IP in pkt:
			ip_src = pkt[IP].src
			ip_dst = pkt[IP].dst
			if pkt.haslayer(TCP) and pkt[TCP].dport==int(nport) :
				learned_telnet_telnet+=1
				print(str(ip_src) + " -> " + str(ip_dst))
				print("learned_telnet_telnet = ",learned_telnet)
		
	def detect(pkt):
		global count_telnet
		global learned_telnet
		if IP in pkt:
			ip_src = pkt[IP].src
			ip_dst = pkt[IP].dst
			if pkt.haslayer(TCP) and pkt[TCP].dport==int(nport) :
				count_telnet+=1
				print(str(ip_src) + " -> " + str(ip_dst))
				print("count_telnet = ",count_telnet)
				if count_telnet == (learned_telnet+1):
						print("Ah ouais c'est chaud\n")
	
	try:
		with timeout(temps, exception=RuntimeError):
			sniff(iface = interface,filter = "port "+nport, prn = scan, store = 0)
	except RuntimeError:
		print("Apprentissage terminé, début du scan")
		sniff(iface = interface,filter = "port "+nport, prn = detect, store = 0)

