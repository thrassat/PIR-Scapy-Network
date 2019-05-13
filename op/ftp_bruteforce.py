from scapy.all import *
import time

#AVEC PCAP

packets = rdpcap('bruteforceFTP.pcap') #Fichier pcap avec tout, faire une fonction qui le crée et le passer en paramètre 
startCaptureTime = packets[0].time
start = time.time()

compteur = 0
edge = 0
new = 0

def scan ():
	global compteur
	for packet in packets:
		while (time.time() - start) < packet.time - startCaptureTime:
			pass
		#packet.show()
		if "Password required for" in (str(packet[TCP].payload)):
			compteur+=1
	print(compteur)
	edge = compteur
	compteur = 0

def detect():
	global compteur
	for packet in packets:
		while (time.time() - start) < packet.time - startCaptureTime:
			pass
		#packet.show()
		if "Password required for" in (str(packet[TCP].payload)):
			compteur+=1
	print(compteur)
	new = compteur

scan()
detect()
