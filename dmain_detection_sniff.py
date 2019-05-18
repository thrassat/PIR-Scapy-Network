from scapy.all import *

#::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::            



#:::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::
#bruteforce telnet : Sniff en direct  /// RECUPERER LA VALEUR DE LA VARIABLE LEARNED A LA FIN DU SNIFF ! 


from scapy.all import *
import sys
import time

count_telnet = 0

try:
    interfaceobj = input("[*] Enter Desired Interface: ")
    ipobj = input("[*] Enter IP IoT: ")
    nport = input("Numéro de port utilisé pour telnet (23 par défault): ")
    learned_telnet = float(input("Max telnet ? "))	
except KeyboardInterrupt:
    print("[*] User Requested Shutdown...")
    print("[*] Exiting...")
    sys.exit(1)

def detect(pkt):
	global learned_telnet
	global count_telnet
	#ecriture dans le fichier pcap 
	wrpcap('atkpart.pcap', pkt, append=True)
	 
	#detection en temps reel de brut force telnet 
	if IP in pkt:
		ip_src = pkt[IP].src
		ip_dst = pkt[IP].dst
		if pkt.haslayer(TCP) and pkt[TCP].dport==int(nport) :
			count_telnet+=1
			x=(count_telnet-learned_telnet)/learned_telnet
			print(str(ip_src) + " -> " + str(ip_dst))
			print("count_telnet = ",count_telnet)
			if x > 0.1 :
				print("attention, telnet_learned dépassé de ",x*100,"%")
		if (pkt.haslayer(ICMP)):
			if pkt.length > 2**16:
				print ()
				print (" -----------------------------------------------------------------> SUSPICION D'ATTAQUE DE TYPE PING of DEATH <-----------------------------------------------------------------")
				print()
            
def sniffing_pcap_telnet():
    sniff(iface = interfaceobj, prn = detect , store = 0) 
    #tel net marche, récuperer learned_telent!!! 
    #,recup tout dans un pcap ! (voir meme trié ! ) OK? A TESTER 
    



#::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::    

if __name__=='__main__': 
	sniffing_pcap_telnet() 
	try:
		while True: 
			pass
	except KeyboardInterrupt:
		print(" :::::::::::::: Fin de la détection :::::::::::::::::::::::::::::")
		x=(count_telnet-learned_telnet)/learned_telnet
		if x > 0.1 :
			print("telnet_learned dépassé de ",x*100,"%, une attaque a sûrement eu lieu")
		sys.exit() 
    
#NOTES : Thread ? 2 éxécution parallèle pour l'instant . 
#           Ou récupérer nos variables maximum ? Fichier ? Print et entree de detection 

#           Faire le script qui tourne sur le pcap final (code yuheng, ftp bruteforce, peut etre d'autre )
#           Fichier de détection faire rentrer les valeurs (avec input au début et apres appel des bons codes ) (un fichier en direct un fichier en final sur le pcap) 
#           Faire les meme calculs sur les heuristiques en direct deja et peut etre meme celle d'apres (ex : si depasse 10% de cette valeur ... trouver d'autre trucs ..) (une fonction qui tourne sur tout les max) 
