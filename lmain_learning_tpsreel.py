
from scapy.all import *
import sys
from interruptingcow import timeout 
import time

count_telnet = 0
learned_telnet = 0

try:
    interfaceobj = input("[*] Enter Desired Interface: ")
    ipobj = input("[*] Enter IP IoT: ")
except KeyboardInterrupt:
    print("[*] User Requested Shutdown...")
    print("[*] Exiting...")
    sys.exit(1)

#::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::            
#ping learning : script à éxécuter en parallèle : ping_learning.py


#:::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::
#bruteforce telnet : Sniff en direct  /// RECUPERER LA VALEUR DE LA VARIABLE LEARNED A LA FIN DU SNIFF ! 

def scan(pkt):
    global learned_telnet
    
    #ecriture dans le fichier pcap 
     wrpcap('learning.pcap', pkt, append=True)
     
    #detection en temps reel de brut force telnet 
    if IP in pkt:
        ip_src = pkt[IP].src
        ip_dst = pkt[IP].dst
        if pkt.haslayer(TCP) and pkt[TCP].dport==int(nport) :
            learned_telnet+=1
            print(str(ip_src) + " -> " + str(ip_dst))
            print("learned_telnet = ",learned_telnet)
            
            
def sniffing_pcap_telnet():
    nport = input("Numéro de port utilisé pour telnet (23 par défault): ")		
    sniff(iface = interfaceobj, prn = scan , store = 0) 
    #dois faire : appel sur telent en direct ,recup tout dans un pcap ! (voir meme trié ! ) OK? A TESTER 
    



#::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::    

if __name__=='__main__': 
    sniffing_pcap_telnet() 
    
#NOTES : Thread ? 2 éxécution parallèle pour l'instant . 
#           Ou récupérer nos variables maximum ? Fichier ? Print et entree de detection 

#           Faire le script qui tourne sur le pcap final (code yuheng, ftp bruteforce, peut etre d'autre )
#           Fichier de détection faire rentrer les valeurs (avec input au début et apres appel des bons codes ) (un fichier en direct un fichier en final sur le pcap) 
#           Faire les meme calculs sur les heuristiques en direct deja et peut etre meme celle d'apres (ex : si depasse 10% de cette valeur ... trouver d'autre trucs ..) (une fonction qui tourne sur tout les max) 