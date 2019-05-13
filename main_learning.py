
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
    nport = input("Numéro de port utilisé pour telnet: ")		
    sniff(iface = interfaceobj, prn = scan , store = 0) #PROBLEME LE SNIFF EST BLOQUANT !!!	
    #dois faire : appel sur telent en direct , recup tout dans un pcap ! (voir meme trié ! ) 
    

#::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::            
#ping average : Besoin d'addr IP objet et interface sniff 

#get_ping renvoi une moyenne du temps de ping en ms sur 3 pings sucessifs 

def get_ping(host, interface, count=3):
  packet = Ether()/IP(dst=host)/ICMP()
  t=0.0
  for x in range(count):
      
      ans,unans=srp(packet,iface=interface, filter='icmp', verbose=0)
      rx = ans[0][1]  #ICMP response juste!
      tx = ans[0][0] #IP + ICMP response
      delta = rx.time-tx.sent_time
      #print ("Ping:", delta)
      t+=delta
      
    return (t/count)*1000    #*1000 pour avoir en ms
  
def check_ping(host, interface): 
    maxtime = 0 
    
    while True:
        total = get_ping(host,interface,3)
        if total > maxtime: 
            maxtime = total 
        time.sleep(.5)


#::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::    

if __name__=='__main__': 

    
#NOTES : Thread ? Sinon bidouille de mon ping ou 2 terminal 
#           Ou récupérer nos variables maximum ? Fichier ? Print et entree de detection 
#           Faire le script qui tourne sur le pcap final (code yuheng, ftp bruteforce, peut etre d'autre )
#           Fichier de détection faire rentrer les valeurs (avec input au début et apres appel des bons codes ) (un fichier en direct un fichier en final sur le pcap) 