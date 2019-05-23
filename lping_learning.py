
from scapy.all import *
import sys




#ping average : Besoin d'addr IP objet et interface sniff 

#get_ping renvoi une moyenne du temps de ping en ms sur 3 pings sucessifs /// RECUPERER MAXTIME ICI

def get_ping(host, interface, count=3):
    packet = Ether()/IP(dst=host)/ICMP()
    t=0.0
    for x in range(count):
        
        ans,unans=srp(packet,iface=interface, filter='icmp', verbose=0)
        rx = ans[0][1]  #ICMP response juste
        tx = ans[0][0] #IP + ICMP response
        delta = rx.time-tx.sent_time
        #print ("Ping:", delta)
        t+=delta
    return (t/count)*1000    #*1000 pour avoir en ms


def check_ping(host, interface): 
    maxtime = 0 
    try:
        while True:
            total = get_ping(host,interface,3)
            if total > maxtime: 
                maxtime = total 
                print("nouveau maxtime : ",maxtime)
            time.sleep(.5)
    except KeyboardInterrupt:
        print(" :::::::::::::: Fin de l'apprentissgae :::::::::::::::::::::::::::::")
        print("La valeur maximale de maxtime a été :",maxtime)
        sys.exit() 
        
        
#::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::    
#Ok ça marche, voir comment on récupère le maxtime final 
if __name__=="__main__": 
    try:
        interfaceobj = input("[*] Enter Desired Interface: ")
        ipobj = input("[*] Enter IP IoT: ")
    except KeyboardInterrupt:
        print("[*] User Requested Shutdown...")
        print("[*] Exiting...")
        sys.exit(1)
   
    check_ping(ipobj,interfaceobj)
    
