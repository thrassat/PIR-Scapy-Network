from scapy.all import *
from lping_learning import get_ping

# AVEC IP OBJET , interface et maximum ping en entrée 
#Renvoi sous forme de string en direct sur la console pour l'instant 

  
if __name__=="__main__": 

    try:
        interfaceobj = input("[*] Enter Desired Interface: ")
        ipobj = input("[*] Enter IP IoT: ")
        maxtime = float(input("[*] Max ping appris ? : "))
    except KeyboardInterrupt:
        print("[*] User Requested Shutdown...")
        print("[*] Exiting...")
        sys.exit(1)
        
    cpt=0
    t1=0
    t2=0
    t3=0
    while True:
        total = get_ping(ipobj,interfaceobj)
        time.sleep(.5)
        # Avoir les 3 dernières valeurs de ping 
        cpt=cpt+1
    
        if cpt == 1: 
            t1=total
        elif cpt == 2: 
            t2=total
        elif cpt==3:
            t3=total
            cpt=0
        
       #Détection     
       
        moyenne = (t1+t2+t3)/3
    
       #Danger si la moyenne des 3 derniers tps du ping sont égaux à 5% du maximum 
       
        if (moyenne) > ((0.05*maxtime)+maxtime): 
            print(":::::::::::::::::::::::::::::::::::::::::: SUSPICION SUR PING TROP LENT :::::::::::::::::::::::::::::::")
            print("LA MOYENNE DES 3 DERNIERS PINGS DEPASSE 5% DU MAX PING",moyenne) 
        
        # Si le temps de ping dépasse 5% du maximum récupéré 
        if total > ((0.1*maxtime)+maxtime): 
            print(":::::::::::::::::::::::::::::::::::::::::: SUSPICION SUR PING TROP LENT :::::::::::::::::::::::::::::::")
            print("UN PING DEPASSE DE 10% LE MAXIMUM ",total)

#:::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::