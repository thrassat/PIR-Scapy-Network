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
    t1 = 0 
    t2 = 0 
    t3 = 0 
    t4 = 1
    
    while True:
        total = get_ping(ipobj,interfaceobj)
        time.sleep(.5)
        # Avoir les 3 dernières valeurs de ping 
        if t4 == 1: 
            t1 = total 
            t4 = 2  
        if t4 == 2: 
            t2 = total 
            t4 = 3  
        if t4 == 3: 
            t3 = total 
            t4 = 1
            
       #Détection      
       
       #Danger si la moyenne des 3 derniers tps du ping sont égaux à 10% du maximum 
       
        if ((t1+t2+t3)/3) ==  ((0.1*maxtime)+maxtime): 
            print(":::::::::::::::::::::::::::::::::::::::::: SUSPICION SUR PING TROP LENT :::::::::::::::::::::::::::::::")
            print("LA MOYENNE DES 3 DERNIERS PINGS DEPASSE 10% DU MAX PING") 
        
        # Si le temps de ping dépasse le maximum récupéré 
        if total > ((0.1*maxtime)+maxtime): 
            print(":::::::::::::::::::::::::::::::::::::::::: SUSPICION SUR PING TROP LENT :::::::::::::::::::::::::::::::")
            print("UN PING DEPASSE DE 10% LE MAXIMUM ",total)

#:::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::