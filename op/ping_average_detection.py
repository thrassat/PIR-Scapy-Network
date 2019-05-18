#! /usr/bin/env python
from scapy.all import *
import lping_learning.py

# AVEC IP OBJET 
try:
    interfaceobj = input("[*] Enter Desired Interface: ")
    ipobj = input("[*] Enter IP IoT: ")
    maxtime = input("[*] Max ping appris ? : ")
except KeyboardInterrupt:
    print("[*] User Requested Shutdown...")
    print("[*] Exiting...")
    sys.exit(1)
  
if __name__=="__main__": 

    t1 = 0 
    t2 = 0 
    t3 = 0 
    t4 = 1
    
    while True:
        total = get_ping(ipobj)
        
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
       
        if (t1+t2+t3)/3 ==  (0.1*maxtime)+maxtime: 
            print("DANGERRRRRRRRR") 
        
        # Si le temps de ping dépasse le maximum récupéré 
        if total > ((0.1*maxtime)+maxtime): 
            print("UN PING 10% DEPASSE LE MAXIMUM")