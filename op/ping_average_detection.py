#! /usr/bin/env python
from scapy.all import *

# AVEC IP OBJET 

# faire propre et faire comme un include pour pas copier coller la fonction check-ping 

#check_ping renvoi une moyenne du temps de ping en ms sur 3 pings sucessifs 
def check_ping(host, count=3):
  packet = Ether()/IP(dst=host)/ICMP()
  t=0.0
  
  for x in range(count):
      
      ans,unans=srp(packet,iface="enp0s3", filter='icmp', verbose=0)
      rx = ans[0][1]  #ICMP response juste!
      tx = ans[0][0] #IP + ICMP response
      delta = rx.time-tx.sent_time
      #print ("Ping:", delta)
      t+=delta
      
  return (t/count)*1000    #*1000 pour avoir en ms
  
  
if __name__=="__main__": 

    #ENTRER LE SEUIL MAXIMUM ICI !! 
    maxtime=800000
    t1 = 0 
    t2 = 0 
    t3 = 0 
    t4 = 1
    
    while True:
        total = check_ping('10.32.1.162')
        
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
       
       #Danger si les 3 derniers tps du ping sont égaux à 10% du maximum 
       
        if (t1+t2+t3)/3 ==  (0.1*maxtime)+maxtime: 
            print("DANGERRRRRRRRR") 
        
        # Si le temps de ping dépasse le maximum récupéré 
        if total > maxtime: 
            print("PING DEPASSE LE MAXIMUM")