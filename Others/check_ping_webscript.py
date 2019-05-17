#! /usr/bin/env python
from scapy.all import *
import numpy as np
import matplotlib.pyplot as plt

#Renvoi la moyenne sur un ping instantané de 3 paquets, ce qu'on peut faire c'est du coup faire du while true de ça tout les demi secondes par exemple, ensuite , arrivé à stocker chaque valeur puis si ça sort : "raise error ou c comment ?" 


def check_ping(host, count=3):
  packet = Ether()/IP(dst=host)/ICMP()
  t=0.0
  
  for x in range(count):
      
      ans,unans=srp(packet,iface="enp0s3", filter='icmp', verbose=0)
      rx = ans[0][1]  #ICMP response juste!
      tx = ans[0][0] #IP + ICMP response
      delta = rx.time-tx.sent_time
      print ("Ping:", delta)
      t+=delta
      
  return (t/count)*1000    #*1000 pour avoir en ms
  
if __name__=="__main__":
    
    maxtime = 0 
    t1 = 0
    t2 = 0
    t3 = 0
    t4 = 1
    
    #Pour print le ping 
    x = np.linspace(0, 1000, 1000)
    y = np.linspace(0,1000,1000)
    plt.ion()
    fig = plt.figure()  #placement de la figure 
    ax = fig.add_subplot(111) #parametrage 1x1 grid     
    line1, = ax.plot(x, y, 'r-')
    
    
    while True:
        total = check_ping('10.32.1.162')
       
       #Avoir le tps ping max et les 3 dernières valeurs courantes de ping 
        if total > maxtime: 
            maxtime = total 
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


       #Affichage résultat 
        line1.set_ydata(total)   
        fig.canvas.draw()
        fig.canvas.flush_events()
        hl, = plt.plot([], [])
        print ("TOTAL", total)
        
        #wait 0,5s 
        time.sleep(.5)


# idée : Trouver le moment ou on détecterait un ping anormal : 
# détecter genre si 1 ping dépasse le maximum récupéré , 3 paquets simultanés sont a 10% du mximum? 
# Phase d'apprentissage : récupérer ça dans un fichier !
# Faire 2 fichiers : un pour la détectione t un pour l'aprrentissagr!
  