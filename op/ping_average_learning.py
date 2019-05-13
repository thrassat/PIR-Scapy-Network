#! /usr/bin/env python
from scapy.all import *

#AVEC IP OBJET et interface connection rasp! 

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
  
  
#Main : on va chercher le maximum 

if __name__=="__main__":
    
    maxtime = 0 
    
    while True:
        total = check_ping('10.32.1.162')
        if total > maxtime: 
            maxtime = total 
            print(maxtime)
        print("PING  : " , total , "et le max est : " , maxtime)
        time.sleep(.5)