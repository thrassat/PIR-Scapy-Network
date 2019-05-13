from scapy.all import *
import time

def pkt_callback(pkt):
    pkt.show()

def main () :
    ipo = "192.168.0.7"
    while 1 :
        ping = IP(dst=ipo, ttl=2)/ICMP() 
        ans = sr1(ping)
        if not (ans is None): 
            tps = ans.time - ping.time
            print(ping.time) 
            print(ans.time)
            print(tps) 
        else : 
            print("Ping échoué") 
        time.sleep(1) 
        
            
            #Si on a bien eu une réponse à notre ping faire ensuite stockage du temps de rep et si on sort erreur et dans le else qui va suivre aussi erreur! 
            #Pour avoir le temps de la recp : lien qu'omar m'a envoyé sur fb , ou sinon la différence de ping.time - ans.time ! 
    
if __name__ == '__main__':
    main()
