from scapy.all import *


    #ping of death ? 
        if (pkt.haslayer(ICMP)):
            if pkt.length() > 2**16:
                print ()
                print " -----------------------------------------------------------------> SUSPICION D'ATTAQUE DE TYPE PING of DEATH <-----------------------------------------------------------------"
                print()
                


#::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::            



#:::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::
#bruteforce telnet : Sniff en direct  /// RECUPERER LA VALEUR DE LA VARIABLE LEARNED A LA FIN DU SNIFF ! 