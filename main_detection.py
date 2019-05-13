

    #ping of death ? 
        if (pkt.haslayer(ICMP)):
            if pkt.length() > 2**16:
                print ()
                print " -----------------------------------------------------------------> SUSPICION D'ATTAQUE DE TYPE PING of DEATH <-----------------------------------------------------------------"
                print()