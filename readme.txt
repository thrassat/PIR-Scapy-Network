README : 

	:::::::::::::::::::::::::::::::::::::::::::::::::::APPRENTISSAGE:::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::
    
Fichiers commençant par l 
    
Deux scripts sont à éxécuter en temps réel : on doit entrer l'IP de l'objet et l'interface réseau de la machine éxécutante.
    - Sniffing + detection de bruteforce telnet + création du .pcap : lmain_learning_tpsreel.py
    - fonction qui ping régulièrement l'objet : lping_learning_tpsreel.py
    
Un script est à éxécuter sur le .pcap final : (ftp brute force, nb packet/s, arp spoofin, syn flood, ack storm) 
    lmain_learning_pcap.py 
    
    

+ Un script à lancerà part, ne s'arrête pas entre la phase de learning et de détection (pour l'ARP spoofing) 
	ArpDefenderTool.py 
		executer la ligne : sudo python3 ArpDefenderTool -a IP OBJ -f INTERFACE RASP 
					puis répondre yes  (y)


:::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::DETECTION:::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::

Fichiers commençant par d

TPS REEL : 

Execution des deux scripts : on doit entrer l'IP de l'objet, l'interface réseau de la machine éxécutante
+ entrer le seuil détecté en learning pour telnet et le port telnet
dmain_detection_sniff.py
+entrer le seuil détecté en learning sur le maxtime du ping
dping_detection_tpsreel.py

SUR PCAP : 
A faire tourner sur le fichier 'learning.pcap' généré par en hase de learning
dmain_detection_pcap.py
