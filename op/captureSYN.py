from scapy.all import *
import time
import plotly.offline as pltoff
import plotly.graph_objs as go

# AVEC PCAP , compte pour syn et ack! a voir pour nb pkt/s général 

packets = rdpcap('banana.pcap')   # PCAP de tout les paquets échangés en apprentissage 
startCaptureTime = packets[0].time
startTime=packets[0].time
deuxiemeCaptureTime = packets[1].time
start = time.time()

lengthPackets = len(packets)
i = 
cmp = 0
listFrequence = []
for packet in packets:
	print("TYPE  "+str(type(startCaptureTime)))
	print("TYPE  "+str(type(packet.time)))
	print("TYPE  "+str(type(start)))
	print("TYPE  "+str(type(time.time() - start)))
	print("TYPE  "+str(type(packet.time - startCaptureTime)))
	print("Length  "+str(lengthPackets))


	while (time.time() - start) < packet.time - startCaptureTime:
		pass


	F = packet['TCP'].flags    # this should give you an integer
	print("flags is "+str(F))
	if F & 'A':
		print('')
		print("Get thr ACK ++++++++++++++++"+"Compteur  is "+str(i))
    		# FIN flag activated
	if F & 'S':
		print('')
		print("Get thr SYN ++++++++++++++++"+"Compteur  is "+str(i))
		print('')

    		# SYN flag activated
			# rest of the flags here

	if  packet.time-startTime >= 0.05:
		listFrequence.append(i)
		if cmp>=1:
			print(" ************        "+str(i-listFrequence[cmp-1]))
			listFrequence.append(i-listFrequence[cmp-1])
		startTime=packets[i].time
		cmp+=1



	FirstTime = packets[i].time
	if i<lengthPackets-1:
		i += 1
		print("Cmp is "+str(i))
	else:
		print(i)

	print(str(i))
	SecondTime = packets[i].time

	print("Protocole is  "+str(packets[i].proto))
	print("TIME IS "+ str(SecondTime-FirstTime))
	print("Source is "+packet[IP].src)
	print("Desti is "+packet[IP].dst)
	#lambda="lambda pcap:IP in pcap and UDP in pcap and pcap[IP].src=='192.168.1.1' and pcap[UDP].sport==80"




	#packet.show()


def line_plots(name):
	id=0

	dataset = {'time': [], 'rx': []}

	for fre in listFrequence:
		dataset['time'].append(id)
		dataset['rx'].append(fre)
		id += 1

	data_g = []
	tr_rx = go.Scatter(
        x = dataset['time'],
        y = dataset['rx'],
        name = 'rx')

	data_g.append(tr_rx)


	layout = go.Layout(title="Line plots",
        xaxis={'title':'time'}, yaxis={'title':'value'})
	fig = go.Figure(data=data_g, layout=layout)
	pltoff.plot(fig, filename=name)


if __name__=='__main__':
	print('gogogogo======================')
	nameFile = "line_plots.html"
	line_plots(nameFile)
