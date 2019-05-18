from scapy.all import *
import time
import plotly.offline as pltoff
import plotly.graph_objs as go

packets = rdpcap('bruteforceFTP.pcap')
startCaptureTime = packets[0].time
startTime=packets[0].time
ecartSensible=3
prochainTime = startTime+ecartSensible



startTimeSYN=packets[0].time
prochainTimeSYN = startTime+1


deuxiemeCaptureTime = packets[1].time
start = time.time()

lengthPackets = len(packets)
i = 0
iSYN = 1
cmp = 0
nmbPaquet = 0
cmpSYN = 0
nmbPaquetSYN = 0

cmpFTPPassword = 0
nmbPaquetFTPPassword = 0


global maxNmbSYN

listFrequence = []
listFrequenceSYN = []
listFrequenceFTPPassword = []




print("Length  "+str(lengthPackets))
print("startTime  "+str(startCaptureTime))

for packet in packets:
	#print("TYPE  "+str(type(startCaptureTime)))
	#print("TYPE  "+str(type(packet.time)))
	#print("TYPE  "+str(type(start)))
	#print("TYPE  "+str(type(time.time() - start)))
	#print("TYPE  "+str(type(packet.time - startCaptureTime)))



	while (time.time() - start) < packet.time - startCaptureTime:
		pass




	#print(" ++++++++++++++++++time now        "+str(packet.time))

	#Detecter tous les 0.05s		#
	#if  packet.time-startTime >= 1:
	#	listFrequence.append(i)
	#	if cmp>=1:
	#		print(" ************Capter        "+str(i-listFrequence[cmp-1])+" paquets en  "+str( packet.time-startTime)+ " s")
	#		listFrequence.append(i-listFrequence[cmp-1])
	#	startTime=packets[i].time
	#	cmp+=1

	print("******START*****"  )
	print("****************")
	print("****************")


	F = packet['TCP'].flags    # this should give you an integer
	Payload = packet['TCP'].payload
	print("flags is "+str(F))


	if  i<lengthPackets-1 and  packets[i].time<=prochainTime and packets[i].time>=startTime :
		#Juste la 1ere fois, le nmb de paquets

		print(" ***Capter juste un paquet normal "  )
		print(" ***No. "+str(nmbPaquet)+" dans l'intervalle"  )
		nmbPaquet+=1


		if "Password required for" in (str(Payload)):
			print('')
			print("+++++++++++++++++++++++++Get FTPPassword ++++++++++++++++"+ " Compteur  is "+str(i))
			print('')
			nmbPaquetFTPPassword+=1
		elif F & 'A':
			print('')
			print("Get thr ACK "+"Compteur  is "+str(i))
		elif F & 'S':
			print('')
			print("+++++++++++++++++++++++++Get SYN ++++++++++++++++"+ " Compteur  is "+str(i))
			print('')
			print(" ***No. "+str(nmbPaquetSYN)+"SYN dans l'intervalle"  )
			nmbPaquetSYN+=1
		else:
			print('Other Flag')


	elif packets[i].time>=prochainTime and packets[i].time>=startTime:
		listFrequence.append(nmbPaquet)
		print("*********************************")
		print(" ************Capter        "+str(listFrequence[cmp])+" paquets entre  "+str(startTime)+ " s et  "+str(prochainTime)+ " s ************")
		nmbPaquet=1
		startTime=prochainTime
		prochainTime+=ecartSensible
		cmp+=1
		# Part SYN
		listFrequenceSYN.append(nmbPaquetSYN)
		print("Capter  "+str(listFrequenceSYN[cmpSYN])+"SYN "+ " $$$$$$$$")
		if F & 'S':
			nmbPaquetSYN=1
		else :
			nmbPaquetSYN=0
		cmpSYN+=1


		# Part FTPPassword
		listFrequenceFTPPassword.append(nmbPaquetFTPPassword)
		print("Capter  "+str(listFrequenceFTPPassword[cmpFTPPassword])+"FTPPassword "+ " $$$$$$$$")
		if "Password required for" in (Payload):
			nmbPaquetFTPPassword=1
		else :
			nmbPaquetFTPPassword=0
		cmpFTPPassword+=1


		while (packets[i].time>=prochainTime):
			vide = 0

			listFrequence.append(vide)
			print(" ************Capter        "+str(listFrequence[cmp])+" paquets entre  "+str(startTime)+ " s et  "+str(prochainTime)+ " s ***********")
			nmbPaquet=1
			startTime=prochainTime
			prochainTime+=ecartSensible
			cmp+=1

			##Part SYN
			listFrequenceSYN.append(vide)
			print(" Capter   "+str(listFrequenceSYN[cmpSYN])+"SYN "+  " $$$$$$$$$$")
			if F & 'S':
				nmbPaquetSYN=1
			else :
				nmbPaquetSYN=0
			cmpSYN+=1


			##Part FTPPassword
			listFrequenceFTPPassword.append(vide)
			print(" Capter   "+str(listFrequenceFTPPassword[cmpFTPPassword])+"FTPPassword "+  " $$$$$$$$$$")
			if "Password required for" in (Payload):
				nmbPaquetFTPPassword=1
			else :
				nmbPaquetFTPPassword=0
			cmpFTPPassword+=1


	else :
		print("ERROR")







	FirstTime = packets[i].time
	if i<lengthPackets-1:
		print("Cmp is "+str(i))
		i += 1

	else:
		print(i)
	SecondTime = packets[i].time

	print("Protocole is  "+str(packets[i].proto))
	print("Maintenant ce paquet son TIME IS "+ str(packet.time))
	print("TIME IS "+ str(SecondTime-FirstTime))
	print("Source is "+packet[IP].src)
	print("Desti is "+packet[IP].dst)
	print("******END*******")

	print("****************")
	print("****************")
	print("")
	print("")
	#lambda="lambda pcap:IP in pcap and UDP in pcap and pcap[IP].src=='192.168.1.1' and pcap[UDP].sport==80"




	#packet.show()



def print_SYNList():
    print("listFrequenceSYN")
    print(listFrequenceSYN)

    maxNmbSYN = max(listFrequenceSYN)
    print("Max is"+str(maxNmbSYN))
    for freSYN in listFrequenceSYN:
        print(str(freSYN))


def print_FTPList():
    print("listFrequenceFTPPassword")
    print(listFrequenceFTPPassword)

    #maxNmbSYN = max(listFrequenceSYN)
    #print("Max is"+str(maxNmbSYN))
    for freFTP in listFrequenceFTPPassword:
        print(str(freFTP))





def line_plots(name):
	id=0

	dataset = {'time': [],'SYNx':[]}
	#dataset = {'time': [], 'rx': [],'SYNx':[]}

	for fre in listFrequence:
		dataset['time'].append(id)
		#dataset['rx'].append(fre)
		id += 1

	for freSYN in listFrequenceSYN:
		dataset['SYNx'].append(freSYN)

	data_g = []
	#tr_rx = go.Scatter(
    #    x = dataset['time'],
    #    y = dataset['rx'],
    #    name = 'rx')

	#data_g.append(tr_rx)


	tr_SYNx = go.Scatter(
        x = dataset['time'],
        y = dataset['SYNx'],
        name = 'SYNx')

	data_g.append(tr_SYNx)



	layout = go.Layout(title="Nombre de paquets par seconde",
        xaxis={'title':'time'}, yaxis={'title':'value'})
	fig = go.Figure(data=data_g, layout=layout)
	pltoff.plot(fig, filename=name)




if __name__=='__main__':
	print('gogogogo======================')
	nameFile = "line_plots.html"
	line_plots(nameFile)
	print_SYNList()
	print_FTPList()
