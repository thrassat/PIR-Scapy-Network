from scapy.all import *
import time
import plotly.offline as pltoff
import plotly.graph_objs as go

#:::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::
#ftp brute froce a recup



#Le fichier qu'on va etudier
packets = rdpcap('TracePcap/bruteforceFTP.pcap')
startCaptureTime = packets[0].time

startTime=packets[0].time
ecartSensibleSYN=1
prochainTime = startTime+ecartSensibleSYN




startTimeFTP=packets[0].time
ecartSensibleFTP=4
prochainTimeFTP = startTimeFTP+ecartSensibleFTP


deuxiemeCaptureTime = packets[1].time
start = time.time()

#Les parametre pour les paquets TCP
lengthPackets = len(packets)
i = 0
cmp = 0
nmbPaquet = 0
listFrequence = []

#Les parametre pour les paquets de SYN
iSYN = 1
cmpSYN = 0
nmbPaquetSYN = 0
listFrequenceSYN = []
#Les parametre pour les paquets de ACK
nmbPaquetACK = 0
cmpACK = 0
listFrequenceACK = []
#Les parametre pour les paquets de FTPPassword
cmpFTPPassword = 0
nmbPaquetFTPPassword = 0
listFrequenceFTPPassword = []
nmbStandardFTP = 0


#Les parametres pour l'analyse des data
maxNmbSYNApp=0
meanNmbSYN=0.0
varianceNmbSYN=0.0
nmbStandardApp =0.0










#print("Length  "+str(lengthPackets))


for packet in packets:
	#On parcourt tous les paquets jusqu'a la derniere packet
	while (time.time() - start) < packet.time - startCaptureTime:
		pass

	print("******START*****"  )
	print("****************")
	print("****************")

	#On traite que le spackets TCP, toute la partie dessous est sous cette condition
	if TCP in packet :
		F = packet['TCP'].flags
		Payload = packet['TCP'].payload
		print("flags is "+str(F))


		if  i<lengthPackets-1 and  packets[i].time<=prochainTime and packets[i].time>=startTime :
			#Enregistrer le nmb de paquets TCP
			print(" ***Capter juste un paquet normal "  )
			print(" ***No. "+str(nmbPaquet)+" dans l'intervalle"  )
			nmbPaquet+=1

			# SYN / ACK
			if F & 'A' and F & 'S':
				print('')
				print("+++++++++++++++++++++Get  SYN / ACK  ++++++++++++++++"+ " Compteur  is "+str(i))
				print('')
				print(" ***No. "+str(nmbPaquetSYN)+"SYN dans l'intervalle"  )
				#nmbPaquetSYN+=1
				#nmbPaquetACK+=1
			# ACK. activer le Compteur de ACK
			elif F & 'A':
				print('')
				print("Get thr ACK "+"Compteur  is "+str(i))
				nmbPaquetACK+=1
			# SYN activer le compteur de SYN
			elif F & 'S':
				print('')
				print("+++++++++++++++++++++++++Get SYN ++++++++++++++++"+ " Compteur  is "+str(i))
				print('')
				print(" ***No. "+str(nmbPaquetSYN)+"SYN dans l'intervalle"  )
				nmbPaquetSYN+=1
			else:
				print('Other Flag')

		#Si un packet depasse l'intervalle, on va enregistrer dans la liste
		elif packets[i].time>=prochainTime and packets[i].time>=startTime:
			#Mettre le compteur dans la liste de packet TCP
			listFrequence.append(nmbPaquet)
			print("*********************************")
			print(" ************Capter        "+str(listFrequence[cmp])+" paquets entre  "+str(startTime)+ " s et  "+str(prochainTime)+ " s ************")
			nmbPaquet=1
			startTime=prochainTime
			prochainTime+=ecartSensibleSYN
			cmp+=1
			# Part SYN
			listFrequenceSYN.append(nmbPaquetSYN)
			print("Capter  "+str(listFrequenceSYN[cmpSYN])+"SYN "+ " $$$$$$$$")
			# Si ce packet est SYN, on met le compteur a 1, sinon c'est juste un packet TCP mais avec d'autres flag
			if F & 'S':
				nmbPaquetSYN=1
			else :
				nmbPaquetSYN=0
			cmpSYN+=1

			# Part ACK
			listFrequenceACK.append(nmbPaquetACK)
			print("Capter  "+str(listFrequenceACK[cmpACK])+"ACK "+ " $$$$$$$$")
			if F & 'A':
				nmbPaquetACK=1
			else :
				nmbPaquetACK=0
			cmpACK+=1

			#la fenetre glissante sur l'intervalle de temps, startTime et prochainTime, jusqu'a la son TIME est plus petit que la prochaineTime
			while (packets[i].time>=prochainTime):
				vide = 0
				#Dans ces intervalles, il n'y aucun de packet tombe la-dessus
				listFrequence.append(vide)
				print(" ************Capter        "+str(listFrequence[cmp])+" paquets entre  "+str(startTime)+ " s et  "+str(prochainTime)+ " s ***********")
				nmbPaquet=1
				startTime=prochainTime
				prochainTime+=ecartSensibleSYN
				cmp+=1

				##Part SYN
				listFrequenceSYN.append(vide)
				print(" Capter   "+str(listFrequenceSYN[cmpSYN])+"SYN "+  " $$$$$$$$$$")
				if F & 'S':
					nmbPaquetSYN=1
				else :
					nmbPaquetSYN=0
				#Indice de la liste listFrequenceSYN va incrementer aussi
				cmpSYN+=1

				##Part ACK
				listFrequenceACK.append(vide)
				print(" Capter   "+str(listFrequenceACK[cmpACK])+"ACK "+  " $$$$$$$$$$")
				if F & 'A':
					nmbPaquetACK=1
				else :
					nmbPaquetACK=0
				#Indice de la liste listFrequenceSYN va incrementer aussi
				cmpACK+=1
		else :
			print("ERROR")


	    ############
	    #Part pour FTPPassword
	    ############
	    ###########3
		if  i<lengthPackets-1 and  packets[i].time<=prochainTimeFTP and packets[i].time>=startTimeFTP :

			if "Password required for" in (str(Payload)):
				print('')
				print("+++++++++++++++++++++++++Get FTPPassword ++++++++++++++++"+ " Compteur  is "+str(i))
				print('')
				nmbPaquetFTPPassword+=1
		elif packets[i].time>=prochainTimeFTP and packets[i].time>=startTimeFTP:

			startTimeFTP=prochainTimeFTP
			prochainTimeFTP+=ecartSensibleFTP
			# Part FTPPassword
			listFrequenceFTPPassword.append(nmbPaquetFTPPassword)
			print("Capter  "+str(listFrequenceFTPPassword[cmpFTPPassword])+"FTPPassword "+ " $$$$$$$$")
			if "Password required for" in (Payload):
				nmbPaquetFTPPassword=1
			else :
				nmbPaquetFTPPassword=0
			# Le compteur pour les packets de FTPPassword
			cmpFTPPassword+=1


			while (packets[i].time>=prochainTimeFTP):
				vide = 0
				startTimeFTP=prochainTimeFTP
				prochainTimeFTP+=ecartSensibleFTP
				##Part FTPPassword
				listFrequenceFTPPassword.append(vide)
				print(" Capter   "+str(listFrequenceFTPPassword[cmpFTPPassword])+"FTPPassword "+  " $$$$$$$$$$")
				# Si ce packet est FTP, on met le compteur a 1, sinon c'est juste un packet TCP mais avec d'autres flag
				if "Password required for" in (Payload):
					nmbPaquetFTPPassword=1
				else :
					nmbPaquetFTPPassword=0
				#Indice de la liste listFrequenceFTPPassword va incrementer aussi
				cmpFTPPassword+=1


		else :
			print("ERROR")




		#L'indice de la liste des packets TCP incremente chaque boucle
		FirstTime = packets[i].time
		if i<lengthPackets-1:
			print("Cmp is "+str(i))
			i += 1
		else:
			print(i)

		print("******END*******")

		print("****************")
		print("****************")
		print("")
		print("")


####################
#La partie Analyse
####################


#Variance
def dev(numbers, mean):
    sdev = 0.0
    for num in numbers:
        sdev = sdev + (num-mean)**2
    return pow(sdev/(len(numbers)-1), 0.5)

#Calculer la moyenne
def mean(numbers):
    s = 0.0
    for num in numbers:
        s = s + num
    return s/len(numbers)

#la valeur au milieu
def median(numbers):
    sorted(numbers)     #sorted（)
    size = len(numbers)
    if size%2 == 0:
        med = (numbers[size//2-1] + numbers[size//2]) / 2
    else:
        med = numbers[size//2]
    return med


def print_SYNList():
	print("listFrequenceSYN")
	print(listFrequenceSYN)
	maxNmbSYN = max(listFrequenceSYN)
	print("Max is"+str(maxNmbSYN))
	print("Valeur moyenne  is "+str(mean(listFrequenceSYN)))
	print("Variance is  "+str(dev(listFrequenceSYN,mean(listFrequenceSYN))))
	print("Valeur au milieu is  "+str(median(listFrequenceSYN)))

	nmbStandard = (mean(listFrequenceSYN)+median(listFrequenceSYN))/2
	print("Valeur standard  "+str(nmbStandard))


def print_ACKList():
	print("listFrequenceACK")
	print(listFrequenceACK)


def print_FTPList():
	print("listFrequenceFTPPassword")
	print(listFrequenceFTPPassword)
	nmbStandardFTP = (mean(listFrequenceFTPPassword)+median(listFrequenceFTPPassword))/2
	print("Valeur standard  "+str(nmbStandardFTP))

###################
#Tracer le graphe sur le ploty
###################
def line_plots(name):
    id=0
    idFTP=0

    #dataset = {'time': [],'SYNx':[]}
    dataset = {'time': [],'timeFTP':[], 'TCPx': [],'SYNx':[],'ACKx':[],'FTPx':[]}

    for fre in listFrequence:
    	dataset['time'].append(id)
    	dataset['TCPx'].append(fre)
    	id +=ecartSensibleSYN


    for freFTP in listFrequenceFTPPassword:
        dataset['timeFTP'].append(idFTP)
        dataset['FTPx'].append(freFTP)
        idFTP+=ecartSensibleFTP

    for freSYN in listFrequenceSYN:
    	dataset['SYNx'].append(freSYN)

    for freACK in listFrequenceACK:
    	dataset['ACKx'].append(freACK)

    data_g = []
    tr_rx = go.Scatter(
        x = dataset['time'],
        y = dataset['TCPx'],
		text='Nmb de paquets /1s',
        name = 'TCPx')

    data_g.append(tr_rx)

    tr_SYNx = go.Scatter(
        x = dataset['time'],
        y = dataset['SYNx'],
		text='Nmb de paquets SYN /1s',
        name = 'SYNx')

    data_g.append(tr_SYNx)


    tr_ACKx = go.Scatter(
        x = dataset['time'],
        y = dataset['ACKx'],
		text='Nmb de paquets ACK par /1s',
        name = 'ACKx')

    data_g.append(tr_ACKx)


    tr_FTPx = go.Scatter(
        x = dataset['timeFTP'],
        y = dataset['FTPx'],
		text='Nmb de paquets FTP par '+str(ecartSensibleFTP)+"s",
        name = 'FTPx')

    data_g.append(tr_FTPx)





    layout = go.Layout(title="Frequence of packets",
        xaxis={'title':'time'}, yaxis={'title':'Frequence'})
    fig = go.Figure(data=data_g, layout=layout)
    pltoff.plot(fig, filename=name)




if __name__=='__main__':
	print('gogogogo======================')
	nameFile = "line_plots.html"
	line_plots(nameFile)
	print_SYNList()
	print_ACKList()
	print_FTPList()

#::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::
#SYN de yu heng

#::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::
