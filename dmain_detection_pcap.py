from scapy.all import *
from scapy.all import *
import time
import plotly.offline as pltoff
import plotly.graph_objs as go


    #ping of death ?
    #    if (pkt.haslayer(ICMP)):
    #        if pkt.length() > 2**16:
    #            print ()
    #            print " -----------------------------------------------------------------> SUSPICION D'ATTAQUE DE TYPE PING of DEATH <-----------------------------------------------------------------"
    #            print()


packets = rdpcap('TracePcap/SYN.pcap')
startCaptureTime = packets[0].time

startTime=packets[0].time
ecartSensibleSYN=1
prochainTime = startTime+ecartSensibleSYN




startTimeFTP=packets[0].time
ecartSensibleFTP=4
prochainTimeFTP = startTimeFTP+ecartSensibleFTP





deuxiemeCaptureTime = packets[1].time
start = time.time()

lengthPackets = len(packets)
i = 0
iSYN = 1
cmp = 0
nmbPaquet = 0
listFrequence = []


cmpSYN = 0
nmbPaquetSYN = 0
listFrequenceSYN = []
nmbStandard = float(input(" Entrer la moyenne de frequence de syn/sec : "))

nmbPaquetACK = 0
cmpACK = 0
listFrequenceACK = []


cmpFTPPassword = 0
nmbPaquetFTPPassword = 0
listFrequenceFTPPassword = []


maxNmbSYNApp=0
meanNmbSYN=0.0
varianceNmbSYN=0.0
nmbStandardApp =0.0










print("Length  "+str(lengthPackets))


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
	if TCP in packet:
                print("******START*****"  )
                print("****************")
                print("****************")


                F = packet['TCP'].flags    # this should give you an integer
                Payload = packet['TCP'].payload
                print("flags is "+str(F))


                if  (i<lengthPackets-1 and  packets[i].time<=prochainTime and packets[i].time>=startTime):
                    #Juste la 1ere fois, le nmb de paquets

                        print(" ***Capter juste un paquet normal "  )
                        print(" ***No. "+str(nmbPaquet)+" dans l'intervalle"  )
                        nmbPaquet+=1


                        if F & 'A' and F & 'S':
                                print('')
                                print("+++++++++++++++++++++Get  SYN / ACK  ++++++++++++++++"+ " Compteur  is "+str(i))
                                print('')
                                print(" ***No. "+str(nmbPaquetSYN)+"SYN dans l'intervalle"  )
                            #nmbPaquetSYN+=1
                            #nmbPaquetACK+=1

                        elif F & 'A':
                                print('')
                                print("Get thr ACK "+"Compteur  is "+str(i))
                                nmbPaquetACK+=1

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
                        prochainTime+=ecartSensibleSYN
                        cmp+=1
                        # Part SYN
                        listFrequenceSYN.append(nmbPaquetSYN)
                        print("Capter  "+str(listFrequenceSYN[cmpSYN])+"SYN "+ " $$$$$$$$")
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




                        while (packets[i].time>=prochainTime):
                                vide = 0

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
                                cmpSYN+=1

                            ##Part ACK
                                listFrequenceACK.append(vide)
                                print(" Capter   "+str(listFrequenceACK[cmpACK])+"ACK "+  " $$$$$$$$$$")
                                if F & 'A':
                                        nmbPaquetACK=1
                                else :
                                        nmbPaquetACK=0
                                cmpACK+=1





                else:
                        print("ERROR")







            #
            #Part pour FTPPassword
            #
            #
                if  (i<lengthPackets-1 and  packets[i].time<=prochainTimeFTP and packets[i].time>=startTimeFTP):



                        if "Password required for" in (str(Payload)):
                                print('')
                                print("+++++++++++++++++++++++++Get FTPPassword ++++++++++++++++"+ " Compteur  is "+str(i))
                                print('')
                                nmbPaquetFTPPassword+=1



                elif (packets[i].time>=prochainTimeFTP and packets[i].time>=startTimeFTP):

                        startTimeFTP=prochainTimeFTP
                        prochainTimeFTP+=ecartSensibleFTP


                    # Part FTPPassword
                        listFrequenceFTPPassword.append(nmbPaquetFTPPassword)
                        print("Capter  "+str(listFrequenceFTPPassword[cmpFTPPassword])+"FTPPassword "+ " $$$$$$$$")
                        if "Password required for" in (Payload):
                                nmbPaquetFTPPassword=1
                        else :
                                nmbPaquetFTPPassword=0
                        cmpFTPPassword+=1


                        while (packets[i].time>=prochainTimeFTP):
                                vide = 0

                                listFrequenceftp.append(vide)
                                print(" ************Capter        "+str(listFrequenceftp[cmp])+" paquets entre  "+str(startTimeFTP)+ " s et  "+str(prochainTimeFTP)+ " s ***********")

                                startTimeFTP=prochainTimeFTP
                                prochainTimeFTP+=ecartSensibleFTP




                            ##Part FTPPassword
                                listFrequenceFTPPassword.append(vide)
                                print(" Capter   "+str(listFrequenceFTPPassword[cmpFTPPassword])+"FTPPassword "+  " $$$$$$$$$$")
                                if "Password required for" in (Payload):
                                        nmbPaquetFTPPassword=1
                                else :
                                        nmbPaquetFTPPassword=0
                                cmpFTPPassword+=1


                else:
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
	print("Valeur standard  "+str(median(listFrequenceSYN)))


def print_ACKList():
	print("listFrequenceACK")
	print(listFrequenceACK)


def print_FTPList():
    print("listFrequenceFTPPassword")
    print(listFrequenceFTPPassword)
    #maxNmbSYN = max(listFrequenceSYN)
    #print("Max is"+str(maxNmbSYN))


def detecter_SYNAttack(nmbStandard):
    if(mean(listFrequenceSYN)-mean(listFrequenceACK)>50):
        if (median(listFrequenceSYN)+mean(listFrequenceSYN))/2-nmbStandard>=5*nmbStandardApp and max(listFrequenceSYN)>80 or max(listFrequenceSYN) - min(listFrequenceSYN)>300:
        	print("###############################")
        	print("#########                 #####")
        	print("######### ATTACK SYN Flood #############")
        	print("#########      DETECTE     ##############")
        	print("#########                 #####")
        	print("###############################")
    else:
        	print("###############################")
        	print("#########                 #####")
        	print("#########    ATTACK SYN Flood #############")
        	print("#########    NON  DETECTE     ##############")
        	print("#########                 #####")
        	print("###############################")







#Tracer le graphe sur le ploty
def line_plots(name):
    id=0
    idFTP=0

    #dataset = {'time': [],'SYNx':[]}
    dataset = {'time': [],'timeFTP':[], 'px': [],'SYNx':[],'ACKx':[],'FTPx':[]}

    for fre in listFrequence:
    	dataset['time'].append(id)
    	dataset['px'].append(fre)
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
        y = dataset['px'],
        text='Nmb de paquets /1s',
        name = 'px')

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





    layout = go.Layout(title="Nombre de paquets par seconde",
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
    detecter_SYNAttack(nmbStandard)
