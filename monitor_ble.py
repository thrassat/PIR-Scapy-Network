#!/usr/bin/env python3
import classes
import settings

def monitor(packet):
	try:
		if packet['BTLE connect request']:
			settings.objets.append(classes.IoT(packet.InitA,"CONNECTED"))
			[setattr(obj,"st","CONNECTED") for obj in settings.objets if obj.adma == packet.AdvA]
	except IndexError:
			pass
		
	try:
		if packet['BTLE ADV_IND']:
			if any((obj.adma == packet.AdvA and obj.st == "CONNECTED") for obj in settings.objets):		
				return "Not good"
			if all(obj.adma != packet.AdvA for obj in settings.objets):
				settings.objets.append(classes.IoT(packet.AdvA,"NOT_CONNECTED"))
	except IndexError:
			pass 



