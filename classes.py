#!/usr/bin/env python3

class IoT:
	def __init__(self,adrmac,state):
		self.adma = adrmac
		self.st = state 
	def __str__(self):
		return "IoT => { mac address :"+self.adma+" ; state : "+self.st+" } "


