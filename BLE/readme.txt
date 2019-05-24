
In our implementation we maintained a list of IoT objects that have their MAC address and CONNECTED or NOT status as attributes. The idea then is to browse our PCAP file and update our list according to that:

If we encounter an ADV packet of an object and it does not find it in the objects list then add it with state NOT CONNECTED.
else if we encounter an ADV packet of an object and that if it is in the object list then :
	if the state of the object in the list is NOT CONNECTED then do nothing.
	otherwise if the state of the object in the list is CONNECTED then remove an error.
If we encounter a CON_REQ package then:
	add the object that sends this request to the object list and change the status from NOT CONNECTED to CONNECTED of the object accepting the request.


