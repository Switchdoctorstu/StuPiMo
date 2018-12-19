# StuPiMo
Stu's Multiple Wemo Emulator for RPi

Uses WiringPi to operate the GPIO pins

There are a few Wemo Emulators out there - FAUXMO etc. but i couldn't be bothered
to learn python and so needed one written in C.


Stuart's Alexa to Raspberry Pi interface 
Device Daemon process

Starts multiple device handler processes monitoring separate TCP Ports
* Responds to device calls:
	GetBinaryState
	SetBinaryState
Starts an SSDP discovery packet handler on the local thread
* Responds to XML discovery packets

Remember to set interface to promiscuous mode with
sudo ifconfig eth0 promisc

Function:
	Opens device handlers on local sockets counting up from PORTBASE (43540)

	Watches for discovery packets on UDP SSDP 239.255.255.250 port 1900
	responds with discovery pointer to http://<ip>:43540+n/setup.xml for each device

	Alexa then polls each logical device
	Devices then respond with configuration xml
	Alexa registers devices based on XML config

	Alexa then Calls devices with GET and SET state requests
	Device handlers then toggle the associated GPIO pins.
