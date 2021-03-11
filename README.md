# StuPiMo
Stu's Multiple Wemo Emulator for RPi


There are a few Wemo Emulators out there - FAUXMO etc. but i couldn't be bothered
to learn python and so needed one written in C.

This code allows a set of relays attached to teh Pi's GPIO ports to be controlled from a 'Smarthome' controller like Alexa or Google Home.

It does this by emulating a Wemo device on the network and responding to UPNP requests from the controller. 


**Stuart's Alexa to Raspberry Pi interface** 

Starts multiple device handler processes monitoring separate TCP Ports
- Responds to device calls:
	- GetBinaryState
	- SetBinaryState

Starts an SSDP discovery packet handler on the local thread
- Responds to XML discovery packets

Starts a Web Server to offer button control of interface pins

Function:

	Opens multiple device handlers on local sockets counting up from PORTBASE (43540)

	Watches for discovery packets on UDP SSDP 239.255.255.250 port 1900
	responds with discovery pointer to http://<ip>:43540+n/setup.xml for each device

	Alexa then polls each logical device
	Devices then respond with configuration xml
	Alexa registers devices based on XML config

	Alexa then Calls devices with GET and SET state requests
	Device handlers then toggle the associated GPIO pins.

Uses WiringPi to operate the GPIO pins
so use the -lwiringPi compiler option

	gcc -o StuPiMo StuPiMo.c -l wiringPi

To start normally:

	./StuPiMo

Or in verbose mode (Dumps all packets to console)

	./StuPiMo -v

UDP requires the interfaces to be running in promiscous mode
check with ifconfig

	ifconfig

and change if needed:

	sudo ifconfig eth0 promisc
	sudo ifconfig wlan0 promisc

I had to make this permanent in local.rc

*Update*
Added extra debug feature   -w0   and -w1

./StuPiMo -w0

This puts just the first client into verbose mode to cut down on the noise to the console to let you debug more easily.


