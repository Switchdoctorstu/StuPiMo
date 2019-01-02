/*

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
	The code lists the IP addresses of the available interfaces and uses the last one found.
		This usually works on the PI as ETH0 is generally highest unless you add in WLAN

	Opens device handlers on local sockets counting up from PORTBASE (43540)

	Watches for discovery packets on UDP SSDP 239.255.255.250 port 1900
	responds with discovery pointer to http://<ip>:43540+n/setup.xml for each device

	Alexa then polls each logical device
	Devices then respond with configuration xml
	Alexa registers devices based on XML config

	Alexa then Calls devices with GET and SET state requests
	Device handlers then toggle the associated GPIO pins.

*/
// Libraries to include
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <time.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <wiringPi.h>		// GPIO Control Library

// global definitions
#define MSGBUFSIZE 1024
#define NUMDEVICES 8
#define NAMELEN 30			// Size of strings passed around
#define PORTBASE 43450		// base IP port to increment up from
#define MAXIF 5				// number of local interfaces (can be used to force the interface as code uses last one found)


// setup device tables
// This populates a table of friendly names - they'll be known as "Socket 1" to "Socket 8"
int setup_names(char friendly[NUMDEVICES][NAMELEN]) {
	int i = 0;
	// use this loop
	for (i = 0; i < NUMDEVICES; i++) {
		sprintf(friendly[i], "Socket %d", i);
	}
	// or the following manual table to populate device names
	/*
	strcpy(friendly[0], "Socket 1");
	strcpy(friendly[1], "Socket 2");
	strcpy(friendly[2], "Socket 3");
	strcpy(friendly[3], "Socket 4");
	strcpy(friendly[4], "Socket 5");
	strcpy(friendly[5], "Socket 6");
	strcpy(friendly[6], "Socket 7");
	strcpy(friendly[7], "Socket 8");
	*/
	return i;
}
//
// device handler
// 
int device( int port, char devicename[NAMELEN], int verbose_mode, int pin)
{
	wiringPiSetup();				// setup GPIO 
	pinMode(pin, OUTPUT);			// set our pin to output
	// Setup Variables
	int ret;						// used for return status etc
	int device_state = 0;			// state of the device 1 = on 0 = off -1 = disconnected
	char msgbuf[MSGBUFSIZE];		// inbound message buffer 
	char packet[MSGBUFSIZE];		// outbound packet buffer
	char response[MSGBUFSIZE - 256];// buffer for payload
	int child_id;				// file descriptor for inbound socket
	char tag[128];				// Tag to search for
	char *p;					// pointer for general use 
	int nbytes;					// number of bytes sent or received
	/*
	* Code starts here
	*/
	// create a TCP socket
	//
	int fd = socket(AF_INET, SOCK_STREAM, 0); // ordinary datagram socket
	if (fd < 0) {
		printf("%s: socket create failed\n", devicename);
		return 1;
	}
	// printf("Socket Created\n");

	// allow multiple sockets to use the same PORT number
	u_int yes = 1;
	if (
		setsockopt(
			fd, SOL_SOCKET, SO_REUSEADDR, (char*)&yes, sizeof(yes)
		) < 0
		) {
		printf("Reusing ADDR failed\n");
		return 1;
	}

	// set up destination address
	struct sockaddr_in addr;		// our local socket address
	memset(&addr, 0, sizeof(addr));  // clear it out
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = htonl(INADDR_ANY); // any inbount address
	addr.sin_port = htons(port);
	// printf("%s: Port set: %d\n",devicename,port);

	// bind to receive address
	if (bind(fd, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
		printf("%s: bind error\n", devicename);
		return 1;
	}
	// printf("%s: Socket Bound\n", devicename);

	// use listen to make the socket ready for connections
	if (listen(fd, 1) < 0)                 // aparently allows 1 requests to queue
	{
		printf("%s:listen error\n",devicename);
		close(fd);
		return 1;
	}
	printf("%s: Listening on port:%d...\n",devicename,port);
	// now just enter a loop
	//
	while (1) {

		int addrlen = sizeof(addr);

		// try to accpt a connection
		child_id = accept(fd, (struct sockaddr *) &addr, &addrlen);
		if (child_id < 0) {
			printf("%s: Error on accept\n",devicename); 
			close(fd);
			return 1;
		}

		// zero the buffer
		memset(&msgbuf, 0, sizeof(msgbuf));
		// read in a packet
		nbytes = recv(
			child_id,
			msgbuf,
			sizeof(msgbuf),
			0
		);

		if (nbytes < 0) {
			printf("Error in recvfrom");
			close(fd);
			close(child_id);
			return 1;
		}

		if (verbose_mode == 1) {
			printf("\n%s:Received Datagram:", devicename);
			msgbuf[nbytes] = '\0';
			puts(msgbuf);
		}

		// check the first 6 bytes for a setup request
		strcpy(tag, "GET /setup");
		ret = strncmp(tag, msgbuf, 6);
		if (ret == 0) {								// datagram is a M-SEARCH 
			printf("%s:Received Setup request:\n", devicename);
			msgbuf[nbytes] = '\0';
			if (verbose_mode == 1) {
				puts(msgbuf);
			}
			// Build the xml payload into a response
			strcpy(response, "<?xml version=\"1.0\"?>\r\n");
			strcat(response, "<root>\r\n");
			strcat(response, "<device>\r\n");
			strcat(response, "<deviceType>urn:Belkin:device:controllee:1</deviceType >\r\n");
			// need to build in friendly name
			strcat(response, "<friendlyName>");
			strcat(response, devicename);
			strcat(response, "</friendlyName>\r\n");
			strcat(response, "<manufacturer>Belkin International Inc.</manufacturer>\r\n");
			strcat(response, "<modelName>Emulated Socket</modelName>\r\n");
			strcat(response, "<modelNumber>3.1415</modelNumber>\r\n");
			sprintf(tag, "<UDN>uuid:Socket-1_0-%d</UDN>\r\n", port);
			strcat(response, tag);
			strcat(response, "<serviceList>\r\n");
			strcat(response, "<service>\r\n");
			strcat(response, "<serviceType>urn:Belkin:service:basicevent:1</serviceType>\r\n");
			strcat(response, "<serviceId>urn:Belkin:serviceId:basicevent1</serviceId>\r\n");
			strcat(response, "<controlURL>/upnp/control/basicevent1</controlURL>\r\n");
			strcat(response, "<eventSubURL>/upnp/event/basicevent1</eventSubURL>\r\n");
			strcat(response, "<SCPDURL>/eventservice.xml</SCPDURL>\r\n");
			strcat(response, "</service>\r\n");
			strcat(response, "</serviceList>\r\n");
			strcat(response, "</device>\r\n");
			strcat(response, "</root>");

			// build Http packet
			strcpy(packet, "HTTP/1.1 200 OK\r\n");
			strcat(packet, "SERVER: Unspecified,UPnP,Unspecified\r\n");
			strcat(packet, "LAST-MODIFIED: 12-12-18\r\n");

			// get the length of the payload
			sprintf(tag, "CONTENT-LENGTH: %d\r\n", strlen(response)); // get the length as a string
			strcat(packet, tag);
			strcat(packet, "CONTENT-TYPE:text/xml\r\n");
			strcat(packet, "CONNECTION:close\r\n\r\n");
			// add the response payload
			strcat(packet, response);
			/* send */
			if (verbose_mode == 1) {
				printf("%s: Sending:\n %s", devicename, packet);
			}
			int cnt = send(child_id, packet, strlen(packet), 0);
			printf("%s: Response sent\n",devicename);
			if (cnt < 0) {
				printf("%s: Error on sendto\n", devicename);
				close(fd);
				close(child_id);
				exit(1);
			}
		}
		// check for inbound post request
		strcpy(tag, "POST /upnp");
		ret = strncmp(tag, msgbuf, 6);
		if (ret == 0) {
			printf("\n%s: Received UPNP request:\n", devicename);
			msgbuf[nbytes] = '\0';
			if (verbose_mode == 1) {
				puts(msgbuf);
			}
			// Parse the received request
			strcpy(tag, "GetBinaryState");
			p = strstr(msgbuf, tag);
			if (p > 0) {
				// we've found get binary state
				// need to respond with state packet
				printf("%s: Get State Requested\n", devicename);

				strcpy(response, "<s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" ");
				strcat(response, "s:encodingStyle = \"http://schemas.xmlsoap.org/soap/encoding/\"><s:Body>\r\n");
				strcat(response, "<u:GetBinaryStateResponse xmlns:u=\"urn:Belkin:service:basicevent:1\">\r\n");

				// read the device state
				sprintf(tag, "<BinaryState>%d</BinaryState>\r\n", device_state);
				strcat(response, tag);
				strcat(response, "</u:GetBinaryStateResponse>\r\n</s:Body> </s:Envelope>\r\n");

				// build full response
				strcpy(packet, "HTTP/1.1 200 OK\r\n");
				strcat(packet, "SERVER: Unspecified,UPnP,Unspecified\r\n");
				strcat(packet, "LAST-MODIFIED: 12-12-18\r\n");

				// get the length of the payload
				sprintf(tag, "CONTENT-LENGTH: %d\r\n", strlen(response)); // get the length as a string
				strcat(packet, tag);
				strcat(packet, "CONTENT-TYPE:text/xml\r\n");
				strcat(packet, "CONNECTION:close\r\n\r\n");
				// add the response payload
				strcat(packet, response);
				/* send */
				if (verbose_mode == 1) {
					printf("sending:\n %s", packet);
				}
				int cnt = send(child_id, packet, strlen(packet), 0);
				if (cnt < 0) {
					printf("error on sendto");
					close(fd);
					close(child_id); 
					exit(1);
				}
			}

			strcpy(tag, "SetBinaryState");
			p = strstr(msgbuf, tag);
			if (p > 0) {   // need to Set binary state
				strcpy(tag, "<BinaryState>");
				p = strstr(msgbuf, tag);
				if (p > 0) {
					// we've found binary state
					char state = *(p + strlen(tag));  // get the state
					printf("state requested: %c \n", *(p + strlen(tag)));
					// set the pins based on the state reveived
					if (state == 0x30) {
						device_state = 0;
						digitalWrite(pin, HIGH);			// Relay card is inverted
						printf("%s:Binary State Set to 0\n",devicename);
					}
					if (state == 0x31) {
						device_state = 1;
						digitalWrite(pin, LOW);	// Relay card is inverted
						printf("%s:Binary State Set to 1\n",devicename);
					}
				}

				strcpy(response, "<s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" ");
				strcat(response, "s:encodingStyle = \"http://schemas.xmlsoap.org/soap/encoding/\"><s:Body>\r\n");
				strcat(response, "<u:SetBinaryStateResponse xmlns:u=\"urn:Belkin:service:basicevent:1\">\r\n");
				// read the device state
				sprintf(tag, "<BinaryState>%d</BinaryState>\r\n", device_state);
				strcat(response, tag);
				strcat(response, "</u:SetBinaryStateResponse>\r\n</s:Body> </s:Envelope>\r\n");
				// build full response
				strcpy(packet, "HTTP/1.1 200 OK\r\n");
				strcat(packet, "Server: Apache / 2.2.14 (Win32)\r\n");
				strcat(packet, "Last - Modified : Sat, 20 Nov 2004 07 : 16 : 26 GMT\r\n");
				strcat(packet, "ETag : \"10000000565a5-2c-3e94b66c2e680\"\r\n");
				strcat(packet, "Accept - Ranges : bytes\r\n");
				// get the length of the payload
				sprintf(tag, "Content-Length: %d\r\n", strlen(response)); // get the length as a string
				strcat(packet, tag);
				strcat(packet, "Content-Type: text/xml\r\n");
				strcat(packet, "CONNECTION: close\r\n\r\n");
				// add the response payload
				strcat(packet, response);
				/* send */
				if (verbose_mode == 1) {
					printf("%s: sending: %s\n", devicename, packet);
				}
				int cnt = send(child_id, packet, strlen(packet), 0);
				if (cnt < 0) {
					printf("%s: Error on sendto\n", devicename);
					close(fd);
					close(child_id); 
					exit(1);
				}
				
			}
		}
	}
	close(fd);	// close our connection
	return 0;
}

// SSDP DAEMON
// myaddress: local IP address to add to SSDP response packets
// verbose mode: 1= print all packets sent and received

int ssdp_main(char myaddress[NAMELEN], int verbose_mode)
{
	// this is the ssdp daemon process that is left behind after the child processes have been spawned
	int ret;						// used for return status etc
	// int verbose_mode = 0;			// extended reporting
	char response[1024];
	char group[NAMELEN];
	char tag[NAMELEN];
	strcpy(group, "239.255.255.250");	// e.g. 239.255.255.250 for SSDP
	int port = 1900;					// port for sdiscovery 1900 
	char msgbuf[MSGBUFSIZE];			// our message buffer 
	int i = 0;							// general loop index

	// create ordinary UDP socket
	int fd = socket(AF_INET, SOCK_DGRAM, 0); // ordinary datagram socket
	if (fd < 0) {
		printf("SSDP: Socket create failed\n");
		return 1;
	}
	printf("Socket Created\n");
	// allow multiple sockets to use the same PORT number
	u_int yes = 1;
	if (setsockopt( fd, SOL_SOCKET, SO_REUSEADDR, (char*)&yes, sizeof(yes)) < 0	) 
	{
		printf("SSDP: Reusing ADDR failed\n");
		return 1;
	}

	// set up destination address
	struct sockaddr_in addr;		// our local socket address
	memset(&addr, 0, sizeof(addr));  // clear it out
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = htonl(INADDR_ANY); // any inbount address
	addr.sin_port = htons(port);
	printf("SSDP: Address set\n");

	// bind to receive address
	if (bind(fd, (struct sockaddr*) &addr, sizeof(addr)) < 0) {
		printf("bind error\n");
		return 1;
	}
	printf("SSDP: Socket Bound\n");

	// use setsockopt() to request that the kernel join a multicast group
	struct ip_mreq mreq;
	mreq.imr_multiaddr.s_addr = inet_addr(group);
	mreq.imr_interface.s_addr = inet_addr("192.168.0.37");
	//mreq.imr_ifindex = 0;
	if (setsockopt(fd, IPPROTO_IP, IP_ADD_MEMBERSHIP, &mreq, sizeof(mreq)) < 0)
	{
		printf("setsockopt error\n");
		return 1;
	}
	printf("SSDP Listening...\n");
	// now just enter a read-print loop
	//
	addr.sin_addr.s_addr = inet_addr(group);
	while (1) {

		int addrlen = sizeof(addr);
		int nbytes = recvfrom(
			fd,
			msgbuf,
			MSGBUFSIZE,
			0,
			(struct sockaddr *) &addr,
			&addrlen
		);
		if (nbytes < 0) {
			printf("Error in recvfrom");
			return 1;
		}
		msgbuf[nbytes] = '\0';

		if (verbose_mode == 1) {
			printf("\nSSDP: Received Datagram:%s\n",msgbuf);
			
		}

		// need to process message
		/*Received Datagram:
			M-SEARCH * HTTP/1.1
			Host: 239.255.255.250:1900
			Man: "ssdp:discover"
			MX: 3
			ST: ssdp:all
			*/
		strcpy(tag, "M-SEARCH");

		// check the first 6 bytes
		ret = strncmp(tag, msgbuf, 6);

		if (ret == 0) {								// datagram is a M-SEARCH 
			printf("\nReceived Search Datagram:\n");
			if (verbose_mode == 1) {
				puts(msgbuf);
			}
			printf("SSDP: Sending responses: ");
			// need to loop through device responses
			for (i = 0; i < NUMDEVICES; i++) {
				// build response message 
				strcpy(response, "HTTP/1.1 200 OK \r\nCACHE-CONTROL: max-age=86400\r\n");
				strcat(response, "DATE: Mon, 22 Jun 2015 17 : 24 : 01 GMT\r\n");
				strcat(response, "EXT:\r\n");
				// code the port number
				sprintf(tag, "LOCATION: http://%s:%d/setup.xml\r\n",myaddress, PORTBASE + i);
				strcat(response, tag);
				strcat(response, "OPT: \"http://schemas.upnp.org/upnp/1/0/\"; ns=01\r\n");
				strcat(response, "01-NLS: 905bfa3c-1dd2-11b2-8928-fd8aebaf491c\r\n");
				strcat(response, "SERVER: Unspecified, UPnP/1.0, Unspecified\r\n");
				strcat(response, "X-User-Agent: redsonic\r\n");
				strcat(response, "ST: urn:Belkin:device:**\r\n");
				// code the USN
				sprintf(tag, "USN: uuid:Socket-1_0-%d::urn:Belkin:device:**\r\n", PORTBASE + i);
				strcat(response, tag);
				
				if (verbose_mode == 1) {
					printf("SSDP: sending: %s\n", response);
				}
				// Send one per device
				int cnt = sendto(fd, response, strlen(response), 0, (struct sockaddr *) &addr, addrlen);
				if (cnt < 0) {
					printf("SSDP: Error on sendto");
					exit(1);
				}
				printf("%d ", i);
				usleep(100000);			// wait 100ms
			}
			printf("\n");
		}
	}
	return 0;
}

// returns the number of interfaces found and a char array of their IPs
int get_if_ips(char ifaddresses[MAXIF][NAMELEN])
{
	int    iSocket = -1;
	struct if_nameindex* pIndex = 0;
	struct if_nameindex* pIndex2 = 0;
	int i = 0;
	printf("Getting Local Interface IP Addresses\n");

	// open a socket to let us ask details about the IP Stack
	if ((iSocket = socket(PF_INET, SOCK_DGRAM, 0)) < 0)
	{
		perror("socket");
		return -1;
	}

	pIndex = pIndex2 = if_nameindex();
	// loop through the interfaces
	while ((pIndex != NULL) && (pIndex->if_name != NULL) &&(i<MAXIF))
	{
		struct ifreq req;
		printf("%d: %s\n", pIndex->if_index, pIndex->if_name);
		strncpy(req.ifr_name, pIndex->if_name, IFNAMSIZ);

		if (ioctl(iSocket, SIOCGIFADDR, &req) < 0)
		{
			if (errno == EADDRNOTAVAIL)
			{
				printf("\tN/A\n");
				++pIndex;
				continue;
			}
			perror("Get IP Address ioctl error\n");
			close(iSocket);
			return -1;
		}

		printf("\t %s\n", inet_ntoa(((struct sockaddr_in*)&req.ifr_addr)->sin_addr));
		sprintf(ifaddresses[i], "%s", inet_ntoa(((struct sockaddr_in*)&req.ifr_addr)->sin_addr));

		++pIndex;
		++i;
	}

	if_freenameindex(pIndex2);
	close(iSocket);
	return i;
}

// This is the main code loop
// executuon starts here
int main(int argc, char *argv[])
{
	// deal with any arguments
	// -v is verbose mode
	int verbose_mode = 0;			// extended reporting
	if (argc > 1) {
		char* arg1 = argv[1];	// get any args 
		if (strncmp(arg1, "-v", 6) == 0) {		// verbose mode check
			verbose_mode = 1;
		}	
	}
	// Local Variables
	int i = 0;  // generic index
	int root_flag = 1;						// mark that this is the root process
	int ret = 0;							// general returns from calls
	int ifcount = 0;						// number of local interfaces
	char ifaddresses[MAXIF][NAMELEN];		// table of local machine interface addresses
	char myaddress[NAMELEN];				// my local IP address as a string
// table of devices
	char friendly[NUMDEVICES][NAMELEN];		// friendly name of the device as alexa will know it
	int port[NUMDEVICES];					// port numbers of the child processes
	int pid[NUMDEVICES];					// process handles for the child devices
	int gpioPin[NUMDEVICES];				// GPIO Pin assignments per device
// Load device table
	ret = setup_names(friendly);			// load the friendly names
	
	// setup ports
	for (i = 0; i < NUMDEVICES; i++) {
		port[i] = PORTBASE + i;
		gpioPin[i] = i;
	}
	// Get the local interface address
	ifcount = get_if_ips(ifaddresses);		// get a list of local IP addresses
	if (ifcount > 0) {
		printf("Found %d interfaces \n", ifcount);

		for (i = 0; i < ifcount; i++) {
			printf("Address:%s\n", ifaddresses[i]);
		}
		strcpy(myaddress, ifaddresses[ifcount - 1]);		// get the last address on the list

		// Start the devices - these are a series of forked processes, one per device
		for (i = 0; i < NUMDEVICES; i++) {
			printf("Root: Spawning \"%s\" on %s port:%d gpio pin:%d\n", friendly[i], myaddress, port[i], gpioPin[i]);
			int newpid = fork();				// Fork a new process here each loop - we'll end up with one child process per device
			if (newpid == 0) {
				// printf("This is being printed from the child process\n");
				root_flag = 0; // we're a child so flag is false
				printf("Child %d: Starting \"%s\" on port %d\n", i, friendly[i], port[i]);
				ret = device(port[i], friendly[i], verbose_mode, gpioPin[i]);
				printf("*** Child %d ended !!\n",i);
				i = NUMDEVICES + 1;	// We're a child process so Force the loop to end
			}
			else {
				// printf("This is being printed in the parent process:\n");
				pid[i] = newpid;
				printf("Root: - the process identifier (pid) of child: %d is: %d\n",i, newpid);
			}
			usleep(500000);			// wait 500ms between device starts
		}
		if (root_flag == 1) {
			// We're still in the root process
			printf("Root: All devices started\n");
			// Start the ssdp responder
			ret = ssdp_main(myaddress, verbose_mode);   // jump to the ssdp responder
		}

		return 1;		// end of code
	}
	else {
		printf("No interfaces found \n");
		return -1;
	}
}

// V0.71
// debugging single device registration - DONE
// Getting local IP address				- DONE (uses last IP on list though)
// Adding GPIO Controls					- DONE
// Tightened reporting					- DONE

