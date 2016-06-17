				Name:Kumar Sasmit
				SBU ID: 110308698
				CSE508: Network Security, Spring 2016

				Homework 2: Programming with Libpcap
-------------------------------------------------------------------------------


Steps taken to set up :
----------------------------------------------------------------------------------------------------------
1.	Downloaded libpcap-1.6.2.tar.gz from http://www.tcpdump.org/ and extracted all the files to the src folder.
2.	sudo apt-get install libpcap-dev
3.	vim mydump.c
4.	To compile: gcc mydump.c -lpcap -o mydump
5.	To run->	./mydump [-h] [-i interface] [-r file] [-s string]

	-i  Listen on network device <interface> (e.g., eth0). If not specified, 
		mydump selects the default interface to listen on.

	-r  Read packets from <file> (tcpdump format).

	-s  Keep only packets that contain <string> in their payload.
	
	-h 	help on options
	
eg.
	To run live capture:
		./mydump -i "eth0"
	To run offline parsing:
		./mydump -r "hw1.pcap"
	To run live capture with filter:
		./mydump -i "eth0" -s <filter>
	To run offline parsing with filter:
		./mydump -r "hw1.pcap" -s <filter>
		
To run using Makefile:
-------------------------
To Compile:	make
To run the program use the option as ./mydump [-h] [-i interface] [-r file] [-s string]

The make file has some sample run commands with hardcoded command line args, they can be executed as:
run live capture: make run_live
run offline capture: make run_offline
run live capture with filter: make run_live_filter
run offline parsing with filter: make run_offline_filter

Description Of Implementation:
-------------------------------------
1. mydump uses the APIs defined in libpcap library.
2. The different segments of a packet has been divided into structures (ip, tcp and ethernet) with their respective fields as members.
3. In the main function the value of filter_exp can be modified to tell libpcap which packets to capture.
	For example:
	 * Expression			Description
	 * ----------			-----------
	 * ip					Capture all IP packets.
	 * tcp					Capture only TCP packets.
	 * tcp port 80			Capture only TCP packets with a port equal to 80.
	 * ip host 10.1.2.3		Capture all IP packets to or from host 10.1.2.3.

4. The program first of all checks the command line arguments that the user enters. It additionally has a help menu which shows
	the details of field options and how they are expected to be entered.
5. After some priliminary check, The program checks if the user wants offline pcap file parsing or live packet capture and the filter 
	expression if entered.
6. If the user has entered for offline parsing, the program checks if the dump file is opening by calling pcap_open_offline(), and then 
	calls pcap_loop()  with file pointer as the handle.
7. If the user has entered for live capture, the program checks if the user has entered the interface, if not it finds the default 
	interface by calling pcap_lookupdev();
8. The function pcap_loop() calls the callback function got_packet() for every packet, The last argument passed in the pcap_loop() is the filter 
	expression entered which is received as the first argument of the callback function.
9. The value of num_packets can be modified to continue the operation for a specified number of packets or can be entered as -1 to continue
	the operation till the end of the pcap file or till ctrl+c is pressed for live capture.
10.The program prints all the packets with the required fields if no filter expression has been mentioned.
11.If the filter expression is mentioned then the program prints all the required fields in all the packets, but payload only for those 
	packets which has the expression in their payload part.(If the filter expression has not been entered, the program prints the payload)
12.For comparing the payload and the filter expression, I have written a separate routine my_strstr(), Since predefined strstr() c library
	function was failing for most of the expression searches.
13.The non-printable characters in the payload part has been printed as '.', same as wireshark.


Included files:
------------------
source file: mydump.c
sample output: output.txt
Makefile
README.txt
hw1.pcap as sample offline pcap file
The downloaded and extracted library.
(I have made a separate copy of all the source files and docs inside the subfolder hw2_docs_and_src_files)


Output Format
---------------------
For each packet, mydump outputs a record containing 
Packet number
Timestamp
Packet length
Ethernet type
Ethernet source host address
Ethernet destination host address
Source IP
Destination IP
Protocol (TCP, UDP, ICMP, OTHER)
Source port
Destination port 
packet payload(if filter is present in it or if no filter is entered)



Reference:
---------------
http://www.tcpdump.org/pcap.html
