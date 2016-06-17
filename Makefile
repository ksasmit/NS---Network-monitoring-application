default:
	gcc mydump.c -lpcap -o mydump
run_live:
	./mydump -i "eth0"
run_offline:
	./mydump -r "hw1.pcap"
run_live_filter:
	./mydump -i "eth0" -s "ubuntu"
run_offline_filter:
	./mydump -r "hw1.pcap" -s "ubuntu"
