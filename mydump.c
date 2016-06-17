/*
 * 1. Ethernet headers are always exactly 14 bytes, so we define this
 * explicitly with "#define". Since some compilers might pad structures to a
 * multiple of 4 bytes - some versions of GCC for ARM may do this -
 * "sizeof (struct sniff_ethernet)" isn't used.
 * 
 * 2. Check the link-layer type of the device that's being opened to make
 * sure it's Ethernet, since that's all we handle in this example. Other
 * link-layer types may have different length headers (see [1]).
 *
 * 3. This is the filter expression that tells libpcap which packets we're
 * interested in (i.e. which packets to capture). Since this source example
 * focuses on IP and TCP, we use the expression "ip", so we know we'll only
 * encounter IP packets. The capture filter syntax, along with some
 * examples, is documented in the tcpdump man page under "expression."
 * Below are a few simple examples:
 *
 * Expression			Description
 * ----------			-----------
 * ip					Capture all IP packets.
 * tcp					Capture only TCP packets.
 * tcp port 80			Capture only TCP packets with a port equal to 80.
 * ip host 10.1.2.3		Capture all IP packets to or from host 10.1.2.3.
 *
 */


#include <pcap.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <time.h>

/* default snap length (maximum bytes per packet to capture) */
#define SNAP_LEN 1518

/* ethernet headers are always exactly 14 bytes [1] */
#define SIZE_ETHERNET 14

/* Ethernet addresses are 6 bytes */
#define ETHER_ADDR_LEN	6
//#define LINE_LEN 16

/* Ethernet header */
struct sniff_ethernet {
        u_char  ether_dhost[ETHER_ADDR_LEN];    /* destination host address */
        u_char  ether_shost[ETHER_ADDR_LEN];    /* source host address */
        u_short ether_type;                     /* IP? ARP? RARP? etc */
};

/* IP header */
struct sniff_ip {
        u_char  ip_vhl;                 /* version << 4 | header length >> 2 */
        u_char  ip_tos;                 /* type of service */
        u_short ip_len;                 /* total length */
        u_short ip_id;                  /* identification */
        u_short ip_off;                 /* fragment offset field */
        #define IP_RF 0x8000            /* reserved fragment flag */
        #define IP_DF 0x4000            /* dont fragment flag */
        #define IP_MF 0x2000            /* more fragments flag */
        #define IP_OFFMASK 0x1fff       /* mask for fragmenting bits */
        u_char  ip_ttl;                 /* time to live */
        u_char  ip_p;                   /* protocol */
        u_short ip_sum;                 /* checksum */
        struct  in_addr ip_src,ip_dst;  /* source and dest address */
};
#define IP_HL(ip)               (((ip)->ip_vhl) & 0x0f)
#define IP_V(ip)                (((ip)->ip_vhl) >> 4)

/* TCP header */
typedef u_int tcp_seq;

struct sniff_tcp {
        u_short th_sport;               /* source port */
        u_short th_dport;               /* destination port */
        tcp_seq th_seq;                 /* sequence number */
        tcp_seq th_ack;                 /* acknowledgement number */
        u_char  th_offx2;               /* data offset, rsvd */
#define TH_OFF(th)      (((th)->th_offx2 & 0xf0) >> 4)
        u_char  th_flags;
        #define TH_FIN  0x01
        #define TH_SYN  0x02
        #define TH_RST  0x04
        #define TH_PUSH 0x08
        #define TH_ACK  0x10
        #define TH_URG  0x20
        #define TH_ECE  0x40
        #define TH_CWR  0x80
        #define TH_FLAGS        (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
        u_short th_win;                 /* window */
        u_short th_sum;                 /* checksum */
        u_short th_urp;                 /* urgent pointer */
};

void
got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);

void
print_payload(const u_char *payload, int len, u_char *args);

void
print_hex_ascii_line(const u_char *payload, int len, int offset);

void
print_app_banner(void);

void
print_app_usage(void);


void help(int r);
int my_strstr(const char* payload,u_char* args,int len);
/*
 * app name/banner
 */
void
print_app_banner(void)
{

	printf("\n\n\t\t\tMYDUMP\n\n");

return;
}

/*
 * print help text
 */
void
print_app_usage(void)
{

	printf("Usage: MYDUMP [interface]\n");
	printf("\n");
	printf("Options:\n");
	printf("    interface    Listen on <interface> for packets.\n");
	printf("\n");

return;
}
//for searching the pattern in payload

int my_hex_ascii_line(const u_char *payload, int len, int offset, u_char *args) //returns 1 if the pattern is found, 0 otherwise
{
	int i;
	int gap;
	const u_char *ch;
	char str[3]="\\0";
	//str[0]='\\' ;
	//str[2]='\0';

	/* offset */
	//printf("%05d   ", offset);
	
	/* hex */
	ch = payload;
	for(i = 0; i < len; i++) {
		//printf("%02x ", *ch);
		ch++;
		/* print extra space after 8th byte for visual aid */
		//if (i == 7)
			//printf(" ");
	}
	/* print space to handle line less than 8 bytes */
	//if (len < 8)
		//printf(" ");
	
	/* fill hex gap with spaces if not full line */
	if (len < 16) {
		gap = 16 - len;
		for (i = 0; i < gap; i++) {
			//printf("   ");
		}
	}
	//printf("   ");
	
	/* ascii (if printable) */
	ch = payload;
	//if(strstr(payload,args))
	if(my_strstr(payload,args,len))
		{
			//printf("%s found in the packet",args);
			return 1;
		}
	for(i = 0; i < len; i++) {
		//if (isprint(*ch))
			//printf("%c", *ch);
		/*else
		{
			printf(".");
			//str[1]=*ch;
			//printf("%s",str);
		}*/
		ch++;
	}

	//printf("\n");

return 0;
}


int my_payload(const u_char *payload, int len, u_char *args) //returns 1 if string is found, otherwise
{

	int len_rem = len;
	int line_width = 16;			/* number of bytes per line */
	int line_len;
	int offset = 0;					/* zero-based offset counter */
	const u_char *ch = payload;

	if (len <= 0)
		return 0;

	/* data fits on one line */
	if (len <= line_width) {
		if(my_hex_ascii_line(ch, len, offset, args) == 1)
			return 1;
	}

	/* data spans multiple lines */
	for ( ;; ) {
		/* compute current line length */
		line_len = line_width % len_rem;
		/* print line */
		if(my_hex_ascii_line(ch, line_len, offset, args)==1)
			return 1;
		/* compute total remaining */
		len_rem = len_rem - line_len;
		/* shift pointer to remaining bytes to print */
		ch = ch + line_len;
		/* add offset */
		offset = offset + line_width;
		/* check if we have line width chars or less */
		if (len_rem <= line_width) {
			/* print last line and get out */
			if(my_hex_ascii_line(ch, len_rem, offset, args)==1)
				return 1;
			break;
		}
	}

return 0;
}


//



/*
 * print data in rows of 16 bytes: offset   hex   ascii
 *
 * 00000   47 45 54 20 2f 20 48 54  54 50 2f 31 2e 31 0d 0a   GET / HTTP/1.1..
 */
void
print_hex_ascii_line(const u_char *payload, int len, int offset)
{

	int i;
	int gap;
	const u_char *ch;
	char str[3]="\\0";
	//str[0]='\\' ;
	//str[2]='\0';

	/* offset */
	//printf("%05d   ", offset);
	
	/* hex */
	ch = payload;
	for(i = 0; i < len; i++) {
		printf("%02x ", *ch);
		ch++;
		/* print extra space after 8th byte for visual aid */
		if (i == 7)
			printf(" ");
	}
	/* print space to handle line less than 8 bytes */
	if (len < 8)
		printf(" ");
	
	/* fill hex gap with spaces if not full line */
	if (len < 16) {
		gap = 16 - len;
		for (i = 0; i < gap; i++) {
			printf("   ");
		}
	}
	printf("   ");
	
	/* ascii (if printable) */
	ch = payload;
	//if(strstr(payload,args))
/*	if(my_strstr(payload,args,len))
		{
			//printf("%s found in the packet",args);
			return;
		}*/
	for(i = 0; i < len; i++) {
		if (isprint(*ch))
			printf("%c", *ch);
		else
		{
			printf(".");
			//str[1]=*ch;
			//printf("%s",str);
		}
		ch++;
	}

	printf("\n");

return;
}

/*
 * print packet payload data (avoid printing binary data)
 */
void
print_payload(const u_char *payload, int len, u_char *args)
{

	if(args != NULL && my_payload(payload, len,args) == 0)
		return;
	int len_rem = len;
	int line_width = 16;			/* number of bytes per line */
	int line_len;
	int offset = 0;					/* zero-based offset counter */
	const u_char *ch = payload;

	if (len <= 0)
		return;

	/* data fits on one line */
	if (len <= line_width) {
		print_hex_ascii_line(ch, len, offset);
		return;
	}

	/* data spans multiple lines */
	for ( ;; ) {
		/* compute current line length */
		line_len = line_width % len_rem;
		/* print line */
		print_hex_ascii_line(ch, line_len, offset);
		/* compute total remaining */
		len_rem = len_rem - line_len;
		/* shift pointer to remaining bytes to print */
		ch = ch + line_len;
		/* add offset */
		offset = offset + line_width;
		/* check if we have line width chars or less */
		if (len_rem <= line_width) {
			/* print last line and get out */
			print_hex_ascii_line(ch, len_rem, offset);
			break;
		}
	}

return;
}

/*
 * dissect/print packet
 */
void
got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{

	int i=0;
	static int count = 1;                   /* packet counter */
	
	/* declare pointers to packet headers */
	const struct sniff_ethernet *ethernet;  /* The ethernet header [1] */
	const struct sniff_ip *ip;              /* The IP header */
	const struct sniff_tcp *tcp;            /* The TCP header */
	const char *payload;                    /* Packet payload */
	time_t c;

	int size_ip;
	int size_tcp;
	int size_payload;
	char buffer[255];
	struct tm tm;
	printf("\n\n *************************************************************************************************************\n\n");
	printf("\nPacket number: %d\n", count);
	count++;
	//printf("\nPacket elapsed time in seconds: %ld\n", header->ts.tv_sec);
	//printf("\nPacket elapsed time in seconds: %ld\n", header->ts.tv_usec);
	snprintf ( buffer, 255, "%ld",header->ts.tv_sec);
	memset(&tm, 0, sizeof(struct tm));
	strptime(buffer, "%s", &tm);
	strftime(buffer, sizeof(buffer), "%b %d %Y %H:%M", &tm);
	printf("\nTimestamp: ");
	puts(buffer);
	//printf("\n");
//	ctime( header->ts.tv_sec );
	printf("\nPacket length: %d\n", header->len);
	
	/* define ethernet header */
	ethernet = (struct sniff_ethernet*)(packet);
	if(NULL != ethernet)
	{
		printf("\nEthernet type : 0x%x ",ethernet->ether_type);
		printf("\nEthernet source host address :");
		for(i=0;i<ETHER_ADDR_LEN;i++)
		{
			printf("%x",ethernet->ether_shost[i]);
			if(i!=ETHER_ADDR_LEN-1)
				printf(":");
		}
		printf("\nEthernet destination host address :");
		for(i=0;i<ETHER_ADDR_LEN;i++)
		{
			printf("%x",ethernet->ether_dhost[i]);
			if(i!=ETHER_ADDR_LEN-1)
				printf(":");
		}
		printf("\n\n");
	}
	
	/* define/compute ip header offset */
	ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);
	size_ip = IP_HL(ip)*4;
	if (size_ip < 20) {
		printf("   * Invalid IP header length: %u bytes\n", size_ip);
		return;
	}

	/* print source and destination IP addresses */
	printf("Source IP : %s\n", inet_ntoa(ip->ip_src));
	printf("Destination IP: %s\n", inet_ntoa(ip->ip_dst));
	
	/* determine protocol */	
	switch(ip->ip_p) {
		case IPPROTO_TCP:
			printf("Protocol: TCP\n");
			break;
		case IPPROTO_UDP:
			printf("Protocol: UDP\n");
			return;
		case IPPROTO_ICMP:
			printf("Protocol: ICMP\n");
			return;
		case IPPROTO_IP:
			printf("Protocol: IP\n");
			return;
		default:
			printf("Protocol: unknown\n");
			return;
	}
	
	/*
	 *  OK, this packet is TCP.
	 */
	
	/* define/compute tcp header offset */
	tcp = (struct sniff_tcp*)(packet + SIZE_ETHERNET + size_ip);
	size_tcp = TH_OFF(tcp)*4;
	if (size_tcp < 20) {
		printf("   * Invalid TCP header length: %u bytes\n", size_tcp);
		return;
	}
	
	printf("Source port: %d\n", ntohs(tcp->th_sport));
	printf("Destination port: %d\n", ntohs(tcp->th_dport));
	
	/* define/compute tcp payload (segment) offset */
	payload = (u_char *)(packet + SIZE_ETHERNET + size_ip + size_tcp);
	
	/* compute tcp payload (segment) size */
	size_payload = ntohs(ip->ip_len) - (size_ip + size_tcp);
	
	/*
	 * Print payload data; it might be binary, so don't just
	 * treat it as a string.
	 */
	if (size_payload > 0) {
		printf("Payload size : %d bytes\n", size_payload);
		print_payload(payload, size_payload,args);
	}

return;
}

int main(int argc, char **argv)
{

	char *dev = NULL;			/* capture device name */
	char errbuf[PCAP_ERRBUF_SIZE];		/* error buffer */
	pcap_t *handle;				/* packet capture handle */

	char filter_exp[] = "ip";		/* filter expression [3] */
	struct bpf_program fp;			/* compiled filter program (expression) */
	bpf_u_int32 mask;			/* subnet mask */
	bpf_u_int32 net;			/* ip */
	int num_packets = -1;			/* number of packets to capture */

	print_app_banner();


//
int c;
int count =0,index =0;
u_char *filter = NULL, *filename=NULL;
int flag_live_capture=0, flag_offline_parse=0, flag_filter_present=0;
	while ((c = getopt (argc, argv, "hi:r:s:")) != -1)
	switch (c)
	{
		case 'i':
			count++;
			dev = optarg;
			flag_live_capture=1;
			break;
		case 'r':
			count++;
			filename = optarg;
			flag_offline_parse=1;
			break;
		case 's':
			count++;
			filter = optarg;
			flag_filter_present=1;
			break;
		case 'h':
			help(1);
			return 0;
			break;
		case '?':
			if (optopt == 'i')
				fprintf (stderr, "Option -%c requires an argument.\n", optopt);
			else if (optopt == 'r')
				fprintf (stderr, "Option -%c requires an argument.\n", optopt);
			else if (optopt == 's')
				fprintf (stderr, "Option -%c requires an argument.\n", optopt);
			else if (isprint (optopt))
				fprintf (stderr, "Unknown option `-%c'.\n", optopt);
			else
				fprintf (stderr,"Unknown option character `\\x%x'.\n", optopt);
			return 1;
		default:
			help(-1);
			return(0);
			break;
	}
	for (index = optind; index < argc; index++)
	{
		printf ("Non-option argument %s\n", argv[index]);
		//strcpy(args.arg[i++],argv[index]);
		//count++;
	}

if(1 == flag_live_capture && 1 == flag_offline_parse)
{
	printf("\n\n Unexpected arguments entered: You can't capture live traffic and parse offline pcap file at the same time!!\n\n");
	return 0;
}
else if(1 == flag_live_capture && 1 == flag_offline_parse)
{
	printf("\n\n Unexpected arguments entered: Enter either live traffic capture or parse offline pcap file option!!\n\n");
	return 0;
}
//
if(1 == flag_offline_parse)
{
	pcap_t *fp;
    char errbuf[PCAP_ERRBUF_SIZE];
    if ( (fp = pcap_open_offline(filename, errbuf) ) == NULL)
    {
        fprintf(stderr,"\nError opening dump file\n");
        return -1;
    }
    printf("Offline Dump file: %s\n", filename);
	printf("Number of packets: %d\n", num_packets);
	printf("Filter expression: %s\n", filter_exp);
    // read and dispatch packets until EOF is reached
    pcap_loop(fp, num_packets, got_packet, filter);
	/* cleanup */
	pcap_close(fp);
	printf("\nCapture complete.\n");
    return 0;
}
else if(1 == flag_live_capture)
{
	if(NULL == dev)
	{
		dev = pcap_lookupdev(errbuf);
		if (dev == NULL) 
		{
			fprintf(stderr, "Couldn't find default device: %s\n",
			    errbuf);
			exit(EXIT_FAILURE);
		}
	}

}

	
	/* get network number and mask associated with capture device */
	if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
		fprintf(stderr, "Couldn't get netmask for device %s: %s\n",
		    dev, errbuf);
		net = 0;
		mask = 0;
	}

	/* print capture info */
	printf("Device: %s\n", dev);
	printf("Number of packets: %d\n", num_packets);
	printf("Filter expression: %s\n", filter_exp);

	/* open capture device */
	handle = pcap_open_live(dev, SNAP_LEN, 1, 1000, errbuf);
	if (handle == NULL) {
		fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
		exit(EXIT_FAILURE);
	}

	/* make sure we're capturing on an Ethernet device [2] */
	if (pcap_datalink(handle) != DLT_EN10MB) {
		fprintf(stderr, "%s is not an Ethernet\n", dev);
		exit(EXIT_FAILURE);
	}

	/* compile the filter expression */
	if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
		fprintf(stderr, "Couldn't parse filter %s: %s\n",
		    filter_exp, pcap_geterr(handle));
		exit(EXIT_FAILURE);
	}

	/* apply the compiled filter */
	if (pcap_setfilter(handle, &fp) == -1) {
		fprintf(stderr, "Couldn't install filter %s: %s\n",
		    filter_exp, pcap_geterr(handle));
		exit(EXIT_FAILURE);
	}

	/* now we can set our callback function */
	pcap_loop(handle, num_packets, got_packet, filter);

	/* cleanup */
	pcap_freecode(&fp);
	pcap_close(handle);

	printf("\nCapture complete.\n");

return 0;
}
void help(int r)
{
	if(r<0)
		printf("\n The command entered is not proper\n ");
	printf("\n \t\t\t\t\tHelp\n ");
	printf("\n---------------------------------------------------------------------------------------------\n");
	printf("\n\t\tEnter one or more option as under\n\n");
	printf("\n\t\t\tmydump [-h] [-i interface] [-r file] [-s string] expression\n\n");
	printf("\t\t-i  Listen on network device <interface> (e.g., eth0). If not specified,\n");
	printf("\t\t\tmydump selects the default interface to listen on.\n\n");
	printf("\t\t-r  Read packets from <file> (tcpdump format).\n\n");
	printf("\t\t-s  Keep only packets that contain <string> in their payload.\n\n");
	printf("\t\t-h 	help on options\n\n");
	printf("\n---------------------------------------------------------------------------------------------\n");
	return ;
}
int my_strstr(const char* payload,u_char* args,int len)
{
	int i=0,j=0,k=0;
	while(i < len)
	{
		if( payload[i] == args[0])
		{
			j=0;k=i;
			i++;
			while(args[j] != '\0')
			{
				if(payload[k] == args[j])
				{
					k++;j++;
				}
				else
				{
					break;
				}
			}
			if(args[j] == '\0')
				return 1;
		}
		else
		{
			i++;
		}
	}
	return 0;
}
