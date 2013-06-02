/* Global definitions for the port bouncer
 * Packet headers and so on
 */

#define _BSD_SOURCE 1

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

/* PCAP declarations */
#include <pcap.h>

/* Standard networking declaration */
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

/*
 * The following system include files should provide you with the 
 * necessary declarations for Ethernet, IP, and TCP headers
 */

#include <net/if.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/tcp.h>
#include <netinet/in.h>

/* Add any other declarations you may need here... */
void process_pkt(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);

#define true 1
#define false 0

struct sockaddr_in bouncerAddr;
struct sockaddr_in serverAddr;
int socket_fd;


/* Structure to be used as a mapping between client and server, also acts as a linked list? */
struct clientServerMapping{
	struct clientServerMapping* prev;
	struct sockaddr_in clientAddr, serverAddr;
	struct clientServerMapping* next;
	u_int16_t protocolType;
        u_int16_t icmpIdentifier;
};
	
struct clientServerMapping map;
struct clientServerMapping* last;

/* ethernet headers are always exactly 14 bytes [1] */
#define SIZE_ETHERNET 14

/* IP header */
struct sniff_ip {
	u_char ip_vhl;		/* version << 4 | header length >> 2 */
	u_char ip_tos;		/* type of service */
	u_short ip_len;		/* total length */
	u_short ip_id;		/* identification */
	u_short ip_off;		/* fragment offset field */
	#define IP_RF 0x8000		/* reserved fragment flag */
	#define IP_DF 0x4000		/* dont fragment flag */
	#define IP_MF 0x2000		/* more fragments flag */
	#define IP_OFFMASK 0x1fff	/* mask for fragmenting bits */
	u_char ip_ttl;		/* time to live */
	u_char ip_p;		/* protocol */
	u_short ip_sum;		/* checksum */
	struct in_addr ip_src,ip_dst; /* source and dest address */
};
#define IP_HL(ip)		(((ip)->ip_vhl) & 0x0f)
#define IP_V(ip)		(((ip)->ip_vhl) >> 4)

