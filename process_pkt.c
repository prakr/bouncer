#include "bouncer.h"
#include "checksum_functions.c"

int checkIPHeader(struct sniff_ip* ip);

int checkICMPHeader(struct sniff_ip* ip, struct icmphdr* icmp);

int checkTCPHeader(struct sniff_ip* ip, struct tcphdr* tcp);

void addToMap(struct clientServerMapping* csMap);

struct clientServerMapping* createMapping(struct sockaddr_in cAddr, struct sockaddr_in sAddr,
		u_int16_t setType, u_int16_t icmpIdentifier);

struct clientServerMapping* getMapping(struct sniff_ip* ip, void* ip_Payload);

void handleICMP(struct sniff_ip* ip, struct icmphdr* icmp);

void handleTCP(struct sniff_ip* ip, struct tcphdr* tcp);

void process_pkt(u_char *args, const struct pcap_pkthdr *header, const u_char *p){
	/* Define pointers for packet's attributes */
	struct sniff_ip *ip;	/* The IP header */
	struct icmphdr *icmp;	/* The ICMP header */
	struct tcphdr *tcp;	/* The TCP header */
	/* Set IP header */
	ip = (struct sniff_ip*)(p + SIZE_ETHERNET);
	/* Set IP payload */
	void* ip_Payload = (void*)(p+SIZE_ETHERNET+IP_HL(ip)*4);
	/*check if packet is for the bouncer else drop */
	if(bouncerAddr.sin_addr.s_addr != ip->ip_dst.s_addr){
		return;
	/* Else check if this source IP is not in the mapping, if so add to map */
	}else if((serverAddr.sin_addr.s_addr != ip->ip_src.s_addr) && !getMapping(ip, ip_Payload)){
		struct sockaddr_in* tmpClientAddr;
		tmpClientAddr = malloc(sizeof(struct sockaddr_in));
		tmpClientAddr->sin_family = PF_INET;
		tmpClientAddr->sin_port = 0;
		tmpClientAddr->sin_addr = ip->ip_src;	
                if(ip->ip_p == 1){
			icmp = (struct icmphdr*) ip_Payload;
			addToMap(createMapping(*tmpClientAddr, serverAddr, 1, icmp->un.echo.id));
		}else if(ip->ip_p == 6){
			tcp = (struct tcphdr*) ip_Payload;
			tmpClientAddr->sin_port = tcp->th_sport;
			addToMap(createMapping(*tmpClientAddr, serverAddr, 0, 0));
		}
		free(tmpClientAddr);
	}
	/* Check IP header*/
	if(!checkIPHeader(ip)){
		return;		/* If not a valid IP header, drop the packet. */
	}
	/* Check type of packet and process*/
	if(ip->ip_p == 1){
		icmp = (struct icmphdr*)ip_Payload;
		handleICMP(ip, icmp);
	}else if(ip->ip_p == 6){
		tcp = (struct tcphdr*)ip_Payload;
		handleTCP(ip, tcp);
	}
}

void handleICMP(struct sniff_ip* ip, struct icmphdr* icmp){
	/* Check ICMP header*/
	if(!checkICMPHeader(ip, icmp)){
		return;
	}
	/* Reassemble the IP header with payload and send packet */
	if(ip->ip_src.s_addr == serverAddr.sin_addr.s_addr){
		struct clientServerMapping* csm = getMapping(ip,(void*)icmp);
		ip->ip_src.s_addr = bouncerAddr.sin_addr.s_addr;
		if(csm == NULL){
			return;
		}
		ip->ip_dst.s_addr = csm->clientAddr.sin_addr.s_addr;
		u_int16_t chksum = ip_chksum(ip);
		if(chksum == 0){
			fprintf(stderr, "Couldn't calculate checksum\n");
			return;
		}
		ip->ip_sum = chksum;
		/* Send processed packet */
		if(sendto(socket_fd, (const u_char*)ip, ntohs(ip->ip_len), 0, 
				(struct sockaddr*) &csm->clientAddr, sizeof(csm->clientAddr)) < 0){
			fprintf(stdout, "Server address: %s\n", inet_ntoa(csm->clientAddr.sin_addr));
			fprintf(stderr, "An error: %s\n", strerror(errno));
			return;                   
		}		
	}else{
		ip->ip_src.s_addr = bouncerAddr.sin_addr.s_addr;
		ip->ip_dst.s_addr = serverAddr.sin_addr.s_addr;
		u_int16_t chksum = ip_chksum(ip);
		if(chksum == 0){
			fprintf(stderr, "Couldn't calculate checsum\n");
			return;
		}
		ip->ip_sum = chksum;
		/* Send processed packet */
		if(sendto(socket_fd, (const u_char*)ip, ntohs(ip->ip_len), 0, 
				(struct sockaddr*) &serverAddr, sizeof(serverAddr)) < 0){
			fprintf(stdout, "Server address: %s\n", inet_ntoa(serverAddr.sin_addr));
			fprintf(stderr, "An error: %s\n", strerror(errno));
			return;                   
		}
	}
}

void handleTCP(struct sniff_ip* ip, struct tcphdr* tcp){
	/* Check TCP header*/
	if(!checkTCPHeader(ip, tcp)){
		return;
	}
	/* Reassemble the IP header with payload and send packet */
	if(ip->ip_src.s_addr == serverAddr.sin_addr.s_addr){
		struct clientServerMapping* csm = getMapping(ip,(void*)tcp);
		ip->ip_src.s_addr = bouncerAddr.sin_addr.s_addr;
		if(csm == NULL){
			fprintf(stdout, "FUCK\n");
			return;
		}
		ip->ip_dst.s_addr = csm->clientAddr.sin_addr.s_addr;
		u_int16_t chksum = ip_chksum(ip);
		if(chksum == 0){
			fprintf(stderr, "Couldn't calculate checksum\n");
			return;
		}
		ip->ip_sum = chksum;
		/* Change back port number so the client thinks it is the right port number */
		if(ntohs(tcp->th_sport) == 80){
			tcp->th_sport = htons(8080);
		}else{
			return;
		}
		tcp->th_sum = tcp_chksum(ip, tcp);
		/* Send processed packet */
		if(sendto(socket_fd, (const u_char*)ip, ntohs(ip->ip_len), 0, 
				(struct sockaddr*) &csm->clientAddr, sizeof(csm->clientAddr)) < 0){
			fprintf(stdout, "Server address: %s\n", inet_ntoa(csm->clientAddr.sin_addr));
			fprintf(stderr, "An error: %s\n", strerror(errno));
			return;                   
		}		
	}else{
		ip->ip_src.s_addr = bouncerAddr.sin_addr.s_addr;
		ip->ip_dst.s_addr = serverAddr.sin_addr.s_addr;
		u_int16_t chksum = ip_chksum(ip);
		if(chksum == 0){
			fprintf(stderr, "Couldn't calculate checsum\n");
			return;
		}
		ip->ip_sum = chksum;
		/* Change port number to the server port */
		if(ntohs(tcp->th_dport) == 8080){
			tcp->th_dport = htons(80);
		}else{
			return;
		}
		/* Recalculate TCP checksum since it incorporates parameters from IP layer */
		tcp->th_sum = tcp_chksum(ip, tcp);
		/* Send processed packet */
		if(sendto(socket_fd, (const u_char*)ip, ntohs(ip->ip_len), 0, 
				(struct sockaddr*) &serverAddr, sizeof(serverAddr)) < 0){
			fprintf(stdout, "Server address: %s\n", inet_ntoa(serverAddr.sin_addr));
			fprintf(stderr, "An error: %s\n", strerror(errno));
			return;                   
		}
	}
}

int checkIPHeader(struct sniff_ip* ip){
	/* Check if invalid IP header length */
	if((IP_HL(ip)*4) < 20){
		return false;
	/* Check if invalid IP version */
	}else if(IP_V(ip) != 4){
		return false;
	/* Check if invalid IP ttl */
	}else if(ip->ip_ttl == 0){ 
		return false; 
	/* Check if invalid IP protocol */
	}else if(ip->ip_p != 6 && ip->ip_p != 1){ 
		return false;
	/* Check for IP evil bit */
	}else if(ntohs(ip->ip_off) & 0x8000){
		return false;
	}	
	return true;
}	

int checkICMPHeader(struct sniff_ip* ip, struct icmphdr* icmp){
	/* Temporarily store the icmp checksum */
	u_int16_t icmpcksum = icmp->checksum;
	/* Check if invalid ICMP type  */
	if(icmp->type != 0 && icmp->type != 8){
		return false;
	/* Check if invalid ICMP reply id */
	}else if(icmp->type == 0 && ip->ip_src.s_addr != serverAddr.sin_addr.s_addr){
		return false;
	/* Check if invalid ICMP sub-code  */
	}else if(icmp->code != 0){
		return false;
	/* Check if invalid ICMP checksum */
	}else if(icmpcksum != icmp_chksum(ip, icmp)){
		return false;
	/* Check if invalid ICMP identifier */
	}else if(icmp->un.echo.id == 0){
		return false;
	}
	/* Set back checksum if valid */
	icmp->checksum = icmpcksum;
	return true;
}	

int checkTCPHeader(struct sniff_ip* ip, struct tcphdr* tcp){	
	/* Check if invalid tcp length */
	if(tcp->th_off < 5){
		return false;
	/* Check if invalid tcp checksum */
	}else if(tcp->th_sum != tcp_chksum(ip, tcp)){
		fprintf(stdout, "Checksum invalid\n");
		return false;
	}
	return true;
}

struct clientServerMapping* getMapping(struct sniff_ip* ip, void* ipPayload){
	struct clientServerMapping* csm = &map;
	if(ip->ip_p == 1){
		struct icmphdr* h = (struct icmphdr*)(ipPayload);
		do{
			if(csm->icmpIdentifier == h->un.echo.id){
				return csm;
			}
			csm = csm->next;
		}while(csm != NULL);
	}else if(ip->ip_p == 6){
		struct tcphdr* h = (struct tcphdr*)(ipPayload);
		do{
			if(csm->clientAddr.sin_port == h->th_dport){
				return csm;
			}
			csm = csm->next;
		}while(csm != NULL);
	}
	return NULL;
}

void addToMap(struct clientServerMapping* csMap){
	if(csMap->prev == NULL){
		map = *csMap;
		last = &map;
		return;
	}
	last->next = csMap;
	last = csMap;
}

struct clientServerMapping* createMapping(struct sockaddr_in cAddr, struct sockaddr_in sAddr,
		u_int16_t setType, u_int16_t icmpIdentifier){
	struct clientServerMapping* newMapping;
	newMapping = malloc(sizeof(struct clientServerMapping));
	if(!newMapping){
		fprintf(stderr, "Couldn't allocate memory\n");
		return NULL;
	}
	if(map.clientAddr.sin_addr.s_addr){
		newMapping->prev = last;
	}else{
		newMapping->prev = NULL;
	}
	newMapping->clientAddr = cAddr;
	newMapping->serverAddr = sAddr;
	newMapping->protocolType = setType;
	newMapping->icmpIdentifier = icmpIdentifier;
	newMapping->next = NULL;
	return newMapping;
}
