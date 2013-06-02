struct ph_tcp{
	u_int32_t 	src_addr;
	u_int32_t 	dst_addr;
	u_int8_t	reserved;
	u_int8_t	protocol;
	u_int16_t	tcplen;
};

u_int16_t in_cksum(const void* addr, unsigned len, u_int16_t init){
	u_int32_t sum;
	const u_int16_t* word;

	sum = init;
	word = addr;

	while(len >= 2){
		sum += *(word++);
		len -= 2;
	}

	if(len > 0){
		u_int16_t tmp;
		*(u_int8_t*)(&tmp) = *(u_int8_t*)word;
		sum += tmp;
	}

	sum = (sum >> 16) + (sum & 0xFFFF);
	sum += (sum >> 16);
	return ((u_int16_t)~sum);
}

u_int16_t ip_chksum(struct sniff_ip* ip){
	u_int16_t csum;
	/* Reset ip checksum field */
	ip->ip_sum = 0;
	/* calculate the ip checksum */
	csum = in_cksum((const void*)ip, (unsigned)sizeof(struct sniff_ip), 0);
	return csum;
}

u_int16_t icmp_chksum(struct sniff_ip* ip, struct icmphdr* icmp){
	u_int16_t csum;
	/* calculate ip payload length in host byte order */
	u_int16_t icmp_len = (u_int16_t)(ntohs(ip->ip_len) - (IP_HL(ip)*4));
	/* reset icmp checksum field */
	icmp->checksum = (u_int16_t)0;
	/* Calculate the icmp checksum */
	csum = in_cksum((const void*)icmp, icmp_len, 0);
	return csum;
}

u_int16_t tcp_chksum(struct sniff_ip* ip, struct tcphdr* tcp){
	struct ph_tcp ph;
	u_int16_t csum;
	/* calculate ip payload length in host byte order */
	u_int16_t tcp_len = (u_int16_t)(ntohs(ip->ip_len) - (IP_HL(ip)*4));
	/* reset tcp checksum field */
	tcp->th_sum = (u_int16_t)0;
	/* tcp pseudo header */
	memset(&ph, 0, sizeof(struct ph_tcp));
	ph.src_addr = ip->ip_src.s_addr;
	ph.dst_addr = ip->ip_dst.s_addr;
	ph.reserved = 0;
	ph.protocol = 6;
	ph.tcplen   = htons(tcp_len);
	/* Calculate the checksum for the pseudo header and the data respectively */	
	csum = in_cksum(&ph, (unsigned)sizeof(ph), 0);
	csum = in_cksum((const void*)tcp, tcp_len, (u_int16_t)~csum);
	return csum;
}
