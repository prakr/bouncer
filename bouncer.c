/* Port Bouncer
* To be called as nbouncer local_ip local_port remote_ip remote_port
*/
#include "bouncer.h"
char bouncer_addr[18];
char target_addr[18];
//struct sockaddr_in bouncerAddr;
unsigned short bouncer_port;
unsigned short target_port;

int main(int argc, char *argv[]){
	/* Include here your code to initialize the PCAP capturing process */
	int opt;
	pcap_t* handle;	
	char error_buf[PCAP_ERRBUF_SIZE];
	/*Initialize network map */
	map.clientAddr.sin_addr.s_addr = 0;
	map.serverAddr.sin_addr.s_addr = 0;
	map.next = NULL;
	map.prev = NULL;
	last = &map;	
	/* Get arguments concerning bouncer */
	strcpy(bouncer_addr, argv[2]);
	bouncer_port = (unsigned short) atoi(argv[3]);
	//Initialize socketaddr_in struct
	bouncerAddr.sin_family = PF_INET;
	bouncerAddr.sin_port = htons(bouncer_port);
	bouncerAddr.sin_addr.s_addr = inet_addr(bouncer_addr);
	/* Get arguments concerning test server */
	strcpy(target_addr, argv[4]);
	target_port = (unsigned short) atoi(argv[5]);
	/* Initialize server address struct */
	serverAddr.sin_family = PF_INET;
	serverAddr.sin_port = htons(target_port);
	serverAddr.sin_addr.s_addr = inet_addr(target_addr);
       	printf ("%d %d\r\n", bouncer_port, target_port);
	/* Create pcap handle */	
       	handle = pcap_open_live(argv[1], 1518, 0, -1, error_buf);
   	if(NULL == handle){
		fprintf(stderr, "Error opening the device for sniffing %s \r\n", error_buf);
		return -1;
	}
	/* Initialize raw socket */
	socket_fd = socket(PF_INET, SOCK_RAW, IPPROTO_RAW);
	if(socket_fd < 0){
		fprintf(stderr, "Error in creating RAW socket \r\n");
		return -1;
	}
	//use socket options
	setsockopt(socket_fd, IPPROTO_IP, IP_HDRINCL, &opt, sizeof(int));
	/* Start to capture */
    	pcap_loop(handle, -1, process_pkt, NULL);
	return 0;
}//End of the bouncer
