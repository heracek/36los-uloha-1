#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <pcap.h>
#include <err.h>
#include <string.h>
#include <time.h>
#define SIZE_ETHERNET 14

int packet_counter = 0; 

/* 4 bytes IP address */
typedef struct ip_address{
    u_char byte1;
    u_char byte2;
    u_char byte3;
    u_char byte4;
}ip_address;

/* 6 bytes MAC address */
typedef struct mac_address{
    u_char byte1;
    u_char byte2;
    u_char byte3;
    u_char byte4;
    u_char byte5;
    u_char byte6;
}mac_address;

/* TCP control bits */
typedef struct control_bits{
	unsigned URG : 1; 
	unsigned ACK : 1; 
	unsigned PSH : 1; 
	unsigned RST : 1; 
	unsigned SYN : 1; 
	unsigned FIN : 1; 
	unsigned TMP : 2; 
}control_bits;

/* Ether header */
typedef struct eth_header{
    mac_address  saddr;     // Source address
    mac_address  daddr;     // Destination address
    u_short typlen;       	// Type / Length
}eth_header;


/* IPv4 header */
typedef struct ip_header{
    u_char  ver_ihl;        // Version (4 bits) + Internet header length (4 bits)
    u_char  tos;            // Type of service 
    u_short tlen;           // Total length 
    u_short identification; // Identification
    u_short flags_fo;       // Flags (3 bits) + Fragment offset (13 bits)
    u_char  ttl;            // Time to live
    u_char  proto;          // Protocol
    u_short crc;            // Header checksum
    ip_address  saddr;      // Source address
    ip_address  daddr;      // Destination address
    u_int   op_pad;         // Option + Padding
}ip_header;

/* UDP header*/
typedef struct udp_header{
    u_short sport;          // Source port
    u_short dport;          // Destination port
    u_short len;            // Datagram length
    u_short crc;            // Checksum
}udp_header;

/* TCP header*/
typedef struct tcp_header{
    u_short sport;          // Source port
    u_short dport;          // Destination port
    u_long  seqnum;         // Sequence Number
    u_long  acknum;         // Acknowledgment Number
	char data_offset; 		// Data Offset
	control_bits ControlBits; // Control Bits
    u_short window; 	    // Window
    u_short crc;            // Checksum
    u_short urg_pointer;    // Urgent Pointer
}tcp_header;



/* prototype of the packet handler */
void packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data);
void IPpacket_handler(const struct ip_header *IPh, const struct pcap_pkthdr *header, const u_char *pkt_data);
void TCPpacket_handler(const struct ip_header *IPh, const struct tcp_header *TCPh, const struct pcap_pkthdr *header, const u_char *pkt_data);
void FTPpacket_handler(const struct ip_header *IPh, const struct tcp_header *TCPh, const struct pcap_pkthdr *header, const u_char *pkt_data);

int main(int argc, char *argv[])
{
    pcap_t *in = NULL;
    char errbuf[PCAP_ERRBUF_SIZE + 1];
    if (1 != argc) { fprintf(stderr, "usage: %s IP IP \n",argv[0]); exit(1); }
    in = pcap_open_offline("-", errbuf);
    if (NULL == in) { fprintf(stderr, "stdin: %s", errbuf);	exit(1); }
    pcap_loop(in, 0, packet_handler, NULL);
    exit(0);
}


void packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data) {
    eth_header *ETHh;
	ETHh = (eth_header *) (pkt_data); 
    if( ETHh->typlen == 8 ) IPpacket_handler( (ip_header *) (pkt_data + SIZE_ETHERNET), header, pkt_data); 
}


void IPpacket_handler(const struct ip_header *IPh, const struct pcap_pkthdr *header, const u_char *pkt_data) {
    u_int ip_len;

    ip_len = (IPh->ver_ihl & 0xf) * 4;
	TCPpacket_handler( IPh, (tcp_header *) ((u_char*)IPh + ip_len), header, pkt_data); 
}

void TCPpacket_handler(const struct ip_header *IPh, const struct tcp_header *TCPh, const struct pcap_pkthdr *header, const u_char *pkt_data) {
    u_int tcp_len;
    u_short sport,dport;
    int i;

    tcp_len = TCPh->data_offset*4;
    
    sport = ntohs( TCPh->sport );
    dport = ntohs( TCPh->dport );
    
    if( ( dport == 21 || sport == 21 ) ) FTPpacket_handler(IPh, TCPh, header, pkt_data); 

}


void FTPpacket_handler(const struct ip_header *IPh, const struct tcp_header *TCPh, const struct pcap_pkthdr *header, const u_char *pkt_data)
{
    u_int tcp_len,ip_len;
    u_short sport,dport;
    int i;

    ip_len = (IPh->ver_ihl & 0xf) * 4;
    tcp_len = TCPh->data_offset*4;
    sport = ntohs( TCPh->sport );
    dport = ntohs( TCPh->dport );

	printf("%d. packet (type: ",packet_counter++);
	if(TCPh->ControlBits.SYN == 1 && TCPh->ControlBits.ACK == 1) printf("SYNC - ACK");
    else if(TCPh->ControlBits.SYN == 1) printf("SYNC");
    else if(TCPh->ControlBits.ACK == 1) printf("ACK");
    else printf("don't care ;)");
    printf(")\n");
    /* print ip addresses and udp ports */
    printf("\t\tsource: %d.%d.%d.%d:%d\n\t\tdestination: %d.%d.%d.%d:%d\n",
    		IPh->saddr.byte1,IPh->saddr.byte2,IPh->saddr.byte3,IPh->saddr.byte4,sport,
    		IPh->daddr.byte1,IPh->daddr.byte2,IPh->daddr.byte3,IPh->daddr.byte4,dport);
    printf("\t\tSYNC#: %d\n\t\tACK#: %d\n",TCPh->seqnum,TCPh->acknum);
    printf("\t\tData: ");
      /* Print the packet */
    for (i=(SIZE_ETHERNET + ip_len + tcp_len ); (i < header->caplen + 1) ; i++) printf("%c", pkt_data[i-1]);
    printf("\n");
}