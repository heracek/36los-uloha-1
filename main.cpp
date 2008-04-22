#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <pcap.h>
#include <err.h>
#include <string.h>
#include <time.h>
#define SIZE_ETHERNET 14

int packet_counter = 0; 

/* 6 bytes MAC address */
typedef struct mac_address{
    u_char byte1;
    u_char byte2;
    u_char byte3;
    u_char byte4;
    u_char byte5;
    u_char byte6;
}mac_address;

/* Ether header */
typedef struct eth_header{
    mac_address  saddr;     // Source address
    mac_address  daddr;     // Destination address
    u_short typlen;       	// Type / Length
}eth_header;

/* 4 bytes IP address */
typedef struct ip_address{
    u_char byte1;
    u_char byte2;
    u_char byte3;
    u_char byte4;
}ip_address;

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

/* TCP control bits */
typedef unsigned char control_bits;
enum control_bits_flags { CWR = 128, ECE = 64, URG = 32, ACK = 16, PSH = 8, RST = 4, SYN = 2, FIN = 1 };
control_bits control_bits_flags_array[] = { CWR, ECE, URG, ACK, PSH, RST, SYN, FIN };
char* control_bits_flags_names[] = { "CWR", "ECE", "URG", "ACK", "PSH", "RST", "SYN", "FIN" };

/* TCP header*/
typedef struct tcp_header {
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

typedef enum tcp_states {
    CLOSED,
    LISTEN,
    SYN_RECEIVED,
    SYN_SENT,
    ESTABLISHED,
    FIN_WAIT_1,
    FIN_WAIT_2,
    CLOSING,
    TIME_WAIT,
    CLOSE_WAIT,
    LAST_ACK
} tcp_states;

typedef struct computer_info {
    ip_address ip;
    u_short port;
    tcp_states tcp_state;
} computer_info;

/* global variables */
computer_info server;
computer_info client;
FILE* OUT_DATA;
FILE* OUT_INFO;

/* prototype of the packet handler */
void textIP2structIP(char *text_ip, ip_address *struct_ip);
int are_ip_addresses_eql(const ip_address *ip_address_1, const ip_address *ip_address_2);
int global_communication_filter_ok(const struct ip_header *IPh, const struct tcp_header *TCPh);
void print_tcp_control_bits(const control_bits *pbits);
void packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data);
void IPpacket_handler(const struct ip_header *IPh, const struct pcap_pkthdr *header, const u_char *pkt_data);
void TCPpacket_handler(const struct ip_header *IPh, const struct tcp_header *TCPh, const struct pcap_pkthdr *header, const u_char *pkt_data);
void FTPpacket_handler(const struct ip_header *IPh, const struct tcp_header *TCPh, const struct pcap_pkthdr *header, const u_char *pkt_data);

int main(int argc, char *argv[])
{
    pcap_t *in = NULL;
    char errbuf[PCAP_ERRBUF_SIZE + 1];
    if (6 != argc) {
        fprintf(stderr, "usage: %s soubor.vstup server_ip server_port client_ip client_port \n",argv[0]);
        exit(1);
    }
    
    in = pcap_open_offline(argv[1], errbuf);
    if (NULL == in) {
        fprintf(stderr, "stdin: %s", errbuf);
        exit(1);
    }
    
    OUT_INFO = fopen("out.info", "w");
    OUT_DATA = fopen("out.data", "w");
    
    textIP2structIP(argv[2], &(server.ip));
    sscanf(argv[3], "%d", &server.port);
    fprintf(OUT_INFO, "address 1: %d.%d.%d.%d:%d\n", server.ip.byte1, server.ip.byte2, server.ip.byte3, server.ip.byte4, server.port);
    printf(argv[4]);
    textIP2structIP(argv[4], &(client.ip));
    sscanf(argv[5], "%d", &client.port);
    fprintf(OUT_INFO, "address 2: %d.%d.%d.%d:%d\n\n", client.ip.byte1, client.ip.byte2, client.ip.byte3, client.ip.byte4, client.port);
    
    pcap_loop(in, 0, packet_handler, NULL);
    
    fclose(OUT_DATA);
    fclose(OUT_INFO);
    
    printf("\n\nall ok\n");
    
    exit(0);
}

void textIP2structIP(char *text_ip, ip_address *struct_ip) {
    unsigned int ip_addr_segments[4]; // scanf requires int
    sscanf(text_ip, "%d.%d.%d.%d", ip_addr_segments, ip_addr_segments + 1, ip_addr_segments + 2, ip_addr_segments + 3);
    
    struct_ip->byte1 = ip_addr_segments[0];
    struct_ip->byte2 = ip_addr_segments[1];
    struct_ip->byte3 = ip_addr_segments[2];
    struct_ip->byte4 = ip_addr_segments[3];
}

/**
 * Returns 1 if (ip_address_1 == ip_address_2). Else returns 0.
 */
int are_ip_addresses_eql(const ip_address *ip_address_1, const ip_address *ip_address_2) {
    if (ip_address_1->byte1 == ip_address_2->byte1 &&
        ip_address_1->byte2 == ip_address_2->byte2 &&
        ip_address_1->byte3 == ip_address_2->byte3 &&
        ip_address_1->byte4 == ip_address_2->byte4
    ) {
        return 1;
    }
    return 0;
}

/**
 * Returns 1 if communication is betwen server and clietn. Else reutrns 0.
 */
int global_communication_filter_ok(const struct ip_header *IPh, const struct tcp_header *TCPh) {
    u_short sport = ntohs( TCPh->sport );
    u_short dport = ntohs( TCPh->dport );
    
    /* src is server - dest is clietn */
    if (are_ip_addresses_eql(&(IPh->saddr), &server.ip) && are_ip_addresses_eql(&(IPh->daddr), &client.ip) &&
        sport == server.port && dport == client.port) {
        return 1;
    }
    
    if (are_ip_addresses_eql(&(IPh->saddr), &client.ip) && are_ip_addresses_eql(&(IPh->daddr), &server.ip) &&
        sport == client.port && dport == server.port) {
        return 1;
    }
    
    return 0;
}

void separator(int *print_separator) {
    if (*print_separator) {
        fprintf(OUT_INFO, ", ");
    } else {
        *print_separator = 1; // print it next time  
    }
}

void print_tcp_control_bits(const control_bits *pbits) {
    int i;
    control_bits bits = *pbits;
    int print_separator = 0;
    
    for (i = 0; i < 8 ; i++) {
        if (bits & control_bits_flags_array[i]) {
            separator(&print_separator);
            fprintf(OUT_INFO, control_bits_flags_names[i]);
        }
    }
    
    //fprintf(OUT_INFO, " 0x%02hhx", *pbits);
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
    tcp_len = TCPh->data_offset*4;
    
    sport = ntohs( TCPh->sport );
    dport = ntohs( TCPh->dport );
    
    if (global_communication_filter_ok(IPh, TCPh)) {
        FTPpacket_handler(IPh, TCPh, header, pkt_data); 
    }
}

void FTPpacket_handler(const struct ip_header *IPh, const struct tcp_header *TCPh, const struct pcap_pkthdr *header, const u_char *pkt_data)
{
    u_int tcp_len,ip_len;
    u_short sport,dport;
    int i;

    ip_len = (IPh->ver_ihl & 0xf) * 4;
    tcp_len = TCPh->data_offset * 4;
    sport = ntohs( TCPh->sport );
    dport = ntohs( TCPh->dport );
    
    fprintf(OUT_INFO, "%d. packet %d > %d [", packet_counter++, sport, dport);
    print_tcp_control_bits(&(TCPh->ControlBits));
    
    fprintf(OUT_INFO, "]\n");
    fprintf(OUT_INFO, "\t\tSYNC#: %lu\n\t\tACK#: %lu\n\t\tWindow: %u\n",
        ntohl(TCPh->seqnum),
        ntohl(TCPh->acknum),
        ntohs(TCPh->window)
    );
    fprintf(OUT_INFO, "\t\tData: ");
      /* Print the packet */
    for (i=(SIZE_ETHERNET + ip_len + tcp_len ); (i < header->caplen + 1) ; i++)
        fprintf(OUT_INFO, "%c", pkt_data[i-1]);
    fprintf(OUT_INFO, "\n");
}