#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/ether.h>
#include <netinet/tcp.h>

void https_callback(u_char *args, const struct pcap_pkthdr* pkthdr, const u_char*
    packet)
{
    static int https_count = 1;
    fprintf(stdout, "HTTPS%3dHTTPS, ", https_count);
    fflush(stdout);
    https_count++;
}

void http_callback(u_char *args, const struct pcap_pkthdr* pkthdr, const u_char*
    packet)
{
    static int http_count = 1;
    fprintf(stdout, "HTTP%3dHTTP, ", http_count);
    fflush(stdout);
    http_count++;
}

void getPacket(u_char *args, const struct pcap_pkthdr *pkthdr, const u_char *packet){
    struct ip *ip;
    struct tcphdr *tcp;
    ip = (struct ip*)(packet+sizeof(struct ether_header));
    tcp = (struct tcphdr*)(packet+sizeof(struct ether_header)+sizeof(struct ip));

    char* src = inet_ntoa(ip->ip_src);

    printf("%s:%d ",src,tcp->source);
    char* dst = inet_ntoa(ip->ip_dst);
    printf(" %s:%d\n", dst, tcp->dest);

}



int main()
{
    int i;
    char *dev;
    char errbuf[PCAP_ERRBUF_SIZE]; 
    char https_errbuf[PCAP_ERRBUF_SIZE];
    char http_errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* https;
    pcap_t* http;
    const u_char *packet;
    struct pcap_pkthdr hdr;
    struct ether_header *eptr;    /* net/ethernet.h */
    struct bpf_program compiled_https;        /* hold compiled program */
    struct bpf_program compiled_http;
    bpf_u_int32 maskp;            /* subnet mask */
    bpf_u_int32 netp;             /* ip */

/* 
    if(argc != 2){
        fprintf(stdout, "Usage: %s \"expression\"\n"
            ,argv[0]);
        return 0;
    }
*/
    /* Now get a device */
    dev = pcap_lookupdev(errbuf);
     
    if(dev == NULL) {
        fprintf(stderr, "%s\n", errbuf);
        exit(1);
    }
        /* Get the network address and mask */
    pcap_lookupnet(dev, &netp, &maskp, errbuf);
 
    /* open device for reading in promiscuous mode */
    https = pcap_open_live(dev, BUFSIZ, 1,-1, https_errbuf);
    http = pcap_open_live(dev, BUFSIZ, 1,-1, http_errbuf);

    if(https == NULL) {
        printf("pcap_open_live(): %s\n", https_errbuf);
        exit(1);
    }

    if(http == NULL) {
        printf("pcap_open_live(): %s\n", http_errbuf);
        exit(1);
    }
 
    /* Now we'll compile the filter expression*/
    if(pcap_compile(https, &compiled_https, "tcp[tcpflags] & (tcp-syn) != 0 and port 443 and src host 192.168.0.4", 0, netp) == -1) {
        fprintf(stderr, "Error calling pcap_compile\n");
        exit(1);
    }

    if(pcap_compile(http, &compiled_http, "tcp[tcpflags] & (tcp-syn) != 0 and port 80 and src host 192.168.0.4", 0, netp) == -1) {
        fprintf(stderr, "Error calling pcap_compile\n");
        exit(1);
    }
    
 
    /* set the filter */
    if(pcap_setfilter(https, &compiled_https) == -1) {
        fprintf(stderr, "Error setting filter\n");
        exit(1);
    }
    
    if(pcap_setfilter(http, &compiled_http) == -1) {
        fprintf(stderr, "Error setting filter\n");
        exit(1);
    }
    
 
    /* loop for callback function */
    pcap_loop(https, -1, https_callback, NULL);

    pcap_loop(http, -1, http_callback, NULL);

    return 0;
}



/*
  --- TODO LIST ---
  Right now just classify the traffic based on the port no
  Next try to get the domain of the destination, this should be a good project to start with
  Plot a graph of the data collected
  Find a way to store the data efficiently
  The application will be running in the background and collecting the data, create another sample console program to print the stats collected
*/
