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
#include <netdb.h>
#include <string.h>

void get_packet(u_char *args, const struct pcap_pkthdr *pkthdr, const u_char *packet){
    struct ip *ip;
    struct tcphdr *tcp;
    int destination_port; 
    ip = (struct ip*)(packet+sizeof(struct ether_header));
    tcp = (struct tcphdr*)(packet+sizeof(struct ether_header)+sizeof(struct ip));

    char* dest = inet_ntoa(ip->ip_dst);
    

    destination_port = ntohs(tcp->dest);

    printf("host: %s ", dest);
    printf("port no: %d ", ntohs(tcp->dest));
    // skip packet size as it may vary for same port and same ip
    printf("Packet size: %d ", pkthdr->len);
    
    //char* src = inet_ntoa(ip->ip_src);


    //destination_port = ntohs(tcp->source);

    //printf("host: %s ", src);
    //printf("port no: %d ", ntohs(tcp->source));
    // skip packet size as it may vary for same port and same ip
    //printf("Packet size: %d ", pkthdr->len);

    //char* ipstr=src;

    struct sockaddr_in sa;    /* input */
    socklen_t len;         /* input */
    char hbuf[NI_MAXHOST];

    memset(&sa, 0, sizeof(struct sockaddr_in));

    /* For IPv4*/
    sa.sin_family = AF_INET;
    sa.sin_addr.s_addr = inet_addr(dest);
    //sa.sin_addr.s_addr = inet_addr(src);
    len = sizeof(struct sockaddr_in);

    if (getnameinfo((struct sockaddr *) &sa, len, hbuf, sizeof(hbuf), 
        NULL, 0, NI_NAMEREQD)) {
        printf("could not resolve hostname\n");
    }
    else {
        printf("hostname= %s\n", hbuf);
    }
}




int main()
{
    int i;
    char *dev;
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* descr;
    const u_char *packet;
    struct pcap_pkthdr hdr;
    struct ether_header *eptr;    /* net/ethernet.h */
    struct bpf_program fp;        /* hold compiled program */
    bpf_u_int32 maskp;            /* subnet mask */
    bpf_u_int32 netp;             /* ip */

    /* Now get a device */
    dev = pcap_lookupdev(errbuf);
     
    if(dev == NULL) {
        fprintf(stderr, "%s\n", errbuf);
        exit(1);
    }

    /* Get the network address and mask */
    pcap_lookupnet(dev, &netp, &maskp, errbuf);
 
    /* open device for reading in promiscuous mode */
    descr = pcap_open_live(dev, BUFSIZ, 1,-1, errbuf);
    if(descr == NULL) {
        printf("pcap_open_live(): %s\n", errbuf);
        exit(1);
    }
 
    /* Now we'll compile the filter expression*/
    if(pcap_compile(descr, &fp, "src host 192.168.0.4", 0, netp) == -1) {
        fprintf(stderr, "Error calling pcap_compile\n");
        exit(1);
    }
 
    /* set the filter */
    if(pcap_setfilter(descr, &fp) == -1) {
        fprintf(stderr, "Error setting filter\n");
        exit(1);
    }
 
    /* loop for callback function */
    pcap_loop(descr, -1, get_packet, NULL);


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
