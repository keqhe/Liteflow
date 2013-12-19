/* Simple Raw Sniffer                                                    */ 
/* Author: Luis Martin Garcia. luis.martingarcia [.at.] gmail [d0t] com  */
/* To compile: gcc simplesniffer.c -o simplesniffer -lpcap               */ 
/* Run as root!                                                          */ 
/*                                                                       */
/* This code is distributed under the GPL License. For more info check:  */
/* http://www.gnu.org/copyleft/gpl.html                                  */

#include <pcap.h> 
#include <string.h> 
#include <stdlib.h> 

#define MAXBYTES2CAPTURE 2048 


/* processPacket(): Callback function called by pcap_loop() everytime a packet */
/* arrives to the network card. This function prints the captured raw data in  */
/* hexadecimal.                                                                */
void processPacket(u_char *arg, const struct pcap_pkthdr* pkthdr, const u_char * packet){ 

 int i=0, *counter = (int *)arg; 

 printf("Packet Count: %d\n", ++(*counter)); 
 printf("Received Packet Size: %d\n", pkthdr->len); 
 printf("Payload:\n"); 
 for (i=0; i<pkthdr->len; i++){ 

    if ( isprint(packet[i]) ) /* If it is a printable character, print it */
        printf("%c ", packet[i]); 
    else 
        printf(". "); 
    
     if( (i%16 == 0 && i!=0) || i==pkthdr->len-1 ) 
        printf("\n"); 
  } 
 return; 
} 



/* main(): Main function. Opens network interface and calls pcap_loop() */
int main(int argc, char *argv[] ){ 
    
 int i=0, count=0; 
 pcap_t *descr = NULL; 
 char errbuf[PCAP_ERRBUF_SIZE], *device=NULL; 
 memset(errbuf,0,PCAP_ERRBUF_SIZE); 

 struct bpf_program fp; //the complied filter
 char filter_exp[] = "ip or arp or icmp";//filter expression
 bpf_u_int32 mask; //Our net mask
 bpf_u_int32 net; //our IP

 if( argc > 1){  /* If user supplied interface name, use it. */
    device = argv[1];
 }
 else{  /* Get the name of the first device suitable for capture */ 
    if (pcap_lookupnet(device, &net, &mask, errbuf) == -1) {
                 fprintf(stderr, "Can't get netmask for device %s\n", device);
                 net = 0;
                 mask = 0;
        }

    if ( (device = pcap_lookupdev(errbuf)) == NULL){
        fprintf(stderr, "ERROR: %s\n", errbuf);
        exit(1);
    }
 }

 printf("Opening device %s\n", device); 
 
 /* Open device in promiscuous mode */ 
 if ( (descr = pcap_open_live(device, MAXBYTES2CAPTURE, 1,  512, errbuf)) == NULL){
    fprintf(stderr, "ERROR: %s\n", errbuf);
    exit(1);
 }
 
 /* Compile and apply the filter */
        if (pcap_compile(descr, &fp, filter_exp, 0, net) == -1) {
                fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(descr));
                return(1);
        }
        if (pcap_setfilter(descr, &fp) == -1) {
                fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(descr));
                return(1);
        }
 
 /* Loop forever & call processPacket() for every received packet*/ 
 if ( pcap_loop(descr, -1, processPacket, (u_char *)&count) == -1){
    fprintf(stderr, "ERROR: %s\n", pcap_geterr(descr) );
    exit(1);
 }

return 0; 

} 

/* EOF*/
