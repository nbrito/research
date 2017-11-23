/* itrace - an ICMP traceroute implementation 
 * 
 * FX <fx@phenoelit.de>
 * Phenoelit (http://www.phenoelit.de)
 *
 * $Id: itrace.c,v 1.9 2001/07/08 14:25:14 fx Exp fx $
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
#include <signal.h>
#include <sys/types.h>
#include <fcntl.h>

#include "protocols.h"
#include "packets.h"

void usage(char *n);

#define IP_ID	0xAFFC

struct {
    int			verbose;
    struct in_addr	dest;
    int			timeout;
    int			maxttl;
    int			reverse;
    int			probes;
    char		*device;
    char		*tdest;
} cfg;

void usage(char *n) {
    fprintf(stderr,
	    "Usage: %s [-vn] [-pX] [-mX] [-tX] -i<dev> -d<destination>\n\n"
	    "-v\tverbose\n"
	    "-n\treverse lookup IPs\n"
	    "-pX\tsend X probes (default=3)\n"
	    "-mX\tmaximum TTL (default=30)\n"
	    "-tX\ttimeout X sec (default=3)\n"
	    "-i<dev>\tuse this device\n"
	    "-d<des>\ttrace to this destination\n"
	    ,n);
}


int main(int argc, char **argv) {
    char		option;
    extern char		*optarg;
    int			sfd,rfd;
    struct sockaddr_in	to,from;
    u_char		*tpacket;
    iphdr_t		*ip;
    icmp_ping_t		*pingh;
    icmphdr_t		*icmp;
    int			psize;
    u_int16_t		cs;
    int			rc,addrsize,allrespond,respond=0,reached=0;
    u_int16_t		TTL;
    unsigned long	start_t;
    struct timespec	sleeper = { 0, 10};
    char		pdata[]="http://www.Phenoelit.de/ - ECHO REQUEST";

    memset(&cfg,0,sizeof(cfg));
    cfg.probes=cfg.timeout=3;
    cfg.maxttl=30;
    while ((option=getopt(argc,argv,"vni:d:t:m:p:"))!=EOF) {
	switch (option) {
	    case 'v': 	/* verbose */
			cfg.verbose++;
			break;
	    case 'd':	/* destination, first as text */
			cfg.tdest=smalloc(strlen(optarg)+1);
			strcpy(cfg.tdest,optarg);
			break;
	    case 't':	if ((cfg.timeout=atoi(optarg))==0) {
			    fprintf(stderr,"%s is an invalid timeout\n",
				    optarg);
			    return (1);
			}
			break;
	    case 'i':	cfg.device=(char *)smalloc(strlen(optarg)+1);
			strcpy(cfg.device,optarg);
			break;
	    case 'm':	if ((cfg.maxttl=atoi(optarg))==0) {
			    fprintf(stderr,"%s is not a valid TTL\n",
				    optarg);
			    return (1);
			}
			break;
	    case 'p':	if ((cfg.probes=atoi(optarg))==0) {
			    fprintf(stderr,"%s is not a valid number of"
				    "probes\n",optarg);
			    return (1);
			}
			break;
	    case 'n':	cfg.reverse=1;
			break;
	    default:	usage(argv[0]);
			return (1);
	}
    }

    /* check device and destination */
    if (!cfg.device) {
	fprintf(stderr,"Sorry, but you have to supply the device with -i\n");
	return (1);
    }
    if (!cfg.tdest) {
	fprintf(stderr,"You should really supply a destination with -d\n");
	return (1);
    } else {
	/* try as a normal IP address */
	if (inet_aton(cfg.tdest,&(cfg.dest))==0) {
	    /* ups, wasn't an IP - maybe a hostname */
	    struct hostent	*hd;
	    if ((hd=gethostbyname(cfg.tdest))==NULL) {
		fprintf(stderr,"Could not resolve destination host\n");
		return (1);
	    } else {
		bcopy(hd->h_addr,(char *)&(cfg.dest),hd->h_length);
		/* memcpy((u_int8_t*)&(cfg.dest),
			(u_int8_t*)&(hd->h_addr_list[0]),IP_ADDR_LEN); */
	    }
	}
    }

    /* itrace begins here */
    if (cfg.verbose) {
	printf("Tracing with ICMP Echos to %s\n",inet_ntoa(cfg.dest));
	printf("Timeout %d, interface %s\n",cfg.timeout,cfg.device);
	printf("Probes %d, maximum TTL %d\n",cfg.probes,cfg.maxttl);
    }

    /* create two sockets: RAW and ICMP. RAW is needed for the modification
     * of the std IP header and ICMP is needed because for some reason I don't
     * understand fully the recvfrom() call does not see nothing on a RAW
     * socket. */
    if ((sfd=init_socket_IP4(cfg.device,0))<0) {
	fprintf(stderr,"could not grab socket\n");
	return (-1);
    }
    if ((rfd=socket(AF_INET,SOCK_RAW,IPPROTO_ICMP))<0) {
	perror("socket(IPPROTO_ICMP)");
	return (-1);
    }
    rc= O_NONBLOCK | fcntl(rfd, F_GETFL);
    fcntl(rfd,F_SETFL,rc);


    psize=sizeof(icmp_ping_t)+sizeof(iphdr_t);
    tpacket=(u_char *)smalloc(sizeof(icmp_ping_t)+sizeof(iphdr_t)+3);
    TTL=1;

    while ((!reached)&&(TTL<=cfg.maxttl)) {
	int		i;
	struct in_addr	last;

	allrespond=0;
	for (i=0;i<cfg.probes;i++) {
	    memset(tpacket,0,psize+3);

	    /* bulid IP packet */
	    ip=(iphdr_t *)tpacket;
	    ip->version=4;
	    ip->ihl=sizeof(iphdr_t)/4;
	    ip->tot_len=htons(psize);
	    ip->protocol=IPPROTO_ICMP;
	    ip->id=htons(TTL);
	    memcpy(&(ip->saddr.s_addr),
		    &(packet_ifconfig.ip.s_addr),IP_ADDR_LEN);
	    memcpy(&(ip->daddr.s_addr),&(cfg.dest),IP_ADDR_LEN);

	    ip->ttl=TTL;

	    /* make ICMP echo request */
	    pingh=(icmp_ping_t *)(tpacket+sizeof(iphdr_t));
	    pingh->icmp.type=ICMP_ECHO;
	    pingh->icmp.code=0;
	    pingh->icmp.checksum=0;
	    pingh->echo.identifier=0xF000;
	    pingh->echo.seq=htons(TTL);
	    memcpy(&(pingh->echo.data),pdata,sizeof(pdata));

	    /* make up checksum */
	    cs=chksum((u_char *)pingh,(psize-sizeof(iphdr_t)));
	    pingh->icmp.checksum=cs;
	    

	    memset(&to,0,sizeof(struct sockaddr_in));
	    to.sin_family=AF_INET;
	    to.sin_port=htons(0);
	    memcpy(&(to.sin_addr),&(ip->daddr),sizeof(to.sin_addr));

	    if (sendto(sfd,tpacket,psize,0,
			(struct sockaddr *) &to,
			sizeof(struct sockaddr_in)) <0) {
		perror("sendto()");
		return(-1);
	    }
	    
	    /* make sure we have no junk in the mem */
	    memset(&from,0,sizeof(struct sockaddr_in));
	    addrsize=sizeof(struct sockaddr_in);
	    start_t=(unsigned long)time(NULL);
	    memset(tpacket,0,psize);

	    respond=0;
	    while (start_t+cfg.timeout>=time(NULL)) {
		if ((rc=recvfrom(rfd,(u_char *)tpacket,psize,0,
			    (struct sockaddr *)&from,
			    &addrsize))>=0) {
		    struct hostent	*hr;
		    char		*name;
		    iphdr_t		*ip2;
		    //icmphdr_t		*icmp2;
		    icmp_ping_t		*p2;

		    ip=(iphdr_t *)tpacket;

		    /* got an ICMP response */
		    icmp=(icmphdr_t *)(tpacket+sizeof(iphdr_t));
		    p2=(icmp_ping_t *)(tpacket+sizeof(iphdr_t));

		    if (icmp->type!=ICMP_ECHOREPLY) {
			/* check whenever it contains the former IP header */
			if (rc>=(2*sizeof(iphdr_t)+sizeof(icmphdr_t)+4)) {
			    ip2=(iphdr_t *)(tpacket+
				    sizeof(iphdr_t)+sizeof(icmphdr_t)+4);
			    /* make sure it was our packet */
			    if (!( 
				(ip2->protocol==IPPROTO_ICMP)
				&&
				(ip2->id==htons(TTL))
				&&
				(!memcmp(&(ip2->saddr.s_addr),
					&(packet_ifconfig.ip.s_addr),
					IP_ADDR_LEN)) 
				&&
				(!memcmp(&(ip2->daddr.s_addr),&(cfg.dest),
					 IP_ADDR_LEN))
				)) {
				if (cfg.verbose>1) {
				    printf("Not in response of probe:\n");
				    printf("\t%s->",inet_ntoa(ip2->saddr));
				    printf("%s\n",inet_ntoa(ip2->daddr));
				}
				continue;
			    }
			} else {
			    if (cfg.verbose) {
				printf("ICMP packet to small to carry"
				    " original IP header\n");
				printf("Should be %d, is %d\n",
				    2*sizeof(iphdr_t)+sizeof(icmphdr_t)+4,
				     rc);
			    }
			}
		    } /* not an echoreply */

		    /* reverse lookup */
		    if ( (cfg.reverse) &&
			    ((hr=gethostbyaddr((char *)&(from.sin_addr),
				    IP_ADDR_LEN,AF_INET))!=NULL)) {
			name=(char *)smalloc(strlen(hr->h_name)+
				strlen(inet_ntoa(from.sin_addr))+4);
			strcpy(name,hr->h_name);
			strcat(name," [");
			strcat(name,inet_ntoa(from.sin_addr));
			strcat(name,"]");
		    } else {
			name=(char *)smalloc(
				strlen(inet_ntoa(from.sin_addr))+4);
			strcat(name,"[");
			strcat(name,inet_ntoa(from.sin_addr));
			strcat(name,"]");
		    }

		    if (icmp->type==ICMP_TIME_EXCEEDED) {
			if ((memcmp(&(last.s_addr),
				    &(ip->saddr.s_addr),IP_ADDR_LEN))
				){
			    memcpy(&(last.s_addr),&(ip->saddr.s_addr),
				    IP_ADDR_LEN);
			} else {
			    break;
			}
			printf("%2d(%d)\t%s\n",TTL,i+1,name);
			allrespond=respond=1;
			break;
		    } else if (icmp->type==ICMP_DEST_UNREACH) {
			if ((icmp->code==ICMP_UNREACH_FIREWALL) ||
			    (icmp->code==ICMP_UNREACH_ADMIN1))
			    printf("%2d(%d)\t%s (firewalled)\n",TTL,i+1,name);
			else 
			    printf("%2d(%d)\t%s (unreachable)\n",TTL,i+1,name);
			allrespond=respond=reached=1;
			break;
		    } else if (icmp->type==ICMP_ECHOREPLY) {
			if ((memcmp(&(last.s_addr),
				    &(ip->saddr.s_addr),IP_ADDR_LEN))
				&&
				(!memcmp(&(p2->echo.data),pdata,sizeof(pdata)))
				&&(p2->echo.identifier==0xF000)
				){
			    memcpy(&(last.s_addr),&(ip->saddr.s_addr),
				    IP_ADDR_LEN);
			} else {
			    break;
			}
			printf("%2d(%d)\t%s (reply)\n",TTL,i+1,name);
			allrespond=respond=reached=1;
			break;
		    }

		    free(name);
		}

		nanosleep(&sleeper,NULL);
	    }
	    if (!respond) {
		if (cfg.verbose) printf("%2d(%d)\tTimeout\n",TTL,i+1);
	    }
	    if (reached||respond) break;
	} /* end of probe for() loop */

	if (!allrespond) 
	    printf("%2d(all)\tTimeout\n",TTL);

	TTL++;
    }

    free(tpacket);
    close(sfd);
    close(rfd);
    return 0;
}


