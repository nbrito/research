/* itrace - a TCP traceroute implementation 
 * 
 * FX <fx@phenoelit.de>
 * Phenoelit (http://www.phenoelit.de)
 *
 * $Id: tctrace.c,v 1.12 2001/07/08 14:25:14 fx Exp fx $
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
#include <time.h>

#include "protocols.h"
#include "packets.h"

void usage(char *n);

struct {
    int			verbose;
    struct in_addr	dest;
    int			timeout;
    int			maxttl;
    int			reverse;
    int			probes;
    int			port;
    int			sport;
    char		*device;
    char		*tdest;
} cfg;

#define SEQ	12345
#define WIN	2048
#define IP_ID	0xAFFE

void usage(char *n) {
    fprintf(stderr,
	    "Usage: %s [-vn] [-pX] [-mX] [-tX] [-DX]"
		" [-SX] -i<dev> -d<destination>\n\n"
	    "-v\tverbose\n"
	    "-n\treverse lookup IPs\n"
	    "-pX\tsend X probes (default=3)\n"
	    "-mX\tmaximum TTL (default=30)\n"
	    "-tX\ttimeout X sec (default=3)\n"
	    "-DX\tdestination port (default=80)\n"
	    "-SX\tsource port (default=1064)\n"
	    "-i<dev>\tuse this device\n"
	    "-d<des>\ttrace to this destination\n"
	    ,n);
}

int main(int argc, char **argv) {
    char		option;
    extern char		*optarg;
    int			sfd,rfd,tcfd;
    struct sockaddr_in	to,from;
    u_char		*tpacket;
    iphdr_t		*ip,*ip2;
    icmphdr_t		*icmp;
    tcphdr_t		*tcp;
    struct pseudohdr	pshdr;
    int			psize;
    int			rc,addrsize,allrespond,respond=0,reached=0;
    u_int16_t		TTL;
    u_int32_t		tseq;
    unsigned long	start_t;
    struct timespec	sleeper = { 0, 10};

    memset(&cfg,0,sizeof(cfg));
    cfg.probes=cfg.timeout=3;
    cfg.maxttl=30;
    cfg.port=80;
    cfg.sport=1064;
    while ((option=getopt(argc,argv,"vni:d:t:m:p:D:S:"))!=EOF) {
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
	    case 'D':	if ((cfg.port=atoi(optarg))==0) {
			    fprintf(stderr,"%s is not a valid port\n"
				    ,optarg);
			    return (1);
			}
			break;
	    case 'S':	if ((cfg.sport=atoi(optarg))==0) {
			    fprintf(stderr,"%s is not a valid port\n"
				    ,optarg);
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
	printf("Tracing with TCP SYNs to %s\n",inet_ntoa(cfg.dest));
	printf("Timeout %d, interface %s\n",cfg.timeout,cfg.device);
    }

    /* create three sockets: RAW,TCP and ICMP. RAW is needed for the 
     * modification of the std IP header and TCP/ICMP are needed because for 
     * some reason I don't understand fully the recvfrom() call does not 
     * see nothing on a RAW socket. */
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
    if ((tcfd=socket(AF_INET,SOCK_RAW,IPPROTO_TCP))<0) {
	perror("socket(IPPROTO_TCP)");
	return (-1);
    }
    rc= O_NONBLOCK | fcntl(tcfd, F_GETFL);
    fcntl(tcfd,F_SETFL,rc);


    TTL=1;
    srand((unsigned int)time(NULL));
    tseq=htonl(1+(long) (65535.0*rand()/(RAND_MAX+1.0)));

    while ((!reached)&&(TTL<=cfg.maxttl)) {
	int		i;
	struct in_addr	last;

	allrespond=0;
	for (i=0;i<cfg.probes;i++) {

	    psize=sizeof(tcphdr_t)+sizeof(iphdr_t);
	    tpacket=(u_char *)smalloc(sizeof(tcphdr_t)+sizeof(iphdr_t)+3);
	    /* bulid IP packet */
	    ip=(iphdr_t *)tpacket;
	    ip->version=4;
	    ip->ihl=sizeof(iphdr_t)/4;
	    ip->tot_len=htons(psize);
	    ip->protocol=IPPROTO_TCP;
	    ip->id=htons(TTL);
	    memcpy(&(ip->saddr.s_addr),
		    &(packet_ifconfig.ip.s_addr),IP_ADDR_LEN);
	    memcpy(&(ip->daddr.s_addr),&(cfg.dest),IP_ADDR_LEN);

	    ip->ttl=TTL;

	    /* make TCP syn packet */
	    tcp=(tcphdr_t *)(tpacket+sizeof(iphdr_t));
	    tcp->th_sport=htons(cfg.sport);
	    tcp->th_dport=htons(cfg.port);
	    tcp->th_seq=tseq;
	    tcp->th_ack=htonl(0);
	    tcp->th_flags=TH_SYN;
	    tcp->th_off=sizeof(tcphdr_t)/4;
	    tcp->th_win=htons(WIN);

	    /* make up checksum */
	    memset(&pshdr,0,sizeof(struct pseudohdr));
	    memcpy(&(pshdr.saddr.s_addr),
		    &(packet_ifconfig.ip.s_addr),IP_ADDR_LEN);
	    memcpy(&(pshdr.daddr.s_addr),&(cfg.dest),IP_ADDR_LEN);
	    pshdr.protocol=IPPROTO_TCP;
	    pshdr.length=htons(sizeof(tcphdr_t));
	    bcopy((char *)tcp,(char *)&pshdr.tcpheader,sizeof(tcphdr_t));
	    tcp->th_sum=chksum((u_char *) &pshdr,
		    sizeof(tcphdr_t)+sizeof(iphdr_t)-8);

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
	    free(tpacket);
	    memset(&from,0,sizeof(struct sockaddr_in));
	    addrsize=sizeof(struct sockaddr_in);
	    start_t=(unsigned long)time(NULL);
	    psize=2*sizeof(iphdr_t)+sizeof(icmphdr_t)+30;
	    tpacket=(u_char *)smalloc(psize+3);

	    respond=0;
	    while (start_t+cfg.timeout>=time(NULL)) {
		if ((rc=recvfrom(rfd,(u_char *)tpacket,psize,0,
			    (struct sockaddr *)&from,
			    &addrsize))>=0) {
		    struct hostent	*hr;
		    char		*name;
		    tcphdr_t		*tcp2;

		    ip=(iphdr_t *)tpacket;

		    /* got an ICMP response */
		    icmp=(icmphdr_t *)(tpacket+sizeof(iphdr_t));

		    /* check whenever it contains the former IP header */
		    if (rc>=(2*sizeof(iphdr_t)+sizeof(icmphdr_t)+4)) {
			ip2=(iphdr_t *)(tpacket+
				sizeof(iphdr_t)+sizeof(icmphdr_t)+4);
			tcp2=(tcphdr_t *)(tpacket+
				2*sizeof(iphdr_t)+sizeof(icmphdr_t)+4);

			/* make sure it was our packet */
			if (!( 
			    (ip2->protocol==IPPROTO_TCP)
			    &&
			    (ip2->id==htons(TTL))
			    &&
			    (!memcmp(&(ip2->saddr.s_addr),
				    &(packet_ifconfig.ip.s_addr),IP_ADDR_LEN)) 
			    &&
			    (!memcmp(&(ip2->daddr.s_addr),&(cfg.dest),
				     IP_ADDR_LEN))
			    &&
			    (tcp2->th_dport==htons(cfg.port))
			    &&
			    (tcp2->th_sport==htons(cfg.sport))
			    &&
			    (tcp2->th_seq==tseq)
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
			if (memcmp(&(last.s_addr),
				    &(ip->saddr.s_addr),IP_ADDR_LEN)) {
			    memcpy(&(last.s_addr),&(ip->saddr.s_addr),
				    IP_ADDR_LEN);
			} else {
			    break;
			    //continue;
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
		    } 

		    free(name);
		}

		memset(tpacket,0,psize);
		if ((rc=recvfrom(tcfd,(u_char *)tpacket,psize,0,
			    (struct sockaddr *)&from,
			    &addrsize))>=sizeof(tcphdr_t)+sizeof(iphdr_t)) {
		    struct hostent	*hr;
		    char		*name;

		    if (rc<sizeof(tcphdr_t)+sizeof(iphdr_t)) {
			printf("FUCK: %d %d\n",rc,
				sizeof(tcphdr_t)+sizeof(iphdr_t));
			printf("wouldn't make an TCp packet\n");
			continue;
		    }
		    ip=(iphdr_t *)tpacket;
		    tcp=(tcphdr_t *)(tpacket+sizeof(iphdr_t));
		    /* we may receive a lot on a TCP socket, so make sure
		     * the answer is from the recipient 
		     * 
		     * the destination test looks stupid, but how do we know
		     * if someone set the interface to promiscuous mode ?*/
		    if (
			    (!memcmp(&(ip->saddr),&(cfg.dest),IP_ADDR_LEN)) 
			    &&
			    (!memcmp(&(from.sin_addr.s_addr),
				     &(cfg.dest),IP_ADDR_LEN)) 
			    &&
			    (!memcmp(&(ip->daddr),
				    &(packet_ifconfig.ip.s_addr),IP_ADDR_LEN))
			    &&
			    (ip->protocol==IPPROTO_TCP)
			    ){

			if (
				( (ntohl(tcp->th_ack)!=ntohl(tseq)+1)
				  &&(ntohl(tcp->th_ack)!=ntohl(tseq)) )
				||
				(tcp->th_dport!=htons(cfg.sport))
				||
				(tcp->th_sport!=htons(cfg.port))
				){
			    /* SEQ+1 not in ACK - not a response to our probe*/
			    // printf("PS."); fflush(stdout);
			    continue;
			}

			if (memcmp(&(last.s_addr),
				    &(ip->saddr.s_addr),IP_ADDR_LEN)) {
			    memcpy(&(last.s_addr),
				    &(ip->saddr.s_addr),IP_ADDR_LEN);
			} else {
			    break;
			    /* not a response to our probe*/
			    // continue;
			}


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

			if (tcp->th_flags & TH_RST) {
			    printf("%2d(%d)\t%s (reached; closed)\n",
				    TTL,i+1,name);
			    allrespond=respond=reached=1;
			    break;
			} else if ( 
				(tcp->th_flags & TH_SYN) &&
				(tcp->th_flags & TH_ACK) ) {
			    printf("%2d(%d)\t%s (reached; open)\n",
				    TTL,i+1,name);
			    allrespond=respond=reached=1;
			    break;
			} else {
			    printf("%2d(%d)\t%s (reached) -- Strange Flags!\n",
				    TTL,i+1,name);
			    allrespond=respond=reached=1;
			    break;
			}

			free(name);
		    }
		} /* end of tcp */

		nanosleep(&sleeper,NULL);
	    }
	    if (!respond) {
		if (cfg.verbose) printf("%2d(%d)\tTimeout\n",TTL,i+1);
	    }
	    if (reached||respond) break;

	    free(tpacket);
	} /* end of probe for() loop */
	if (!allrespond) 
	    printf("%d(all)\tTimeout\n",TTL);

	TTL++;
    }

    close(sfd);
    close(rfd);
    close(tcfd);
    return 0;
}


