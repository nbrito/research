/* timestamp - ICMP timestamp requester
 * 
 * FX <fx@phenoelit.de>
 * Phenoelit (http://www.phenoelit.de)
 *
 * $Id: timestamp.c,v 1.1 2001/08/11 17:23:41 fx Exp $
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

struct {
    int			verbose;
    struct in_addr	dest;
    int			timeout;
    char		*tdest;
} cfg;

void usage(char *n) {
    fprintf(stderr,
	    "Usage: %s -d <destination> -t <timeout>\n"
	    ,n);
}


int main(int argc, char **argv) {
    char		option;
    extern char		*optarg;
    int			rfd;
    struct sockaddr_in	to,from;
    u_char		*tpacket;
    iphdr_t		*ip;
    icmphdr_t		*icmp;
    icmp_timestamp_t	*stamp;
    int			psize;
    u_int16_t		cs;
    int			rc,addrsize,respond=0;
    unsigned long	start_t;
    struct timespec	sleeper = { 0, 10};
#define BSIZE	(sizeof(iphdr_t)+sizeof(icmphdr_t)+200)
#define IDENT	0x0FF0

    memset(&cfg,0,sizeof(cfg));
    cfg.timeout=3;
    while ((option=getopt(argc,argv,"vd:t:"))!=EOF) {
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
	    default:	usage(argv[0]);
			return (1);
	}
    }

    /* check destination */
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

    if ((rfd=socket(AF_INET,SOCK_RAW,IPPROTO_ICMP))<0) {
	perror("socket(IPPROTO_ICMP)");
	return (-1);
    }

    /* make the request packet */
    psize=sizeof(icmphdr_t)+sizeof(icmp_timestamp_t);
    tpacket=(u_char *)smalloc(psize+3);

    /* make ICMP mask request */
    icmp=(icmphdr_t *)tpacket;
    icmp->type=ICMP_TIMESTAMP;
    stamp=(icmp_timestamp_t *)(tpacket+sizeof(icmphdr_t));
    stamp->identifier=htons(IDENT);
    /* make up checksum */
    cs=chksum((u_char *)icmp,psize);
    icmp->checksum=cs;

    memset(&to,0,sizeof(struct sockaddr_in));
    to.sin_family=AF_INET;
    to.sin_port=htons(0);
    memcpy(&(to.sin_addr),&(cfg.dest),sizeof(to.sin_addr));

    if (sendto(rfd,tpacket,psize,0,
		(struct sockaddr *) &to,
		sizeof(struct sockaddr_in)) <0) {
	perror("sendto()");
	return(-1);
    }
    
    rc= O_NONBLOCK | fcntl(rfd, F_GETFL);
    fcntl(rfd,F_SETFL,rc);

    /* make sure we have no junk in the mem */
    memset(&from,0,sizeof(struct sockaddr_in));
    addrsize=sizeof(struct sockaddr_in);
    start_t=(unsigned long)time(NULL);
    free(tpacket);
    tpacket=(u_char *)smalloc(BSIZE);
    psize=BSIZE;

    respond=0;
    while (start_t+cfg.timeout>=time(NULL)) {
	if ((rc=recvfrom(rfd,(u_char *)tpacket,psize,0,
		    (struct sockaddr *)&from,
		    &addrsize))>=0) {
	    struct hostent	*hr;
	    char		*name;

	    ip=(iphdr_t *)tpacket;

	    /* got an ICMP response */
	    icmp=(icmphdr_t *)(tpacket+sizeof(iphdr_t));
	    stamp=(icmp_timestamp_t *)(tpacket+sizeof(iphdr_t)+
                sizeof(icmphdr_t));

	    /* reverse lookup */
	    if ( (hr=gethostbyaddr((char *)&(from.sin_addr),
			    IP_ADDR_LEN,AF_INET))!=NULL) {
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


	    if (icmp->type==ICMP_TIMESTAMPREPLY) {
		printf("%s\trecv/trans: %u/%u\n",
			name,
			ntohl(stamp->recvts),
			ntohl(stamp->transts));
		cfg.timeout=0;
		/* printf("%s\t%s\n",
			name,
			ctime((time_t *)&(stamp->recvts))); */
	    }
	}

	nanosleep(&sleeper,NULL);
    }

    free(tpacket);
    close(rfd);
    return 0;
}


