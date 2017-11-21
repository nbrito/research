/* IRDP Responder
 *
 * FX <fx@phenoelit.de>
 * Phenoelit (http://www.phenoelit.de)
 * (c) 2k
 *
 * $Id: irdpresponder.c,v 1.5 2001/06/17 19:43:48 fx Exp $
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

#include <netinet/in.h>                 /* for IPPROTO_bla consts */
#include <netpacket/packet.h>
#include <net/ethernet.h>               /* to get my own ETH addr */
#include <net/if.h>

#include <pcap.h>
#include <net/bpf.h>

#include "protocols.h"
#include "packets.h"


/* definitions */
#define IP_ADDR_LEN	4
#define IP_IRDP_TTL	0x80
#define IP_BCAST	"255.255.255.255"

#define DEFAULT_LIFETIME	1800
#define CAPLENGTH		1514
#define ADVERTTIME		10

#define BANNER		"IRDP Responder $Revision: 1.5 $\n"\
			"\t(c) 2k FX <fx@phenoelit.de>\n"\
			"\tPhenoelit (http://www.phenoelit.de)\n"

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
pcap_t			*cap;
int			stop_flag=0;

/************************************
 * prototypes */
void	usage(char *n);
u_char	*construct_irdp_advertisement_d(int *psize,struct in_addr *dest);
int	initialize_pcap(void);
void	signaler(int sig);
void	evaluate_packet(u_char *frame, int frame_length);


/* the main function */
int	main(int argc, char **argv) {
    char		option;
    extern char		*optarg;
    int			plength;
    unsigned long int	t1=0;

    u_char              *pcap_data, *ppacket;
    struct pcap_pkthdr  *pcap_head,phead;


    memset(&cfg,0,sizeof(cfg));
    cfg.lifetime=DEFAULT_LIFETIME;
    cfg.pref=1;
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

    printf(BANNER);

    /* init PCAP */
    if (initialize_pcap()==(-1)) return (1);

    /* get mem for pcap's header structure */
    pcap_head=(struct pcap_pkthdr *)smalloc(sizeof(struct pcap_pkthdr));

    /* signal handling */
    signal(SIGTERM,&signaler);
    signal(SIGABRT,&signaler);
    signal(SIGINT,&signaler);

    while (!stop_flag) {
	if ((pcap_data=(u_char *)pcap_next(cap,pcap_head))!=NULL) {
	    /* make a local copy of the data */
	    memcpy(&phead,pcap_head,sizeof(struct pcap_pkthdr));
	    ppacket=(u_char *)smalloc(phead.caplen);
	    memcpy(ppacket,pcap_data,phead.caplen);
	    evaluate_packet(ppacket,phead.caplen);
	    free(ppacket);
	}
	if ((t1+ADVERTTIME)<(unsigned long)time(NULL)) {
	    t1=(unsigned long)time(NULL);
	    if (cfg.verbose) 
		printf("sending intervall update to %s\n",inet_ntoa(cfg.dest));
	    rawpacket=construct_irdp_advertisement_d(&plength,&(cfg.dest));
	    sendpack_IP4(atsock,rawpacket,plength);
	    free(rawpacket);
	}
    }

    /* at the end of the day, close our socket */
    close(atsock);

    return (0);
}



/********************** FUNCTIONS **********************/
void	evaluate_packet(u_char *frame,int frame_length) {
    struct ether_header		*eth;
    iphdr_t			*ip;
    irdp_solicitation_t		*irdph;
    int				plength;

    if (cfg.verbose>2) printf("... Packet ...\n");

    eth=(struct ether_header *)frame;
    if (ntohs(eth->ether_type)==ETHERTYPE_IP) {

	if (cfg.verbose>2) printf("\tIP\n");
	ip=(iphdr_t *)(frame+sizeof(struct ether_header));

	/* if it is from myself, igore it */
	if (!memcmp(&(ip->saddr),
		    &(packet_ifconfig.ip.s_addr),IP_ADDR_LEN)) return;
	if (cfg.verbose>2) printf("\tnot me\n");
	/* if it is from the spoofed self, igore it */
	if (!memcmp(&(ip->saddr),&(cfg.src),IP_ADDR_LEN)) return;

	/* if we are limmited to one host, check it */
	/*if (cfg.set_dest) {
	    if (memcmp(&(ip->saddr),&(cfg.dest),IP_ADDR_LEN)) return;
	} */

	if (ip->protocol==IPPROTO_ICMP) {
	    /* it's an ICMP */
	    if (cfg.verbose>2) printf("\ticmp\n");
	    irdph=(irdp_solicitation_t *)(frame+sizeof(struct ether_header)+
		    sizeof(iphdr_t));
	    if (irdph->type==ICMP_SOLICITATION) {
		/* it's actually a solicitation */
		if (cfg.verbose>2) printf("\tIRDP request\n");

		if (cfg.verbose) 
		    printf("sending response to %s\n",inet_ntoa(ip->saddr));

		/* create the packet */
		rawpacket=construct_irdp_advertisement_d(&plength,&(ip->saddr));
		sendpack_IP4(atsock,rawpacket,plength);
		free(rawpacket);
	    } 
	}
    } /* not IP */ 

    return;
}



void	signaler(int sig) {
    stop_flag++;
    if (cfg.verbose>2)
	fprintf(stderr,"\nSignal received.\n");
    pcap_close(cap);
}


int	initialize_pcap(void) {
    char                pcap_err[PCAP_ERRBUF_SIZE]; /* buffer for pcap errors */
    struct bpf_program  cfilter;                   /* the compiled filter */
    bpf_u_int32		network,netmask;

    /* get my network and netmask */
    if (pcap_lookupnet(cfg.device,&network,&netmask,pcap_err)!=0) {
	fprintf(stderr,"pcap_lookupnet(): %s\n",pcap_err);
	return (-1);
    }

    /* open the sniffer */
    if ((cap=pcap_open_live(cfg.device,CAPLENGTH,
		    1, /* in promi mode */
		    0, /* not timeouts */
		    pcap_err))==NULL) {
	fprintf(stderr,"pcap_open_live(): %s\n",pcap_err);
	return (-1);
    }

    if (pcap_datalink(cap)!=DLT_EN10MB) {
	fprintf(stderr,"works on Ethernet only, sorry.\n");
	return (-1);
    }

    if (pcap_compile(cap,&cfilter,NULL,0,netmask)!=0) {
	pcap_perror(cap,"pcap_compile()");
	return (-1);
    }

    if (pcap_setfilter(cap,&cfilter)!=0) {
	pcap_perror(cap,"pcap_setfilter()");
	return (-1);
    }
    
    return 0;
}

/* constructs the IRDP request packet
 * * Returns a pointer to the packet or NULL if failed
 * * returns also the size in *psize */
u_char	*construct_irdp_advertisement_d(int *psize,struct in_addr *dest) {
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
    memcpy(&(iph->daddr.s_addr),&(dest->s_addr),IP_ADDR_LEN);

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
	    "%s [-v[v[v]]] -i <interface>\n\t"
	    "[-S <spoofed source IP>] [-D <destination ip>]\n\t"
	    "[-l <lifetime in sec, default: 1800>] [-p <preference>]\n",
	    n);
    exit (1);
}
