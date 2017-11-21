/* ASS
 * Autonomous System Scanner
 * - IGRP
 *
 * FX <fx@phenoelit.de>
 * Phenoelit (http://www.phenoelit.de)
 * (c) 2k
 *
 * $Id: ass_v1.c,v 1.20 2001/07/08 13:14:16 fx Exp $
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
#include <signal.h>

#include "protocols.h"
#include "packets.h"
#include "build.h"

/* we need a sniffer enigine here */
#include <pcap.h>
#include <net/bpf.h>

/* definitions */
#define IPTTL		0x80
#define RIP_PORT	520
#define HSRP_PORT	1985
#define EIGRP_HELLO_TIME	12

#define IP_BCAST	"255.255.255.255"
#define CAPLENGTH	1542
#define DEST_LENGTH	15

#define BANNER		"ASS [Autonomous System Scanner] $Revision: 1.20 $\n"\
			"\t(c) 2k++ FX <fx@phenoelit.de>\n"\
			"\tPhenoelit (http://www.phenoelit.de)\n"

#define FCHAR_IGRP		'I'
#define FCHAR_EIGRP		'E'
#define FCHAR_EIGRP_RT		'e'
#define FCHAR_IRDP		'R'
#define FCHAR_CDP		'C'
#define FCHAR_RIPv1		'1'
#define FCHAR_RIPv2		'2'
#define FCHAR_HSRP		'H'
#define FCHAR_OSPF		'O'
#define FCHAR_ACTIVE_ALL	"IER12"

/* new result management 
 * ... types */
typedef struct {
    struct in_addr	dest;
    unsigned int	as;
    unsigned long	delay;
    unsigned long	bandw;
    unsigned int	mtu;
    unsigned int	reliability;
    unsigned int	load;
    unsigned int	hopcount;
    void		*next;			// next record
} RES_route_igrp_t;

typedef struct {
    unsigned long	as;
    unsigned short	ios_major;
    unsigned short	ios_minor;
    unsigned short	eigrp_major;
    unsigned short	eigrp_minor;
    void 		*next;
} RES_route_eigrp_t;

typedef struct {
    unsigned long	as;
    unsigned int	type;	/* external or internal */
    struct in_addr	nexthop;
    /* external */
    struct in_addr	origrouter;
    unsigned long	origas;
    unsigned long	externalmetric;
    unsigned short	externallink;
    /* general */
    unsigned long 	delay;
    unsigned long	bandwidth;
    unsigned long	mtu;
    unsigned short	hopcount;
    unsigned short 	reliability;
    unsigned short	load;
    struct in_addr	netmask;
    struct in_addr	dest;
    void		*next;
} RES_route_eigrprt_t;

typedef struct {
    struct in_addr	dest;
    unsigned long	preference;
    void		*next;
} RES_route_irdp_t;

typedef struct {
    struct in_addr	dest;
    unsigned long	metric;
    void		*next;
} RES_route_ripv1_t;

#define RIP2AUTH_NONE	0
#define RIP2AUTH_TEXT	2
#define RIP2AUTH_MD5	3
typedef struct {
    struct in_addr	dest;
    struct in_addr	mask;
    struct in_addr	nexthop;
    unsigned int	routetag;
    unsigned long	metric;
    void		*next;
} RES_route_ripv2_t;

typedef struct {
    struct in_addr	virtip;
    char		auth[9];
    struct ether_addr	vmac;
    unsigned short	version;
    unsigned short	state;
    unsigned short 	hello;
    unsigned short	hold;
    unsigned short	group;
    unsigned short	prio;
    void		*next;
} RES_route_hsrp_t;

typedef struct {
    /* from header */
    struct in_addr	source;
    struct in_addr	area;
    int			authtype;
    char		authdata[9];
    /* from hello */
    struct in_addr	netmask;
    struct in_addr	designated;
    struct in_addr	backup;
    unsigned long	dead;
    unsigned short	prio;
    unsigned int	hello;
    void		*next;
} RES_route_ospf_t;

#define CAP_IGRP	0x001
#define CAP_IRDP	0x002
#define CAP_EIGRP	0x004
#define CAP_RIPv1	0x008
#define CAP_CDP		0x010
#define CAP_HSRP	0x020
#define CAP_RIPv2	0x040
#define CAP_OSPF	0x080
#define CAP_RIPv2auth	0x100
#define CAP_EIGRP_RT	0x200

typedef struct {
    struct in_addr	addr;
    unsigned int	capa;
    RES_route_igrp_t	*igrp;
    RES_route_irdp_t	*irdp;
    RES_route_ripv1_t	*rip1;
    RES_route_ripv2_t	*rip2;
    unsigned short	rip2auth_type;
    char		rip2pw[17];
    RES_route_eigrp_t	*eigrp;
    RES_route_eigrprt_t	*eigrpr;
    RES_route_hsrp_t	*hsrp;
    RES_route_ospf_t	*ospf;
    void		*next;		// next record
} result_t;


/* config */
struct {
    int			verbose;
    char		*device;

    u_int16_t		as_start,as_stop;
    int			eigrpmc;

    int			spoof_src;
    struct in_addr	src;
    int			set_dest;
    struct in_addr	dest;

    int			prom;
    int			cont;
    int			passive;
    unsigned long	sdelay;
    char		*active_protos;
} cfg;

/************************************
 * globals */
u_char			*rawpacket;
int			atsock;
pcap_t			*cap;

int			stop_flag=0;

result_t		*anchor;


/************************************
 * prototypes */
void	usage(char *n);

/* IGRP construction */
u_char	*construct_igrp_request(u_int16_t autosys, int *psize);
/* EIGRP construction */
u_char	*construct_eigrp_request(struct in_addr *dd, 
	u_int32_t autosys, int *psize);
/* IRDP construction */
u_char	*construct_irdp_request(int *psize);
/* RIP construction */
u_char	*construct_rip_request(int *psize);
u_char	*construct_rip2_request(int *psize);

/* PCAP */
int     initialize_pcap(void);
void	signaler(int sig);
void	evaluate_packet(u_char *frame,int frame_length);
void 	net_listen(void);

/* result management */
int	add_route(int rtype,struct in_addr *addr,unsigned int as,void *data);
void	print_results(void);
void	clean_results(void);


/* the main function */
int	main(int argc, char **argv) {
    char		option;
    extern char		*optarg;

    unsigned long	tm1;
    int			i;
    /* scanner packet */
    int			plength;
    /* finding former findings */
    result_t		*c;
    RES_route_eigrp_t	*ceigrp;


    memset(&cfg,0,sizeof(cfg));
    cfg.passive=cfg.prom=1;
    while ((option=getopt(argc,argv,"vcpAMi:a:b:S:D:T:P:"))!=EOF) {
	switch (option) {
	    case 'v':	/* verbose */
			cfg.verbose++;
			break;
	    case 'i':	/* local network device */
			cfg.device=smalloc(strlen(optarg)+1);
			strcpy(cfg.device,optarg);
			break;
	    case 'a':	/* autonomous system start*/
			cfg.as_start=atoi(optarg);
			break;
	    case 'b':	/* autonomous system stop */
			cfg.as_stop=atoi(optarg);
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
	    case 'p':	/* promiscous mode */
			cfg.prom=0;
			break;
	    case 'c':	/* don't continue capture */
			cfg.cont++;
			break;
	    case 'T':	/* delay between each packet */
			cfg.sdelay=atol(optarg);
			break;
	    case 'A':	/* not passive */
			cfg.passive=0;
			break;
	    case 'M':	/* EIGRP mutlicast scan */
			cfg.eigrpmc++;
			break;
	    case 'P':	/* selection of protocols */
			cfg.active_protos=smalloc(strlen(optarg)+1);
			strcpy(cfg.active_protos,optarg);
			break;
	    default:	usage(argv[0]);
	}
    }

    if (!cfg.device) usage(argv[0]);
    if (!cfg.set_dest)
	inet_aton(IP_BCAST,&(cfg.dest));

    if (cfg.as_stop==0) 
	cfg.as_stop=65535;
    if (cfg.as_start>cfg.as_stop) {
	fprintf(stderr,"Start has to be smaller then stop ...\n");
	return (1);
    }
    if (cfg.passive) cfg.cont=0;
    if (cfg.active_protos==NULL) {
	cfg.active_protos=smalloc(strlen(FCHAR_ACTIVE_ALL)+1);
	strcpy(cfg.active_protos,FCHAR_ACTIVE_ALL);
    }


    /* set up socket ... */
    if ((atsock=init_socket_IP4(cfg.device,1))==(-1)) return(1);
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

    if (!cfg.passive) {

	printf("Scanning\n"); fflush(stdout);

	/* scan for IRDP */
	if (strchr(cfg.active_protos,FCHAR_IRDP)!=NULL) {
	    if (cfg.verbose) printf("+ scanning IRDP ...\n");
	    rawpacket=construct_irdp_request(&plength);
	    sendpack_IP4(atsock,rawpacket,plength);
	    tm1=(unsigned long)time(NULL);
	    while ((!stop_flag)&&(tm1+1>(unsigned long)time(NULL))) 
		net_listen();
	    sendpack_IP4(atsock,rawpacket,plength);
	    free(rawpacket);
	}

	/* scan for RIPv1 */
	if (strchr(cfg.active_protos,FCHAR_RIPv1)!=NULL) {
	    if (cfg.verbose) printf("+ scanning RIPv1 ...\n");
	    rawpacket=construct_rip_request(&plength);
	    sendpack_IP4(atsock,rawpacket,plength);
	    tm1=(unsigned long)time(NULL);
	    while ((!stop_flag)&&(tm1+1>(unsigned long)time(NULL))) 
		net_listen();
	    sendpack_IP4(atsock,rawpacket,plength);
	    free(rawpacket);
	}

	/* scan for RIPv2 */
	if (strchr(cfg.active_protos,FCHAR_RIPv2)!=NULL) {
	    if (cfg.verbose) printf("+ scanning RIPv2 ...\n");
	    rawpacket=construct_rip2_request(&plength);
	    sendpack_IP4(atsock,rawpacket,plength);
	    tm1=(unsigned long)time(NULL);
	    while ((!stop_flag)&&(tm1+1>(unsigned long)time(NULL))) 
		net_listen();
	    sendpack_IP4(atsock,rawpacket,plength);
	    free(rawpacket);
	}

	/* scan IGRP */
	if (strchr(cfg.active_protos,FCHAR_IGRP)!=NULL) {
	    if (cfg.verbose) printf("+ scanning IGRP ...\n");
	    for (i=cfg.as_start;i<=cfg.as_stop;i++) {

		if (cfg.verbose>2) {
		    printf("Scanning %s - AS# %d\n",
			    inet_ntoa(cfg.dest),i);
		}
		
		/* send packet */
		rawpacket=construct_igrp_request(i,&plength);
		sendpack_IP4(atsock,rawpacket,plength);
		free(rawpacket);
		
		net_listen();

		//if (cfg.sdelay) usleep(cfg.sdelay);
		if ((cfg.sdelay)&&((i%cfg.sdelay)==0)) 
		    usleep(10000);
		if (stop_flag) break;
	    }
	}

	/* scan for EIGRP */
	/* IF the destination is set, scan for AS information on this 
	 * router like in IGRP.
	 * IF no destination is set, wait some time for EIGRP HELLOS and 
	 * then scan for their data 
	 */
	if (strchr(cfg.active_protos,FCHAR_EIGRP)!=NULL) {
	    if ((cfg.set_dest)||(cfg.eigrpmc)) {
		struct in_addr	eigrpd;

		if (cfg.set_dest)
		    memcpy(&eigrpd,&(cfg.dest),sizeof(struct in_addr));
		else 
		    inet_aton("224.0.0.10",&eigrpd);

		if (cfg.verbose) printf("+ scanning EIGRP ...\n");
		for (i=cfg.as_start;i<=cfg.as_stop;i++) {

		    if (cfg.verbose>2) {
			printf("Scanning %s - AS# %d\n",
				inet_ntoa(eigrpd),i);
		    }
		    
		    /* send packet */
		    rawpacket=construct_eigrp_request(&eigrpd,
			    (unsigned long)i,&plength);
		    sendpack_IP4(atsock,rawpacket,plength);
		    free(rawpacket);
		    
		    net_listen();

		    //if (cfg.sdelay) usleep(cfg.sdelay);
		    if ((cfg.sdelay)&&((i%cfg.sdelay)==0)) 
			usleep(10000);
		    if (stop_flag) break;
		}
	    } /*end if directed scan */else {
		if (cfg.verbose) 
		    printf("+ wainting for EIGRP HELLOs (%us) ...\n",
			    EIGRP_HELLO_TIME);

		tm1=(unsigned long)time(NULL);
		while ((!stop_flag)&&(tm1+EIGRP_HELLO_TIME>
			    (unsigned long)time(NULL))) 
		    net_listen();

		c=anchor;
		while (c!=NULL) {
		    ceigrp=c->eigrp;
		    while (ceigrp!=NULL) {
			if (cfg.verbose) 
			    printf("++ scanning EIGRP AS %lu on %s\n",
				    ceigrp->as,inet_ntoa(c->addr));

			rawpacket=construct_eigrp_request(
				&(c->addr),ceigrp->as,&plength);
			sendpack_IP4(atsock,rawpacket,plength);
			free(rawpacket);

			tm1=(unsigned long)time(NULL);
			while ((!stop_flag)&&(tm1+1>(unsigned long)time(NULL))) 
			    net_listen();

			ceigrp=ceigrp->next;
		    }
		    c=c->next;
		} /* end of temporary result loop */
	    } /* end if EIGRP scan with no destination */
	} /* end of EIGRP selected scan */

    } /* end of active mode */ else {
	printf("passive listen ... (hit Ctrl-C to finish)\n"); fflush(stdout);
    }

    if (!cfg.cont) {
	/* ... continue capture, may be there are still responses */
	if (!cfg.passive)
	    printf("\nContinuing capture ... (hit Ctrl-C to finish)\n");
	while (!stop_flag) net_listen();
    } else {
	printf("\n");
    }

    /* at the end of the day, close our socket */
    pcap_close(cap);
    close(atsock);

    print_results();
    clean_results();

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
    igrp_t			*igrp;
    igrp_system_entry_t		*isys;
    icmphdr_t			*icmph;
    irdp_t			*irdph;
    irdp_rec_t			*irdpr;
    udphdr_t			*udp;
    ripv1hdr_t			*rip1;
    ripv1addr_t			*raddr;
    ripv2addr_t			*raddr2; /* size is equal to v1 ... anyway */
    eigrp_t			*eigrp;
    eigrpsoft_t			*eigrps;
    eigrpintroute_t		*eigrpr;
    hsrp_t			*hsrp;
    ospf_header_t		*ospfh;

    /* for CDP */
    struct eth_LLC		*eth_llc;
    u_char			*cdpt;
    struct cdp_address_entry	*cdpa;
    
    int				i;
    

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

	/* IGRP  ??? */
	if (ip->protocol==IPPROTO_IGRP) {

	    /* size check */
	    if ((sizeof(struct ether_header)+sizeof(iphdr_t)+sizeof(igrp_t))
		    >frame_length) return;
	    if (cfg.verbose>2) printf("\tigrp\n");
	    igrp=(igrp_t *)(frame+sizeof(struct ether_header)+
		    sizeof(iphdr_t));

	    if (cfg.verbose>1) { printf("%c",FCHAR_IGRP); fflush(stdout); }

	    /* if this wasn't an update, just add the router */
	    if (igrp->opcode!=IGRP_OPCODE_UPDATE) {
		add_route(CAP_IGRP,&(ip->saddr),
			ntohs(igrp->autosys),NULL); 

	    } else {

		/* now, check for routes in the update */
		if (cfg.verbose>2) 
		    printf("\t%d exterior routes in update"
			    " (experimental)\n"
			    "\t%d interior routes in update"
			    " (experimental)\n"
			    "\t%d system routes in update\n",
			    ntohs(igrp->exterior),
			    ntohs(igrp->interior),
			    ntohs(igrp->system));


		for (i=0;i<ntohs(igrp->system);i++) {

		    if (
			    (sizeof(struct ether_header)+
			    sizeof(iphdr_t)+
			    sizeof(igrp_t)+
			    (i+1*sizeof(igrp_system_entry_t)))
			    >frame_length) {
			fprintf(stderr,"WARNING: IGRP packet says it contains"
				" %d system routes but ends after %d\n",
				igrp->system,i);
			return ;
		    }
		    isys=(igrp_system_entry_t *)(frame+
			    sizeof(struct ether_header)+
			    sizeof(iphdr_t)+
			    sizeof(igrp_t)+
			    (i*sizeof(igrp_system_entry_t)));

		    add_route(CAP_IGRP,&(ip->saddr),
			    ntohs(igrp->autosys),isys); 
		} 
	    } /* end of UPDATE */

	    /* end of IGRP */
	} else if (ip->protocol==IPPROTO_ICMP) {
	    /* it's an ICMP */
	    if (cfg.verbose>2) printf("\ticmp\n");
	    icmph=(icmphdr_t *)(frame+sizeof(struct ether_header)+
		    sizeof(iphdr_t));
	    if (icmph->type==ICMP_ROUTER_ADVERT) {
		/* it's actually a router advertisement */
		if (cfg.verbose>2) printf("\tIRDP\n");
		if (cfg.verbose>1) { printf("%c",FCHAR_IRDP); fflush(stdout); }

		if ( (sizeof(struct ether_header)+sizeof(iphdr_t)+
			    sizeof(icmphdr_t)+sizeof(irdp_t))
			>frame_length) return;
		irdph=(irdp_t *)(frame+sizeof(struct ether_header)+
			sizeof(iphdr_t)+sizeof(icmphdr_t));

		for (i=0;i<(irdph->num_addr);i++) {
		    if ( (sizeof(struct ether_header)
			    +sizeof(iphdr_t)
			    +sizeof(icmphdr_t)
			    +sizeof(irdp_t)
			    +(i+1*sizeof(irdp_rec_t)))
			    >frame_length) {
			fprintf(stderr,"WARNING: IRDP packet says it contains"
				" %d routes but ends after %d\n",
				irdph->num_addr,i);
			return ;
		    }
		    irdpr=(irdp_rec_t *)(frame
			    +sizeof(struct ether_header)
			    +sizeof(iphdr_t)
			    +sizeof(icmphdr_t)
			    +sizeof(irdp_t)
			    +(i*sizeof(irdp_rec_t)));

		    add_route(CAP_IRDP,&(ip->saddr),
			    0,irdpr); 
		} /* end of for */
	    } /* end of ICMP IRDP */
	} /* end if IPPROTO_ICMP */
	else if (ip->protocol==IPPROTO_UDP) {
	    if (cfg.verbose>2) printf("\tudp\n");
	    udp=(udphdr_t *)(frame+sizeof(struct ether_header)+
		    sizeof(iphdr_t));
	    if (ntohs(udp->dport)==RIP_PORT) {
		if ((sizeof(struct ether_header)+sizeof(iphdr_t)+
			sizeof(udphdr_t)+sizeof(ripv1hdr_t))>frame_length) 
		    return;
		/* RIP ! */
		rip1=(ripv1hdr_t *)(frame+sizeof(struct ether_header)+
			sizeof(iphdr_t)+sizeof(udphdr_t));
		if (rip1->version==1) {
		    if (cfg.verbose>2) printf("\tRIPv1\n");
		    if (cfg.verbose>1) { 
			printf("%c",FCHAR_RIPv1); 
			fflush(stdout);
		    }

		    i=1;
		    while ( 
			    (sizeof(struct ether_header)
			    +sizeof(iphdr_t)
			    +sizeof(udphdr_t)
			    +sizeof(ripv1hdr_t)
			    +i*sizeof(ripv1addr_t))<=frame_length) {

			raddr=(ripv1addr_t *)
			    (frame+sizeof(iphdr_t)+sizeof(udphdr_t)+
			     sizeof(struct ether_header)+sizeof(ripv1hdr_t)+
			     (i-1)*sizeof(ripv1addr_t));
			if (ntohs(raddr->addrfamily)==2) {
			    add_route(CAP_RIPv1,&(ip->saddr),0,raddr); 
			} else {
			    if (cfg.verbose) 
				printf("RIPv1 addr not IP.\n");
			}
			i++;
		    }
		} /* end RIPv1 */
		else if (rip1->version==2) {
		    if (cfg.verbose>2) printf("\tRIPv2\n");
		    if (cfg.verbose>1) { 
			printf("%c",FCHAR_RIPv2); 
			fflush(stdout);
		    }

		    i=1;
		    while ( 
				(sizeof(struct ether_header)
				+sizeof(iphdr_t)
				+sizeof(udphdr_t)
				+sizeof(ripv2hdr_t)
				+i*sizeof(ripv2addr_t))<=frame_length) {

			raddr2=(ripv2addr_t *)
			    (frame+sizeof(iphdr_t)+sizeof(udphdr_t)+
			     sizeof(struct ether_header)+sizeof(ripv2hdr_t)+
			     (i-1)*sizeof(ripv2addr_t));
			if (ntohs(raddr2->addrfamily)==2) {
			    add_route(CAP_RIPv2,&(ip->saddr),0,raddr2); 
			} else if (ntohs(raddr2->addrfamily)==0xFFFF) {
			    add_route(CAP_RIPv2auth,&(ip->saddr),0,raddr2); 
			} else {
			    if (cfg.verbose) 
				printf("RIPv2 addr not IP or auth.\n");
			}
			i++;
		    }
		} /* end RIPv2 */
		else 
		    fprintf(stderr,"The program seems to be stoneage:"
			    " RIP version %u ???\n",rip1->version);
	    } /* end of RIP (UDP port)*/
	    else if (ntohs(udp->dport)==HSRP_PORT) {
		if ((sizeof(struct ether_header)+sizeof(iphdr_t)+
			sizeof(udphdr_t)+sizeof(hsrp_t))>frame_length) 
		    return;
		hsrp=(hsrp_t *)(frame+sizeof(struct ether_header)+
			sizeof(iphdr_t)+sizeof(udphdr_t));
		if (cfg.verbose>2) printf("\tHSRP\n");
		if (cfg.verbose>1) { printf("%c",FCHAR_HSRP); fflush(stdout);}
		if (hsrp->opcode==HSRP_OPCODE_HELLO) 
		    /* only HELLOs are supported */
		    add_route(CAP_HSRP,&(ip->saddr),0,hsrp); 
	    } /* end of HSRP port */
	} /* enf of UDP */
	else if (ip->protocol==IPPROTO_EIGRP) {
	    if (cfg.verbose>2) printf("\teigrp\n");
	    if (cfg.verbose>1) { printf("%c",FCHAR_EIGRP); fflush(stdout);}
	    eigrp=(eigrp_t *)(frame+sizeof(struct ether_header)
		    +sizeof(iphdr_t));
	    if (eigrp->opcode==EIGRP_HELLO) {
		int	f=0;
		i=0;
		while ( 
			(sizeof(struct ether_header)
			+sizeof(iphdr_t)
			+sizeof(eigrp_t)
			+i
			+sizeof(eigrpsoft_t))<=frame_length) {
		    /* as long as there could be still a software
		     * section in there ... */
		    eigrps=(eigrpsoft_t *)(frame+sizeof(struct ether_header)
			    +sizeof(iphdr_t) 
			    +sizeof(eigrp_t) 
			    +i);
		    i+=ntohs(eigrps->length);
		    if (ntohs(eigrps->type)==EIGRP_TYPE_SOFT) {
			add_route(CAP_EIGRP,&(ip->saddr),
				ntohl(eigrp->as),eigrps); 
			f++;
			break;
		    }
		} /* end of loop through eigrp */
		if (!f) 
		    /* if there was no software info in EIGRP HELLO, add it */
		    add_route(CAP_EIGRP,&(ip->saddr),
			    ntohl(eigrp->as),NULL); 
	    } /* end of HELLO */ else if (eigrp->opcode==EIGRP_UPDATE) {
		i=0;
		while ( 
			(sizeof(struct ether_header)
			+sizeof(iphdr_t)
			+sizeof(eigrp_t)
			+i
			+sizeof(eigrpintroute_t))<=frame_length) {
		    /* as long as there could be one more 
		     * internal route in there ... */
		    eigrpr=(eigrpintroute_t *)(frame+sizeof(struct ether_header)
			    +sizeof(iphdr_t) 
			    +sizeof(eigrp_t) 
			    +i);
		    i+=ntohs(eigrpr->length);
		    if ((ntohs(eigrpr->type)==EIGRP_TYPE_IN_ROUTE) 
			    ||(ntohs(eigrpr->type)==EIGRP_TYPE_EX_ROUTE)) {
			if (cfg.verbose>1) { 
			    printf("%c",FCHAR_EIGRP_RT); fflush(stdout);
			}
			add_route(CAP_EIGRP_RT,&(ip->saddr),
				ntohl(eigrp->as),eigrpr); 
		    }
		} /* end of loop through eigrp */
	    } /* end of UPDATE */
	} /* end of EIGRP */
	else if (ip->protocol==IPPROTO_OSPF) {
	    if (cfg.verbose>2) printf("\tOSPF\n");
	    if (cfg.verbose>1) { printf("%c",FCHAR_OSPF); fflush(stdout);}

	    if ((sizeof(struct ether_header)+sizeof(iphdr_t)+
			sizeof(ospf_header_t)+sizeof(ospf_hello_t))
		    >frame_length) {
		add_route(CAP_OSPF,&(ip->saddr),0,NULL);
	    } else {
		/* there is enough stuff in it to be OSPF hello */
		ospfh=(ospf_header_t *)(frame+sizeof(struct ether_header)
			+sizeof(iphdr_t));
		if ((ospfh->version!=2)||(ospfh->type!=OSPF_HELLO))
		    add_route(CAP_OSPF,&(ip->saddr),0,NULL);
		else 
		    /* version 2 supported, it's Hello and long enough */
		    add_route(CAP_OSPF,&(ip->saddr),0,ospfh);
	    }
	} /* end of OSPF */
    } /* not IP */ 

    /* maybe it's CDP, this could help */

    eth_llc=(struct eth_LLC *)(frame
	    +sizeof(struct eth_ieee802_3));
    if (
	    (ntohs(eth_llc->proto)==0x2000)&&
	    (eth_llc->orgcode[0]==0x00)&&
	    (eth_llc->orgcode[1]==0x00)&&
	    (eth_llc->orgcode[2]==0x0c)) {
	/* could be CDP */

	if (cfg.verbose>1) { printf("%c",FCHAR_CDP); fflush(stdout); } 
	else if (cfg.verbose>2) printf("CDP packet ...\n");

	cdpt=(u_char *)(frame
		+sizeof(struct eth_ieee802_3)
		+sizeof(struct eth_LLC)
		+sizeof(struct cdphdr));

	do {
	    if (ntohs(*((u_int16_t *)cdpt))==TYPE_ADDRESS) {
		if (cfg.verbose>2) 
		    printf("Number of addr's in it: %d\n",
			ntohl(*((u_int32_t *)(cdpt+2*sizeof(u_int16_t)))));

		cdpa=(struct cdp_address_entry *)(cdpt+
			2*sizeof(u_int16_t)+sizeof(u_int32_t));
		if (cdpa->proto!=0xCC) {
		    if (cfg.verbose) printf("CDP not speaking IP at"
			    "%02x:%02x:%02x:%02x:%02x:%02x\n",
			    *((u_char*)frame+6)&0xFF,
			    *((u_char*)frame+7)&0xFF,
			    *((u_char*)frame+8)&0xFF,
			    *((u_char*)frame+9)&0xFF,
			    *((u_char*)frame+10)&0xFF,
			    *((u_char*)frame+11)&0xFF);
		} else {
		    struct in_addr caa;

		    memcpy(&(caa.s_addr),&(cdpa->addr),IP_ADDR_LEN);
		    add_route(CAP_CDP,&caa,0,NULL); 
		}
	    }
	    cdpt+=htons(
		    *((u_int16_t *)((u_char*)cdpt+sizeof(u_int16_t)))
		    );

	} while (
		((u_char*)cdpt-(u_char*)frame)
		+htons(
		    *((u_int16_t *)((u_char*)cdpt+sizeof(u_int16_t)))
		    )
		<frame_length);
	/* means: loop as long through the CDP sections until the pointer
	 * would reach outside the packet */
    }
    return;
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
		    cfg.prom, /* in promi mode */
		    0, /* no timeouts sometimes don't work ...*/
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


/* constructs the IGRP request packet
 * * Returns a pointer to the packet or NULL if failed
 * * returns also the size in *psize */
u_char	*construct_igrp_request(u_int16_t autosys, int *psize) {
#define PADDING_SIZE	14
    u_char			*tpacket;
    iphdr_t			*iph;
    igrp_t			*igrph;
    u_int16_t			cs;		/* checksum */
    char			all_igrp[]="224.0.0.10";


    *psize=PADDING_SIZE+sizeof(igrp_t)+sizeof(iphdr_t);
    tpacket=(u_char *)smalloc(PADDING_SIZE+sizeof(igrp_t)+sizeof(iphdr_t)
	    +3 /* for my checksum function, which sometimes 
		  steps over the mark */
	    );

    /* make up IP packet */
    iph=(iphdr_t *)tpacket;

    iph->version=4;
    iph->ihl=sizeof(iphdr_t)/4;

    iph->tot_len=htons(*psize);
    iph->ttl=IPTTL;
    iph->protocol=IPPROTO_IGRP;

    memcpy(&(iph->saddr.s_addr),&(cfg.src.s_addr),IP_ADDR_LEN);
    if (!cfg.set_dest) 
	inet_aton(all_igrp,(struct in_addr *)&(iph->daddr));
    else
	memcpy(&(iph->daddr.s_addr),&(cfg.dest.s_addr),IP_ADDR_LEN);

    /* make up the IGRP header */
    igrph=(igrp_t *)(tpacket+sizeof(iphdr_t));
    igrph->version=1;
    igrph->opcode=2;		/* Update */
    igrph->edition=0;
    igrph->autosys=htons(autosys);
    igrph->interior=0;
    igrph->system=0;
    igrph->exterior=0;

    /* make up checksum */
    cs=chksum((u_char *)igrph,(*psize-sizeof(iphdr_t)));
    igrph->checksum=cs;

    return tpacket;
}


/* constructs the EIGRP request packet
 * * Returns a pointer to the packet or NULL if failed
 * * returns also the size in *psize */
u_char	*construct_eigrp_request(struct in_addr *dd, 
	u_int32_t autosys, int *psize) {
    u_char			*tpacket;
    iphdr_t			*iph;
    eigrp_t			*eigrph;
    eigrppara_t			*epara;
    eigrpsoft_t			*esoft;
    u_int16_t			cs;		/* checksum */
    char			all_igrp[]="224.0.0.10";


    *psize=sizeof(iphdr_t)+sizeof(eigrp_t)
	+sizeof(eigrppara_t)+sizeof(eigrpsoft_t);
    tpacket=(u_char *)smalloc(*psize
	    +3 /* for my checksum function, which sometimes 
		  steps over the mark */
	    );

    /* make up IP packet */
    iph=(iphdr_t *)tpacket;

    iph->version=4;
    iph->ihl=sizeof(iphdr_t)/4;

    iph->tot_len=htons(*psize);
    iph->ttl=IPTTL;
    iph->protocol=IPPROTO_EIGRP;

    memcpy(&(iph->saddr.s_addr),&(cfg.src.s_addr),IP_ADDR_LEN);
    if (dd==NULL) 
	inet_aton(all_igrp,(struct in_addr *)&(iph->daddr));
    else
	memcpy(&(iph->daddr.s_addr),&(dd->s_addr),IP_ADDR_LEN);

    /* make up the IGRP header */
    eigrph=(eigrp_t *)(tpacket+sizeof(iphdr_t));
    eigrph->version=2;
    eigrph->opcode=EIGRP_HELLO;
    eigrph->as=htonl(autosys);

    epara=(eigrppara_t *)(tpacket+sizeof(iphdr_t)+sizeof(eigrp_t));
    epara->type=htons(EIGRP_TYPE_PARA);
    epara->length=htons(sizeof(eigrppara_t));
    epara->k1=epara->k3=1;
    epara->holdtime=htons(15);

    esoft=(eigrpsoft_t *)(tpacket+sizeof(iphdr_t)
	    +sizeof(eigrp_t)+sizeof(eigrppara_t));
    esoft->type=htons(EIGRP_TYPE_SOFT);
    esoft->length=htons(sizeof(eigrpsoft_t));
    esoft->iosmaj=12;
    esoft->iosmin=2;
    esoft->eigrpmaj=1;
    esoft->eigrpmin=0;

    /* make up checksum */
    cs=chksum((u_char *)eigrph,(*psize-sizeof(iphdr_t)));
    eigrph->checksum=cs;

    return tpacket;
}

/* constructs the IRDP request packet
 * * Returns a pointer to the packet or NULL if failed
 * * returns also the size in *psize */
u_char	*construct_irdp_request(int *psize) {
    u_char			*tpacket;
    iphdr_t			*iph;
    irdp_solicitation_t		*irdph;
    u_int16_t			cs;		/* checksum */


    *psize=sizeof(irdp_solicitation_t)+sizeof(iphdr_t);
    tpacket=(u_char *)smalloc(sizeof(irdp_solicitation_t)+sizeof(iphdr_t)
	    +3 /* for my checksum function, which sometimes 
		  steps over the mark */
	    );

    /* make up IP packet */
    iph=(iphdr_t *)tpacket;

    iph->version=4;
    iph->ihl=sizeof(iphdr_t)/4;

    iph->tot_len=htons(*psize);
    iph->ttl=IPTTL;
    iph->protocol=IPPROTO_ICMP;

    memcpy(&(iph->saddr.s_addr),&(cfg.src.s_addr),IP_ADDR_LEN);
    memcpy(&(iph->daddr.s_addr),&(cfg.dest.s_addr),IP_ADDR_LEN);

    /* make up the irdp_solicitation_t header */
    irdph=(irdp_solicitation_t *)(tpacket+sizeof(iphdr_t));
    irdph->type=ICMP_SOLICITATION;
    irdph->code=0;
    irdph->checksum=0;
    irdph->reserved=0;

    /* make up checksum */
    cs=chksum((u_char *)irdph,(*psize-sizeof(iphdr_t)));
    irdph->checksum=cs;

    return tpacket;
}

/* constructs the RIP1 request packet
 * * Returns a pointer to the packet or NULL if failed
 * * returns also the size in *psize */
u_char	*construct_rip_request(int *psize) {
    u_char			*tpacket;
    iphdr_t			*iph;
    udphdr_t			*udp;
    ripv1hdr_t                  *rip;
    ripv1addr_t                 *ripaddr;


    *psize=sizeof(udphdr_t)+sizeof(iphdr_t)+
	sizeof(ripv1hdr_t)+sizeof(ripv1addr_t);
    tpacket=(u_char *)smalloc(sizeof(udphdr_t)+sizeof(iphdr_t)+
	    sizeof(ripv1hdr_t)+sizeof(ripv1addr_t)
	    +3 /* for my checksum function, which sometimes 
		  steps over the mark */
	    );

    /* make up IP packet */
    iph=(iphdr_t *)tpacket;

    iph->version=4;
    iph->ihl=sizeof(iphdr_t)/4;

    iph->tot_len=htons(*psize);
    iph->ttl=IPTTL;
    iph->protocol=IPPROTO_UDP;

    memcpy(&(iph->saddr.s_addr),&(cfg.src.s_addr),IP_ADDR_LEN);
    memcpy(&(iph->daddr.s_addr),&(cfg.dest.s_addr),IP_ADDR_LEN);

    /* make up the UDP header */
    udp=(udphdr_t *)(tpacket+sizeof(iphdr_t));
    udp->sport=htons(RIP_PORT);
    udp->dport=htons(RIP_PORT);
    udp->length=htons(*psize-sizeof(iphdr_t));

    /* make up the RIPv1 request */
    rip=(ripv1hdr_t *)(tpacket+sizeof(iphdr_t)+sizeof(udphdr_t));
    rip->command=RIP_COMMAND_REQUEST;
    rip->version=1;

    /* metric has to be 16 in a all-routes request */
    ripaddr=(ripv1addr_t *)(tpacket+sizeof(iphdr_t)+sizeof(udphdr_t)+
	    sizeof(ripv1hdr_t));
    ripaddr->metric=htonl(0x10);

    return tpacket;
}

/* constructs the RIP2 request packet
 * * Returns a pointer to the packet or NULL if failed
 * * returns also the size in *psize */
u_char	*construct_rip2_request(int *psize) {
    u_char			*tpacket;
    iphdr_t			*iph;
    udphdr_t			*udp;
    char			all_rip2[]="224.0.0.9";
    ripv2hdr_t                  *rip;
    ripv2addr_t                 *ripaddr;


    *psize=sizeof(udphdr_t)+sizeof(iphdr_t)+
	sizeof(ripv2hdr_t)+sizeof(ripv2addr_t);
    tpacket=(u_char *)smalloc(sizeof(udphdr_t)+sizeof(iphdr_t)+
	    sizeof(ripv2hdr_t)+sizeof(ripv2addr_t)
	    +3 /* for my checksum function, which sometimes 
		  steps over the mark */
	    );

    /* make up IP packet */
    iph=(iphdr_t *)tpacket;

    iph->version=4;
    iph->ihl=sizeof(iphdr_t)/4;

    iph->tot_len=htons(*psize);
    iph->ttl=IPTTL;
    iph->protocol=IPPROTO_UDP;

    memcpy(&(iph->saddr.s_addr),&(cfg.src.s_addr),IP_ADDR_LEN);
    if (!cfg.set_dest)
	inet_aton(all_rip2,(struct in_addr *)&(iph->daddr));
    else
	memcpy(&(iph->daddr.s_addr),&(cfg.dest.s_addr),IP_ADDR_LEN);

    /* make up the UDP header */
    udp=(udphdr_t *)(tpacket+sizeof(iphdr_t));
    udp->sport=htons(RIP_PORT);
    udp->dport=htons(RIP_PORT);
    udp->length=htons(*psize-sizeof(iphdr_t));

    /* make up the RIPv1 request */
    rip=(ripv2hdr_t *)(tpacket+sizeof(iphdr_t)+sizeof(udphdr_t));
    rip->command=RIP_COMMAND_REQUEST;
    rip->version=2;

    /* metric has to be 16 in a all-routes request */
    ripaddr=(ripv2addr_t *)(tpacket+sizeof(iphdr_t)+sizeof(udphdr_t)+
	    sizeof(ripv2hdr_t));
    ripaddr->metric=htonl(0x10);

    return tpacket;
}


void	usage(char *n) {
    printf(
	    "%s [-v[v[v]]] -i <interface> [-A] [-p] [-c] [-M] [-P IER12]\n"
	    "\t[-a <autonomous system start> -b <autonomous system stop>]\n"
	    "\t[-S <spoofed source IP>] [-D <destination ip>]\n"
	    "\t[-T <packets per delay>]\n",
	    n);
    exit (1);
}


int	add_route(int rtype,struct in_addr *addr,unsigned int as,void *data) {
    result_t		*current,*c2;
    RES_route_igrp_t	*c_igrp;
    RES_route_irdp_t	*c_irdp;
    RES_route_ripv1_t	*c_rip;
    RES_route_ripv2_t	*c_rip2;
    RES_route_eigrp_t	*c_eigrp;
    RES_route_eigrprt_t	*c_eigrpr;
    RES_route_hsrp_t	*c_hsrp;
    RES_route_ospf_t	*c_ospf;
    igrp_system_entry_t	*isys;
    irdp_rec_t		*irdpr;
    ripv1addr_t		*rip1a;
    ripv2addr_t		*rip2a;
    ripv2auth_t		*rip2auth;
    eigrpsoft_t		*eigrps;
    eigrpextroute_t	*eigrper;
    eigrpintroute_t	*eigrpir;
    hsrp_t		*hsrp;
    ospf_header_t	*ospfh;
    ospf_hello_t	*ospfl;
    u_int32_t		temp;
    int			i;

    current=anchor;
    c2=NULL;
    /* look for already exisiting one */
    while (current!=NULL) {
	if (!memcmp(&(current->addr),addr,sizeof(struct in_addr))) break;
	c2=current;
	current=current->next;
    }

    /* if not existing, add one */
    if (current==NULL) {
	current=smalloc(sizeof(result_t));
	memcpy(&(current->addr),addr,sizeof(struct in_addr));

	if (c2) c2->next=current;
	/* if it is the first, make it anchor */
	if (anchor==NULL) anchor=current;
    }

    /* may be there are no routes in it ... */
    if (rtype==0) return 0;

    switch (rtype) { 
	case CAP_IGRP: /* add an IGRP route */
	    current->capa=current->capa|CAP_IGRP;
	    isys=(igrp_system_entry_t *)data;
	    
	    if (current->igrp==NULL) {
		current->igrp=(RES_route_igrp_t *)
		    smalloc(sizeof(RES_route_igrp_t));
		c_igrp=current->igrp;
	    } else {
		c_igrp=current->igrp;
		while (c_igrp!=NULL) {
		    if (
			    (!memcmp(&(c_igrp->dest.s_addr),
				     &(isys->destination),3))
			    &&
			    (c_igrp->as==as))
			/* destination already known for this router */
			return 1;
		    c_igrp=c_igrp->next;
		}
		/* go to the last valid entry */
		c_igrp=current->igrp;
		while (c_igrp->next!=NULL) c_igrp=c_igrp->next;
		c_igrp->next=(RES_route_igrp_t *)
		    smalloc(sizeof(RES_route_igrp_t));
		c_igrp=c_igrp->next;
	    }
	    /* at this point c_igrp points to an empty record */
		
	    if (data!=NULL) {
		memcpy(&(c_igrp->dest.s_addr),&(isys->destination),3);
		memset(&temp,0,sizeof(temp));
		memcpy(((u_int8_t *)&temp)+1,&(isys->delay),3);
		c_igrp->delay=ntohl(temp);
		memset(&temp,0,sizeof(temp));
		memcpy(((u_int8_t *)&temp)+1,&(isys->bandwith),3);
		c_igrp->bandw=ntohl(temp);
		c_igrp->mtu=ntohs(isys->mtu);
		c_igrp->reliability=isys->reliability;
		c_igrp->load=isys->load;
		c_igrp->hopcount=isys->hopcount;
		c_igrp->as=as;
	    }

	    break;

	    /* 
	     * IRDP 
	     */
	case CAP_IRDP:
	    current->capa=current->capa|CAP_IRDP;
	    irdpr=(irdp_rec_t *)data;
	    
	    if (current->irdp==NULL) {
		current->irdp=(RES_route_irdp_t *)
		    smalloc(sizeof(RES_route_irdp_t));
		c_irdp=current->irdp;
	    } else {
		c_irdp=current->irdp;
		while (c_irdp!=NULL) {
		    if (!memcmp(&(c_irdp->dest.s_addr),
				&(irdpr->addr),IP_ADDR_LEN))
			/* destination already known for this router */
			return 1;
		    c_irdp=c_irdp->next;
		}
		/* go to the last valid entry */
		c_irdp=current->irdp;
		while (c_irdp->next!=NULL) c_irdp=c_irdp->next;
		c_irdp->next=(RES_route_irdp_t *)
		    smalloc(sizeof(RES_route_irdp_t));
		c_irdp=c_irdp->next;
	    }
	    /* at this point c_irdp points to an empty record */

	    memcpy(&(c_irdp->dest.s_addr),&(irdpr->addr),IP_ADDR_LEN);
	    c_irdp->preference=ntohl(irdpr->pref);
	    break;


	    /* 
	     * RIPv1
	     */
	case CAP_RIPv1:
	    current->capa=current->capa|CAP_RIPv1;
	    rip1a=(ripv1addr_t *)data;

	    if (current->rip1==NULL) {
		current->rip1=(RES_route_ripv1_t *)
		    smalloc(sizeof(RES_route_ripv1_t));
		c_rip=current->rip1;
	    } else {
		c_rip=current->rip1;
		while (c_rip!=NULL) {
		    if (!memcmp(&(c_rip->dest.s_addr),
				&(rip1a->address),IP_ADDR_LEN))
			/* destination already known for this router */
			return 1;
		    c_rip=c_rip->next;
		}
		/* go to the last valid entry */
		c_rip=current->rip1;
		while (c_rip->next!=NULL) c_rip=c_rip->next;
		c_rip->next=(RES_route_ripv1_t *)
		    smalloc(sizeof(RES_route_ripv1_t));
		c_rip=c_rip->next;
	    }
	    /* at this point c_rip points to an empty record */

	    memcpy(&(c_rip->dest.s_addr),&(rip1a->address),IP_ADDR_LEN);
	    c_rip->metric=ntohl(rip1a->metric);
	    break;


	    /* 
	     * RIPv2
	     */
	case CAP_RIPv2:
	    current->capa=current->capa|CAP_RIPv2;
	    rip2a=(ripv2addr_t *)data;

	    if (current->rip2==NULL) {
		current->rip2=(RES_route_ripv2_t *)
		    smalloc(sizeof(RES_route_ripv2_t));
		c_rip2=current->rip2;
	    } else {
		c_rip2=current->rip2;
		while (c_rip2!=NULL) {
		    if (!memcmp(&(c_rip2->dest.s_addr),
				&(rip2a->address),IP_ADDR_LEN))
			/* destination already known for this router */
			return 1;
		    c_rip2=c_rip2->next;
		}
		/* go to the last valid entry */
		c_rip2=current->rip2;
		while (c_rip2->next!=NULL) c_rip2=c_rip2->next;
		c_rip2->next=(RES_route_ripv2_t *)
		    smalloc(sizeof(RES_route_ripv2_t));
		c_rip2=c_rip2->next;
	    }
	    /* at this point c_rip points to an empty record */

	    memcpy(&(c_rip2->dest.s_addr),&(rip2a->address),IP_ADDR_LEN);
	    memcpy(&(c_rip2->mask.s_addr),&(rip2a->netmask),IP_ADDR_LEN);
	    memcpy(&(c_rip2->nexthop.s_addr),&(rip2a->nexthop),IP_ADDR_LEN);
	    c_rip2->metric=ntohl(rip2a->metric);
	    c_rip2->routetag=ntohs(rip2a->routetag);
	    break;


	    /* 
	     * RIPv2 Authentication
	     */
	case CAP_RIPv2auth:
	    current->capa=current->capa|CAP_RIPv2auth;
	    rip2auth=(ripv2auth_t *)data;

	    current->rip2auth_type=htons(rip2auth->authtype);
	    memset(&(current->rip2pw),0,sizeof(current->rip2pw));
	    memcpy(&(current->rip2pw),&(rip2auth->auth),16);
	    break;

	    /* 
	     * EIGRP passive
	     */
	case CAP_EIGRP:
	    current->capa=current->capa|CAP_EIGRP;
	    eigrps=(eigrpsoft_t *)data;

	    if (current->eigrp==NULL) {
		current->eigrp=(RES_route_eigrp_t *)
		    smalloc(sizeof(RES_route_eigrp_t));
		c_eigrp=current->eigrp;
	    } else {
		c_eigrp=current->eigrp;
		while (c_eigrp!=NULL) {
		    if (c_eigrp->as==as)
			/* autonomous system already known for this router */
			return 1;
		    c_eigrp=c_eigrp->next;
		}
		/* go to the last valid entry */
		c_eigrp=current->eigrp;
		while (c_eigrp->next!=NULL) c_eigrp=c_eigrp->next;
		c_eigrp->next=(RES_route_eigrp_t *)
		    smalloc(sizeof(RES_route_eigrp_t));
		c_eigrp=c_eigrp->next;
	    }
	    /* at this point c_eigrp points to an empty record */
	    c_eigrp->as=as;

	    if (eigrps!=NULL) {
		c_eigrp->ios_major=eigrps->iosmaj;
		c_eigrp->ios_minor=eigrps->iosmin;
		c_eigrp->eigrp_major=eigrps->eigrpmaj;
		c_eigrp->eigrp_minor=eigrps->eigrpmin;
	    }
	    break;


	    /* 
	     * EIGRP active
	     */
	case CAP_EIGRP_RT:
	    current->capa=current->capa|CAP_EIGRP_RT;
	    /* could be both ... */
	    eigrpir=(eigrpintroute_t *)data;
	    eigrper=(eigrpextroute_t *)data;

	    if (current->eigrpr==NULL) {
		current->eigrpr=(RES_route_eigrprt_t *)
		    smalloc(sizeof(RES_route_eigrprt_t));
		c_eigrpr=current->eigrpr;
	    } else {
		c_eigrpr=current->eigrpr;
		while (c_eigrpr!=NULL) {
		    /* check the EIGRP type */
		    if (ntohs(eigrpir->type)==EIGRP_TYPE_IN_ROUTE) {
			if ((c_eigrpr->as==as)
				&&(!memcmp(&(c_eigrpr->dest.s_addr),
				    &(eigrpir->dest),
				    (int)(eigrpir->prefix_length/8)))
				&&(c_eigrpr->type==ntohs(eigrpir->type))) {
			/* autonomous system and destination
			 * already known for this router */
			    return 1;
			}
		    } else {
			if ((c_eigrpr->as==as)
				&&(!memcmp(&(c_eigrpr->dest.s_addr),
				    &(eigrper->dest),
				    (int)(eigrper->prefix_length/8)))
				&&(c_eigrpr->type==ntohs(eigrper->type))) {
			/* autonomous system and destination
			 * already known for this router */
			    return 1;
			}
		    }
		    c_eigrpr=c_eigrpr->next;
		}
		/* go to the last valid entry */
		c_eigrpr=current->eigrpr;
		while (c_eigrpr->next!=NULL) c_eigrpr=c_eigrpr->next;
		c_eigrpr->next=(RES_route_eigrprt_t *)
		    smalloc(sizeof(RES_route_eigrprt_t));
		c_eigrpr=c_eigrpr->next;
	    }
	    /* at this point c_eigrp points to an empty record */
	    c_eigrpr->as=as;
	    c_eigrpr->type=ntohs(eigrpir->type);
	    memcpy(&(c_eigrpr->nexthop),&(eigrper->nexthop),IP_ADDR_LEN);
	    /* from here one, the packet format changes for external and 
	     * internal routes IP */
	    if (c_eigrpr->type==EIGRP_TYPE_EX_ROUTE) {
		/* external route */
		memcpy(&(c_eigrpr->origrouter),
			&(eigrper->origrouter),IP_ADDR_LEN);
		c_eigrpr->origas=ntohl(eigrper->origas);
		c_eigrpr->externalmetric=ntohl(eigrper->external_metric);
		c_eigrpr->externallink=eigrper->external_link;

		c_eigrpr->delay=ntohl(eigrper->delay);
		c_eigrpr->bandwidth=ntohl(eigrper->bandwidth);
		memset(&temp,0,sizeof(temp));
		memcpy(((u_int8_t *)&temp)+1,&(eigrper->mtu),3);
		c_eigrpr->mtu=ntohs(temp);
		c_eigrpr->hopcount=eigrper->hopcount;
		c_eigrpr->reliability=eigrper->reliability;
		c_eigrpr->load=eigrper->load;

		temp=0xFFFFFFFF;
		for (i=0;i<32-eigrper->prefix_length;i++) 
		    temp=temp<<1;
		temp=htonl(temp);
		memcpy(&(c_eigrpr->netmask),&temp,4);
		memcpy(&(c_eigrpr->dest),&(eigrper->dest),
			(int)(eigrper->prefix_length/8));
	    } else {
		/* internal route */
		c_eigrpr->delay=ntohl(eigrpir->delay);
		c_eigrpr->bandwidth=ntohl(eigrpir->bandwidth);
		memset(&temp,0,sizeof(temp));
		memcpy(((u_int8_t *)&temp)+1,&(eigrpir->mtu),3);
		c_eigrpr->mtu=ntohs(temp);
		c_eigrpr->hopcount=eigrpir->hopcount;
		c_eigrpr->reliability=eigrpir->reliability;
		c_eigrpr->load=eigrpir->load;

		temp=0xFFFFFFFF;
		for (i=0;i<32-eigrpir->prefix_length;i++) 
		    temp=temp<<1;
		temp=htonl(temp);
		memcpy(&(c_eigrpr->netmask),&temp,4);
		memcpy(&(c_eigrpr->dest),&(eigrpir->dest),
			(int)(eigrpir->prefix_length/8));
	    }
	    break;


	    /* 
	     * OSPF passive
	     */
	case CAP_OSPF:
	    current->capa=current->capa|CAP_OSPF;
	    ospfh=(ospf_header_t *)data;

	    if (current->ospf==NULL) {
		current->ospf=(RES_route_ospf_t *)
		    smalloc(sizeof(RES_route_ospf_t));
		c_ospf=current->ospf;
	    } else {
		c_ospf=current->ospf;
		while (c_ospf!=NULL) {
		    if (
			    (!memcmp(&(c_ospf->area.s_addr),&(ospfh->area),
				     IP_ADDR_LEN))
			    &&
			    (!memcmp(&(c_ospf->source.s_addr),
				     &(ospfh->source),IP_ADDR_LEN))
			    )
			/* area/source already known for this router */
			return 1;
		    c_ospf=c_ospf->next;
		}
		/* go to the last valid entry */
		c_ospf=current->ospf;
		while (c_ospf->next!=NULL) c_ospf=c_ospf->next;
		c_ospf->next=(RES_route_ospf_t *)
		    smalloc(sizeof(RES_route_ospf_t));
		c_ospf=c_ospf->next;
	    }
	    /* at this point c_ospf points to an empty record */

	    if (ospfh!=NULL) {
		memcpy(&(c_ospf->source.s_addr),&(ospfh->source),IP_ADDR_LEN);
		memcpy(&(c_ospf->area.s_addr),&(ospfh->area),IP_ADDR_LEN);
		memcpy(&(c_ospf->authdata),&(ospfh->authdata),8);
		c_ospf->authtype=ntohs(ospfh->authtype);
		ospfl=(ospf_hello_t *)(data+sizeof(ospf_header_t));
		memcpy(&(c_ospf->netmask.s_addr),&(ospfl->netmask),IP_ADDR_LEN);
		memcpy(&(c_ospf->designated.s_addr),
			&(ospfl->designated),IP_ADDR_LEN);
		memcpy(&(c_ospf->backup.s_addr),&(ospfl->backup),IP_ADDR_LEN);
		c_ospf->dead=ntohl(*((u_int32_t *)&(ospfl->dead_interval)));
		c_ospf->prio=ospfl->priority;
		c_ospf->hello=ntohs(ospfl->hello_interval);
	    }
	    break;


	    /* 
	     * HSRP passive
	     */
	case CAP_HSRP:
	    current->capa=current->capa|CAP_HSRP;
	    hsrp=(hsrp_t *)data;

	    if (current->hsrp==NULL) {
		current->hsrp=(RES_route_hsrp_t *)
		    smalloc(sizeof(RES_route_hsrp_t));
		c_hsrp=current->hsrp;
	    } else {
		c_hsrp=current->hsrp;
		while (c_hsrp!=NULL) {
		    if (!memcmp(&(c_hsrp->virtip.s_addr),
				&(hsrp->virtip),IP_ADDR_LEN))
			/* virtual ip already known for this router */
			return 1;
		    c_hsrp=c_hsrp->next;
		}
		/* go to the last valid entry */
		c_hsrp=current->hsrp;
		while (c_hsrp->next!=NULL) c_hsrp=c_hsrp->next;
		c_hsrp->next=(RES_route_hsrp_t *)
		    smalloc(sizeof(RES_route_hsrp_t));
		c_hsrp=c_hsrp->next;
	    }
	    /* at this point c_hsrp points to an empty record */
	    memcpy(&(c_hsrp->virtip.s_addr),hsrp->virtip,IP_ADDR_LEN);
	    memset(&(c_hsrp->auth),0,sizeof(c_hsrp->auth));
	    memcpy(&(c_hsrp->auth),hsrp->auth,8);
	    c_hsrp->version=hsrp->version;
	    c_hsrp->state=hsrp->state;
	    c_hsrp->hello=hsrp->hellotime;
	    c_hsrp->hold=hsrp->holdtime;
	    c_hsrp->group=hsrp->group;
	    c_hsrp->prio=hsrp->prio;
	    break;


	    /*
	     * CDP
	     */
	case CAP_CDP:
	    current->capa=current->capa|CAP_CDP;
	    break;

	default:
	    fprintf(stderr,"Well ... internal function called with "
		    "bullshit argument. bad sign!\n");
	    exit(-15);
    }

    return 0;
}


void	print_results(void) {
    result_t		*current;
    RES_route_igrp_t	*c_igrp;
    RES_route_irdp_t	*c_irdp;
    RES_route_ripv1_t	*c_rip1;
    RES_route_ripv2_t	*c_rip2;
    RES_route_eigrp_t	*c_eigrp;
    RES_route_eigrprt_t	*c_eigrpr;
    RES_route_hsrp_t	*c_hsrp;
    RES_route_ospf_t	*c_ospf;

    printf("\n\n>>>Results>>>\n");

    current=anchor;
    while (current!=NULL) {
	printf("Router %15s\t(",inet_ntoa(current->addr));

	/* capabilities */
	if (current->capa&CAP_IGRP) printf("IGRP ");
	if (current->capa&CAP_IRDP) printf("IRDP ");
	if (current->capa&CAP_CDP) printf("CDP ");
	if (current->capa&CAP_RIPv1) printf("RIPv1 ");
	if (current->capa&CAP_RIPv2) printf("RIPv2 ");
	if (current->capa&CAP_EIGRP) printf("EIGRP ");
	if (current->capa&CAP_HSRP) printf("HSRP ");
	if (current->capa&CAP_OSPF) printf("OSPF ");
	printf(")\n");

	/* display all IGRP results */
	c_igrp=current->igrp;
	while (c_igrp!=NULL) {
	    printf("\tIGRP [%5d] %17s  (",c_igrp->as,
		    inet_ntoa(c_igrp->dest));
	    printf("%lu,%lu,%u,%u,%u,%u)\n",
		    c_igrp->delay, c_igrp->bandw, c_igrp->mtu, 
		    c_igrp->reliability, c_igrp->load, c_igrp->hopcount);
	    c_igrp=c_igrp->next;
	}
	/* display all IRDP results */
	c_irdp=current->irdp;
	while (c_irdp!=NULL) {
	    printf("\tIRDP [ n/a ] %17s  (preference %lu)\n",
		    inet_ntoa(c_irdp->dest),c_irdp->preference);
	    c_irdp=c_irdp->next;
	}
	/* RIPv1 */
	c_rip1=current->rip1;
	while (c_rip1!=NULL) {
	    printf("\tRIP1 [ n/a ] %17s  (metric %lu",
		    inet_ntoa(c_rip1->dest),c_rip1->metric);
	    if (c_rip1->metric==16) printf(" [unreachable])\n");
	    else printf(")\n");
	    c_rip1=c_rip1->next;
	}
	/* RIPv2 Authentication */
	if (current->capa&CAP_RIPv2auth) {
	    switch (current->rip2auth_type) {
		case RIP2AUTH_NONE: printf("\tRIP2 [ n/a ] %17s\n","no auth");
				    break;
		case RIP2AUTH_TEXT: printf("\tRIP2 [ n/a ] %17s  ","text auth");
				    printf("(auth '%s')\n",current->rip2pw); 
				    break;
		case RIP2AUTH_MD5:  printf("\tRIP2 [ n/a ] %17s  ","md5 auth");
				    printf("(hash %02X%02X%02X%02X%02X%02X"
					    "%02X%02X%02X%02X%02X%02X%02X"
					    "%02X%02X%02X)\n",
					    current->rip2pw[0]&0xFF,
					    current->rip2pw[1]&0xFF,
					    current->rip2pw[2]&0xFF,
					    current->rip2pw[3]&0xFF,
					    current->rip2pw[4]&0xFF,
					    current->rip2pw[5]&0xFF,
					    current->rip2pw[6]&0xFF,
					    current->rip2pw[7]&0xFF,
					    current->rip2pw[8]&0xFF,
					    current->rip2pw[9]&0xFF,
					    current->rip2pw[10]&0xFF,
					    current->rip2pw[11]&0xFF,
					    current->rip2pw[12]&0xFF,
					    current->rip2pw[13]&0xFF,
					    current->rip2pw[14]&0xFF,
					    current->rip2pw[15]&0xFF);
				    break;
		default: printf("\tRIP2 [ n/a ] %17s\n","unknown auth");
	    }
	}
	/* RIPv2 */
	c_rip2=current->rip2;
	while (c_rip2!=NULL) {
	    printf("\tRIP2 [ n/a ] %17s  /",inet_ntoa(c_rip2->dest));
	    printf("%s, next: ",inet_ntoa(c_rip2->mask));
	    printf("%s\n",inet_ntoa(c_rip2->nexthop));
	    printf("\t%33s"," ");
	    printf("(tag %u, mtr %lu",c_rip2->routetag,c_rip2->metric);
	    if (c_rip2->metric==16) printf(" [unreachable])\n"); 
	    else printf(")\n");
	    c_rip2=c_rip2->next;
	}
	/* EIGRP */
	c_eigrp=current->eigrp;
	while (c_eigrp!=NULL) {
	    printf("\tEIGRP[%5lu] %17s  (IOS %u.%u, EIGRP %u.%u)\n",
		    c_eigrp->as,"",c_eigrp->ios_major,c_eigrp->ios_minor,
		    c_eigrp->eigrp_major, c_eigrp->eigrp_minor);
	    c_eigrp=c_eigrp->next;
	}
	/* EIGRP Routes*/
	c_eigrpr=current->eigrpr;
	while (c_eigrpr!=NULL) {
	    printf("\tEIGRP[%5lu] %17s  ",
		    c_eigrpr->as,inet_ntoa(c_eigrpr->dest));
	    printf("/%s, next hop: ",inet_ntoa(c_eigrpr->netmask));
	    printf("%s\n",inet_ntoa(c_eigrpr->nexthop));
	    if (c_eigrpr->type==EIGRP_TYPE_EX_ROUTE) {
		printf("\t%13s%17s  "," ","external");
		printf("(%s,%lu,%lu,",inet_ntoa(c_eigrpr->origrouter),
			c_eigrpr->origas,c_eigrpr->externalmetric);
		switch (c_eigrpr->externallink) {
		    case 1:	printf("from IGRP)"); break;
		    case 2:	printf("from EIGRP)"); break;
		    case 3:	printf("from Static Routing)"); break;
		    case 4:	printf("from RIP)"); break;
		    case 5:	printf("from Hello)"); break;
		    case 6:	printf("from OSPF)"); break;
		    case 7:	printf("from IS-IS)"); break;
		    case 8:	printf("from EGP)"); break;
		    case 9:	printf("from BGP)"); break;
		    case 10:	printf("from IDRP)"); break;
		    case 11:	printf("Connected Link)"); break;
		    default:	printf("LINK UNKNOWN)"); 
		}
		printf("\n\t%32s"," ");
	    } else {
		printf("\t%13s%17s  "," ","internal");
	    }
	    //printf("\t%32s(%lu,%lu,%lu,%u,%u,%u)\n"," ",
	    printf("(%lu,%lu,%lu,%u,%u,%u)\n",
		    c_eigrpr->delay, c_eigrpr->bandwidth, c_eigrpr->mtu, 
		    c_eigrpr->reliability, c_eigrpr->load, c_eigrpr->hopcount);

	    c_eigrpr=c_eigrpr->next;
	}
	/* HSRP */
	c_hsrp=current->hsrp;
	while (c_hsrp!=NULL) {
	    printf("\tHSRP [%5u] %17s  (",
		    c_hsrp->group,inet_ntoa(c_hsrp->virtip));
	    switch (c_hsrp->state) {
		case HSRP_STATE_INITIAL:printf("Initial,"); break;
		case HSRP_STATE_LEARN:	printf("Learn,"); break;
		case HSRP_STATE_LISTEN:	printf("Listen,"); break;
		case HSRP_STATE_SPEAK:	printf("Speak,"); break;
		case HSRP_STATE_STANDBY:printf("Standby,"); break;
		case HSRP_STATE_ACTIVE:	printf("Active,"); break;
		default:		printf("Stat %u,",c_hsrp->state);
	    }
	    printf(" auth '%s',%u,%u,%u)\n",c_hsrp->auth,c_hsrp->hello,
		    c_hsrp->hold, c_hsrp->prio);
	    c_hsrp=c_hsrp->next;
	}
	/* OSPF */
	c_ospf=current->ospf;
	while (c_ospf!=NULL) {
	    printf("\tOSPF [ n/a ] %17s  (",inet_ntoa(c_ospf->source));
	    if (*((u_int32_t*)(&(c_ospf->area)))==0) {
		printf("Area: BACKBONE, ");
	    } else {
		printf("Area: %s, ",inet_ntoa(c_ospf->area));
	    } 
	    switch (c_ospf->authtype) {
		case 0:	printf("no auth,"); break;
		case 1:	printf("auth '%s',",c_ospf->authdata); break;
		case 2:	printf("crypto auth,"); break;
	    }
	    printf("\n\t%33s"," ");
	    printf("mask %s,",inet_ntoa(c_ospf->netmask));
	    printf("\n\t%33s"," ");
	    printf("Dsg: %s,",inet_ntoa(c_ospf->designated));
	    printf("\n\t%33s"," ");
	    printf("Bkp: %s,",inet_ntoa(c_ospf->backup));
	    printf("\n\t%33s"," ");
	    printf("Dead %lu, Prio %u, Hello %u)\n",
		    c_ospf->dead,c_ospf->prio,c_ospf->hello);

	    c_ospf=c_ospf->next;
	}

	current=current->next;
    }
}


void	clean_results(void) {
    result_t		*k,*current;
    RES_route_igrp_t	*k_igrp,*c_igrp;
    RES_route_irdp_t	*k_irdp,*c_irdp;
    RES_route_ripv1_t	*k_rip1,*c_rip1;
    RES_route_eigrp_t	*k_eigrp,*c_eigrp;
    RES_route_eigrprt_t	*k_eigrpr,*c_eigrpr;
    RES_route_hsrp_t	*k_hsrp,*c_hsrp;
    RES_route_ospf_t	*k_ospf,*c_ospf;

    current=anchor;
    while (current!=NULL) {

	c_igrp=current->igrp;
	while (c_igrp!=NULL) {
	    k_igrp=c_igrp;
	    c_igrp=c_igrp->next;
	    free(k_igrp);
	}
	c_irdp=current->irdp;
	while (c_irdp!=NULL) {
	    k_irdp=c_irdp;
	    c_irdp=c_irdp->next;
	    free(k_irdp);
	}
	c_rip1=current->rip1;
	while (c_rip1!=NULL) {
	    k_rip1=c_rip1;
	    c_rip1=c_rip1->next;
	    free(k_rip1);
	}
	c_rip1=(RES_route_ripv1_t *)current->rip2;
	while (c_rip1!=NULL) {
	    k_rip1=c_rip1;
	    c_rip1=c_rip1->next;
	    free(k_rip1);
	}
	c_eigrp=current->eigrp;
	while (c_eigrp!=NULL) {
	    k_eigrp=c_eigrp;
	    c_eigrp=c_eigrp->next;
	    free(k_eigrp);
	}
	c_eigrpr=current->eigrpr;
	while (c_eigrpr!=NULL) {
	    k_eigrpr=c_eigrpr;
	    c_eigrpr=c_eigrpr->next;
	    free(k_eigrpr);
	}
	c_hsrp=current->hsrp;
	while (c_hsrp!=NULL) {
	    k_hsrp=c_hsrp;
	    c_hsrp=c_hsrp->next;
	    free(k_hsrp);
	}
	c_ospf=current->ospf;
	while (c_ospf!=NULL) {
	    k_ospf=c_ospf;
	    c_ospf=c_ospf->next;
	    free(k_ospf);
	}

	k=current;
	current=current->next;
	free(k);
    }
}



