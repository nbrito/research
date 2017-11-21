/* protos - Protocol availability scanner
 * 
 * FX <fx@phenoelit.de>
 * Phenoelit (http://www.phenoelit.de)
 *
 * $Id: protos.c,v 1.13 2001/06/16 13:33:34 fx Exp $
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
#include <sys/wait.h>
#include <fcntl.h>

#include "protocols.h"
#include "packets.h"
#include "protocol-numbers.h"

/* 
 * moved into protocol-numbers.h, which in turn is generated from
 * ftp://ftp.isi.edu/in-notes/iana/assignments/protocol-numbers
 * becuse IANA thinks it's fun to add proto numbers all nose long 
 * 
typedef struct proto_t {
    int		number;
    char	*keyword;
    char	*name;
} Protocols; */

typedef struct {
    struct in_addr	addr;
    int			p[256];
    void		*next;
} target_t;

struct {
    int		verbose;
    int		dontping;
    int		afterscan;
    int		invert;
    int		probes;
    int		slowscan;
    int		sleeptime;
    int		longdisp;
    char	*device;
    char	*dest;
} cfg;

/* globals */
#define PADDING		128
#define DEFAULTPROBES	5
#define DEFAULTSLEEP	1
#define DEFAULTAFTER	3
#define DEFAULTSLOW	0
#define DEFAULTINVERT	1
#define IP_ID		0xAFFA
#define PING_TIMEOUT	5

target_t		*anchor;
sig_atomic_t		stop_flag=0;

/* prototypes */
int 	create_target_list(void);
int	is_there(struct in_addr *t);
int 	print_targets(void);
int 	scan_list(void);
int 	recv_icmp(pid_t pid);
void	signaler(int sig);
void	usage(void);


int main(int argc, char **argv) {
    char		option;
    extern char		*optarg;
    pid_t		scanpid;
    int			retcode,i;
    target_t		*res;

    memset(&cfg,0,sizeof(cfg));
    cfg.probes=DEFAULTPROBES;
    cfg.sleeptime=DEFAULTSLEEP;
    cfg.afterscan=DEFAULTAFTER;
    cfg.slowscan=DEFAULTSLOW;
    cfg.invert=DEFAULTINVERT;
    while ((option=getopt(argc,argv,"vVusLWd:i:p:S:"))!=EOF) {
	switch(option) {
	    case 'v':	cfg.verbose++;
			break;
	    case 'V':	cfg.invert=0;
			break;
	    case 'u':	cfg.dontping++;
			break;
	    case 's':	cfg.slowscan=1;
			break;
	    case 'L':	cfg.longdisp++;
			break;
	    case 'p':	if ((cfg.probes=atoi(optarg))==0) {
			    printf("Probes reverted to default\n");
			    cfg.probes=DEFAULTPROBES;
			}
			break;
	    case 'S':	if ((cfg.sleeptime=atoi(optarg))==0) {
			    fprintf(stderr,"Sleeptime reverted to default\n");
			    cfg.sleeptime=DEFAULTSLEEP;
			}
			break;
	    case 'a':	cfg.afterscan=atoi(optarg);
			break;
	    case 'd':	cfg.dest=smalloc(strlen(optarg)+1);
			strcpy(cfg.dest,optarg);
			break;
	    case 'i':	cfg.device=smalloc(strlen(optarg)+1);
			strcpy(cfg.device,optarg);
			break;
	    case 'W':	/* print protocol list and exit */
			for (i=0;i<PROTOCOLS-1;i++) 
			    printf("%d\t%-13s%s\n",
				    prts[i].number,
				    prts[i].keyword,
				    prts[i].name);
			return (0);
			break;	/* not reached */
	    default:	usage();
			return(1);
	}
    }

    if (geteuid()!=0) {
	fprintf(stderr,"You don't try this as user, do you? Become r00t!\n");
	return(1);
    }

    if ((cfg.dest==NULL)||(cfg.device==NULL)) return(1);
    if (create_target_list()!=0) return(1);
    signal(SIGINT,&signaler);
    if (cfg.verbose) print_targets();

    /* the verbose shit */
    if (cfg.verbose) {
	printf("Running in verbose mode\n"
		"\tAfterscan delay is %d\n",cfg.afterscan);
	if (cfg.slowscan) {
	    printf("\tSleeptime between probes is %d secs in slow scan\n",
		    cfg.sleeptime);
	} else {
	    printf("\trunning in fast scan - pause every %d probes\n",
		    cfg.sleeptime);
	} 
	printf("\tcontinuing scan afterwards for %d secs\n",cfg.afterscan);
	if (!cfg.invert) {
	    printf("\tNOT supported protocols will be reported\n");
	} else {
	    printf("\tsupported protocols will be reported\n");
	} 
	printf("\tyou supplied the target(s) %s\n",cfg.dest);
    }

    if ((scanpid=fork())<0) {
	fprintf(stderr,"Fork() failed\n");
	return(-1);
    } else if (scanpid==0) {
	/* me child */
	exit(scan_list());
    } else {
	/* me parrent */
	if (cfg.verbose>1) printf("Spawn child %d\n",scanpid);

	retcode=recv_icmp(scanpid);
	if (retcode<0) {
	    fprintf(stderr,"Killing child %d due error in receiver\n",scanpid);
	    kill(scanpid,SIGTERM);
	} else if (retcode==1) {
	    fprintf(stderr,"Killing child %d due CTRL-C break\n",scanpid);
	    kill(scanpid,SIGTERM);
	}
    }

    if (retcode==0) {
	printf(">>>>>>>>> RESULTS >>>>>>>>>>\n");
	while (anchor!=NULL) {
	    int	chk;

	    chk=0;
	    if (!cfg.invert) {
		/* normal operation - NOT display */
		printf("\n%s is NOT running (but may be capable of):\n",
			inet_ntoa(anchor->addr));
		if (!cfg.longdisp) printf("\t");
		for (i=0;i<PROTOCOLS-1;i++) {
		    if (anchor->p[i]==0) {
			if (cfg.longdisp) 
			    printf("%-13s\t%s\n",prts[i].keyword,prts[i].name);
			else 
			    printf("%s ",prts[i].keyword);
			chk++;
		    } else if (anchor->p[i]==2) {
			if (cfg.longdisp) 
			    printf("%-13s\t%s (filtered)\n",prts[i].keyword,
				    prts[i].name);
			else 
			    printf("(F) %s ",prts[i].keyword);
			chk++;
		    }
		}
		if (chk) 
		    printf("\n"); 
		else 
		    printf("\t... does not even care to send ICMP unreachable"
			    " messages ...\n");
	    } else {
		/* invert operation, show what's supported */
		printf("\n%s may be running (did not negate):\n",
			inet_ntoa(anchor->addr));

		for (i=0;i<PROTOCOLS-1;i++) 
			if (anchor->p[i]==0) chk++;
		if (chk) {
		    if (!cfg.longdisp) printf("\t");
		    for (i=0;i<PROTOCOLS-1;i++) {
			if (anchor->p[i]==1) {
			    if (cfg.longdisp) 
				printf("%-13s\t%s\n",prts[i].keyword,
					prts[i].name);
			    else 
				printf("%s ",prts[i].keyword);
			    chk++;
			}
		    }
		    printf("\n"); 
		} else 
		    printf("\t... does not even care to send ICMP unreachable"
			    " messages ...\n");
	    }
	    res=anchor;
	    anchor=anchor->next;
	    free(res);
	}
    }
	    
    return (0);
}


int recv_icmp(pid_t pid) {
    int			rfd;
    u_char		*response;
    int			rlength,i,addrsize;
    iphdr_t		*ip2;
    icmphdr_t		*icmp;
    target_t		*tgt;
    struct sockaddr_in	from;
    int			pidstat,foundflag;
    int			cdone=0,normalend=0;
    long int		t1;

    if ((rfd=socket(AF_INET,SOCK_RAW,IPPROTO_ICMP))<0) {
	perror("socket()");
	return(-1);
    }
    i=O_NONBLOCK|fcntl(rfd,F_GETFL);
    fcntl(rfd,F_SETFL,i);

    if (cfg.verbose>2) printf("waiting for the child to become alive\n");
    do {
	usleep(10);
    } while (waitpid(pid,&pidstat,WNOHANG)>0);
    if (cfg.verbose>2) printf("child is alive, starting to listen for ICMP\n");

    do {
	memset(&from,0,sizeof(struct sockaddr_in));
	addrsize=sizeof(struct sockaddr_in);
	rlength=PADDING+2*sizeof(iphdr_t)+sizeof(icmphdr_t)+4;
	response=smalloc(rlength);
	
	if (recvfrom(rfd,(u_char *)response,rlength,0,
		    (struct sockaddr *)&from,
		    &addrsize)>0) {
	    icmp=(icmphdr_t *)(response+sizeof(iphdr_t));
	    /* check if it is unreachable message */
	    if (icmp->type==ICMP_DEST_UNREACH) {
		/* oh.. good. */
		if (icmp->code==ICMP_UNREACH_PROTO) {
		    if (cfg.verbose>2) 
			printf("%s reports an unreachable protocol\n",
				inet_ntoa(from.sin_addr));
		    ip2=(iphdr_t *)(response+sizeof(iphdr_t)
			    +sizeof(icmphdr_t)+4);
		    if (cfg.verbose>1) 
			printf("%s reports protocol %d unreachable\n",
				inet_ntoa(from.sin_addr),ip2->protocol);
		    /* search target in list and update record */
		    tgt=anchor;
		    foundflag=0;
		    while(tgt!=NULL) {
			if (!memcmp(&(tgt->addr),&(from.sin_addr),
				    IP_ADDR_LEN)) {
			    foundflag=1;
			    tgt->p[ip2->protocol]=0;
			    break;
			}
			tgt=tgt->next;
		    }
		    if (!foundflag) {
			if (cfg.verbose>2) {
			    printf("Strange response from %s"
				    " regarding packet\n",
				    inet_ntoa(from.sin_addr));
			    printf("\t%d.%d.%d.%d->%d.%d.%d.%d (proto %d)\n",
				    *((u_int8_t *)&(ip2->saddr)),
				    *((u_int8_t *)&(ip2->saddr)+1),
				    *((u_int8_t *)&(ip2->saddr)+2),
				    *((u_int8_t *)&(ip2->saddr)+3),
				    *((u_int8_t *)&(ip2->daddr)),
				    *((u_int8_t *)&(ip2->daddr)+1),
				    *((u_int8_t *)&(ip2->daddr)+2),
				    *((u_int8_t *)&(ip2->daddr)+3),
				    ip2->protocol);
			}
			/* it is a multihomes box which replys with the wrong
			 * interface - add anyway */
			memcpy(&(from.sin_addr.s_addr),
				&(ip2->daddr.s_addr),IP_ADDR_LEN);
			tgt=anchor;
			foundflag=0;
			while(tgt!=NULL) {
			    if (!memcmp(&(tgt->addr),&(from.sin_addr),
					IP_ADDR_LEN)) {
				foundflag=1;
				tgt->p[ip2->protocol]=0;
			    }
			    tgt=tgt->next;
			}
			if ((!foundflag)&&(cfg.verbose>2))
			    printf("reponse from %s is not related"
				    " to a probe\n",
				    inet_ntoa(from.sin_addr));
		    }
		} /* is unreachable protocol */ else if (
			(icmp->code==ICMP_UNREACH_FIREWALL)) {
		    if (cfg.verbose>2) 
			printf("%s reports an firewalled protocol\n",
				inet_ntoa(from.sin_addr));
		    ip2=(iphdr_t *)(response+sizeof(iphdr_t)
			    +sizeof(icmphdr_t)+4);
		    if (cfg.verbose>1) 
			printf("%s reports protocol %d firewalled\n",
				inet_ntoa(from.sin_addr),ip2->protocol);
		    /* search target in list and update record */
		    tgt=anchor;
		    foundflag=0;
		    while(tgt!=NULL) {
			if (!memcmp(&(tgt->addr),&(from.sin_addr),
				    IP_ADDR_LEN)) {
			    foundflag=1;
			    tgt->p[ip2->protocol]=2;
			}
			tgt=tgt->next;
		    }
		    if (!foundflag) {
			if (cfg.verbose>2) {
			    printf("Strange response from %s"
				    " regarding packet\n",
				    inet_ntoa(from.sin_addr));
			    printf("\t%d.%d.%d.%d->%d.%d.%d.%d (proto %d)\n",
				    *((u_int8_t *)&(ip2->saddr)),
				    *((u_int8_t *)&(ip2->saddr)+1),
				    *((u_int8_t *)&(ip2->saddr)+2),
				    *((u_int8_t *)&(ip2->saddr)+3),
				    *((u_int8_t *)&(ip2->daddr)),
				    *((u_int8_t *)&(ip2->daddr)+1),
				    *((u_int8_t *)&(ip2->daddr)+2),
				    *((u_int8_t *)&(ip2->daddr)+3),
				    ip2->protocol);
			}
			/* it is a multihomes box which replys with the wrong
			 * interface - add anyway */
			memcpy(&(from.sin_addr.s_addr),
				&(ip2->daddr.s_addr),IP_ADDR_LEN);
			tgt=anchor;
			foundflag=0;
			while(tgt!=NULL) {
			    if (!memcmp(&(tgt->addr),&(from.sin_addr),
					IP_ADDR_LEN)) {
				foundflag=1;
				tgt->p[ip2->protocol]=2;
			    }
			    tgt=tgt->next;
			}
			if ((!foundflag)&&(cfg.verbose>2))
			    printf("reponse from %s is not related"
				    " to a probe\n",
				    inet_ntoa(from.sin_addr));
		    }
		} /* is firewalled protocol */ else if (
			(icmp->code==ICMP_UNREACH_PORT)) {
		    if (cfg.verbose) {
			ip2=(iphdr_t *)(response+sizeof(iphdr_t)
				+sizeof(icmphdr_t)+4);
			printf("Port unreachable - therefore protocol"
				" %s is running\n",
				prts[ip2->protocol].keyword);
		    }
		} else if ((icmp->code==ICMP_UNREACH_HOST)&&
			(memcmp(&(from.sin_addr),&(packet_ifconfig.ip),4)!=0)){
		    ip2=(iphdr_t *)(response+sizeof(iphdr_t)
			    +sizeof(icmphdr_t)+4);
		    printf("%s reports host unreachable for ",
			    inet_ntoa(from.sin_addr));
		    printf("%d.%d.%d.%d\n",
			    *((u_int8_t *)&(ip2->daddr)),
			    *((u_int8_t *)&(ip2->daddr)+1),
			    *((u_int8_t *)&(ip2->daddr)+2),
			    *((u_int8_t *)&(ip2->daddr)+3));
		} else if (icmp->code==ICMP_UNREACH_NET) {
		    printf("Network unreachable: %s\n",
			    inet_ntoa(from.sin_addr));
		} else {
		    printf("Unreachable code %d\n",icmp->code);
		}
	    } /* general: unreachable */
	} /* recvfrom*/
	usleep(10);
	
	if (!cdone) {
	    if (waitpid(pid,&pidstat,WNOHANG)!=0) {
		cdone=1;
		t1=(long int)time(NULL);
	    }
	} else {
	    if ((long int)time(NULL)>(t1+cfg.afterscan)) {
		normalend=1;
	    }
	}

    } while (
	    (!normalend)&&(!stop_flag));

    close(rfd);
    if (cfg.verbose>1) {
	if (!stop_flag) printf("Child is dead\n");
	else printf("STOP flagged\n");
    }

    if (stop_flag) return(1);

    return (0);
}


int scan_list() {
    int			sfd;
    u_char		*packet;
    int			plength,i,j;
    iphdr_t		*ip;
    target_t		*tgt;

    /* initialize sockets ... */
    if ((sfd=init_socket_IP4(cfg.device,0))<0) {
	fprintf(stderr,"Could not grab a socket\n");
	return(-1);
    }
    /* pre-make IP packet */
    packet=smalloc(sizeof(iphdr_t)+PADDING+1);
    plength=sizeof(iphdr_t)+PADDING;

    ip=(iphdr_t *)packet;
    ip->version=4;
    ip->ihl=sizeof(iphdr_t)/4;
    ip->tot_len=htons(plength);
    ip->ttl=60;
    ip->id=htons(IP_ID);
    memcpy(&(ip->saddr.s_addr),&(packet_ifconfig.ip.s_addr),IP_ADDR_LEN);

    /* for syncronisation */
    sleep(1);

    tgt=anchor;
    while (tgt!=NULL) {

	if (cfg.verbose) printf("Scanning %s\n",inet_ntoa(tgt->addr));
	/* scan all protocols */
	for (i=0;i<=PROTOCOLS;i++) {
	    if (cfg.verbose>2) printf("\tprotocol %s\n",prts[i].keyword);
	    /* complete the IP packet */
	    ip->protocol=i;
	    memcpy(&(ip->daddr.s_addr),&(tgt->addr),IP_ADDR_LEN);

	    for (j=0;j<cfg.probes;j++) {
		sendpack_IP4(sfd,packet,plength);
		if (cfg.slowscan) {
		    sleep(cfg.sleeptime);
		} else {
		    if (i%cfg.sleeptime==0) {
			usleep(100000);
		    }
		}
	    }

	}
	tgt=tgt->next;
	if (cfg.slowscan) {
	    sleep(cfg.sleeptime*3);
	} else {
	    sleep(1);
	}
    }

    close(sfd);
    if (cfg.verbose>1) printf("Child finished\n");
    return (0);
}

int is_there(struct in_addr *t) {
    target_t	*c;

    if ((c=anchor)==NULL) return 0;
    while (c!=NULL) {
	if (memcmp(&(c->addr),t,4)==0) return 1;
	c=c->next;
    }
    return 0;
}

int print_targets() {
    target_t	*c;

    if ((c=anchor)==NULL) return 0;
    while (c!=NULL) {
	printf("TARGET\t%s\n",inet_ntoa(c->addr));
	c=c->next;
    }
    return 0;
}

int create_target_list(void) {
    int			sfd;
    target_t		*current,*new;
    u_int32_t		tnet,tnet2,l;
    char		*tp,*tp2;
    struct in_addr	n,m,mm;
    int			i;
    unsigned long int	t1;
    int			ppp;
#define PINGTIMEOUT	10
#define PING_ROUND	3

    anchor=NULL;
    if (!strchr(cfg.dest,'/')) {

	if (inet_aton(cfg.dest,&n)==0) {
	    fprintf(stderr,"%s seems to be a bad destination\n",cfg.dest);
	    return (-1);
	}
	if (!cfg.dontping) {
	    if (icmp_ping(&(n),PING_TIMEOUT,cfg.verbose)!=0) {
		fprintf(stderr,"single target not responding\n");
		return (-1);
	    }
	}

	/* this is just one */
	anchor=smalloc(sizeof(target_t));
	memcpy(&(anchor->addr),&(n),sizeof(struct in_addr));
	for (i=0;i<PROTOCOLS-1;i++) anchor->p[i]=1;

    } else {
	u_int32_t	q = 0xFFFFFFFF;
	int		lx1,lx2;
	/* multiple targets ....
	 * first, we have to figure out where ... */
	tp=smalloc(strlen(cfg.dest)+1);
	strcpy(tp,cfg.dest);
	tp2=strchr(tp,'/');
	tp2[0]='\0';
	tp2++;

	if (!strchr(tp2,'.')) {
	    lx1=atoi(tp2);
	    for (lx2=32;lx2>lx1;lx2--) q=q<<1; 
	    q=htonl(q);
	    memcpy(&(m.s_addr),&q,4);
	    if (cfg.verbose>2) printf("\tNetmask: %s\n",inet_ntoa(m));
	} else {
	    if (inet_aton(tp2,&m)==0) {
		fprintf(stderr,"%s seems to be a stange mask\n",tp2);
		return (-1);
	    }
	}
	memcpy(&mm,&m,sizeof(m));

	if (inet_aton(tp,&n)==0) {
	    fprintf(stderr,"%s seems to be a stange network address\n",tp);
	    return (-1);
	}

	/* calculate first and last address. */
	tnet = ntohl(  n.s_addr&m.s_addr  );
	tnet2= ntohl(  (m.s_addr^0xFFFFFFFF)|n.s_addr  );

	/* show addresses we are going to scan */
	if (cfg.verbose) {
	    n.s_addr=htonl(tnet);
	    m.s_addr=htonl(tnet2);
	    printf("Scanning from %s ",inet_ntoa(n));
	    printf("to %s\n",inet_ntoa(m));
	}

	/* add the records to the target list */
	t1=(unsigned long int)time(NULL);
	ppp=0;
	l=tnet;
	current=NULL;

	if ((sfd=socket(AF_INET,SOCK_RAW,IPPROTO_ICMP))<0) {
	    perror("socket()");
	    return(-1);
	}
	if (makebcast(sfd)!=0) return(-1);
	makenonblock(sfd);

	while ((!cfg.dontping)&&
		((unsigned long int)time(NULL)<(t1+PINGTIMEOUT)) ) {
            struct sockaddr_in  sin,fromaddr;
	    u_char                      *tpacket;
	    icmp_ping_t                 *pingh;
	    int                         psize;
	    u_int16_t                   pident;
	    int                         rc,addrsize;


	    psize=sizeof(icmp_ping_t);
	    tpacket=(u_char *)smalloc(sizeof(icmp_ping_t)+64);
            pident=0xAF0D;
	    /* make up the icmp header */
	    pingh=(icmp_ping_t *)tpacket;
	    pingh->icmp.type=ICMP_ECHO;
	    pingh->icmp.code=0;
	    pingh->echo.identifier=htons(pident);
	    pingh->icmp.checksum=chksum((u_char *)pingh,psize);

	    memset(&sin,0,sizeof(struct sockaddr_in));
	    sin.sin_family=AF_INET;
	    sin.sin_port=htons(0);

	    if (ppp<PING_ROUND) l++;
	    if (l>tnet2) { 
		l=tnet; ppp++; 
		if (cfg.verbose>1) printf("ping round is at %d\n",ppp);
	    }
	    n.s_addr=htonl(l);
	    usleep(10000);

	    if (ppp<PING_ROUND) {
		memcpy(&(sin.sin_addr),&n,sizeof(sin.sin_addr));
		if (sendto(sfd,tpacket,psize,0,
			(struct sockaddr *) &sin,
			sizeof(struct sockaddr_in)) <0) {
		    perror("sendto()");
		    return(-1);
		}
	    }

	    memset(&fromaddr,0,sizeof(struct sockaddr_in));
	    addrsize=sizeof(struct sockaddr_in);
	    memset(tpacket,0,psize);

	    if ((rc=recvfrom(sfd,(u_char *)tpacket,psize,0,
		    (struct sockaddr *)&fromaddr,
		    &addrsize))>=0) {
		pingh=(icmp_ping_t *)(tpacket+sizeof(iphdr_t));

		if (pingh->icmp.type==ICMP_ECHOREPLY) {
		    if (ntohs(pingh->echo.identifier)==pident) {
			/* normal response */
			if (cfg.verbose>1)
			    printf("%s respond ... good\n",
				inet_ntoa(fromaddr.sin_addr));

			if ( /* same network check */
			    (n.s_addr&mm.s_addr)==
			    (fromaddr.sin_addr.s_addr&mm.s_addr)
			    ) {
			    /* add the record of who respond */
			    if (is_there(&(fromaddr.sin_addr))==0) {
				new=current;
				current=smalloc(sizeof(target_t));
				memcpy(&(current->addr),&(fromaddr.sin_addr),
					sizeof(struct in_addr));
				for (i=0;i<PROTOCOLS-1;i++) current->p[i]=1;
				if (new==NULL) { new=current; } 
				else { new->next=current; }
				if (anchor==NULL) { anchor=current; }
			    } /* is_there check */
			} /* same network */ else {
			    printf("echo reply from system"
				    " outside range (%s)\n",
				    inet_ntoa(fromaddr.sin_addr));
			} /* not same network */
		    } /* ping ID */
		} /* end of echo reply */
	    } /* end of packet found */
	} /* while time */
	close(sfd);
    } /* if more then one */

    if (anchor==NULL) return(-1);

    return 0;
}



void signaler(int sig) {
    stop_flag=1;
}

void usage(void) {
    printf(
     "Usage: ./protos -i eth0 -d 10.1.2.3 -v\n"
     "-v             verbose\n"
     "-V             show which protocols are not supported\n"
     "-u             don't ping targets first\n"
     "-s             make the scan slow (for very remote devices)\n"
     "-L             show the long protocol name and it's reference (RFC)\n"
     "-p x           number of probes (default=5)\n"
     "-S x           sleeptime is x (default=1)\n"
     "-a x           continue scan afterwards for x seconds (default=3)\n"
     "-d dest        destination (IP or IP/MASK)\n"
     "-i interface   the eth0 stuff\n"
     "-W             don't scan, just print the protocol list\n"
				);
    exit(1);
}
