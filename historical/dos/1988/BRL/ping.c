/*
 *			P I N G . C
 *
 * Using the InterNet Control Message Protocol (ICMP) "ECHO" facility,
 * measure round-trip-delays and packet loss across network paths.
 *
 * Author -
 *	Mike Muuss
 *	U. S. Army Ballistic Research Laboratory
 *	December, 1983
 * Modified at Uc Berkeley
 * Record Route and verbose headers - Phil Dykstra, BRL, March 1988.
 *
 * Status -
 *	Public Domain.  Distribution Unlimited.
 *
 * Bugs -
 *	More statistics could always be gathered.
 *	This program has to run SUID to ROOT to access the ICMP socket.
 */

#include <stdio.h>
#include <errno.h>
#include <sys/time.h>

#include <sys/param.h>
#include <sys/socket.h>
#include <sys/file.h>

#include <netinet/in_systm.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netdb.h>

#define	PING_MAXWAIT	10	/* max time to wait for response, sec. */
#define	PING_MAXPACKET	4096	/* max packet size */
#define PING_NUMERIC	1	/* return dotted quads */
#define PING_VERBOSE	2	/* verbose flag */
#define PING_QUIET	4	/* quiet flag */
#define PING_DEBUG	8	/* turn on socket debugging */
#define PING_DONTROUTE	16	/* dont route pings*/
#define	PING_RROUTE	32	/* record route flag */
#define PING_FLOOD	64	/* floodping flag */
#define PING_CISCO	128	/* cisco style ping */
#define	PING_NROUTES	9	/* number of record route slots (9 max) */
#ifndef MAXHOSTNAMELEN
#define MAXHOSTNAMELEN	64
#endif

u_char	packet[PING_MAXPACKET];
int	i, pingflags;
extern	int errno;

int s;			/* Socket file descriptor */
struct hostent *hp;	/* Pointer to host info */
struct timezone tz;	/* leftover */

struct sockaddr whereto;/* Who to ping */
int datalen;		/* How much data */

char usage[] =
"Usage:  ping [-cdfnqrvR] host [packetsize [count [preload]]]\n";

char *hostname;
char hnamebuf[MAXHOSTNAMELEN];

int npackets;
int preload = 0;		/* number of packets to "preload" */
int ntransmitted = 0;		/* sequence # for outbound packets = #sent */
int ident;

int nreceived = 0;		/* # of packets we got back */
int timing = 0;
int tmin = 999999999;
int tmax = 0;
int tsum = 0;			/* sum of all times, for doing average */
int finish(), catcher();
char *inet_ntoa();
char *pr_addr();

char rspace[3+4*PING_NROUTES+1];	/* record route space */

/*
 * 			M A I N
 */
main(argc, argv)
char *argv[];
{
	char **av = argv;
	int on = 1;

	struct sockaddr_in pktaddr;
	struct sockaddr_in *to = (struct sockaddr_in *) &whereto;
	struct protoent *proto;
	int maxpkt = sizeof (packet);
	int addrlen = sizeof (pktaddr);
	int rcvlen, nfds, fdmask;

	struct timeval timeout;
	timeout.tv_sec = 0;
	timeout.tv_usec = 10000;

         	argc--, av++;
	while (argc > 0 && *av[0] == '-') {
		while (*++av[0]) switch (*av[0]) {
			case 'c':
				pingflags |= PING_CISCO;
				break;
			case 'd':
				pingflags |= PING_DEBUG;
				break;
			case 'f':
				pingflags |= PING_FLOOD;
				/* timeout.tv_usec = 0; */
				break;
			case 'n':
				pingflags |= PING_NUMERIC;
				break;
			case 'q':
				pingflags |= PING_QUIET;
				break;
			case 'r':
				pingflags |= PING_DONTROUTE;
				break;
			case 'v':
				pingflags |= PING_VERBOSE;
				break;
			case 'R':
				pingflags |= PING_RROUTE;
				break;
		}
		argc--, av++;
	}
	if(argc < 1 || argc > 4)  {
		printf(usage);
		exit(1);
	}

	bzero((char *)&whereto, sizeof(struct sockaddr) );
	to->sin_family = AF_INET;
	to->sin_addr.s_addr = inet_addr(av[0]);
	if(to->sin_addr.s_addr != (unsigned)-1) {
		strcpy(hnamebuf, av[0]);
		hostname = hnamebuf;
	} else {
		hp = gethostbyname(av[0]);
		if (hp) {
			to->sin_family = hp->h_addrtype;
			bcopy(hp->h_addr, (caddr_t)&to->sin_addr, hp->h_length);
			strncpy( hnamebuf, hp->h_name, sizeof(hnamebuf)-1 );
			hostname = hnamebuf;
		} else {
			printf("%s: unknown host %s\n", argv[0], av[0]);
			exit(1);
		}
	}

	if( argc >= 2 )
		datalen = atoi( av[1] );
	else
		datalen = 64-8;
	if (datalen > PING_MAXPACKET) {
		fprintf(stderr, "ping: packet size too large\n");
		exit(1);
	}
	if (datalen >= sizeof(struct timeval))	/* can we time 'em? */
		timing = 1;

	if (argc >= 3)
		npackets = atoi(av[2]);

	if (argc == 4)
		preload = atoi(av[3]);

	ident = getpid() & 0xFFFF;

	if ((proto = getprotobyname("icmp")) == NULL) {
		fprintf(stderr, "icmp: unknown protocol\n");
		exit(10);
	}
	if ((s = socket(AF_INET, SOCK_RAW, proto->p_proto)) < 0) {
		perror("ping: socket");
		exit(5);
	}
	fdmask = 1 << s;
	nfds = s + 1;

	if (pingflags & PING_DEBUG) {
		setsockopt(s, SOL_SOCKET, SO_DEBUG, &on, sizeof(on));
	}
	if (pingflags & PING_DONTROUTE) {
		setsockopt(s, SOL_SOCKET, SO_DONTROUTE, &on, sizeof(on));
	}
	/* Record Route option */
	if( pingflags & PING_RROUTE ) {
#ifdef IP_OPTIONS
		rspace[IPOPT_OPTVAL] = IPOPT_RR;
		rspace[IPOPT_OLEN] = sizeof(rspace)-1;
		rspace[IPOPT_OFFSET] = IPOPT_MINOFF;
		if( setsockopt(s, IPPROTO_IP, IP_OPTIONS, rspace, sizeof(rspace)) < 0 ) {
			perror( "Record route" );
			exit( 42 );
		}
#else /* IP_OPTIONS */
		fprintf( stderr, "ping: record route not available on this machine.\n" );
		exit( 42 );
#endif /* IP_OPTIONS */
	}

	if(to->sin_family == AF_INET) {
		printf("PING %s (%s): %d data bytes\n", hostname,
		  inet_ntoa(to->sin_addr.s_addr), datalen);
	} else {
		printf("PING %s: %d data bytes\n", hostname, datalen );
	}
	setlinebuf( stdout );

	signal( SIGINT, finish );
	signal(SIGALRM, catcher);

	/* fire off them quickies */
	for(i=0; i < preload; i++)
		pinger();

	if(pingflags & PING_FLOOD) {
		for (;;) {
			pinger();
			if( select(32, &fdmask, 0, 0, &timeout) == 0)
				continue;
			if((rcvlen = recvfrom(s, packet, maxpkt, 0,
			  &pktaddr, &addrlen)) < 0) {
				if( errno != EINTR )
					perror("\nping: recvfrom");
				continue;
			}
			pr_pack( packet, rcvlen, &pktaddr );
			if (npackets && nreceived >= npackets)
				finish();
		}
	} else if(pingflags & PING_CISCO) {
		for(;;) {
			alarm(1);
			pinger();
			if((rcvlen = recvfrom(s, packet, maxpkt, 0,
			  &pktaddr, &addrlen)) < 0) {
				if( errno != EINTR )
					perror("\nping: recvfrom");
			}
			pr_pack( packet, rcvlen, &pktaddr );
			if (npackets && nreceived >= npackets)
				finish();
		}
	} else {
		catcher();	/* start things going */
		for (;;) {
			if((rcvlen = recvfrom(s, packet, maxpkt, 0,
			  &pktaddr, &addrlen)) < 0) {
				if( errno == EINTR )
					continue;
				perror("ping: recvfrom");
				continue;
			}
			pr_pack( packet, rcvlen, &pktaddr );
			if (npackets && nreceived >= npackets)
				finish();
		}
	}
	/*NOTREACHED*/
}

/*
 * 			C A T C H E R
 * 
 * This routine causes another PING to be transmitted, and then
 * schedules another SIGALRM for 1 second from now.
 * 
 * Bug -
 * 	Our sense of time will slowly skew (ie, packets will not be launched
 * 	exactly at 1-second intervals).  This does not affect the quality
 *	of the delay and loss statistics.
 */
catcher()
{
	int waittime;

	if(pingflags & PING_CISCO) {
		putchar('!');
		fflush(stdout);
	}
	pinger();
	if (npackets == 0 || ntransmitted < npackets)
		alarm(1);
	else {
		if (nreceived) {
			waittime = 2 * tmax / 1000;
			if (waittime == 0)
				waittime = 1;
		} else
			waittime = PING_MAXWAIT;
		signal(SIGALRM, finish);
		alarm(waittime);
	}
}

/*
 * 			P I N G E R
 * 
 * Compose and transmit an ICMP ECHO REQUEST packet.  The IP packet
 * will be added on by the kernel.  The ID field is our UNIX process ID,
 * and the sequence number is an ascending integer.  The first 8 bytes
 * of the data portion are used to hold a UNIX "timeval" struct in VAX
 * byte-order, to compute the round-trip time.
 */
pinger()
{
	static u_char outpack[PING_MAXPACKET];
	register struct icmp *icp = (struct icmp *) outpack;
	int i, cc;
	register struct timeval *tp = (struct timeval *) &outpack[8];
	register u_char *datap = &outpack[8+sizeof(struct timeval)];

	icp->icmp_type = ICMP_ECHO;
	icp->icmp_code = 0;
	icp->icmp_cksum = 0;
	icp->icmp_seq = ntransmitted++;
	icp->icmp_id = ident;		/* ID */

	cc = datalen+8;			/* skips ICMP portion */

	if (timing)
		gettimeofday( tp, &tz );

	for( i=8; i<datalen; i++)	/* skip 8 for time */
		*datap++ = i;

	/* Compute ICMP checksum here */
	icp->icmp_cksum = in_cksum( icp, cc );

	/* cc = sendto(s, msg, len, flags, to, tolen) */
	i = sendto( s, outpack, cc, 0, &whereto, sizeof(struct sockaddr) );

	if( i < 0 || i != cc )  {
		if( i<0 )  perror("sendto");
		printf("ping: wrote %s %d chars, ret=%d\n",
			hostname, cc, i );
		fflush(stdout);
	}
	if(pingflags & PING_FLOOD) {
		putchar('.');
		fflush(stdout);
	}
}

/*
 *			P R _ P A C K
 *
 * Print out the packet, if it came from us.  This logic is necessary
 * because ALL readers of the ICMP socket get a copy of ALL ICMP packets
 * which arrive ('tis only fair).  This permits multiple copies of this
 * program to be run without having intermingled output (or statistics!).
 */
pr_pack( buf, cc, from )
char *buf;
int cc;
struct sockaddr_in *from;
{
	struct ip *ip;
	register struct icmp *icp;
	register long *lp = (long *) packet;
	register int i;
	struct timeval tv;
	struct timeval *tp;
	int hlen, triptime;

	from->sin_addr.s_addr = ntohl( from->sin_addr.s_addr );
	gettimeofday( &tv, &tz );

	/* Check the IP header */
	ip = (struct ip *) buf;
	hlen = ip->ip_hl << 2;
	if( cc < hlen + ICMP_MINLEN ) {
		if( pingflags & PING_VERBOSE )
			printf("packet too short (%d bytes) from %s\n", cc,
				inet_ntoa(ntohl(from->sin_addr.s_addr)));
		return;
	}

	/* Now the ICMP part */
	cc -= hlen;
	icp = (struct icmp *)(buf + hlen);
	if( icp->icmp_type == ICMP_ECHOREPLY ) {
		if( icp->icmp_id != ident )
			return;			/* 'Twas not our ECHO */

		nreceived++;
		if (timing) {
			tp = (struct timeval *)&icp->icmp_data[0];
			tvsub( &tv, tp );
			triptime = tv.tv_sec*1000+(tv.tv_usec/1000);
			tsum += triptime;
			if( triptime < tmin )
				tmin = triptime;
			if( triptime > tmax )
				tmax = triptime;
		}

		if( pingflags & PING_QUIET)
			return;

		if( pingflags & PING_FLOOD) {
			putchar('\b');
			fflush(stdout);
		} else if( pingflags & PING_CISCO) {
			putchar('.');
			fflush(stdout);
		} else {
			printf("%d bytes from %s: icmp_seq=%d", cc,
			  inet_ntoa(ntohl(from->sin_addr.s_addr)),
			  icp->icmp_seq );
			if (timing)
				printf(" time=%d ms\n", triptime );
			else
				putchar('\n');
		}
	} else {
		/* We've got something other than an ECHOREPLY */
		if( !(pingflags & PING_VERBOSE) )
			return;

		printf("%d bytes from %s: ",
		  cc, pr_addr(ntohl(from->sin_addr.s_addr)) );
		pr_icmph( icp );
	}

	/* Display any IP options */
	/* XXX - we should eventually do this for all packets with options */
	if( hlen > 20 && icp->icmp_type == ICMP_ECHOREPLY ) {
		unsigned char *cp;
		/*printf("%d byte IP header:\n", hlen);*/
		cp = (unsigned char *)buf + sizeof(struct ip) + 3;
		for( i = 0; i < PING_NROUTES; i++ ) {
			unsigned long l;
			l = (*cp<<24) | (*(cp+1)<<16) | (*(cp+2)<<8) | *(cp+3);
			/* give the nameserver a break! */
			if( l == 0 )
				printf("0.0.0.0\n");
			else
				printf("%s\n", pr_addr(ntohl(l)) );
			cp += 4;
		}
	}
}

/*
 *			I N _ C K S U M
 *
 * Checksum routine for Internet Protocol family headers (C Version)
 *
 */
in_cksum(addr, len)
u_short *addr;
int len;
{
	register int nleft = len;
	register u_short *w = addr;
	register int sum = 0;
	u_short answer = 0;

	/*
	 *  Our algorithm is simple, using a 32 bit accumulator (sum),
	 *  we add sequential 16 bit words to it, and at the end, fold
	 *  back all the carry bits from the top 16 bits into the lower
	 *  16 bits.
	 */
	while( nleft > 1 )  {
		sum += *w++;
		nleft -= 2;
	}

	/* mop up an odd byte, if necessary */
	if( nleft == 1 ) {
		*(u_char *)(&answer) = *(u_char *)w ;
		sum += answer;
	}

	/*
	 * add back carry outs from top 16 bits to low 16 bits
	 */
	sum = (sum >> 16) + (sum & 0xffff);	/* add hi 16 to low 16 */
	sum += (sum >> 16);			/* add possible carry */
	answer = ~sum;		/* ones complement & truncate to 16 bits */
	return (answer);
}

/*
 * 			T V S U B
 * 
 * Subtract 2 timeval structs:  out = out - in.
 * 
 * Out is assumed to be >= in.
 */
tvsub( out, in )
register struct timeval *out, *in;
{
	if( (out->tv_usec -= in->tv_usec) < 0 )   {
		out->tv_sec--;
		out->tv_usec += 1000000;
	}
	out->tv_sec -= in->tv_sec;
}

/*
 *			F I N I S H
 *
 * Print out statistics, and give up.
 * Heavily buffered STDIO is used here, so that all the statistics
 * will be written with 1 sys-write call.  This is nice when more
 * than one copy of the program is running on a terminal;  it prevents
 * the statistics output from becomming intermingled.
 */
finish()
{
	putchar('\n');
	fflush(stdout);
	printf("\n----%s PING Statistics----\n", hostname );
	printf("%d packets transmitted, %d packets received",
	  ntransmitted, nreceived);
	if (ntransmitted)
		if( nreceived > ntransmitted)
			printf(" -- somebody's printing up packets!\n");
		else
			printf(", %d%% packet loss\n", 
			  (int) (((ntransmitted-nreceived)*100) /
			  ntransmitted));
	if (nreceived && timing)
		printf("round-trip (ms)  min/avg/max = %d/%d/%d\n",
		  tmin, tsum / nreceived, tmax);
	fflush(stdout);
	if (nreceived)
		exit(0);
	else
		exit(1);
}

static char *ttab[] = {
	"Echo Reply",		/* ip + seq + udata */
	"Dest Unreachable",	/* net, host, proto, port, frag, sr + IP */
	"Source Quench",	/* IP */
	"Redirect",		/* redirect type, gateway, + IP  */
	"Echo",
	"Time Exceeded",	/* transit, frag reassem + IP */
	"Parameter Problem",	/* pointer + IP */
	"Timestamp",		/* id + seq + three timestamps */
	"Timestamp Reply",	/* " */
	"Info Request",		/* id + sq */
	"Info Reply"		/* " */
};

/*
 *  Print a descriptive string about an ICMP header.
 */
pr_icmph( icp )
struct icmp *icp;
{
	switch( icp->icmp_type ) {
	case ICMP_ECHOREPLY:
		printf("Echo Reply\n");
		/* XXX ID + Seq + Data */
		break;
	case ICMP_UNREACH:
		switch( icp->icmp_code ) {
		case ICMP_UNREACH_NET:
			printf("Destination Network Unreachable\n");
			break;
		case ICMP_UNREACH_HOST:
			printf("Destination Host Unreachable\n");
			break;
		case ICMP_UNREACH_PROTOCOL:
			printf("Destination Protocol Unreachable\n");
			break;
		case ICMP_UNREACH_PORT:
			printf("Destination Port Unreachable\n");
			break;
		case ICMP_UNREACH_NEEDFRAG:
			printf("Fragmentation needed and DF set\n");
			break;
		case ICMP_UNREACH_SRCFAIL:
			printf("Source Route Failed\n");
			break;
		default:
			printf("Dest Unreachable, Bad Code: 0x%x\n", icp->icmp_code );
			break;
		}
		/* Print returned IP header information */
		pr_retip( icp->icmp_data );
		break;
	case ICMP_SOURCEQUENCH:
		printf("Source Quench\n");
		pr_retip( icp->icmp_data );
		break;
	case ICMP_REDIRECT:
		switch( icp->icmp_code ) {
		case ICMP_REDIRECT_NET:
			printf("Network Redirect");
			break;
		case ICMP_REDIRECT_HOST:
			printf("Host Redirect");
			break;
		case ICMP_REDIRECT_TOSNET:
			printf("Type of Service and Network Redirect");
			break;
		case ICMP_REDIRECT_TOSHOST:
			printf("Type of Service and Host Redirect");
			break;
		default:
			printf("Redirect, Bad Code: 0x%x", icp->icmp_code );
			break;
		}
		printf(" (New addr: 0x%08x)\n", icp->icmp_hun.ih_gwaddr );
		pr_retip( icp->icmp_data );
		break;
	case ICMP_ECHO:
		printf("Echo Request\n");
		/* XXX ID + Seq + Data */
		break;
	case ICMP_TIMXCEED:
		switch( icp->icmp_code ) {
		case ICMP_TIMXCEED_INTRANS:
			printf("Time to live exceeded in transit\n");
			break;
		case ICMP_TIMXCEED_REASS:
			printf("Fragment reassembly time exceeded\n");
			break;
		default:
			printf("Time exceeded, Bad Code: 0x%x\n", icp->icmp_code );
			break;
		}
		pr_retip( icp->icmp_data );
		break;
	case ICMP_PARAMPROB:
		switch( icp->icmp_code ) {
		case 0:
			printf("Parameter problem: error detected at byte 0x%02x\n",
			  icp->icmp_hun.ih_pptr );
		default:
			printf("Unspecified parameter problem\n");
		}
		pr_retip( icp->icmp_data );
		break;
	case ICMP_TSTAMP:
		printf("Timestamp\n");
		/* XXX ID + Seq + 3 timestamps */
		break;
	case ICMP_TSTAMPREPLY:
		printf("Timestamp Reply\n");
		/* XXX ID + Seq + 3 timestamps */
		break;
	case ICMP_IREQ:
		printf("Information Request\n");
		/* XXX ID + Seq */
		break;
	case ICMP_IREQREPLY:
		printf("Information Reply\n");
		/* XXX ID + Seq */
		break;
	case ICMP_MASKREQ:
		printf("Address Mask Request\n");
		break;
	case ICMP_MASKREPLY:
		printf("Address Mask Reply\n");
		break;
	default:
		printf("Bad ICMP type: 0x%x\n", icp->icmp_type);
	}
}

/*
 *  Print an IP header with options.
 */
pr_iph( ip )
struct ip *ip;
{
	int	hlen;
	unsigned char *cp;

	hlen = ip->ip_hl << 2;
	cp = (unsigned char *)ip + 20;	/* point to options */

	printf("Vr HL TOS Len  ID   Flg Off  TTL Pro Cksm Src      Dst      Data\n");
	printf("%1x  %1x  %02x  %04x %04x %1x   %04x %02x  %02x  %04x %08x %08x",
	  ip->ip_v, ip->ip_hl, ip->ip_tos, ip->ip_len, ip->ip_id,
	  ((ip->ip_off)&0xe000)>>13, (ip->ip_off)&0x1fff, ip->ip_ttl, ip->ip_p,
	  ip->ip_sum, ntohl(ip->ip_src.s_addr), ntohl(ip->ip_dst.s_addr));
	/* dump and option bytes */
	while( hlen-- > 20 ) {
		printf( "%02x", *cp++ );
	}
	printf("\n");
}

/*
 *  Return an ascii host address
 *  as a dotted quad and optionally with a hostname
 */
char *
pr_addr( l )
unsigned long l;
{
	struct	hostent	*hp;
	static	char	buf[80];

	if((pingflags & PING_NUMERIC) ||
	  (hp = gethostbyaddr(&l, 4, AF_INET)) == NULL )
		sprintf( buf, "%s", inet_ntoa(l) );
	else
		sprintf( buf, "%s (%s)", hp->h_name, inet_ntoa(l) );

	return( buf );
}

/*
 *  Dump some info on a returned (via ICMP) IP packet.
 */
pr_retip( ip )
struct ip *ip;
{
	int	hlen;
	unsigned char	*cp;

	pr_iph( ip );
	hlen = ip->ip_hl << 2;
	cp = (unsigned char *)ip + hlen;

	if( ip->ip_p == 6 ) {
		printf( "TCP: from port %d, to port %d (decimal)\n",
			(*cp*256+*(cp+1)), (*(cp+2)*256+*(cp+3)) );
	} else if( ip->ip_p == 17 ) {
		printf( "UDP: from port %d, to port %d (decimal)\n",
			(*cp*256+*(cp+1)), (*(cp+2)*256+*(cp+3)) );
	}
}
