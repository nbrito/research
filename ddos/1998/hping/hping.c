/*
 * hping.c
 * Copyright (C) 1998 Salvatore Sanfilippo - antirez - <md5330 () mclink it>
 *                                                    <antirez () seclab com>
 * This source is covered by the GNU GPL
 * alpha version, last update 04/12/98
 * compile it under linux. (Do you want make a porting?, mail me please)
 *
 * Intesis SECURITY LAB            Phone: +39-02-671563.1
 * Via Settembrini, 35             Fax: +39-02-66981953
 * I-20124 Milano  ITALY           Email: antirez () seclab com
 */

#define _BSD_SOURCE

#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <netinet/in.h>
#include <netinet/ip_icmp.h>
#include <netdb.h>
#include <unistd.h>
#include <sys/ioctl.h>
#ifdef __GLIBC__                /* please, if this #ifdef doesn't work */
                                /* with some Linux distr. email me.    */
#include <netinet/if_ether.h>   /* tested on Debian 2.0 */
#else
#include <linux/if_ether.h>     /* tested on RedHat 4.1 */
#endif
#include <net/if_arp.h>
#include <net/if.h>
#include <signal.h>
#include <time.h>
#include <sys/time.h>
#include <errno.h>

/* usefull defines */
#ifndef TRUE
#define TRUE    1
#define FALSE   0
#endif
#ifndef IFNAMSIZ
#define IFNAMSIZ 16
#endif

/* header size of some physical layer type */
#define PPPHDR_SIZE     0
#define ETHHDR_SIZE     sizeof(struct ethhdr)
#define LOHDR_SIZE      sizeof(struct ethhdr)
#define UNKNOWNHDR_SIZE 0

/* packet size (physical header size + ip header + tcp header + 0 data bytes) */
#define LINK_PACKETSIZE ( linkhdr_size +        \
                          sizeof(struct iphdr)+ \
                          sizeof(struct tcphdr) )
/* ip packet size */
#define IP_PACKETSIZE   ( sizeof(struct iphdr) + sizeof(struct tcphdr) )

/* absolute offsets */
#define ABS_OFFSETLINK  0
#define ABS_OFFSETIP    linkhdr_size
#define ABS_OFFSETTCP   ( linkhdr_size + sizeof(struct iphdr) )
#define ABS_OFFSETICMP  ( linkhdr_size + sizeof(struct iphdr) )

/* ip realtive offsets */
#define IP_OFFSETIP     0
#define IP_OFFSETTCP    sizeof(struct iphdr)

/* defaults */
#define DEFAULT_SENDINGWAIT 1   /* wait 1 sec. between sending each packets */
#define DEFAULT_DPORT       0
#define DEFAULT_COUNT      -1   /* -1 == forever */
#define DEFAULT_TTL        64

/* fragmentation macros */
#define MORE_FRAGMENTS ((unsigned short)0x2000)
#define NO_MORE_FRAGMENTS ((unsigned short)0x0000)

/* globals var
*/
unsigned int tcp_th_flags = 0;
int     sockpacket, sockraw,                    /* sockets fd */
        finsent = 0, rstrecv = 0,               /* fin sent & reset received */
        sending_wait = DEFAULT_SENDINGWAIT,     /* see DEFAULT_SENDINGWAIT def*/
        linkhdr_size,                           /* physical layer header size */
        opt_numeric     = FALSE,
        opt_quiet       = FALSE,
        fragmentation   = FALSE,
        src_ttl         = DEFAULT_TTL,
        dport           = DEFAULT_DPORT,
        sport,
        initsport,
        count           = DEFAULT_COUNT;
char    targetname[1024],                       /* target hostname */
        targetstraddr[1024],
        ifname[1024] = {'\0'},                  /* interface name */
        ifstraddr[1024];                        /* interface address */
struct sockaddr_in local, remote;
struct delaytable_element {
        int seq;
        int sec;
        long usec;
};
volatile struct delaytable_element delaytable[20];
int     delaytable_index = 0;

/* protos
*/
int     parse_options(int, char**);             /* parse command line options */
int     get_if_name(void);                      /* get interface name & addr. */
int     get_linkhdrsize(char*);                 /* get link layer hdr size */
int     open_sockpacket(void);                  /* open SOCK_PACKET socket */
int     close_sockpacket(int);                  /* close SOCK_PACKET socket */
int     open_sockraw(void);                     /* open SOCK_RAW socket */
void    sendfin(int);                           /* send one FIN */
void    ip_sender (char*, char*, char*, unsigned int, int, unsigned short);
void    waitresets(void);                       /* wait RST replies */
void    print_statistics(int);                  /* print statistics */
void    usage(void);                            /* shows a short help */
void    resolver(struct sockaddr*, char*);      /* resolver */
void    icmpunreach_log(char*, unsigned short); /* logs icmp ureached */
void    icmptimeexc_log(char*, unsigned short); /* logs icmp time exc */
long    get_utime(void);                        /* return current usec */
u_short cksum(u_short *buf, int nwords);        /* compute 16bit checksum */

/* main
*/
int main(int argc, char **argv)
{
        if ( parse_options(argc, argv) == -1 ) usage();

        /* get interface's name and address */
        if ( get_if_name() == -1 ) {
                printf("[main] no such device\n");
                exit(1);
        }

        if ( get_linkhdrsize(ifname) == -1 ) {
                printf("[main] physical layer header size unknown\n");
                exit(1);
        }

        /* trying to open sockpacket socket and raw socket */
        sockraw = open_sockraw();
        if (sockraw == -1) {
                printf("[main] can't open raw socket\n");
                exit(1);
        }

        sockpacket = open_sockpacket();
        if (sockpacket == -1) {
                printf("[main] can't open packet socket\n");
                exit(1);
        }

        resolver((struct sockaddr*)&local, ifstraddr);
        resolver((struct sockaddr*)&remote, targetname);

        srand(time(NULL));                      /* randomize */
        initsport = 1024 + (rand() % 2000);     /* set initial source port */
        sport = initsport;

        strncpy(targetstraddr, inet_ntoa(remote.sin_addr), sizeof(targetstraddr));
        printf("HPING %s (%s %s): %d data bytes\n", targetname, ifname, targetstraddr, IP_PACKETSIZE);

        signal(SIGALRM, sendfin);
        signal(SIGINT, print_statistics);
        signal(SIGTERM, print_statistics);
        kill(getpid(), SIGALRM);

        waitresets();

        return 0;
}

int parse_options(int argc, char **argv)
{
        char c;

        if (argc < 2) return -1;

        strncpy(targetname, argv[1], 1024);

        while ( (c = getopt(argc, argv, "c:i:nqI:hp:t:FSRPAUf")) != EOF )
        {
                switch(c)
                {
                        case '?':
                                return -1;
                        case 'c':
                                count = atoi(optarg);
                                break;
                        case 'i':
                                sending_wait = atoi(optarg);
                                break;
                        case 'n':
                                opt_numeric = TRUE;
                                break;
                        case 'q':
                                opt_quiet = TRUE;
                                break;
                        case 'I':
                                strncpy (ifname, optarg, 1024);
                                break;
                        case 'h':
                                return -1;
                        case 'p':
                                dport = atoi(optarg);
                                break;
                        case 't':
                                src_ttl = atoi(optarg);
                                break;
                        case 'F':
                                tcp_th_flags |= TH_FIN;
                                break;
                        case 'S':
                                tcp_th_flags |= TH_SYN;
                                break;
                        case 'R':
                                tcp_th_flags |= TH_RST;
                                break;
                        case 'P':
                                tcp_th_flags |= TH_PUSH;
                                break;
                        case 'A':
                                tcp_th_flags |= TH_ACK;
                                break;
                        case 'U':
                                tcp_th_flags |= TH_URG;
                                break;
                        case 'f':
                                fragmentation = TRUE;
                                break;
                }
        }

        /* force some conditions */

        if (tcp_th_flags == 0)                  /* tcp flags ain't set */
                tcp_th_flags |= TH_FIN;         /* default it's FIN */

        if (count <= 0 && count != -1) {
                printf("[parse_options] count must > 0\n");
                exit(1);
        }

        if (sending_wait <= 0) {
                printf("[prase_options] bad timing interval\n");
                exit(1);
        }
        return 1;
}

int get_if_name(void)
{
        int fd;
        struct ifconf ifc;
        struct ifreq ibuf[16], ifr, *ifrp, *ifend;
        struct sockaddr_in sa;

        if ( (fd = socket(AF_INET, SOCK_DGRAM, 0)) == -1) {
                perror("[get_if_name] socket()");
                return -1;
        }

        bzero((void*)ibuf, sizeof(ibuf));       /* reset buffer */
        ifc.ifc_len = sizeof ibuf;              /* set buffer size... */
        ifc.ifc_buf = (caddr_t) ibuf;           /* and buffer pointer */

        /* gets interfaces list */
        if ( ioctl(fd, SIOCGIFCONF, (char*)&ifc) == -1 ||
             ifc.ifc_len < sizeof(struct ifreq)         ) {
                perror("[get_if_name] ioctl()");
                return -1;
        }

        /* ifrp points to buffer and ifend points to buffer's end */
        ifrp = ibuf;
        ifend = (struct ifreq*) ((char*)ibuf + ifc.ifc_len);

        for (; ifrp < ifend; ifrp++) {
                strncpy(ifr.ifr_name, ifrp->ifr_name, sizeof(ifr.ifr_name));

                if ( ioctl(fd, SIOCGIFFLAGS, (char*)&ifr) == -1) {
                        perror("[get_if_name] ioctl()");
                        return -1;
                }

                if ( !(ifr.ifr_flags & IFF_UP) ) continue; /* if is down */
                if ( strstr(ifr.ifr_name, "lo") ) continue; /* loopback */
                if ( ifname[0] != '\0' )        /* opt -I set */
                        if ( !strstr(ifr.ifr_name, ifname) ) /* don't match */
                                continue;

                /* interface found */
                strncpy(ifname, ifr.ifr_name, 1024);
                memcpy(&sa, &(ifrp->ifr_addr), sizeof(struct sockaddr_in));
                strncpy(ifstraddr, inet_ntoa(sa.sin_addr), 1024);
                return 0;
        }
        /* interface not found, use 'lo' */
        strncpy(ifname, "lo", 1024);
        strncpy(ifstraddr, "127.0.0.1", 1024);
        return 0;
}

int get_linkhdrsize(char *ifname)
{
        if ( strstr(ifname, "ppp") )
        {
                linkhdr_size = PPPHDR_SIZE;
                return 0;
        }
        else if ( strstr(ifname, "eth") )
        {
                linkhdr_size = ETHHDR_SIZE;
                return 0;
        }
        else if ( strstr(ifname, "lo") )
        {
                linkhdr_size = LOHDR_SIZE;
                return 0;
        }
        else
                return 1;
}

int open_sockraw()
{
        int s;

        s = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
        if (s == -1) {
                perror("[open_sockraw] socket()");
                return -1;
        }

        return s;
}

int open_sockpacket()   /* set promiscuose mode for future use */
{
        int s;
        struct ifreq ifr;

        s = socket(AF_INET, SOCK_PACKET, htons(ETH_P_IP));
        if (s == -1) {
                perror("[open_sockpacket] socket()");
                return -1;
        }

        strncpy(ifr.ifr_name, ifname, sizeof(ifr.ifr_name));
        if ( ioctl(s, SIOCGIFFLAGS, &ifr) == -1) {    /* get interface flags */
                perror("[open_sockpacket] ioctl()");
                return -1;
        }
        ifr.ifr_flags |= IFF_PROMISC;   /* set promiscuose mode */
        if ( ioctl(s, SIOCSIFFLAGS, &ifr) == -1) {    /* set interface flags */
                perror("[open_sockpacket] ioctl()");
                return -1;
        }

        return s;
}

int close_sockpacket(int s)
{
        struct ifreq ifr;

        strncpy(ifr.ifr_name, ifname, IFNAMSIZ);
        if ( ioctl(s, SIOCGIFFLAGS, &ifr) == -1) {    /* get interface flags */
                perror("[open_sockpacket] ioctl()");
                return -1;
        }
        ifr.ifr_flags ^= IFF_PROMISC;   /* unset promiscuose mode */
        if ( ioctl(s, SIOCSIFFLAGS, &ifr) == -1) {    /* set interface flags */
                perror("[open_sockpacket] ioctl()");
                return -1;
        }

        return close(s);
}

void resolver (struct sockaddr * addr, char *hostname)
{
        struct  sockaddr_in *address;
        struct  hostent     *host;

        address = (struct sockaddr_in *)addr;

        bzero((char *)address, sizeof(struct sockaddr_in));
        address->sin_family = AF_INET;
        address->sin_addr.s_addr = inet_addr(hostname);

        if ( (int)address->sin_addr.s_addr == -1) {
                host = gethostbyname(hostname);
                if (host) {
                        bcopy( host->h_addr,
                        (char *)&address->sin_addr,host->h_length);
                } else {
                        perror("Could not resolve address");
                        exit(1);
                }
        }
}

void ip_sender (char* src, char* dst, char *data, unsigned int datalen, int more_fragments, unsigned short fragoff)
{
        char                    *packet;
        int                     result, packetsize;
        struct iphdr            *ip;

        packetsize = sizeof(struct iphdr) + datalen;
        if ( (packet = malloc(packetsize)) == NULL) {
                perror("[ip_sender] malloc()");
                return;
        }
        ip = (struct iphdr*) packet;

        bzero(packet, packetsize);
        /* copy src and dst address */
        bcopy(src, &ip->saddr, sizeof(ip->saddr));
        bcopy(dst, &ip->daddr, sizeof(ip->daddr));

        /* ip header */
        ip->version     = 4;
        ip->ihl         = sizeof(struct iphdr)/4;
        ip->tos         = 0;
        ip->tot_len     = htons(packetsize);
        ip->id          = htons(getpid() & 255);
        ip->frag_off    |= htons(more_fragments);
        ip->frag_off    |= htons(fragoff >> 3); /* shift three flags bit */
        ip->ttl         = src_ttl;
        ip->protocol    = 6; /* tcp */
        ip->check       = 0; /* always computed by the kernel */

        /* copies data */
        bcopy(data, packet+sizeof(struct iphdr), datalen);

        result = sendto(sockraw, packet, packetsize, 0, (struct sockaddr*)&remote, sizeof(remote));

        if (result == -1 && errno != EINTR) {
                perror("[ip_sender] sendto()");
                close(sockraw);
                close_sockpacket(sockpacket);
                exit(1);
        }
        free(packet);
}

void sendfin (int signal_id)
{
        int                     tcphdr_size;
        char                    *packet_tcphdr;
        struct tcphdr           *tcp;
        struct tcp_pseudohdr
        {
                struct in_addr saddr;
                struct in_addr daddr;
                u_char zero;
                u_char protocol;
                u_short lenght;
                struct tcphdr tcpheader;
        } pseudoheader;

        tcphdr_size = sizeof(struct tcphdr);
        if ( (packet_tcphdr = malloc(tcphdr_size)) == NULL) {
                perror("[sendfin] malloc()");
                return;
        }
        tcp =  (struct tcphdr*) packet_tcphdr;

        signal(SIGALRM, sendfin);
        bzero(packet_tcphdr, tcphdr_size);

        /* tcp header */
        tcp->th_dport   = htons(dport);
        tcp->th_sport   = htons(sport);
        tcp->th_seq     = htonl(rand());
        tcp->th_ack     = htonl(0);
        tcp->th_off     = sizeof(struct tcphdr)/4;
        tcp->th_win     = htons(512);
        tcp->th_flags   = tcp_th_flags;

        /* compute checksum */
        bzero(&pseudoheader, 12+sizeof(struct tcphdr));
        pseudoheader.saddr.s_addr = local.sin_addr.s_addr;
        pseudoheader.daddr.s_addr = remote.sin_addr.s_addr;
        pseudoheader.protocol = 6; /* tcp */
        pseudoheader.lenght = htons(sizeof(struct tcphdr));
        bcopy((char*) tcp, (char*) &pseudoheader.tcpheader, sizeof(struct tcphdr));
        tcp->th_sum = cksum((u_short*) &pseudoheader, 12+sizeof(struct tcphdr));

        if (!fragmentation)
        {
                ip_sender((char*)&local.sin_addr,(char*)&remote.sin_addr, packet_tcphdr, tcphdr_size, 
NO_MORE_FRAGMENTS, 0);
        }
        else
        {
                ip_sender((char*)&local.sin_addr,(char*)&remote.sin_addr, packet_tcphdr, 16, MORE_FRAGMENTS, 0);
                ip_sender((char*)&local.sin_addr,(char*)&remote.sin_addr, packet_tcphdr+16, 4, NO_MORE_FRAGMENTS, 16);
        }

        /* adds this fin in delaytable */
        delaytable[delaytable_index % 20].seq = sport - initsport;
        delaytable[delaytable_index % 20].sec = time(NULL);
        delaytable[delaytable_index % 20].usec = get_utime();
        delaytable_index++;     /* inc. index */

        finsent++;              /* inc. sent fin counter */

        if (count != -1 && count == finsent)    /* count reached */
                print_statistics(0);

        alarm(sending_wait);
        sport++;                /* inc. source port */
}


/* this isn't a good  general checksum algorithm, but i don't need to pad tcp's
   segments, so it's good for me. */
u_short cksum(u_short *buf, int nwords)
{
        unsigned long sum;
        u_short *w = buf;

        for (sum = 0; nwords > 0; nwords-=2)
                sum += *w++;

        sum = (sum >> 16) + (sum & 0xffff);
        sum += (sum >> 16);
        return ~sum;
}

void    waitresets(void)
{
        char    packet[LINK_PACKETSIZE+16],
                recvflags[1024];
        struct  iphdr   *ip     = (struct iphdr*) (packet + ABS_OFFSETIP);
        struct  tcphdr  *tcp    = (struct tcphdr*) (packet + ABS_OFFSETTCP);
        struct  icmphdr *icmp   = (struct icmphdr*) (packet + ABS_OFFSETICMP);
        struct  iphdr   *icmp_iph = (struct iphdr*) (packet + ABS_OFFSETICMP + 8);

        bzero((void*)packet, sizeof(packet));

        while(1)
        {
                char    src_addr[1024],
                        dst_addr[1024];
                int     src_port, dst_port, size, rstseq, winsize,
                        sec_delay, usec_delay;
                float   ms_delay;
                struct  in_addr src, dst;

                size = recv(sockpacket, &packet, LINK_PACKETSIZE+16, 0);
                if (size == -1 && errno != EINTR)
                        print_statistics(-1);
                bcopy( &(ip->saddr), &src, sizeof(struct in_addr) );
                bcopy( &(ip->daddr), &dst, sizeof(struct in_addr) );
                strncpy(src_addr, inet_ntoa(src), 1024);
                strncpy(dst_addr, inet_ntoa(dst), 1024);
                src_port = ntohs(tcp->th_sport);
                dst_port = ntohs(tcp->th_dport);

                if ( ip->protocol == IPPROTO_TCP &&
                     !memcmp(&ip->saddr, &remote.sin_addr, sizeof(ip->saddr)) &&
                     !memcmp(&ip->daddr, &local.sin_addr, sizeof(ip->daddr)) &&
                     src_port == dport
                )
                {
                        int i, fin_tablepos = -1;

                        rstseq = dst_port - initsport;
                        winsize = ntohs(tcp->th_win);
                        recvflags[0] = '\0';
                        if (tcp->th_flags & TH_RST) strcat(recvflags, "R");
                        if (tcp->th_flags & TH_SYN) strcat(recvflags, "S");
                        if (tcp->th_flags & TH_ACK) strcat(recvflags, "A");
                        if (tcp->th_flags & TH_FIN) strcat(recvflags, "F");
                        if (tcp->th_flags & TH_PUSH) strcat(recvflags, "P");
                        if (tcp->th_flags & TH_URG) strcat(recvflags, "U");

                        for (i=0; i<20; i++)
                                if (delaytable[i].seq == rstseq) {
                                        fin_tablepos = i;
                                        break;
                                }
                        if (fin_tablepos != -1)
                        {
                                sec_delay = time(NULL) - delaytable[fin_tablepos].sec;
                                usec_delay = get_utime() - delaytable[fin_tablepos].usec;
                                ms_delay = (sec_delay * 1000) + ((float)usec_delay / 1000);
                        } else
                                ms_delay = 0;   /* not in table.. */

                        printf("%d bytes from %s: flags=%s seq=%d ttl=%d win=%d time=%.1f ms\n", size, src_addr, 
recvflags, rstseq, ip->ttl, winsize, ms_delay);
                        fflush(stdout);
                        rstrecv++;
                }

                if ( ip->protocol == IPPROTO_ICMP )
                {
                        if ( icmp->type == 3 && /* Dest. Unreachable */
                             !memcmp(&icmp_iph->daddr, &remote.sin_addr, sizeof(ip->daddr)) &&
                             !memcmp(&ip->daddr, &local.sin_addr, sizeof(ip->daddr))
                        )
                                icmpunreach_log(src_addr, icmp->code);

                        else if (icmp->type == 11 && /* Time exceeded */
                                 !memcmp(&icmp_iph->daddr, &remote.sin_addr, sizeof(ip->daddr)) &&
                                 !memcmp(&ip->daddr, &local.sin_addr, sizeof(ip->daddr))
                        )
                                icmptimeexc_log(src_addr, icmp->code);
                }
        }
}

void    icmptimeexc_log(char *src_addr, unsigned short icmp_code)
{
        switch(icmp_code)
        {
                case ICMP_EXC_TTL:
                        printf("TTL 0 during transit from %s\n", src_addr);
                        break;
                case ICMP_EXC_FRAGTIME:
                        printf("TTL 0 during reassembly from %s\n", src_addr);
        }
}

void    icmpunreach_log(char *src_addr, unsigned short icmp_code)
{
        switch(icmp_code)
        {
                case ICMP_HOST_UNREACH:
                        printf("Host Unreachable from %s\n", src_addr);
                        break;
                case ICMP_PORT_UNREACH:
                        printf("Port Unreachable from %s\n", src_addr);
                        break;
                default:
                        printf("ICMP Unreachable type %d from %s\n", icmp_code, src_addr);
                        break;
        }
}

void    print_statistics(int signal_id)
{
        unsigned int lossrate;

        close_sockpacket(sockpacket);

        if (rstrecv > 0)
                lossrate = 100 - ((rstrecv*100)/finsent);
        else
                if (!finsent)
                        lossrate = 0; /* no packets sent, no packets loss... */
                else
                        lossrate = 100; /* packets sent... nadaz returned */

        printf("\n--- %s hping statistic ---\n", targetname);
        printf("%d packets tramitted, %d packets received, %d%% packet loss\n", finsent, rstrecv, lossrate);
        exit(0);
};

void    usage(void)
{
        int     index = 0;
        char    *helpdata[] = {
                "usage: hping host [options]\n",
                "\tc - packets count\n",
                "\ti - wait\n"
                "\tn - numeric output\n",
                "\tq - quiet\n",
                "\tI - interface name\n",
                "\tp - destination port (default 0)\n",
                "\tt - ttl (default 64)\n",
                "\th - shows this help\n",
                "\tF - set FIN flag\n",
                "\tS - set SYN flag\n",
                "\tR - set RST flag\n",
                "\tP - set PUSH flag\n",
                "\tA - set ACK flag\n",
                "\tU - set URG flag\n",
                "\tf - splits packets in two fragments\n",
                NULL };

        while (helpdata[index])
        {
                printf(helpdata[index]);
                ++index;
        }
        exit(0);
};

long get_utime(void)
{
        struct timeval tmptv;

        gettimeofday(&tmptv, NULL);
        return tmptv.tv_usec;
}
