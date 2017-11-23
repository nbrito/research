#define VERSION "The NEMESIS Project - version 0.666 (alpha)"
#define CODERS "(c) 1999 obecian"

#include <stdio.h>
#include <strings.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/in.h>
#include <libnet.h>
#include <sys/types.h>

n_time otime,	/* originating time */
       rtime,	/* received time */
       ttime;	/* xmitted time */
u_short id,		/* IP id */
      frag,		/* frag shit */
     sport,		/* source port */
     dport;		/* destination port */
u_long source,	/* source address */
         dest,	/* destination address */
		  seq,  /* sequence number */
         mask,	/* subnet mask (icmp_mask) */
          gwy;	/* preferred gateway (icmp_redirect) */
u_char enet_src[6], /* source MAC address */
       enet_dst[6], /* destination MAC address */
               ttl,	/* time to live */
               tos, /* type of service */
             proto, /* protocol type */
              type, /* ICMP packet type */
              code, /* ICMP packet code */
          *payload, /* payload pointer */
       options[40]; /* IP options pointer */

int got_link, got_options, got_payload; /* sanity checks */
int option_s;	/* IP option size */
int payload_s;  /* payload size */

char *device;	/* network device */

int verbose; /* verbosity */

int buildicmp ();

void usage (char *);
void defaults ();		/* defaults for packet fields */

#ifndef IPOPT_SECURITY
#define IPOPT_SECURITY	130
#endif
