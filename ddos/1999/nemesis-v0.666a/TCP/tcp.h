#define VERSION "The NEMESIS Project - version 0.666 (alpha)"
#define CODERS "(c) 1999 obecian"

#include <stdio.h>
#include <strings.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/in.h>
#include <libnet.h>
#include <sys/types.h>

u_short id,		/* IP id */
	  urgp,		/* TCP urgent data pointer */
      frag,		/* frag shit */
     sport,		/* source port */
     dport,		/* destination port */
       win,		/* window size */
    fl_opt;		/* TCP flag options */

u_long source,	/* source address */
         dest,	/* destination address */
		  seq,  /* sequence number */
          ack;  /* acknowledgement number */

u_char enet_src[6], /* source MAC address */
       enet_dst[6], /* destination MAC address */
               ttl,	/* time to live */
               tos,	/* type of service */
          *payload,	/* payload pointer */
       options[40],	/* IP options pointer */
             flags;	/* enum flags */

int got_link, got_options, got_payload; /* sanity checks */

int option_s;	/* IP option size */
int payload_s;	/* payload size */

char *device;	/* network device */

int verbose; /* verbosity */

int buildtcp(); /* phear */

void usage (char *);
void defaults ();	/* defaults for packet fields */

#ifndef IPOPT_SECURITY
#define IPOPT_SECURITY  130
#endif

/* flag bits */
#define SYN  (1     )
#define ACK  (1 << 1)
#define RST  (1 << 2)
#define PSH  (1 << 3)
#define URG  (1 << 4)
#define FIN  (1 << 5)

