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
      frag,		/* frag shit */
  interval,		/* secs since last pkt sent */
  ospf_age;		/* OSPF advertisement age */
u_long source,	/* source address */
         dest,	/* destination address */
  	 neighbor,	/* neighbor router */
       addrid,  /* advertising router id */
       addaid,  /* advertising area id */
	   router,  /* advertising router */
         auth[2],  /* authentication type */
         mask;	/* subnet mask (icmp_mask) */
u_char ttl,		/* time to live */
       tos,  	/* type of service */
  *payload,		/* payload pointer */
  options[40],		/* IP options pointer */
  priority,		/* OSPF priority */
  ooptions;		/* OSPF options */
u_int dead_int, /* dead router interval in secs */
      seqnum,   /* seqnum for LSA */
      rtrid;    /* router id for LSA */

int got_options, got_payload; /* sanity checks */

int option_s;	/* IP options size */
int payload_s;  /* payload size */
int ospftype;	/* which OSPF packet to launch */

char *device;	/* network device */

int verbose; /* verbosity */

int buildospf ();
int build_hello ();
int build_lsa ();
int build_lsr ();

void usage (char *);
void defaults ();		/* defaults for packet fields */

#ifndef IPOPT_SECURITY
#define IPOPT_SECURITY	130
#endif
