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
     sport,		/* source port */
     dport;		/* destination port */
u_long source,	/* source address */
         dest;	/* destination address */
u_char ttl,		/* time to live */
       tos,  	/* type of service */
  *payload,		/* payload pointer */
  options[40];		/* IP options pointer */

int got_options, got_payload; /* sanity check */

int option_s;	/* IP option size */
int payload_s;  /* payload size */

char *device;	/* network device */

int verbose; /* verbosity */

int buildudp ();

void usage (char *);
void defaults ();		/* defaults for packet fields */

#ifndef IPOPT_SECURITY
#define IPOPT_SECURITY	130
#endif
