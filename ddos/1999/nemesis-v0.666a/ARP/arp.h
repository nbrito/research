#define VERSION "The NEMESIS Project - version 0.666 (alpha)"
#define CODERS "(c) 1999 obecian"

#include <stdio.h>
#include <strings.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/in.h>
#include <libnet.h>
#include <sys/types.h>

u_long source, /* source address */ 
		 dest; /* destination address */
u_char *payload,	/* payload pointer */
       enet_src[6],	/* source MAC address */
       enet_dst[6];	/* destination MAC address */

int got_link, got_payload; /* sanity check */

int payload_s;  /* payload size */

char *device;	/* network device */

int verbose; /* verbosity */

int buildarp ();

void usage (char *);
void defaults ();		/* defaults for packet fields */

#ifndef IPOPT_SECURITY
#define IPOPT_SECURITY	130
#endif
