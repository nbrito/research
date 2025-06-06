/*
 * Copyright (c) 1983 The Regents of the University of California.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms are permitted
 * provided that the above copyright notice and this paragraph are
 * duplicated in all such forms and that any documentation,
 * advertising materials, and other materials related to such
 * distribution and use acknowledge that the software was developed
 * by the University of California, Berkeley.  The name of the
 * University may not be used to endorse or promote products derived
 * from this software without specific prior written permission.
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND WITHOUT ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, WITHOUT LIMITATION, THE IMPLIED
 * WARRANTIES OF MERCHANTIBILITY AND FITNESS FOR A PARTICULAR PURPOSE.
 *
 *	@(#)defs.h	5.6 (Berkeley) 9/19/88
 */

#include <sys/types.h>
#include <sys/socket.h>

#include <net/route.h>
#include <netns/ns.h>
#include <netns/idp.h>
#if defined(vax) || defined(pdp11)
#define xnnet(x) ((u_long) (x)->rip_dst[1] << 16 | (u_long) (x)->rip_dst[0] )
#else
#define xnnet(x) ((u_long) (x)->rip_dst[0] << 16 | (u_long) (x)->rip_dst[1] )
#endif
#define	IDPPORT_RIF	1

#include <stdio.h>
#include <syslog.h>

#include "protocol.h"
#include "trace.h"
#include "interface.h"
#include "table.h"
#include "af.h"


/*
 * When we find any interfaces marked down we rescan the
 * kernel every CHECK_INTERVAL seconds to see if they've
 * come up.
 */
#define	CHECK_INTERVAL	(5*60)

#define equal(a1, a2) \
	(bcmp((caddr_t)(a1), (caddr_t)(a2), sizeof (struct sockaddr)) == 0)
#define	min(a,b)	((a)>(b)?(b):(a))

struct	sockaddr_ns addr;	/* Daemon's Address */
int	s;			/* Socket to listen on */
int	kmem;
int	supplier;		/* process should supply updates */
int	install;		/* if 1 call kernel */
int	lookforinterfaces;	/* if 1 probe kernel for new up interfaces */
int	performnlist;		/* if 1 check if /vmunix has changed */
int	externalinterfaces;	/* # of remote and local interfaces */
int	timeval;		/* local idea of time */
int	noteremoterequests;	/* squawk on requests from non-local nets */

char	packet[MAXPACKETSIZE+sizeof(struct idp)+1];
struct	rip *msg;

char	**argv0;

extern	char *sys_errlist[];
extern	int errno;

char	*malloc();
int	exit();
int	sendmsg();
int	supply();
int	timer();
int	cleanup();
