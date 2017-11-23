#include "icmp.h"
#define ICMP_S 0x8

int
buildicmp ()
{
	int c, n;
    static int sockfd;
    static u_char *pkt;
	struct libnet_link_int *l;
	struct ipoption ipopt;
	char errbuf[256];

	if (got_link && !device)
	{
		printf ("Unspecified Device.\n");
		exit (1);
	}

	if (payload != NULL)
		payload_s = strlen(payload);
	if (*options != NULL)
		option_s = strlen(options);

	
    pkt = malloc (IP_MAXPACKET);
    sockfd = libnet_open_raw_sock (IPPROTO_RAW);

    if (sockfd < 0)
    {
        perror ("socket");
        exit (1);
    }

	if (got_link)
	{ /* data link layer transport */
        if ((l = libnet_open_link_interface(device, errbuf)) == NULL)
        {
            fprintf (stderr, "libnet_open_link_interface: %s\n", errbuf);
            exit (1);
        }
		if (libnet_init_packet(ICMP_S + LIBNET_IP_H + LIBNET_ETH_H + payload_s, &pkt) == -1)
		{
			printf ("libnet_init_packet memory error");
			exit (1);
		}

		libnet_build_ethernet (enet_dst,
                               enet_src,
                               ETHERTYPE_IP,
                               NULL,
                               0,
                               pkt);

		libnet_build_ip (ICMP_S + LIBNET_IP_H + payload_s,  /* size of packet */
                         tos,       /* type of service */
                         id,        /* IP id */
                         0,     /* frag */
                         ttl,       /* TTL */
                         IPPROTO_ICMP,  /* transport protocol */
                         source,    /* source address */
                         dest,  /* destination address */
                         NULL,  /* IP payload pointer */
                         0,     /* IP payload size */
                         pkt + LIBNET_ETH_H);  /* packet header memory */

		if (type == ICMP_ECHOREPLY) /* type = 0 */
        	libnet_build_icmp_echo (type,   /* ICMP type */
                                0,  /* ICMP code */
                                id, /* ICMP id */
                                seq,    /* sequence number */
                                payload,    /* ICMP payload pointer */
                                payload_s,  /* ICMP payload size */
                                pkt + LIBNET_ETH_H + LIBNET_IP_H);    /* packet memory header */

	    if (type == ICMP_UNREACH) /* type = 3 */
            libnet_build_icmp_unreach (type,    /* ICMP type */
                                   code,    /* ICMP code */
                                   0,   /* ICMP original length */
                                   tos, /* type of service */
                                   0,   /* ICMP id */
                                   0,   /* frag */
                                   ttl, /* TTL */
                                   IPPROTO_ICMP,    /* transport protocol */
                                   dest,    /* destination address */
                                   source,  /* source address */
                                   payload, /* ICMP payload pointer */
                                   payload_s,   /* ICMP payload size */
                                   pkt + LIBNET_ETH_H + LIBNET_IP_H); /* packet memory header */

    	if (type == ICMP_REDIRECT) /* type = 5 */
        	libnet_build_icmp_redirect (type,   /* ICMP type */
                                    code,   /* ICMP code */
                                    gwy,    /* preferred gateway */
                                    0,  /* ICMP original length */
                                    tos,    /* type of service */
                                    id, /* ICMP id */
                                    0,  /* frag */
                                    ttl,    /* TTL */
                                    IPPROTO_ICMP,   /* transport protocol */
                                    dest,   /* destination address */
                                    source,     /* source address */
                                    payload,    /* ICMP payload pointer */
                                    payload_s,  /* ICMP payload size */
                                    pkt + LIBNET_ETH_H + LIBNET_IP_H);    /* packet header memory */

    	if (type == ICMP_ECHO) /* type = 8 */
        	libnet_build_icmp_echo (type,   /* ICMP type */
                                0,  /* ICMP code */
                                id, /* ICMP id */
                                seq,    /* sequence number */
                                payload,    /* ICMP payload pointer */
                                payload_s,  /* ICMP payload size */
                                pkt + LIBNET_ETH_H + LIBNET_IP_H);    /* packet header memory */
    	if (type == ICMP_TIMXCEED) /* type = 11 */
        	libnet_build_icmp_timeexceed (type,     /* ICMP type */
                                      code,     /* ICMP code */
                                      0,    /* ICMP orig length */
                                      tos,  /* type of service */
                                      id,   /* ICMP id */
                                      0,    /* frag */
                                      ttl,  /* TTL */
                                      IPPROTO_ICMP,     /* transport protocol
*/
                                      dest,     /* destination address */
                                      source,   /* source address */
                                      payload,      /* ICMP payload pointer */
                                      payload_s,    /* ICMP payload size */
                                      pkt + LIBNET_ETH_H + LIBNET_IP_H);  /* packet header memory */
    	if(type == ICMP_TSTAMP) /* type = 13 */
       		libnet_build_icmp_timestamp(type, /* ICMP type */
                                   0, /* ICMP code */
                                   id, /* ICMP id */
                                   seq, /* sequence number */
                                   otime, /* original timestamp */
                                   0, /* receive timestamp */
                                   0, /* transmit timestamp */
                                   payload, /* ICMP payload pointer */
                                   payload_s, /* ICMP payload size */
                                   pkt + LIBNET_ETH_H + LIBNET_IP_H); /* packet header memory */

    	if(type == ICMP_TSTAMPREPLY) /* type = 14 */
        	libnet_build_icmp_timestamp(type, /* ICMP type */
                                    0, /* ICMP code */
                                    id, /* ICMP id */
                                    seq, /* sequence number */
                                    0, /* original timestamp */
                                    rtime, /* receive timestamp */
                                    ttime, /* transmit timestamp */
                                    payload, /* ICMP payload pointer */
                                    payload_s, /* ICMP payload size */
                                    pkt + LIBNET_ETH_H + LIBNET_IP_H); /* packet header memory */
    	if (type == ICMP_MASKREQ) /* type = 17 */
        	libnet_build_icmp_mask (type,   /* ICMP type */
                                0,  /* ICMP code */
                                id, /* ICMP id */
                                seq,    /* sequence number */
                                mask,   /* address mask */
                                payload,    /* ICMP payload pointer */
                                payload_s,  /* ICMP payload size */
                                pkt + LIBNET_ETH_H + LIBNET_IP_H);    /* packet header memory */
    	if (type == ICMP_MASKREPLY) /* type = 18 */
        	libnet_build_icmp_mask (type,   /* ICMP type */
                                0,  /* ICMP code */
                                id, /* ICMP id */
                                seq,    /* sequence number */
                                mask,   /* address mask */
                                payload,    /* ICMP payload pointer */
                                payload_s,  /* ICMP payload size */
                                pkt + LIBNET_ETH_H + LIBNET_IP_H);    /* packet header memory */

		libnet_do_checksum (pkt + LIBNET_ETH_H, IPPROTO_IP, LIBNET_IP_H);
        libnet_do_checksum (pkt + LIBNET_ETH_H, IPPROTO_ICMP, ICMP_S + payload_s + option_s);
        memcpy(ipopt.ipopt_list, options, option_s);
        *(ipopt.ipopt_list) = IPOPT_SECURITY;
        *(ipopt.ipopt_list + 1) = 1;
        c = libnet_insert_ipo(&ipopt, /* pointer to ipopt struct */
                          option_s, /* Length of option list */
                          pkt); /* Packet header memory */

		n = libnet_write_link_layer (l, device, pkt, LIBNET_ETH_H + LIBNET_IP_H
+ ICMP_S + payload_s + option_s);
	
		if (n != LIBNET_ETH_H + ICMP_S + LIBNET_IP_H + payload_s + option_s)
		{
			fprintf (stderr, "Incomplete data transmission.  Only wrote %d bytes\n", n);
		}
		else
		{
			if (verbose) 
				printf ("Wrote %d byte ICMP packet through linktype %d\n", n, l->linktype);
		}
		libnet_destroy_packet(&pkt);
		return (n);
	} /* end of data link layer */
	else 
	{ /* ip layer transport */
    	libnet_build_ip (ICMP_S + LIBNET_IP_H + payload_s,	/* size of packet */
                     tos,		/* type of service */
                     id,		/* IP id */
                     0,		/* frag */
                     ttl,		/* TTL */
                     IPPROTO_ICMP,	/* transport protocol */
                     source,	/* source address */
                     dest,	/* destination address */
                     NULL,	/* IP payload pointer */
                     0,		/* IP payload size */
                     pkt);	/* packet header memory */

    	if (type == ICMP_ECHOREPLY) /* type = 0 */
        	libnet_build_icmp_echo (type,	/* ICMP type */
                                0,	/* ICMP code */
                                id,	/* ICMP id */
                                seq,	/* sequence number */
                                payload,	/* ICMP payload pointer */
                                payload_s,	/* ICMP payload size */
                                pkt + IP_H);	/* packet memory header */

    	if (type == ICMP_UNREACH) /* type = 3 */
        	libnet_build_icmp_unreach (type,	/* ICMP type */
                                   code,	/* ICMP code */
                                   0,	/* ICMP original length */
                                   tos,	/* type of service */
                                   0,	/* ICMP id */
                                   0,	/* frag */
                                   ttl,	/* TTL */
                                   IPPROTO_ICMP,	/* transport protocol */
                                   dest,	/* destination address */
                                   source,	/* source address */
                                   payload,	/* ICMP payload pointer */
                                   payload_s,	/* ICMP payload size */
                                   pkt + IP_H);	/* packet memory header */

    	if (type == ICMP_REDIRECT) /* type = 5 */
        	libnet_build_icmp_redirect (type,	/* ICMP type */
                                    code,	/* ICMP code */
                                    gwy,	/* preferred gateway */
                                    0,	/* ICMP original length */
                                    tos,	/* type of service */
                                    id,	/* ICMP id */
                                    0,	/* frag */
                                    ttl,	/* TTL */
                                    IPPROTO_ICMP,	/* transport protocol */
                                    dest,	/* destination address */
                                    source,		/* source address */
                                    payload,	/* ICMP payload pointer */
                                    payload_s,	/* ICMP payload size */
                                    pkt + IP_H);	/* packet header memory */

    	if (type == ICMP_ECHO) /* type = 8 */
        	libnet_build_icmp_echo (type,	/* ICMP type */
                                0,	/* ICMP code */
                                id,	/* ICMP id */
                                seq,	/* sequence number */
                                payload,	/* ICMP payload pointer */
                                payload_s,	/* ICMP payload size */
                                pkt + IP_H);	/* packet header memory */

    	if (type == ICMP_TIMXCEED) /* type = 11 */
        	libnet_build_icmp_timeexceed (type,		/* ICMP type */
                                      code,		/* ICMP code */
                                      0,	/* ICMP orig length */
                                      tos,	/* type of service */
                                      id,	/* ICMP id */
                                      0,	/* frag */
                                      ttl,	/* TTL */
                                      IPPROTO_ICMP,		/* transport protocol */
                                      dest,		/* destination address */
                                      source,	/* source address */
                                      payload,		/* ICMP payload pointer */
                                      payload_s,	/* ICMP payload size */
                                      pkt + IP_H);	/* packet header memory */

    	if(type == ICMP_TSTAMP) /* type = 13 */
       		libnet_build_icmp_timestamp(type, /* ICMP type */
                                   0, /* ICMP code */
                                   id, /* ICMP id */
                                   seq, /* sequence number */
                                   otime, /* original timestamp */
                                   0, /* receive timestamp */
                                   0, /* transmit timestamp */
                                   payload, /* ICMP payload pointer */
                                   payload_s, /* ICMP payload size */
                                   pkt + IP_H); /* packet header memory */

		if(type == ICMP_TSTAMPREPLY) /* type = 14 */
			libnet_build_icmp_timestamp(type, /* ICMP type */
                                    0, /* ICMP code */
                                    id, /* ICMP id */
                                    seq, /* sequence number */
                                    0, /* original timestamp */
                                    rtime, /* receive timestamp */
                                    ttime, /* transmit timestamp */
                                    payload, /* ICMP payload pointer */
                                    payload_s, /* ICMP payload size */
                                    pkt + IP_H); /* packet header memory */

    	if (type == ICMP_MASKREQ) /* type = 17 */
        	libnet_build_icmp_mask (type,	/* ICMP type */
                                0,	/* ICMP code */
                                id,	/* ICMP id */
                                seq,	/* sequence number */
                                mask,	/* address mask */
                                payload,	/* ICMP payload pointer */
                                payload_s,	/* ICMP payload size */
                                pkt + IP_H);	/* packet header memory */

    	if (type == ICMP_MASKREPLY) /* type = 18 */
        	libnet_build_icmp_mask (type,	/* ICMP type */
                                0,	/* ICMP code */
                                id,	/* ICMP id */
                                seq,	/* sequence number */
                                mask,	/* address mask */
                                payload,	/* ICMP payload pointer */
                                payload_s,	/* ICMP payload size */
                                pkt + IP_H);	/* packet header memory */

    	libnet_do_checksum (pkt, IPPROTO_ICMP, ICMP_H + IP_H + payload_s);

    	memcpy(ipopt.ipopt_list, options, option_s);
    	*(ipopt.ipopt_list) = IPOPT_SECURITY;
    	*(ipopt.ipopt_list + 1) = 1;

    	c = libnet_insert_ipo(&ipopt, /* pointer to ipopt struct */
                          option_s, /* Length of option list */
                          pkt); /* Packet header memory */


    	c = libnet_write_ip (sockfd, pkt, ICMP_S + (2 * LIBNET_IP_H) + payload_s + option_s);

		if (c < ICMP_S + IP_H + payload_s + option_s)
    	{
        	libnet_destroy_packet (&pkt);
			fprintf (stderr, "write_ip\n");
        	return 1;
    	}
		if (verbose)
			printf ("Wrote %d bytes\n", c);
    	libnet_destroy_packet (&pkt);
    	return 0;
	} /* end of ip layer */
}
