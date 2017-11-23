#include "tcp.h"

int buildtcp()
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

    pkt = malloc(LIBNET_TCP_H + LIBNET_IP_H + payload_s + option_s);
    sockfd = libnet_open_raw_sock(IPPROTO_RAW);

    if(sockfd < 0) {
        perror("socket");
        exit(1);
    }   

	if (got_link)
	{ /* data link layer transport */
		if ((l = libnet_open_link_interface(device, errbuf)) == NULL)
		{
			fprintf (stderr, "libnet_open_link_interface: %s\n", errbuf);
			exit (1);
		}	
		if (libnet_init_packet(LIBNET_TCP_H + LIBNET_IP_H + LIBNET_ETH_H + payload_s, &pkt) == -1)
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

    	libnet_build_ip(LIBNET_TCP_H + payload_s,  /* size of packet */
                    tos, /* type of service */
                    id, /* IP id */
                    frag, /* frag */
                    ttl, /* TTL */
                    IPPROTO_TCP, /* transport protocol */
                    source, /* source address */
                    dest, /* destination address */
                    NULL, /* IP payload pointer */
                    0, /* IP payload size */
                    pkt + LIBNET_ETH_H); /* packet header memory */

    	libnet_build_tcp(sport, /* source port */
                     dport, /* destination port */
                     seq, /* sequence number */
                     ack, /* acknowledgement number */
                     flags, /* TCP flags */
                     win, /* window size */
                     urgp, /* URG pointer */
                     payload, /* TCP payload pointer */
                     payload_s, /* TCP payload size */
                     pkt + LIBNET_IP_H + LIBNET_ETH_H); /* packet header memory */

		libnet_do_checksum (pkt + LIBNET_ETH_H, IPPROTO_TCP, LIBNET_TCP_H + payload_s + option_s);

		memcpy(ipopt.ipopt_list, options, option_s);
        *(ipopt.ipopt_list) = IPOPT_SECURITY;
        *(ipopt.ipopt_list + 1) = 1;

        c = libnet_insert_ipo(&ipopt, /* pointer to ipopt struct */
                          option_s, /* Length of option list */
                          pkt); /* Packet header memory */

        n = libnet_write_link_layer (l, device, pkt, LIBNET_ETH_H + LIBNET_IP_H + LIBNET_TCP_H + payload_s + option_s);
        if (n != LIBNET_ETH_H + LIBNET_TCP_H + LIBNET_IP_H + payload_s + option_s)
        {
            fprintf (stderr, "Incomplete data transmission.  Only wrote %d bytes \n", n);
        }
        else
        {
			if (verbose)
            	printf ("Wrote %d byte TCP packet through linktype %d\n", n, l->linktype);
        }
        libnet_destroy_packet(&pkt);
        return (n);
	} /* end of data link layer */
	else
	{ /* ip layer transport */
    	libnet_build_ip(LIBNET_TCP_H + payload_s,  /* size of packet */
                    tos, /* type of service */
                    id, /* IP id */
                    frag, /* frag */
                    ttl, /* TTL */
                    IPPROTO_TCP, /* transport protocol */
                    source, /* source address */
                    dest, /* destination address */
                    NULL, /* IP payload pointer */
                    0, /* IP payload size */
                    pkt); /* packet header memory */

    	libnet_build_tcp(sport,	/* source port */
                     dport, /* destination port */
                     seq, /* sequence number */
                     ack, /* acknowledgement number */
                     flags, /* TCP flags */
                     win, /* window size */
                     urgp, /* URG pointer */
                     payload, /* TCP payload pointer */
                     payload_s, /* TCP payload size */
                     pkt + LIBNET_IP_H); /* packet header memory */

    	libnet_do_checksum(pkt, IPPROTO_TCP, LIBNET_TCP_H + payload_s);
	
		memcpy(ipopt.ipopt_list, options, option_s);
    	*(ipopt.ipopt_list) = IPOPT_SECURITY;
    	*(ipopt.ipopt_list + 1) = 1;
		c = libnet_insert_ipo(&ipopt, /* pointer to ipopt struct */
                          option_s, /* Length of option list */
                          pkt); /* Packet header memory */

		if (c == -1)
		{
			fprintf (stderr, "Can't add options, discarding them.\n");
		}

    	c = libnet_write_ip(sockfd,
                        pkt,
                        LIBNET_TCP_H + LIBNET_IP_H + payload_s + option_s);


    	if (c < LIBNET_TCP_H + LIBNET_IP_H + payload_s + option_s)
		{
        	libnet_destroy_packet(&pkt);
        	fprintf(stderr, "write_ip\n");
        	return 1;
    	}
		if (verbose)
			printf ("Wrote %d bytes\n", c);
    	libnet_destroy_packet(&pkt);
    	return 0;
	} /* end of ip layer */
}
