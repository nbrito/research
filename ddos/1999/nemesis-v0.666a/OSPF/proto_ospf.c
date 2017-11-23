#include "ospf.h"

int buildospf ()
{
	int state;

	switch (ospftype)
	{
	case 1: 
		if (verbose)
			printf ("\nOSPF Hello\n");
		state = build_hello ();
		break; 
	case 2:
		if (verbose)
			printf ("\nOSPF Link State Advertisement\n");
		state = build_lsa ();
		break;
	case 3:
		if (verbose)
			printf ("\nOSPF Link State Request\n");
		state = build_lsr ();
		break;
	}	
}

int
build_hello ()
{
	static int sockfd;
	static u_char *pkt;
	struct ipoption ipopt;
	int c;

	pkt = malloc (IP_MAXPACKET);
	sockfd = libnet_open_raw_sock(IPPROTO_RAW);
	if (sockfd < 0)
	{
		perror ("socket");
		exit (1);
	}

	libnet_build_ip (LIBNET_OSPF_H + LIBNET_AUTH_H + LIBNET_HELLO_H, /* size of packet */
						tos, /* type of service */
						id, /* IP id */
						frag, /* frag shit - best not to frag (IP_DF) */
						ttl, /* TTL */
						IPPROTO_OSPF, /* transport protocol */
						source, /* source address */
						dest, /* destination address */
						NULL, /* IP payload pointer */
						0, /* IP payload size */
						pkt); /* packet header memory */

	libnet_build_ospf (LIBNET_HELLO_H + LIBNET_AUTH_H, /* size of packet */
						LIBNET_OSPF_HELLO, /* OSPF type */
						addrid, /* router ID */
						addaid, /* area ID */
						LIBNET_OSPF_AUTH_NULL, /* auth type */
						NULL, /* OSPF payload pointer */
						0, /* OSPF payload size */
						pkt + IP_H); /* packet header memory */

	auth[0] = 0;
	auth[1] = 0;
	
	LIBNET_OSPF_AUTHCPY (pkt + LIBNET_OSPF_H + IP_H, auth);

	libnet_build_ospf_hello (mask, /* OSPF netmask */
							interval, /* secs since last pkt sent */
							ooptions, /* OSPF options */
							priority, /* OSPF priority */
							dead_int, /* Time til router is deemed down */
							source, /* designated router */
							source, /* backup router */
							neighbor, /* address of neigbor router */
							payload, /* OSPF payload pointer */
							payload_s, /* OSPF payload size */
							pkt + IP_H + LIBNET_OSPF_H + LIBNET_AUTH_H); /* pkt hdr mem */

	libnet_do_checksum (pkt, IPPROTO_OSPF, LIBNET_OSPF_H + LIBNET_HELLO_H + LIBNET_IP_H + LIBNET_AUTH_H + payload_s);

	memcpy(ipopt.ipopt_list, options, option_s);
	*(ipopt.ipopt_list) = IPOPT_SECURITY;
	*(ipopt.ipopt_list + 1) = 1;

	c = libnet_write_ip (sockfd, pkt, LIBNET_OSPF_H + LIBNET_HELLO_H + LIBNET_IP_H + LIBNET_AUTH_H + payload_s);

	if (c < LIBNET_OSPF_H + LIBNET_HELLO_H + LIBNET_IP_H + LIBNET_AUTH_H + payload_s)
	{
		libnet_destroy_packet (&pkt);
		fprintf (stderr, "libnet_write_ip\n");
		return 1;
	} else {
		printf ("%d bytes written\n", c);
	}
	libnet_destroy_packet (&pkt);
	return 0;
}

int
build_lsa ()
{
	static int sockfd;
	static u_char *pkt;
	struct ipoption ipopt;
	int c;

    pkt = malloc (IP_MAXPACKET);
    sockfd = libnet_open_raw_sock(IPPROTO_RAW);
    if (sockfd < 0)
    {
        perror ("socket");
        exit (1);
    }

	libnet_build_ip (LIBNET_OSPF_H + LIBNET_AUTH_H + LIBNET_LSA_H + LIBNET_LS_NET_LEN, /* size of packet */
						tos, /* type of service */
						id, /* IP id */
						frag, /* frag shit - best to not frag */
						ttl, /* TTL */
						IPPROTO_OSPF, /* transport protocol */
						source, /* source address */
						dest, /* destination address */
						NULL, /* IP payload pointer */
						0, /* IP payload size */
						pkt); /* packet header memory */

	libnet_build_ospf (LIBNET_AUTH_H + LIBNET_LSA_H + LIBNET_LS_NET_LEN, /* size of packet */
						LIBNET_OSPF_LSA, /* OSPF type */
						addrid, /* router ID */
						addaid, /* area ID */
						LIBNET_OSPF_AUTH_NULL, /* auth type */
						NULL, /* OSPF payload pointer */
						0, /* OSPF payload size */
						pkt + LIBNET_IP_H); /* packet header memory */
	
	auth[0] = 0;
	auth[1] = 0;
		
	LIBNET_OSPF_AUTHCPY (pkt + LIBNET_OSPF_H + LIBNET_IP_H, auth);

	libnet_build_ospf_lsa (ospf_age,
						ooptions,
						LIBNET_LS_TYPE_NET,
						addrid,
						source,
						seqnum,
						LIBNET_LS_NET_LEN,
						NULL,
						0,
						pkt + LIBNET_AUTH_H + LIBNET_OSPF_H + LIBNET_IP_H);

	libnet_build_ospf_lsa_net (mask,
                               rtrid,
                               payload,
                               payload_s,
                               pkt + LIBNET_LSA_H + LIBNET_AUTH_H +
                               LIBNET_OSPF_H + LIBNET_IP_H);

	libnet_do_checksum (pkt, IPPROTO_OSPF, LIBNET_IP_H + LIBNET_OSPF_H +
                        LIBNET_AUTH_H + LIBNET_LSA_H + LIBNET_LS_NET_LEN +
                        payload_s);

	memcpy(ipopt.ipopt_list, options, option_s);
   	*(ipopt.ipopt_list) = IPOPT_SECURITY;
   	*(ipopt.ipopt_list + 1) = 1;

	c = libnet_insert_ipo(&ipopt, /* pointer to ipopt struct */
                          option_s, /* Length of option list */
                          pkt); /* Packet header memory */

	libnet_do_checksum (pkt + LIBNET_IP_H + LIBNET_OSPF_H + LIBNET_AUTH_H,
                        IPPROTO_OSPF_LSA, LIBNET_LS_NET_LEN + LIBNET_LSA_H +
                        payload_s + option_s);

    c = libnet_write_ip (sockfd, pkt, LIBNET_IP_H + LIBNET_OSPF_H +
                         LIBNET_AUTH_H + LIBNET_LSA_H + LIBNET_LS_NET_LEN +
                         payload_s + option_s);

	if (c < LIBNET_IP_H + LIBNET_OSPF_H + LIBNET_AUTH_H + LIBNET_LSA_H +
        LIBNET_LS_NET_LEN + payload_s + option_s)
	{	
		libnet_destroy_packet (&pkt);
		fprintf (stderr, "write_ip\n");
		return 1;
	}
     
	if (verbose)
		printf ("Wrote %d bytes\n", c);
	libnet_destroy_packet (&pkt);
	return 0;                 
}

int 
build_lsr () 
{
    static int sockfd;
    static u_char *pkt;
    struct ipoption ipopt;
	int c;

    pkt = malloc (IP_MAXPACKET);
    sockfd = libnet_open_raw_sock(IPPROTO_RAW);
    if (sockfd < 0)
    {
        perror ("socket");
        exit (1);
    }

	libnet_build_ip (LIBNET_OSPF_H + LIBNET_AUTH_H + LIBNET_LSR_H, /* size of packet */
                        tos, /* type of service */
                        id, /* IP id */
                        frag, /* Don't frag - IP_DF */
                        ttl, /* TTL */
                        IPPROTO_OSPF, /* transport protocol */
                        source, /* source address */
                        dest, /* destination address */
                        NULL, /* IP payload pointer */
                        0, /* IP payload size */
                        pkt); /* packet header memory */

	auth[0] = 0;
	auth[1] = 0;

    libnet_build_ospf (LIBNET_AUTH_H + LIBNET_LSR_H, LIBNET_OSPF_LSR,
            addrid, addaid, LIBNET_OSPF_AUTH_NULL, NULL, 0, pkt +
            LIBNET_IP_H);

    libnet_build_ospf (LIBNET_AUTH_H + LIBNET_LSR_H, /* size of packet */
						LIBNET_OSPF_LSR, /* OSPF type */
                        addrid, /* router ID */
                        addaid, /* area ID */
                        LIBNET_OSPF_AUTH_NULL, /* auth type */
                        NULL, /* OSPF payload pointer */
                        0, /* OSPF payload size */
                        pkt + LIBNET_IP_H); /* packet header memory */

    LIBNET_OSPF_AUTHCPY (pkt + LIBNET_OSPF_H + LIBNET_IP_H, auth);

	libnet_build_ospf_lsr (LIBNET_LS_TYPE_RTR,
                           rtrid,
                           router,
                           payload,
                           payload_s,
                           pkt + LIBNET_IP_H + LIBNET_OSPF_H + LIBNET_AUTH_H); 
	
	libnet_do_checksum (pkt, IPPROTO_OSPF, LIBNET_IP_H + LIBNET_OSPF_H +
                        LIBNET_AUTH_H + LIBNET_LSR_H + payload_s);

	memcpy(ipopt.ipopt_list, options, option_s);
	*(ipopt.ipopt_list) = IPOPT_SECURITY;
	*(ipopt.ipopt_list + 1) = 1;

	c = libnet_write_ip (sockfd, pkt, LIBNET_IP_H + LIBNET_OSPF_H +
                         LIBNET_AUTH_H + LIBNET_LSR_H + payload_s +
                         option_s);

    if (c < LIBNET_IP_H + LIBNET_OSPF_H + LIBNET_AUTH_H + LIBNET_LSR_H +
        payload_s + option_s) 
    {
        libnet_destroy_packet (&pkt);
        fprintf (stderr, "write_ip\n");
        return 1;
    }

    if (verbose)
        printf ("Wrote %d bytes\n", c);
    libnet_destroy_packet (&pkt);
    return 0;
}

