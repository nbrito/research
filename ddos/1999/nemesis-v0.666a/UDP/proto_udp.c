#include "udp.h"

int
buildudp ()
{
	int c;
    static int sockfd;
    static u_char *pkt;	
	
	struct ipoption ipopt;
	
	if (payload != NULL)
    	payload_s = strlen (payload);
	if (*options != NULL)
		option_s = strlen (options);

    pkt = malloc (UDP_H + IP_H + payload_s + option_s);
    sockfd = libnet_open_raw_sock (IPPROTO_RAW);

    if (sockfd < 0)
    {
        perror ("socket");
        exit (1);
    }

    libnet_build_ip (UDP_H + payload_s,	/* size of packet */
                     tos,		/* type of service */
                     id,		/* IP id */
                     0,		/* frag */
                     ttl,		/* TTL */
                     IPPROTO_UDP,	/* transport protocol */
                     source,	/* source address */
                     dest,	/* destination address */
                     NULL,	/* IP payload pointer */
                     0,		/* IP payload size */
                     pkt);	/* packet header memory */

    libnet_build_udp (sport,	/* source port */
                      dport,	/* destination port */
                      payload,	/* UDP payload pointer */
                      payload_s,	/* UDP payload size */
                      pkt + IP_H);	/* packet header memory */

    libnet_do_checksum (pkt, IPPROTO_UDP, UDP_H + payload_s);

	memcpy (ipopt.ipopt_list, options, option_s);
	*(ipopt.ipopt_list) = IPOPT_SECURITY;
    *(ipopt.ipopt_list + 1) = 1;

	c = libnet_insert_ipo(&ipopt, /* pointer to ipopt struct */
                          option_s, /* Length of option list */
                          pkt); /* Packet header memory */

	c = libnet_write_ip (sockfd, pkt, UDP_H + IP_H + payload_s + option_s);

    if (c < UDP_H + IP_H + payload_s + option_s)
    {
        libnet_destroy_packet(&pkt);
		fprintf(stderr, "libnet_write_ip\n");
        return 1;
    }
	libnet_destroy_packet(&pkt);
    return 0;
}
