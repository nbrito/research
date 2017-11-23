#include "arp.h"

int
buildarp ()
{
    int n;
    static u_char *pkt;
    char errbuf[256];
    struct libnet_link_int *l;
    if (!device)
    {
        printf ("Unspecified Device.\n");
        exit (1);
    }
    l = libnet_open_link_interface (device, errbuf);
    if (!l)
    {
        printf ("libnet_open_link_interface: %s\n", errbuf);
        exit (1);
    }
    if (libnet_init_packet (LIBNET_ARP_H + LIBNET_ETH_H, &pkt) == -1)
    {
        printf ("libnet_init_packet memory error");
        exit (1);
    }

    libnet_build_ethernet (enet_dst,
                           enet_src,
                           ETHERTYPE_ARP,
                           NULL,
                           0,
                           pkt);

    libnet_build_arp (ARPHRD_ETHER,	/* hardware address type */
                      ETHERTYPE_IP,	/* protocol address type */
                      6, /* hardware address length */
                      4, /* protocol address length */
                      ARPOP_REQUEST, /* opcode command */
                      enet_src,	/* sender hardware address */
                      (u_char *) & source,/* sender protocol (IP) address */
                      enet_dst,	/* target hardware address */
                      (u_char *) & dest, /* destination protocol (IP) address */
                      payload,	/* ARP payload pointer */
                      payload_s, /* ARP payload size */
                      pkt + ETH_H);	/* packet header memory */

    n = libnet_write_link_layer (l,
                                 device,
                                 pkt,
                                 LIBNET_ARP_H + LIBNET_ETH_H + payload_s);

	if (verbose)
   		printf ("Wrote %d byte ARP packet through linktype %d\n", n, l->linktype);
    libnet_destroy_packet (&pkt);
    return (n);
}
