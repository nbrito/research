/* Phenoelit IRPAS 
 * protocol definitions
 *
 * $Id: protocols.h,v 1.9 2001/10/18 12:02:58 fx Exp $
 */
#ifndef _PROTOCOLS_H_
#define _PROTOCOLS_H_

#include <net/ethernet.h>
#include <net/if.h>
#include <netinet/in.h>

/* ************************************************************
 * Ethernet Frames
 * ************************************************************/
typedef struct {
    struct ether_addr   daddr;
    struct ether_addr   saddr;
    u_int16_t           type;
} etherIIhdr_t;

/* IEEE 802.3, LLC related structs */
struct eth_ieee802_3 {
    struct ether_addr   daddr;
    struct ether_addr   saddr;
    u_int16_t           length;
};

struct eth_LLC {
    u_int8_t            DSAP;
    u_int8_t            SSAP;
    u_int8_t            Control;
    u_int8_t            orgcode[3];
    u_int16_t           proto;
};

struct eth_LLC_short {
    u_int8_t            DSAP;
    u_int8_t            SSAP;
    u_int8_t            Control;
    u_int8_t            orgcode[3];
    u_int16_t           proto;
};

/* ************************************************************
 * CDP frames
 * ************************************************************/

/* CDP header */
struct cdphdr {
    u_int8_t            version;
    u_int8_t            ttl;
    u_int16_t           checksum;
};
/* CDP sections */
#define TYPE_DEVICE_ID          0x0001
#define TYPE_ADDRESS            0x0002
#define TYPE_PORT_ID            0x0003
#define TYPE_CAPABILITIES       0x0004
#define TYPE_IOS_VERSION        0x0005
#define TYPE_PLATFORM           0x0006
#define TYPE_VTP_MGMT		0x0009
#define TYPE_VLAN		0x000a
#define TYPE_DUPLEX		0x000b

struct cdp_device {
    u_int16_t           type;           /* 0x0001 */
    u_int16_t           length;
    u_char              device;         /* pointer to device name */
};

struct cdp_address {
    u_int16_t           type;           /* 0x0002 */
    u_int16_t           length;
    u_int32_t           number;         /* number of addresses */
};

struct cdp_address_entry {
    u_int8_t            proto_type;     /* 0x1 for NLPID */
    u_int8_t            length;         /* 0x1 for IP */
    u_int8_t            proto;          /* 0xCC for IP */
    u_int8_t            addrlen[2];
    u_char              addr;
};

struct cdp_port {
    u_int16_t           type;           /* 0x0003 */
    u_int16_t           length;
    u_char              port;           /* pointer to port name */
};


#define CDP_CAP_LEVEL1          0x40
#define CDP_CAP_FORWARD_IGMP    0x20
#define CDP_CAP_NETWORK_LAYER   0x10
#define CDP_CAP_LEVEL2_SWITCH   0x08
#define CDP_CAP_LEVEL2_SRB      0x04
#define CDP_CAP_LEVEL2_TRBR     0x02
#define CDP_CAP_LEVEL3_ROUTER   0x01
struct cdp_capabilities {
    u_int16_t           type;           /* 0x0004 */
    u_int16_t           length;         /* is 8 */
    u_int32_t           capab;
};

struct cdp_software {
    u_int16_t           type;           /* 0x0005 */
    u_int16_t           length;
    u_char              software;       /* pointer to software string */
};

struct cdp_platform {
    u_int16_t           type;           /* 0x0006 */
    u_int16_t           length;
    u_char              platform;       /* pointer to platform string */
};

typedef struct {
    u_int16_t           type;           
    u_int16_t           length;
    u_char              value;           /* pointer to port name */
} cdp_generic_t;

/* ************************************************************
 * PPPoE 
 * ************************************************************/
typedef struct {
    u_int8_t		version:4,type:4	__attribute__ ((packed));
    u_int8_t		code			__attribute__ ((packed));
    u_int16_t           session			__attribute__ ((packed));
    u_int16_t           payload_len		__attribute__ ((packed));
} pppoe_data_t;


/* ************************************************************
 * ARP version 4
 * ************************************************************/
#define ARPOP_REQUEST   1               /* ARP request.  */
#define ARPOP_REPLY     2               /* ARP reply.  */
#define ARPOP_RREQUEST  3               /* RARP request.  */
#define ARPOP_RREPLY    4               /* RARP reply.  */
typedef struct {
    u_int16_t	hardware;
    u_int16_t	protocol;
    u_int8_t	hw_size;
    u_int8_t	proto_size;
    u_int16_t	opcode;
    u_int8_t	sha[ETH_ALEN];   	/* Sender hardware address.  */
    u_int8_t 	sip[4];	          	/* Sender IP address.  */
    u_int8_t 	tha[ETH_ALEN];   	/* Target hardware address.  */
    u_int8_t 	tip[4];          	/* Target IP address.  */
} arphdr_t;


/* ************************************************************
 * IP version 4
 * ************************************************************/
#define IPPROTO_ICMP	0x01
#define IPPROTO_IGRP    0x09
#define IPPROTO_UDP	0x11
#define IPPROTO_EIGRP	0x58
#define IPPROTO_OSPF	0x59
#define IPPROTO_GRE	0x2f

#define IP_ADDR_LEN	4
typedef struct {
        u_int8_t        ihl:4,          /* header length */
                        version:4;      /* version */
        u_int8_t        tos;            /* type of service */
        u_int16_t       tot_len;        /* total length */
        u_int16_t       id;             /* identification */
        u_int16_t       off;            /* fragment offset field */
        u_int8_t        ttl;            /* time to live */
        u_int8_t        protocol;       /* protocol */
        u_int16_t       check;          /* checksum */
        struct in_addr  saddr;
        struct in_addr  daddr;  	/* source and dest address */
} iphdr_t;

/* ************************************************************
 * TCP
 * ************************************************************/
typedef struct {
    u_int16_t th_sport;         /* source port */
    u_int16_t th_dport;         /* destination port */
    u_int32_t th_seq;             /* sequence number */
    u_int32_t th_ack;             /* acknowledgement number */
#if __BYTE_ORDER == __LITTLE_ENDIAN
    u_int8_t th_x2:4;           /* (unused) */
    u_int8_t th_off:4;          /* data offset */
#endif
#if __BYTE_ORDER == __BIG_ENDIAN
    u_int8_t th_off:4;          /* data offset */
    u_int8_t th_x2:4;           /* (unused) */
#endif
    u_int8_t th_flags;
#define TH_FIN  0x01
#define TH_SYN  0x02
#define TH_RST  0x04
#define TH_PUSH 0x08
#define TH_ACK  0x10
#define TH_URG  0x20
    u_int16_t th_win;           /* window */
    u_int16_t th_sum;           /* checksum */
    u_int16_t th_urp;           /* urgent pointer */
} tcphdr_t;

struct pseudohdr {
    struct in_addr saddr;
    struct in_addr daddr;
    u_char zero;
    u_char protocol;
    u_short length;
    tcphdr_t tcpheader;
};

/* ************************************************************
 * UDP
 * ************************************************************/
typedef struct {
    u_int16_t	sport			__attribute__ ((packed));
    u_int16_t	dport			__attribute__ ((packed));
    u_int16_t	length			__attribute__ ((packed));
    u_int16_t	checksum		__attribute__ ((packed));
} udphdr_t;


/* ************************************************************
 * IGRP 
 * ************************************************************/
#define IGRP_OPCODE_REQUEST     2
#define IGRP_OPCODE_UPDATE      1

typedef struct {
    u_int8_t            opcode:4,version:4	__attribute__ ((packed));
    u_int8_t            edition			__attribute__ ((packed));
    u_int16_t           autosys			__attribute__ ((packed));
    u_int16_t           interior		__attribute__ ((packed));
    u_int16_t           system			__attribute__ ((packed));
    u_int16_t           exterior		__attribute__ ((packed));
    u_int16_t           checksum		__attribute__ ((packed));
} igrp_t;

/* 
 * comment:
 *      the thing with delay[3] ... is very ugly, but I'm not good 
 *      in representing this perhaps 3 byte long data type correctly.
 *      Cisco's documentation has still free space for improvements  ...
 */
typedef struct {
    u_int8_t            destination[3]  __attribute__ ((packed));
    u_int8_t            delay[3]        __attribute__ ((packed));
    u_int8_t            bandwith[3]     __attribute__ ((packed));
    u_int16_t           mtu             __attribute__ ((packed));
    u_int8_t            reliability     __attribute__ ((packed));
    u_int8_t            load            __attribute__ ((packed));
    u_int8_t            hopcount        __attribute__ ((packed));
} igrp_system_entry_t;


/* ************************************************************
 * ICMP
 * ************************************************************/
#define ICMP_ECHOREPLY          0       /* Echo Reply                   */
#define ICMP_DEST_UNREACH       3       /* Destination Unreachable      */
#define ICMP_SOURCE_QUENCH      4       /* Source Quench                */
#define ICMP_REDIRECT           5       /* Redirect (change route)      */
#define ICMP_ECHO               8       /* Echo Request                 */
#define ICMP_ROUTER_ADVERT	9	/* router advertisement 	*/
#define ICMP_SOLICITATION	10	/* router solicitation		*/
#define ICMP_TIME_EXCEEDED      11      /* Time Exceeded                */
#define ICMP_PARAMETERPROB      12      /* Parameter Problem            */
#define ICMP_TIMESTAMP          13      /* Timestamp Request            */
#define ICMP_TIMESTAMPREPLY     14      /* Timestamp Reply              */
#define ICMP_INFO_REQUEST       15      /* Information Request          */
#define ICMP_INFO_REPLY         16      /* Information Reply            */
#define ICMP_ADDRESS            17      /* Address Mask Request         */
#define ICMP_ADDRESSREPLY       18      /* Address Mask Reply           */
/* Codes for REDIRECT. */
#define ICMP_REDIR_NET          0       /* Redirect Net                 */
#define ICMP_REDIR_HOST         1       /* Redirect Host                */
#define ICMP_REDIR_NETTOS       2       /* Redirect Net for TOS         */
#define ICMP_REDIR_HOSTTOS      3       /* Redirect Host for TOS        */
/* codes for unreach */
#define ICMP_UNREACH_NET	0
#define ICMP_UNREACH_HOST	1
#define ICMP_UNREACH_PROTO	2	/* protocol unreachable 	*/
#define ICMP_UNREACH_PORT	3	/* port unreachable 		*/
#define ICMP_UNREACH_FRAG	4	/* fragmentation needed and DF	*/
#define ICMP_UNREACH_SOURCE	5	/* source route failed 		*/
#define ICMP_UNREACH_ADMIN1	9	/* administratively prohibited	*/
#define ICMP_UNREACH_TOS	11	/* unreach fro TOS		*/
#define ICMP_UNREACH_FIREWALL	13	/* port filtered 		*/

typedef struct {
    u_int8_t type			__attribute__ ((packed));
    u_int8_t code			__attribute__ ((packed));
    u_int16_t checksum			__attribute__ ((packed));
} icmphdr_t;

typedef struct {
    u_int16_t	identifier		__attribute__ ((packed));
    u_int16_t	seq			__attribute__ ((packed));
    u_int8_t	data[56]		__attribute__ ((packed));
} icmp_echohdr_t;

typedef struct {
    icmphdr_t		icmp		__attribute__ ((packed));
    icmp_echohdr_t	echo		__attribute__ ((packed));
} icmp_ping_t;

typedef struct {
    u_int16_t	identifier		__attribute__ ((packed));
    u_int16_t	seq			__attribute__ ((packed));
    u_int8_t	mask[4]			__attribute__ ((packed));
} icmp_netmask_t;

typedef struct {
    u_int16_t   identifier		__attribute__ ((packed));
    u_int16_t   seq			__attribute__ ((packed));
    u_int32_t   origts			__attribute__ ((packed));
    u_int32_t   recvts			__attribute__ ((packed));
    u_int32_t   transts			__attribute__ ((packed));
} icmp_timestamp_t;

typedef struct {
    u_int8_t	num_addr		__attribute__ ((packed));
    u_int8_t	addrsize		__attribute__ ((packed));
    u_int16_t	lifetime		__attribute__ ((packed));
} irdp_t;

typedef struct {
    u_int8_t	addr[4]			__attribute__ ((packed));
    u_int32_t	pref			__attribute__ ((packed));
} irdp_rec_t;

typedef struct {
    u_int8_t	type			__attribute__ ((packed));
    u_int8_t	code			__attribute__ ((packed));
    u_int16_t	checksum		__attribute__ ((packed));
    u_int32_t	reserved		__attribute__ ((packed));
} irdp_solicitation_t;

typedef struct {
    u_int8_t	type			__attribute__ ((packed));
    u_int8_t	code			__attribute__ ((packed));
    u_int16_t	checksum		__attribute__ ((packed));
    u_int8_t	gateway[4]		__attribute__ ((packed));
    u_int8_t	headerdata[28]		__attribute__ ((packed));
} icmp_redirect_t;

/* ************************************************************
 * OSPF
 * ************************************************************/
#define OSPF_HELLO      1
#define OSPF_DB_DESC    2
#define OSPF_LS_REQ     3
#define OSPF_LS_UPD     4
#define OSPF_LS_ACK     5

#define OSPF_AUTH_NONE          0
#define OSPF_AUTH_SIMPLE        1
#define OSPF_AUTH_CRYPT         2

typedef struct {
    u_int8_t	version			__attribute__ ((packed));
    u_int8_t	type			__attribute__ ((packed));
    u_int16_t	length			__attribute__ ((packed));
    u_int8_t	source[4]		__attribute__ ((packed));
    u_int8_t	area[4]			__attribute__ ((packed));
    u_int16_t	checksum		__attribute__ ((packed));
    u_int16_t	authtype		__attribute__ ((packed));
    u_int8_t	authdata[8]		__attribute__ ((packed));
} ospf_header_t;

typedef struct {
    u_int8_t	netmask[4]		__attribute__ ((packed));
    u_int16_t	hello_interval		__attribute__ ((packed));
    u_int8_t	options			__attribute__ ((packed));
    u_int8_t	priority		__attribute__ ((packed));
    u_int8_t	dead_interval[4] 	__attribute__ ((packed));
    u_int8_t	designated[4]		__attribute__ ((packed));
    u_int8_t	backup[4]		__attribute__ ((packed));
    //u_int8_t	activeneig[4]		__attribute__ ((packed));
} ospf_hello_t;

/* ************************************************************
 * Spanning Tree (STP)
 * ************************************************************/

typedef struct {
    u_int16_t	protocolid 		__attribute__ ((packed));
    u_int8_t	version 		__attribute__ ((packed));
    u_int8_t	BPDU_type 		__attribute__ ((packed));
    u_int8_t	BPDU_flags 		__attribute__ ((packed));
    u_int16_t	root_priority 		__attribute__ ((packed));
    u_int8_t	root_id[6] 		__attribute__ ((packed));
    u_int8_t	root_path_cost[4] 	__attribute__ ((packed));
    u_int16_t	bridge_priority 	__attribute__ ((packed));
    u_int8_t	bridge_id[6] 		__attribute__ ((packed));
    u_int16_t	port_id 		__attribute__ ((packed));
    u_int16_t	message_age 		__attribute__ ((packed));
    u_int16_t	max_age 		__attribute__ ((packed));
    u_int16_t	hello_time 		__attribute__ ((packed));
    u_int16_t	forward_delay 		__attribute__ ((packed));
} stp_t;

/* ************************************************************
 * EIGRP
 * ************************************************************/

#define EIGRP_UPDATE    0x01
#define EIGRP_REQUEST   0x02
#define EIGRP_QUERY     0x03
#define EIGRP_REPLY     0x04
#define EIGRP_HELLO     0x05

#define EIGRP_TYPE_PARA		0x0001
#define EIGRP_TYPE_SOFT		0x0004
#define EIGRP_TYPE_IN_ROUTE	0x0102
#define EIGRP_TYPE_EX_ROUTE	0x0103

typedef struct {
   u_int8_t	version			__attribute__ ((packed));
   u_int8_t	opcode			__attribute__ ((packed));
   u_int16_t	checksum		__attribute__ ((packed));
   u_int32_t	flags			__attribute__ ((packed));
   u_int32_t	seq			__attribute__ ((packed));
   u_int32_t	ack			__attribute__ ((packed));
   u_int32_t	as			__attribute__ ((packed));
} eigrp_t;

typedef struct {
    u_int16_t	type			__attribute__ ((packed));
    u_int16_t	length			__attribute__ ((packed));
    u_int8_t	iosmaj			__attribute__ ((packed));
    u_int8_t	iosmin			__attribute__ ((packed));
    u_int8_t	eigrpmaj		__attribute__ ((packed));
    u_int8_t	eigrpmin		__attribute__ ((packed));
} eigrpsoft_t;

typedef struct {
    u_int16_t	type			__attribute__ ((packed));
    u_int16_t	length			__attribute__ ((packed));
    u_int8_t	k1			__attribute__ ((packed));
    u_int8_t	k2			__attribute__ ((packed));
    u_int8_t	k3			__attribute__ ((packed));
    u_int8_t	k4			__attribute__ ((packed));
    u_int8_t	k5			__attribute__ ((packed));
    u_int8_t	reseved			__attribute__ ((packed));
    u_int16_t	holdtime		__attribute__ ((packed));
} eigrppara_t;

typedef struct {
    u_int16_t	type			__attribute__ ((packed));
    u_int16_t	length			__attribute__ ((packed));
    u_int8_t	nexthop[4]		__attribute__ ((packed));
    u_int8_t	origrouter[4]		__attribute__ ((packed));
    u_int32_t	origas			__attribute__ ((packed));
    u_int32_t	tag			__attribute__ ((packed));
    u_int32_t	external_metric		__attribute__ ((packed));
    u_int16_t	reserved_1		__attribute__ ((packed));
    u_int8_t	external_link		__attribute__ ((packed));
    u_int8_t	flags			__attribute__ ((packed));
    u_int32_t	delay			__attribute__ ((packed));
    u_int32_t	bandwidth		__attribute__ ((packed));
    u_int8_t	mtu[3]			__attribute__ ((packed));
    u_int8_t	hopcount		__attribute__ ((packed));
    u_int8_t	reliability		__attribute__ ((packed));
    u_int8_t	load			__attribute__ ((packed));
    u_int16_t	reserved_2		__attribute__ ((packed));
    u_int8_t	prefix_length		__attribute__ ((packed));
    		/* Warning: 
		 * this filed is variable and depends on prefix_length 
		 * 8= 1
		 * 16=2
		 * 24=3
		 * 32=4*/
    u_int8_t	dest			__attribute__ ((packed));
} eigrpextroute_t;

typedef struct {
    u_int16_t	type			__attribute__ ((packed));
    u_int16_t	length			__attribute__ ((packed));
    u_int8_t	nexthop[4]		__attribute__ ((packed));
    u_int32_t	delay			__attribute__ ((packed));
    u_int32_t	bandwidth		__attribute__ ((packed));
    u_int8_t	mtu[3]			__attribute__ ((packed));
    u_int8_t	hopcount		__attribute__ ((packed));
    u_int8_t	reliability		__attribute__ ((packed));
    u_int8_t	load			__attribute__ ((packed));
    u_int16_t	reserved_2		__attribute__ ((packed));
    u_int8_t	prefix_length		__attribute__ ((packed));
    		/* Warning: 
		 * this filed is variable and depends on prefix_length 
		 * 8= 1
		 * 16=2
		 * 24=3
		 * 32=4*/
    u_int8_t	dest			__attribute__ ((packed));
} eigrpintroute_t;

/* ************************************************************
 * RIP v1
 * ************************************************************/
#define RIP_PORT		520
#define RIP_COMMAND_REQUEST	1
#define RIP_COMMAND_RESPONSE	2

typedef struct {
    u_int8_t	command		__attribute__ ((packed));
    u_int8_t	version		__attribute__ ((packed));
    u_int16_t	zero		__attribute__ ((packed));
} ripv1hdr_t;

typedef struct {
    u_int16_t	addrfamily	__attribute__ ((packed));
    u_int16_t	zero1		__attribute__ ((packed));
    u_int8_t	address[4]	__attribute__ ((packed));
    u_int16_t	zero2[4]	__attribute__ ((packed));
    u_int32_t	metric		__attribute__ ((packed));
} ripv1addr_t;

typedef struct {
    u_int8_t	command		__attribute__ ((packed));
    u_int8_t	version		__attribute__ ((packed));
    u_int16_t	domain		__attribute__ ((packed));
} ripv2hdr_t;

typedef struct {
    u_int16_t	addrfamily	__attribute__ ((packed));
    u_int16_t	routetag	__attribute__ ((packed));
    u_int8_t	address[4]	__attribute__ ((packed));
    u_int8_t	netmask[4]	__attribute__ ((packed));
    u_int8_t	nexthop[4]	__attribute__ ((packed));
    u_int32_t	metric		__attribute__ ((packed));
} ripv2addr_t;

typedef struct {
    u_int16_t	addrfamily	__attribute__ ((packed));
    u_int16_t	authtype	__attribute__ ((packed));
    u_int8_t	auth[16]	__attribute__ ((packed));
} ripv2auth_t;

/* ************************************************************
 * GRE
 * ************************************************************/
typedef struct {
    u_int16_t	flags;
    u_int16_t	proto;
} grehdr_t;

/* ************************************************************
 * HSRP
 * ************************************************************/
#define HSRP_OPCODE_HELLO  0
#define HSRP_OPCODE_COUP   1
#define HSRP_OPCODE_RESIGN 2

#define HSRP_STATE_INITIAL  0
#define HSRP_STATE_LEARN    1
#define HSRP_STATE_LISTEN   2
#define HSRP_STATE_SPEAK    4
#define HSRP_STATE_STANDBY  8
#define HSRP_STATE_ACTIVE  16

typedef struct {
    u_int8_t	version;
    u_int8_t	opcode;
    u_int8_t	state;
    u_int8_t	hellotime;
    u_int8_t	holdtime;
    u_int8_t	prio;
    u_int8_t	group;
    u_int8_t	reserved;
    u_int8_t	auth[8];
    u_int8_t	virtip[4];
} hsrp_t;

/* ************************************************************
 * DHCP
 * ************************************************************/
#define DHCP_CLIENT_PORT	68
#define DHCP_SERVER_PORT	67
#define DHCPDISCOVER		1
#define DHCPOFFER		2
#define DHCPREQUEST		3
#define DHCPDECLINE		4
#define DHCPACK			5
#define DHCPNAK			6
#define DHCPRELEASE		7
#define DHCPINFORM		8
typedef struct {
    u_int8_t	msgtype				__attribute__ ((packed));
    u_int8_t	hwtype				__attribute__ ((packed));
    u_int8_t	hwalen				__attribute__ ((packed));
    u_int8_t	hops				__attribute__ ((packed));
    u_int32_t	transid				__attribute__ ((packed));
    u_int16_t	seconds				__attribute__ ((packed));
    u_int16_t	bcastflags			__attribute__ ((packed));
    u_int32_t	ciaddr				__attribute__ ((packed));
    u_int32_t	yiaddr				__attribute__ ((packed));
    u_int32_t	siaddr				__attribute__ ((packed));
    u_int32_t	giaddr				__attribute__ ((packed));
    u_char	chaddr[16]			__attribute__ ((packed));
    u_char	sname[64]			__attribute__ ((packed));
    u_char	file[128]			__attribute__ ((packed));
    u_int8_t	cookie[4]			__attribute__ ((packed));
} dhcp_t;

#define DHCP_OPTION_DISCOVER	53
#define DHCP_OPTION_PARAMETERS	55
#define DHCP_OPTION_CLIENTID	61
typedef struct {
    u_int8_t	type;
    u_int8_t	length;
    u_int8_t	value;
} dhcp_option_t;

#endif _PROTOCOLS_H_
