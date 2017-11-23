/* IRPAS project - packet library
 *
 * FX <fx@phenoelit.de>
 * Phenoelit (http://www.phenoelit.de)
 * (c) 2k
 *
 * $Id: packets.c,v 1.2 2001/06/16 18:17:31 fx Exp $
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <time.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <arpa/inet.h>

#include <protocols.h>
#include <packets.h>


packet_ifconfig_t	packet_ifconfig;


/* pings the host, waits 'timeout' seconds and reports to stdout 
 * depending on the level of 'verbose'
 *
 * returns 0 on OK, -1 on error, 1 on timeout */
int     icmp_ping(struct in_addr *t,int timeout,int verbose) {
#define RESP_ONE	1
#define RESP_MORE	2
    int				sfd;
    struct sockaddr_in  	sin,fromaddr;
    u_char			*tpacket;
    icmp_ping_t			*pingh;
    int				psize;
    u_int16_t			pident;
    int				rc,addrsize,respond=0;
    unsigned long		start_t;
    struct timespec		sleeper = { 0, 10 };


    if ((sfd=socket(AF_INET,SOCK_RAW,IPPROTO_ICMP))<0) {
	perror("socket()");
	return(-1);
    }

    rc=1;
    if (setsockopt(sfd,SOL_SOCKET,SO_BROADCAST,(void *)&rc,sizeof(int))!=0) { 
	perror("setsockopt"); 
	return (-1); 
    }

    psize=sizeof(icmp_ping_t);
    tpacket=(u_char *)smalloc(sizeof(icmp_ping_t)
	    +3 /* for my checksum function, which sometimes 
		  steps over the mark */
	    );

    pident=1+(u_int16_t) (65535.0*rand()/(RAND_MAX+1.0));
    /* make up the icmp header */
    pingh=(icmp_ping_t *)tpacket;
    pingh->icmp.type=ICMP_ECHO;
    pingh->icmp.code=0;
    pingh->echo.identifier=htons(pident);
    pingh->icmp.checksum=chksum((u_char *)pingh,psize);

    memset(&sin,0,sizeof(struct sockaddr_in));
    sin.sin_family=AF_INET;
    sin.sin_port=htons(0);
    memcpy(&(sin.sin_addr),t,sizeof(sin.sin_addr));

    if (sendto(sfd,tpacket,psize,0,
                (struct sockaddr *) &sin,
                sizeof(struct sockaddr_in)) <0) {
        perror("sendto()");
        return(-1);
    }

    rc= O_NONBLOCK | fcntl(sfd, F_GETFL);
    fcntl(sfd,F_SETFL,rc);

    memset(&fromaddr,0,sizeof(struct sockaddr_in));
    addrsize=sizeof(struct sockaddr_in);
    start_t=(unsigned long)time(NULL);
    memset(tpacket,0,psize);

    while (start_t+timeout>=time(NULL)) {
	if ((rc=recvfrom(sfd,(u_char *)tpacket,psize,0,
		    (struct sockaddr *)&fromaddr,
		    &addrsize))>=0) {
	    pingh=(icmp_ping_t *)(tpacket+sizeof(iphdr_t));

	    if (pingh->icmp.type==ICMP_ECHOREPLY) {

		if ( /* address has to be the same */
			(!memcmp(&(fromaddr.sin_addr),
			    &(sin.sin_addr),sizeof(sin.sin_addr)))
			&&
			(ntohs(pingh->echo.identifier)==pident)
			){
		    /* normal response */
		    respond=RESP_ONE;
		    if (verbose>1) 
			printf("%s respond ... good\n",
				inet_ntoa(fromaddr.sin_addr));
		    break;

		} else if (
			/** SECTION that handles bcast and network addrs **/

			/* address is different - possibly bcast*/
			(memcmp(&(fromaddr.sin_addr),
			    &(sin.sin_addr),sizeof(sin.sin_addr)))
			&&
			(ntohs(pingh->echo.identifier)==pident)
			) {
		    if (verbose) {
			fprintf(stderr,"%s respond instead of ",
				inet_ntoa(fromaddr.sin_addr));
			fprintf(stderr,"%s (broadcast or network address?)\n",
				inet_ntoa(sin.sin_addr));
		    }
		    if (respond==0) respond=RESP_ONE; else respond=RESP_MORE;
		}
		/* it may be an ECHO REPLY, but it's not our's */
	    }
	    /* it's not an ECHO REPLY, therefore it is not OK */
	}

	nanosleep(&sleeper,NULL);
    }

    if (!respond) {
	if (verbose) {
	    printf("%s not responding to ICMP Echo request\n",
		    inet_ntoa(*t));
	}
	free(tpacket);
	close(sfd);
	return 1;
    } else if (respond==RESP_MORE) {
	if (verbose) {
	    printf("%s is broadcast or network\n",
		    inet_ntoa(*t));
	}
	free(tpacket);
	close(sfd);
	return 1;
    } else {
	if (verbose) {
	    printf("%s is alive\n",
		    inet_ntoa(*t));
	}
	free(tpacket);
	close(sfd);
	return 0;
    }

    /* not reached */
    return 0;
}


void	makenonblock(int s) {
    int		rc=1;

    rc= O_NONBLOCK | fcntl(s, F_GETFL);
    fcntl(s,F_SETFL,rc);
}

int	makebcast(int s) {
    int		rc=1;

    if (setsockopt(s,SOL_SOCKET,SO_BROADCAST,(void *)&rc,sizeof(int))!=0) { 
	perror("setsockopt"); 
	return (-1); 
    }
    return(0);
}


/* opens the raw socket,
 * RETURNS 0 on success or -1 on error */
int     init_socket_eth(char *device) {
    int			sfd;
    struct ifreq        ifr;

    if ((sfd=socket(PF_INET, SOCK_PACKET, htons(ETH_P_ALL)))<0) {
	perror("socket()");
	return (-1);
    }

    /* get HW addr */
    memset(&ifr,0,sizeof(ifr));
    strncpy(ifr.ifr_name, device, sizeof (ifr.ifr_name));
    if (ioctl(sfd, SIOCGIFHWADDR, &ifr) < 0 ) {
        perror("ioctl()");
        return (-1);
    }
    memcpy(&(packet_ifconfig.eth),&ifr.ifr_hwaddr.sa_data,ETH_ALEN);

    /* grab the IP address */
    memset(&ifr,0,sizeof(ifr));
    strncpy(ifr.ifr_name, device, sizeof (ifr.ifr_name));
    if (ioctl(sfd, SIOCGIFADDR, &ifr) < 0 ) {
	perror("ioctl()");
	return (-1);
    }
    memcpy(&(packet_ifconfig.ip.s_addr),
	    &(*(struct sockaddr_in *)&ifr.ifr_addr).sin_addr.s_addr,
	    IP_ADDR_LEN);

    /* get MTU for size */
    memset(&ifr,0,sizeof(ifr));
    strncpy(ifr.ifr_name, device, sizeof (ifr.ifr_name));
    if (ioctl(sfd, SIOCGIFMTU, &ifr) < 0 ) {
        perror("ioctl()");
        return (-1);
    }
    packet_ifconfig.mtu=ifr.ifr_mtu;

    /* get broadcast addr for size */
    memset(&ifr,0,sizeof(ifr));
    strncpy(ifr.ifr_name, device, sizeof (ifr.ifr_name));
    if (ioctl(sfd, SIOCGIFBRDADDR, &ifr) < 0 ) {
        perror("ioctl()");
        return (-1);
    }
    memcpy(&(packet_ifconfig.bcast.s_addr),
	    &(*(struct sockaddr_in *)&ifr.ifr_addr).sin_addr.s_addr,
	    IP_ADDR_LEN);

    return sfd;
}


/* creates the socket
 * Returns the socket or -1 on error */
int     init_socket_IP4(char *device, int broadcast) {
    int                 sfd;
    struct ifreq        ifr;
    int                 t=1;

    if ((sfd=socket(AF_INET,SOCK_RAW,IPPROTO_RAW))<0) {
        perror("socket()");
        return(-1);
    }

    /* make a broadcast enabled socket if desired */
    if (broadcast) {
	if (setsockopt(
		    sfd,SOL_SOCKET,SO_BROADCAST,
		    (void *)&t,sizeof(int)) != 0) {
	    perror("setsockopt");
	    return (-1);
	}
    }

    /* get HW addr */
    memset(&ifr,0,sizeof(ifr));
    strncpy(ifr.ifr_name, device, sizeof (ifr.ifr_name));
    if (ioctl(sfd, SIOCGIFHWADDR, &ifr) < 0 ) {
        perror("ioctl()");
        return (-1);
    }
    memcpy(&(packet_ifconfig.eth),&ifr.ifr_hwaddr.sa_data,ETH_ALEN);

    /* grab the IP address */
    memset(&ifr,0,sizeof(ifr));
    strncpy(ifr.ifr_name, device, sizeof (ifr.ifr_name));
    if (ioctl(sfd, SIOCGIFADDR, &ifr) < 0 ) {
	perror("ioctl()");
	return (-1);
    }
    memcpy(&(packet_ifconfig.ip.s_addr),
	    &(*(struct sockaddr_in *)&ifr.ifr_addr).sin_addr.s_addr,
	    IP_ADDR_LEN);

    /* get MTU for size */
    memset(&ifr,0,sizeof(ifr));
    strncpy(ifr.ifr_name, device, sizeof (ifr.ifr_name));
    if (ioctl(sfd, SIOCGIFMTU, &ifr) < 0 ) {
        perror("ioctl()");
        return (-1);
    }
    packet_ifconfig.mtu=ifr.ifr_mtu;

    /* get broadcast addr for size */
    memset(&ifr,0,sizeof(ifr));
    strncpy(ifr.ifr_name, device, sizeof (ifr.ifr_name));
    if (ioctl(sfd, SIOCGIFBRDADDR, &ifr) < 0 ) {
        perror("ioctl()");
        return (-1);
    }
    memcpy(&(packet_ifconfig.bcast.s_addr),
	    &(*(struct sockaddr_in *)&ifr.ifr_addr).sin_addr.s_addr,
	    IP_ADDR_LEN);

    return sfd;
}



/* sends out a raw IP packet 
 * returns 0 on success or -1 on error */
int     sendpack_IP4(int sfd, u_char *packet,int plength) {
    struct sockaddr_in  sin;
    iphdr_t             *iph;

    iph=(iphdr_t *)packet;

    memset(&sin,0,sizeof(struct sockaddr_in));
    sin.sin_family=AF_INET;
    sin.sin_port=htons(0);
    memcpy(&(sin.sin_addr),&(iph->daddr),sizeof(sin.sin_addr));

    if (sendto(sfd,packet,plength,0,
                (struct sockaddr *) &sin,
                sizeof(struct sockaddr_in)) <=0) {
        perror("sendto()");
        return(-1);
    }

    return 0;
}


/* send's the ethernet frame,
 * RETURNS the number of octets send or -1 on error */
int     sendpack_eth(char *device, int atsock, 
		u_char *frame, int frame_length) {
    struct sockaddr     sa;
    int                 sendBytes;

    memset(&sa,0,sizeof(sa));
    strncpy(sa.sa_data,device,sizeof(sa.sa_data));

    sendBytes=sendto(atsock,frame,frame_length,0,&sa,sizeof(sa));
    if (sendBytes<0) {
        perror("send_ethernet_frame(): sendto");
        return (-1);
    } else if (sendBytes<frame_length) {
#ifdef __DEBUG__
        fprintf(stderr,"send_ethernet_frame(): "
                "WARNING: short send %d out off %d\n",sendBytes,frame_length);
#endif __DEBUG__
    }

    return sendBytes;
}


/* returns an initialized pointer to a memory area 
 * or hard-exits on failure */
void    *smalloc(size_t size) {
    void        *p;

    if ((p=malloc(size))==NULL) {
        fprintf(stderr,"smalloc(): malloc failed\n");
        exit (-2);
    }
    memset(p,0,size);
    return p;
}


/* returns the checksum 
 * WARNING: if left over bytes are present, the memory after *data has to
 * contain 0x00 series and should be part of the buffer
 * -> make the buffer for data at least count+1 bytes long ! */
u_int16_t chksum(u_char *data, unsigned long count) {
    u_int32_t           sum = 0;
    u_int16_t           *wrd;

    wrd=(u_int16_t *)data;
    while( count > 1 )  {
        sum = sum + *wrd;
        wrd++;
        count -= 2;
    }

    /*  Add left-over byte, if any */
    if( count > 0 ) {
#ifdef __DEBUG__
            printf("Left over byte: %04X\n",((*wrd & 0xFF)<<8));
#endif __DEBUG__
        sum = sum + ((*wrd &0xFF)<<8);
    }

    /*  Fold 32-bit sum to 16 bits */
    while (sum>>16) {
        sum = (sum & 0xffff) + (sum >> 16);
    }

    return (~sum);
}


