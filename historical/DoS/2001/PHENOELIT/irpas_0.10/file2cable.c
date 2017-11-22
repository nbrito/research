/* frame sender
 *
 * FX <fx@phenoelit.de>
 * Phenoelit (http://www.phenoelit.de)
 * (c) 2k1
 *
 * $Id: file2cable.c,v 1.3 2001/07/07 17:44:30 fx Exp $
 */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <netinet/in.h>
#include <rpc/types.h>
#include <netdb.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <errno.h>
#include <fcntl.h>

#include "protocols.h"
#include "packets.h"

struct {
    char		*device;
    int			verbose;
    char		*filename;
} cfg;

void usage(char *n);
void hexdump(unsigned char *c,int len);
void lamont_hdump(unsigned char *bp, unsigned int length);

/* ******************* MAIN ******************** */

int main(int argc,char **argv) {
    char		option;
    extern char		*optarg;

    int			atsock,fd;		
    unsigned char	*buffer;
    struct stat		sbuf;

    /* for flooding */

    memset(&cfg,0,sizeof(cfg));
    while ((option=getopt(argc,argv,"vi:f:"))!=EOF) {
	switch (option) {
	    /* general */
	    case 'v':	cfg.verbose++;
			break;
	    case 'i':	cfg.device=(char *)smalloc(strlen(optarg));
			strcpy(cfg.device,optarg);
			break;
	    case 'f':	cfg.filename=(char *)smalloc(strlen(optarg));
			strcpy(cfg.filename,optarg);
			break;

	    /* fallback */
	    default:	usage(argv[0]);
	}
    }

    if (!(cfg.device&&cfg.filename)) usage(argv[0]);
    printf("file2cable - by FX <fx@phenoelit.de>\n"
	    "\tThanx got to Lamont Granquist & fyodor"
	    " for their hexdump()\n");

    if (stat(cfg.filename,&sbuf)!=0) {
	perror("stat()");
	exit (1);
    } else {
	if (cfg.verbose) 
	    printf("%s - %ld bytes raw data\n",cfg.filename,sbuf.st_size);
	buffer=(unsigned char *)smalloc(sbuf.st_size);
	if ((fd=open(cfg.filename,O_RDONLY))<0) {
	    perror("open()");
	    exit (1);
	}
	read(fd,buffer,sbuf.st_size);
	close(fd);
    }

    if (cfg.verbose) {
	lamont_hdump(buffer,sbuf.st_size);
	printf("Packet length: %d\n",(int)sbuf.st_size);
    }
    
    if ((atsock=init_socket_eth(cfg.device))<=0) exit(1);

    sendpack_eth(cfg.device,atsock,buffer,sbuf.st_size);
    close(atsock);
	
    return 0;
}

void hexdump(unsigned char *c,int len) {
    /* stolen from tcpdump, then kludged extensively by fyodor, then stolen
     * by me from nmap's util.c */
    static const char asciify[] = "................................ !\"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~.................................................................................................................................";
    int 	i;

    i=0;
    while (i++<len) {
	printf("%02X(%c) ",(unsigned int)(*c),asciify[(int)(*c)]);
	c++;
	if (i%8==0) printf("\n");
    }
    printf("\n");
}

/* A better version of hdump, from Lamont Granquist.  Modified slightly
   by Fyodor (fyodor@DHP.com) 
   obviously stolen from nmap (util.c)*/
void lamont_hdump(unsigned char *bp, unsigned int length) {

  /* stolen from tcpdump, then kludged extensively */

  static const char asciify[] = "................................ !\"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~.................................................................................................................................";

  register const u_short *sp;
  register const u_char *ap;
  register u_int i, j;
  register int nshorts, nshorts2;
  register int padding;

  printf("\n\t");
  padding = 0;
  sp = (u_short *)bp;
  ap = (u_char *)bp;
  nshorts = (u_int) length / sizeof(u_short);
  nshorts2 = (u_int) length / sizeof(u_short);
  i = 0;
  j = 0;
  while(1) {
    while (--nshorts >= 0) {
      printf(" %04x", ntohs(*sp));
      sp++;
      if ((++i % 8) == 0)
        break;
    }
    if (nshorts < 0) {
      if ((length & 1) && (((i-1) % 8) != 0)) {
        printf(" %02x  ", *(u_char *)sp);
        padding++;
      }
      nshorts = (8 - (nshorts2 - nshorts));
      while(--nshorts >= 0) {
        printf("     ");
      }
      if (!padding) printf("     ");
    }
    printf("  ");

    while (--nshorts2 >= 0) {
      printf("%c%c", asciify[*ap], asciify[*(ap+1)]);
      ap += 2;
      if ((++j % 8) == 0) {
        printf("\n\t");
        break;
      }
    }
    if (nshorts2 < 0) {
      if ((length & 1) && (((j-1) % 8) != 0)) {
        printf("%c", asciify[*ap]);
      }
      break;
    }
  }
  if ((length & 1) && (((i-1) % 8) == 0)) {
    printf(" %02x", *(u_char *)sp);
    printf("                                       %c", asciify[*ap]);
  }
  printf("\n");
}

void usage(char *n) {
    printf( "%s [-v] -i <interface> -f <file>\n", n);
    exit(0);
}
