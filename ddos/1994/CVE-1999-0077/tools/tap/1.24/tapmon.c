/*
 * read/write /dev/tapc* utility
 */
#include <stdio.h>
/* #include <ctype.h> */
#include <sys/types.h>
/* #include <sys/time.h> */
#include <fcntl.h>
#include <sys/filio.h>
#include <sys/termios.h>

#define STDIN	0
#define STDOUT	1

#define NAME	"/dev/tapc%d"
#define CLONENAME "/dev/tapcx"

#define ESCAPE	31	/* CTRL-_ */

#ifndef lint
static	char sccsid[] = "@(#)tapmon.c	1.24 3/22/92";
#endif

char *myname;

int viatty;
struct termios old,new;

usage()
{
	(void)fprintf(stderr,"Usage: %s [-r] <tap-id>\n",myname);
	(void)fprintf(stderr,"       tap-id: 0-255|x\n");
	exit(1);
}

main(argc,argv)
int argc;
char *argv[];
{
	unsigned long id;
	int f,r;
	char name[sizeof(NAME)+3];
	char *ptr;
	int c,errflg=0,reverse=0;
	extern char *optarg;
	extern int optind;

	myname=argv[0];


	while ((c = getopt(argc, argv, "r")) != -1){
		switch (c) {
		case 'r':
			reverse++;
			break;
		case '?':
		default:
			errflg++;
		}
	}
	if (errflg||(optind+1)!=argc) {
		usage();
	}

	if(!strcmp(argv[optind],"x"))
		sprintf(name,CLONENAME);
	else {
		id=strtol(argv[optind],&ptr,0);
		if(id>255||*ptr!='\0')
			usage();
		sprintf(name,NAME,id);
	}

	if((f=open(name,O_RDWR|(reverse?O_NDELAY:0)))<0){
		perror(name);
		exit(1);
	}

	ttyset(name);
	r=connect(f);
	close(f);
	ttyreset();
	return(r);
}

ttyset(name)
char *name;
{
	if(isatty(STDIN)){
		viatty=1;
		fprintf(stderr,"CONNECTED TO %s\n",name);
		fprintf(stderr,"ESCAPE CHARACTER IS CTRL-%c\n",ESCAPE+'@');
		if(ioctl(STDIN,TCGETS,&old)==(-1)){
			perror("TCGETS");
			exit(1);
		}
		new=old;
		new.c_iflag = 0;
		/* new.c_oflag = 0;*/
		new.c_lflag = 0;
		if(ioctl(STDIN,TCSETS,&new)==(-1)){
			perror("TCSETS");
			exit(1);
		}
	}
}

ttyreset()
{
	if(viatty){
		if(ioctl(STDIN,TCSETS,&old)==(-1)){
			perror("TCSETS");
			exit(1);
		}
		fprintf(stderr,"\nCONNECTION CLOSED\n");
	}
}

connect(f)
{
	register int n,s;
	int x,w;
	fd_set fdset;
	char buf[512];

	s=sizeof(buf);
	w=f+1;
	FD_ZERO(&fdset);
	FD_SET(STDIN,&fdset);
	FD_SET(f,&fdset);

	while((x=select(w,&fdset,NULL,NULL,NULL))){
		if( FD_ISSET (f, &fdset)){
			if(ioctl(f,FIONREAD,&n)==(-1)){
				perror(myname);
				return(10);
			}
			if(!n)
				break;
			n = (n<s)?n:s;
			if(read(f,buf,n)!=n){
				perror(myname);
				return(11);
			}
			(void)write(STDOUT,buf,n);
		}
		if( FD_ISSET (STDIN, &fdset)){
			if(ioctl(STDIN,FIONREAD,&n)==(-1)){
				perror(myname);
				return(12);
			}
			if(!n)
				break;
			n = (n<s)?n:s;
			if(read(STDIN,buf,n)!=n){
				perror(myname);
				return(13);
			}
			if(viatty&&buf[0]==ESCAPE)
				break;	
			(void)write(f,buf,n);
		}
		FD_SET(STDIN,&fdset); /* again and again */
		FD_SET(f,&fdset);
	}
	return(0);
}
