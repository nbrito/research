#include <stdio.h>
#include <fcntl.h>
#include <sys/filio.h>
#define STDOUT	1

#ifndef lint
static	char sccsid[] = "@(#)tapmon.c	1.5 3/19/92";
#endif

usage(myname)
char *myname;
{
	fprintf(stderr,"Usage: %s down|up\n",myname);
	exit(1);
}

main(argc,argv)
int argc;
char *argv[];
{
	char *tapcname;
	int f;
	int s;
	int n;
	char buf[512];

	if(argc!=2){
		usage(argv[0]);
	}
	if(!strcmp(argv[1],"down"))
		tapcname="/dev/tapc0";
	else if(!strcmp(argv[1],"up"))
		tapcname="/dev/tapc1";
	else
		usage(argv[0]);

	if((f=open(tapcname,O_RDONLY))<0){
		perror(tapcname);
		exit(1);
	}
	s=sizeof(buf);
	while(read(f,buf,1)==1){
		write(STDOUT,buf,1);
		if(ioctl(f,FIONREAD,&n)==(-1)){
			perror("FIONREAD");
			exit(1);
		}
		n = (n<s)?n:s;
		if(read(f,buf,n)!=n){
			perror(tapcname);
			exit(1);
		}
		write(STDOUT,buf,n);
	}
	exit(0);
}
