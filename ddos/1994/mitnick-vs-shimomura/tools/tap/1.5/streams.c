
#include <stdio.h>
#include <sys/stropts.h> 

#ifndef lint
static	char sccsid[] = "@(#)streams.c	1.5 3/19/92";
#endif

int silence = 0;

pop(fd,namewanted)
char *namewanted;
{
	char name[64];

	if(ioctl(fd, I_LOOK, name) != -1) {
		if(!strcmp(name,namewanted)){
			if(!silence)
				fprintf(stderr,"popping module: %s\n", name);
			if(ioctl(fd,I_POP,0) == -1)
				if(!silence)
					perror("ioctl I_POP");
		}else{

			if(!silence)
				fprintf(stderr,
				"module %s not pop,module %s is on stack top\n",
				namewanted,name);
		}
	} else {
		if(!silence)
			fprintf(stderr,"no module on stack\n");
	}
}

push(fd,name)
char *name;
{
	if(!silence)
		fprintf(stderr,"pushing module: %s\n", name);
	if (ioctl(fd, I_PUSH, name) < 0) 
		if(!silence)
			perror(name);
}

main(argc, argv)
int argc;
char **argv;
{
	int c,errflg=0;
	extern char *optarg;
	extern int optind;

	while ((c = getopt(argc, argv, "so:u:")) != -1){
		switch (c) {
		case 'o':
			pop(0,optarg);
			break;
		case 'u':
			push(0,optarg);
			break;
		case 's':
			silence = ~silence;
			break;
		case '?':
		default:
			errflg++;
		}
	}
	if (errflg||optind!=argc||argc==1) {
		(void)fprintf(stderr, 
			"Usage: %s [-s] [-o module-to-pop] [-u module-to-push] ...\n",
			argv[0]);
		(void)fprintf(stderr,
			"       the order of all options is important\n");
		exit (2);
	}
}
