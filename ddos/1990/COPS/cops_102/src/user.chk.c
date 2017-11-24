#include <stdio.h>
#include <pwd.h>
#include <sys/types.h>
#include <sys/stat.h>

/* Any file writable by all will be flagged */
#define DMODE 002

#define MODE1 004
#define MODE2 040

/* #define DMODE2 020 */

/* potentially dangerous files */
char *ftable[] = {
	"rhosts",
	"profile",
	"login",
	"logout",
	"cshrc",
	"bashrc",
	"kshrc",
	"tcshrc",
	"netrc",
	"forward",
	"dbxinit",
	"distfile",
	"exrc",
	"emacsrc"
};
char *ft;
char *ftr, *malloc();

char generic_file[100];

main(argc,argv)
int argc;
char **argv;
{
register int fmode;
register int index;
struct passwd *pp;
static struct stat statb;

if (argc != 1) {
	printf("Usage: %s\n",argv[0]);
	exit(1);
	}

ft = malloc(100);
ftr = malloc(100);

while ((pp = getpwent()) != (struct passwd *)0) {
	if (stat(pp->pw_dir,&statb) < 0) {
		continue;
		}

	index = 0;
	/*
	 *   Use the home-dir, and add on each potential security threat
	 * file to the path one at a time.  Then check each file to see
	 * if it breaks with the modes established up above
	 *
	*/
	for (ft = ftable[index]; index < 13; ft = ftable[++index]) {
		if (strlen(pp->pw_dir) != 1)
			sprintf(generic_file, "%s/.%s", pp->pw_dir,ft);
		else 
			sprintf(generic_file, "%s.%s", pp->pw_dir,ft);

		if (stat(generic_file,&statb) < 0)
			continue;

		if (statb.st_mode & DMODE) 
			printf("Warning!  User %s:\t%s is mode \t0%3.3o!\n",
	       		pp->pw_name,generic_file,statb.st_mode&~S_IFMT);

		/* check for mode on .netrc files; should be non-readable */
		if (!strcmp("netrc", ftable[index]))
			if (statb.st_mode & MODE1 || statb.st_mode & MODE2)
				printf("Warning!  User %s:\t%s is readable; mode \t0%3.3o!\n",
	       			pp->pw_name,generic_file,statb.st_mode&~S_IFMT);
		}

	}

exit(0);
}
