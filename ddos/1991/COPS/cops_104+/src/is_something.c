/*
    Usage: is_xxx [-gv] <filename>

    This checks determines whether a file is (group or world)
  writable, readable, or SUID, and returns a 0 if false, 1 if true.
  The -g option checks for group status, the -v option prints out
  the result as well.

  	Permissions bits:		  vvv--- Permission bits
   	        1 = execute		00000
   	        2 = writable		 ^
   	        4 = readable		 + Setuid bits

  	Setuid bits:
   	        1 = sticky
   	        2 = set group id
   	        4 = set user od

    Pete Shipley (shipley@mica.berkeley.edu) gutted my original code,
  made in cleaner and smarter, and combined everything into one compact
  file.  What a deal, huh?  Then I came along and beat up his code and
  made it look ugly again (I changed the is_writeable option to return
  true if _any_ parent directories are writable, not just the target.  So
  you can blame me if you want.  Better yet, just send me a patch if I
  blew it.)

*/

#include <sys/types.h>
#include <sys/stat.h>

#ifdef SETUID
#define G_TEST 02000	/* set group id */
#define W_TEST 04000	/* set user id */
#define G_REPORT_STRING	"%s is set gid\n"
#define W_REPORT_STRING	"%s is set uid\n"
#endif SETUID

#ifdef READABLE
#define G_TEST 00040	/* group readable */
#define W_TEST 00004	/* world readable */
#define G_REPORT_STRING	"%s is group readable\n"
#define W_REPORT_STRING	"%s is world readable\n"
#endif READABLE

#ifdef WRITABLE
#define G_TEST 00020	/* group writable */
#define W_TEST 00002	/* world writable */
#define G_REPORT_STRING	"%s is group writable\n"
#define W_REPORT_STRING	"%s is world writable\n"
#endif WRITABLE

main(argc,argv)
int argc;
char **argv;
{
    register int group = 0,
	    verbose = 0,
	    xmode;

    static struct stat statb;

    /* check out arguments */
    if (argc < 2) {
	(void) printf("Usage: %s [-gv] file\n",argv[0]);
	exit(0);
    }

    /* parse arguments */
    if (argc > 2) {
	while (argv[1][0] == '-' && argv[1][1] != '\0') {
	    if (argv[1][1] == 'g') { group++; argv++; }
	    if (argv[1][1] == 'v') { verbose++; argv++; }
	}
    }

    /* get stats on file in question */
    if (stat(*++argv,&statb) < 0) {
	perror(*argv);
	exit(2);
    }

/*
           the write stuff, so to speak...
     What I'm doing in this mess is to parse the file in question, check out
   whole path; 'cause if anything is world writable, you can compromise.

*/
#ifdef WRITABLE
{
char foo_dirs[256][256];  /* 256 levels of dirs, max len each 256 chars */
char *foo_file;
int i = 0, j;

	foo_file = *argv;
	strcpy(foo_dirs[i++], foo_file);

	j=strlen(foo_file) - 1;
	do {
		if (foo_file[j] == '/')
			strncpy(foo_dirs[i++], foo_file, j);
	} while (--j > 0);

	for (j = 0; j < i; j++)
		{
		if (stat(foo_dirs[j],&statb) < 0)
			continue;
		else if (!group) {
			if (statb.st_mode & W_TEST)
				exit(0);
			}
		else if (statb.st_mode & G_TEST)
			exit(0);
		}

	exit(1);
}
#endif WRITABLE

    /* test premissions on file in question */
    if (group) {
	xmode = statb.st_mode & G_TEST;
    } else {
	xmode = statb.st_mode & W_TEST;
    }

    /* report finding */

    if(verbose && xmode) {
	(void) printf( (group ? G_REPORT_STRING : W_REPORT_STRING), *argv);
    }

    exit(!xmode);
}
