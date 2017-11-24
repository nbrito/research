/*
    Usage:

 is_able filename {w|g|s|S}       {r|w|B|b|s}
         (world/group/SUID/SGID   read/write/{read&write}/{suid&write}/s[ug]id)

    The second arg of {r|w} determines whether a file is (group or world
  depending on the first arg of {w|g}) writable/readable, or if it is
  SUID/SGID (first arg, either s or S, respectively), and prints out a
  short message to that effect.

 So:
    is_able w w		# checks if world writable
    is_able g r		# checks if group readable
    is_able s s		# checks if SUID
    is_able S b		# checks if world writable and SGID

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
#include <ctype.h>
#include <stdio.h>

#define G_READ_TEST 00044	/* group (or world) readable */
#define W_READ_TEST 00004	/* world readable */
#define G_READ_STRING	"Warning!  %s is group readable!\n"
#define W_READ_STRING	"Warning!  %s is _World_ readable!\n"

#define G_WRITE_TEST 00022	/* group (or world) writable */
#define W_WRITE_TEST 00002	/* world writable */
#define G_WRITE_STRING	"Warning!  %s is group writable!\n"
#define W_WRITE_STRING	"Warning!  %s is _World_ writable!\n"

#define SGID_TEST 02000		/* set group id */
#define SUID_TEST 04000		/* set user id */
#define SUID_STRING	"Warning!  %s is SUID!\n"
#define SGID_STRING	"Warning!  %s is SGID!\n"

char usage[]="Usage: is_able file {w|g|S|s} {r|w|B|b|}\n";

main(argc,argv)
int argc;
char **argv;
{
char file[256], wg, rwb, gstring[35],wstring[35],suidstring[35];
register int group, read, write, both, suid, sgid, verbose, xmode;
static struct stat statb;

group=read=write=suid=sgid=both=verbose=xmode=0;

/* check out arguments */
if (argc != 4) {
	fprintf(stderr, usage);
	exit(1);
	}

/* parse arguments */
strcpy(file, argv[1]);

/* get stats on file in question -- if doesn't exist, exit */
if (stat(file,&statb) < 0) {
	fprintf(stderr, file);
	exit(2);
	}

wg   = argv[2][0];		/* world or group */
rwb  = argv[3][0];		/* read/write/both */

/* set the report string and some flags */
if (wg == 'g') group = 1;
else if (wg == 's') suid = 1;
else if (wg == 'S') sgid = 1;

if (rwb == 'r') {
	if (group) strcpy(gstring, G_READ_STRING);
	else strcpy(wstring, W_READ_STRING);
	read = 1;
	}
else if (rwb == 's')
	(suid?strcpy(suidstring,SUID_STRING):strcpy(suidstring,SGID_STRING));

else if (rwb == 'w') {
	if (group) strcpy(gstring, G_WRITE_STRING);
	else strcpy(wstring, W_WRITE_STRING);
	write = 1;
	}
else if (rwb == 'b') {
	/* do the write first, then read check */
	if (group) strcpy(gstring, G_WRITE_STRING);
	else strcpy(wstring, W_WRITE_STRING);
	if (suid) strcpy(suidstring,SUID_STRING);
	both = read = write = 1;
	}
else if (rwb == 'B') {
	/* do the write first, then s[ug]id check */
	if (suid) strcpy(suidstring, SUID_STRING);
	else if (sgid) strcpy(suidstring, SGID_STRING);
	else {
		fprintf(stderr, usage);
		exit(1);
		}
	both = write = 1;
	}
else {
	fprintf(stderr, usage);
	exit(1);
	}

/*
 *         the write stuff, so to speak...
 *   What I'm doing in this mess is to parse the file in question, check out
 * whole path; 'cause if anything is world writable, you can compromise.
 * For instance, if /usr is world writable, then /usr/spool/mail is
 * compromisable, no matter what its permissions are.
 *
*/
if (write) {
	/* 256 levels of dirs, max len each 256 chars */
	char foo_dirs[256][256];
	char *foo_file;
	int i = 0, j;

	foo_file = file;
	strcpy(foo_dirs[i++], foo_file);

	j=strlen(foo_file) - 1;
	do {
		if (foo_file[j] == '/')
			strncpy(foo_dirs[i++], foo_file, j);
	} while (--j > 0);

	for (j = 0; j < i; j++) {
		if (stat(foo_dirs[j],&statb) < 0)
			continue;
		xmode=statb.st_mode;
		if (!group) {
			if (xmode & W_WRITE_TEST) {
				printf( wstring, file);
				if (both) goto bboth;
				exit(!xmode);
				}
			}
		else if (xmode & G_WRITE_TEST) {
			printf(gstring, file);
			if (both) goto bboth;
			exit(!xmode);
			}
		}

if (!both) exit(!xmode);
}

bboth:
if (both) if (stat(file,&statb) < 0) {
		fprintf(stderr, file);
		exit(2);
		}

/* find premissions on file in question */
if (group)
	xmode = statb.st_mode & G_READ_TEST;
else
	xmode = statb.st_mode & W_READ_TEST;

if (wg == 's') {
	/* check SUID */
	xmode = statb.st_mode & SUID_TEST;
	if (xmode) printf( suidstring, file);
	exit (!xmode);
	}
if (wg == 'S') {
	/* check SGID */
	xmode = statb.st_mode & SGID_TEST;
	if (xmode) printf( suidstring, file);
	exit (!xmode);
	}

if (rwb == 'b') {
	/* do the read now */
	if (group) strcpy(gstring, G_READ_STRING);
	else strcpy(wstring, W_READ_STRING);
	}

/* report finding */
if (xmode) printf( (group ? gstring : wstring), file);

exit(!xmode);
}
