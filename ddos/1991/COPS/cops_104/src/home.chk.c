/*

-------------------------------------------------------------------------
Modification: Aug 2, 1989
Author: Dan Farmer

  I made a minor change to this; it uses a bit mask instead of comparing
to various ok modes.  Otherwise it is unchanged....
-------------------------------------------------------------------------

Original Comment:

This was posted to comp.unix.wizards and net.sources, but I also wanted to
send it here, both for those that don't read or get news, and so that it
will be in the archives for posterity....

On the UNIX Security list, quite a while back, mention was made of
problems that could occur when home directories of users are writable.
(Installing |"some command" in ~uucp/.forward remotely and things like
that.)  This prompted me to write the enclosed program, both to check
for this, and to help protect users against themselves.

The program looks at all the home directories listed in /etc/passwd,
and prints a message if they don't exist, are not directories, or
their mode is not in the "table" of "OK" modes.  I'm using stat()
instead of lstat(), so symbolic links are perfectly acceptable, as
long as they point to directories....  This program should run on any
version of UNIX that I can think of; if it doesn't, please let me
know.

The list of good modes is, of course, subjective.  I initially used
the first set, then added the second set based on the output of the
first run.  I didn't add all the mismatched modes I found; just the
ones that were fairly normal and that I didn't want to hear about....

The program is surprisingly (to me) fast.  It took under a second on
our decently loaded VAX-11/785 running 4.3BSD with 501 passwd entries!

This program is placed in the public domain - you have only your
conscience to stop you from saying "hey, look at this neat program I
wrote"....

	Enjoy!

John Owens		Old Dominion University - Norfolk, Virginia, USA
john@ODU.EDU		old arpa: john%odu.edu@RELAY.CS.NET
+1 804 440 3915		old uucp: {seismo,harvard,sun,hoptoad}!xanth!john
*/

#include <pwd.h>
#include <sys/types.h>
#include <sys/stat.h>


/* mask for modes.... (world writable) */
#define DMODE 002

main(argc,argv)
char **argv;
{
	register int mode;
	register int *p;
	struct passwd *pp;
	static struct stat statb;

	if (argc != 1) {
		printf("Usage: %s\n",argv[0]);
		exit(1);
	}

	while ((pp = getpwent()) != (struct passwd *)0) {
		if (stat(pp->pw_dir,&statb) < 0) {
		/*
			perror(pp->pw_dir);
		*/
			continue;
		}

		if ((statb.st_mode & S_IFMT) != S_IFDIR) {
			printf("Warning!  User %s's home directory %s is not a directory! (mode 0%o)\n",
				pp->pw_name,pp->pw_dir,statb.st_mode);
			continue;
		}

		mode = statb.st_mode & ~S_IFMT;

		if (!(mode & DMODE)) goto ok;

				/* note that 3.3 will print 4 if needed */
		printf("Warning!  User %s's home directory %s is mode 0%3.3o!\n",
		       pp->pw_name,pp->pw_dir,mode);
ok:	;
	}

	exit(0);

}
