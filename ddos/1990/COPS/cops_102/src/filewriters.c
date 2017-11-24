/* Copyright 1985 Robert W. Baldwin */
/* Copyright 1986 Robert W. Baldwin */

/*
   August 15, 1989: Dan Farmer
   One line changed -- #38 is the old line, #41 is my version.
   See comment for details...
*/
static	char	*notice85 = "Copyright 1985 Robert W. Baldwin";
static	char	*notice86 = "Copyright 1986 Robert W. Baldwin";

/*
 * Useage: filewriters pathname
 * Writes on stdout the list of people who can write the file.
 * This writer's list contains three tokens, the owner, the group, and
 * the 'all others' group, respectively.
 * If either group does not have write access, then that token is
 * replace with the token "NONE".  If the 'all others' group has
 * write access then that token is "OTHER".
 *
 * Notice that the owner of a file can always write it because the
 * owner can change the file access mode.
 *
 * BUG: should handle links correctly.
 */

#include	<stdio.h>
#include	<sys/types.h>
#include	<sys/stat.h>
#include	<grp.h>
#include	<pwd.h>

/*
  changed this line from upper to lower case 's'.
  Ultrix barfed 'cause already defined in sys/stat.h,
  no one else seemed to mind...

#define	S_GWRITE	(S_IWRITE >> 3)
*/

#ifdef cray
struct group *getgrgid();
#endif

#define	s_GWRITE	(S_IWRITE >> 3)		/* Group write access. */
#define	S_OWRITE	(S_IWRITE >> 6)		/* Other write access. */


main(argc, argv)
int	argc;
char	*argv[];
{
	int	i;
	struct	stat	buf;

/*
 * Make sure the file exists.
 */
 	if (argc != 2)  {
		fprintf(stderr, "%s: wrong number of args.\n", argv[0]);
		exit(1);
		}
	if (stat(argv[1], &buf) != 0)  {
		fprintf(stderr, "%s: File %s does not exist.\n",
			argv[0], argv[1]);
		exit(1);
		}
/*
 * Produce list of writers.
 * Owner can always write.
 */
	printf("        ");
	print_uid(stdout, buf.st_uid);
	printf(" ");
	if (s_GWRITE & (buf.st_mode))  {
		print_gid(stdout, buf.st_gid);
		}
	else {
		printf("NONE");
		}
	printf(" ");
	if (S_OWRITE & buf.st_mode)  {
		printf("OTHER");
		}
	else {
		printf("NONE");
		}
	printf("\n");
	exit(0);
}


print_uid(out, uid)
FILE	*out;
int	uid;
{
	struct	passwd	*pwent;
	
	if ((pwent = getpwuid(uid)) == NULL)  {
		fprintf(stderr, "Bad user id %d.\n", uid);
		exit(1);
		}
	fprintf(out, "%s", pwent->pw_name);
}


print_gid(out, gid)
FILE	*out;
int	gid;
{
	struct	group	*grpent;
	
	if ((grpent = getgrgid(gid)) == NULL)  {
		fprintf(stderr, "Bad group id %d.\n", gid);
		exit(1);
		}
	fprintf(out, "%s", grpent->gr_name);

}

