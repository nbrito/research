/* Copyright 1985 Robert W. Baldwin */
/* Copyright 1986 Robert W. Baldwin */
static	char	*notice85 = "Copyright 1985 Robert W. Baldwin";
static	char	*notice86 = "Copyright 1986 Robert W. Baldwin";

/*
 * useage: members GroupName
 * Writes to stdout the list of UserNames that are in the given group.
 * The UserNames are separated by space or newline characters.
 *
 */

#include	<stdio.h>
#include	<grp.h>
#include	<pwd.h>


#ifdef cray
struct	group	*getgrnam();
#endif

main(argc, argv)
int	argc;
char	*argv[];
{
	int	i;
	int	gid;
	struct	group	*grent;
	struct	passwd	*pwent;
	char	**user;

/*
 * Print the list of group members from /etc/group.
 */
	if ((grent = getgrnam(argv[1])) == NULL)  {
		fprintf(stderr, "%s: Bad group name %s.\n",
			argv[0], argv[1]);
		exit(1);
		}
	gid = grent->gr_gid;
	for (user = grent->gr_mem ; *user != NULL ; user++)  {
		fprintf(stdout, "%s ", *user);
		}
	fprintf(stdout, "\n");
	endgrent();
/*
 * The passwd file must also be examined to find members of the group.
 * Duplicates may occur, but the higher level code shouldn't care about them.
 */
	while ((pwent = getpwent()) != NULL)  {
		if (pwent->pw_gid != gid)
			continue;
		fprintf(stdout, "%s ", pwent->pw_name);
		}
	fprintf(stdout, "\n");
	endpwent();
}

