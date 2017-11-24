/* Copyright 1985 Robert W. Baldwin */
/* Copyright 1986 Robert W. Baldwin */
static	char	*notice85 = "Copyright 1985 Robert W. Baldwin";
static	char	*notice86 = "Copyright 1986 Robert W. Baldwin";

/*
 * Reset the info files used by Kuang.
 */


#include	<stdio.h>

char	*filelist[] = {
	"uids.k",
	"Success",
	"uids.k",
	"uids.p",
	"uids.n",
	"uids.x",
	"gids.k",
	"gids.p",
	"gids.n",
	"gids.x",
	"files.k",
	"files.p",
	"files.n",
	"files.x",
	"",
	};

main(argc, argv)
int	argc;
char	*argv[];
{
	int	i;

	for (i = 0 ; filelist[i][0] != NULL ; i++)  {
		if (freopen(filelist[i], "w", stdout) == NULL)  {
			fprintf(stderr, "%s: can't open %s.\n",
				argv[0], filelist[i]);
			exit(1);
			}
		}
}

