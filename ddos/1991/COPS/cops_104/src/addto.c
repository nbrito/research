/* Copyright 1985 Robert W. Baldwin */
/* Copyright 1986 Robert W. Baldwin */
static	char	*notice85 = "Copyright 1985 Robert W. Baldwin";
static	char	*notice86 = "Copyright 1986 Robert W. Baldwin";

/*
  August 15, added "Warning!"  To prepend warning messages.
    -- dan farmer
*/


/* 
 * Add a goal, check for duplicates and completions.
 * Trace messages written to stdout, success messages written to stderr.
 * Usage: addto fileroot key comments
 * Files are arranged in families based on a root name; for example,
 *    uids.k  -- uids we Know how to access
 *    uids.n  -- uids to process Next
 *    uids.p  -- uids Pending results (for duplicate detection)
 *    uids.x  -- uids being eXamined currently
 */


#include	<stdio.h>

#define	LINELEN	600		/* Max chars in a line. */
#define	SUCCESS	"Success"	/* Filename to put success messages. */

main(argc, argv)
int	argc;
char	*argv[];
{
	char	*type = argv[1];
	char	*key = argv[2];
	int	i;
	char	linebuf[LINELEN];
 	char	keypending[150];
	char	filename[150];
	FILE	*tmpfile;

	if (argc < 3)  {
		fprintf(stderr, "addto: missing arguments\n");
		exit(1);
		}
		
	tmpfile = NULL;
		
 	keypending[0] = NULL;
	strcat(keypending, key);
	strcat(keypending, " ");
/*
 * If the uid is known, print out the comments and exit.
 */
	filename[0] = NULL;
	strcat(filename, type);
	strcat(filename, ".k");
	if ((tmpfile = fopen(filename, "r")) == NULL)  {
		fprintf(stderr, "addto: can't open %s.\n", filename);
		exit(1);
		}
	while (fgets(linebuf, LINELEN, tmpfile) != NULL)  {
		if (strncmp(linebuf, key, strlen(key)) == 0)  {
			if ((tmpfile = freopen(SUCCESS,"a",tmpfile)) == NULL) {
				fprintf(stderr, "addto: can't open %s.\n",
					SUCCESS);
				exit(1);
				}
			fprintf(stderr, "Success^G^G\t");
			fprintf(tmpfile, "Warning!  ");
			for (i = 1 ; i < argc ; i++)  {
				fprintf(tmpfile, argv[i]);
				fprintf(tmpfile, " ");
				fprintf(stderr, argv[i]);
				fprintf(stderr, " ");
				}
			fprintf(tmpfile, "\n");
			fprintf(stderr, "\n");
			
			exit(0);
			}
		}
/*
 * If a duplicate, don't add it.
 */
	filename[0] = NULL;
	strcat(filename, type);
	strcat(filename, ".p");
	if (freopen(filename, "r", tmpfile) == NULL)  {
		fprintf(stderr, "addto: can't open %s.\n", filename);
		exit(1);
		}
	while (fgets(linebuf, LINELEN, tmpfile) != NULL)  {
		if (strncmp(linebuf, keypending, strlen(keypending)) == 0)  {
			exit(0);	/* Its a duplicate. */
			}
		}
/*
 * Add the goal to the pending file. 
 */
	filename[0] = NULL;
	strcat(filename, type);
	strcat(filename, ".p");
	if (freopen(filename, "a", tmpfile) == NULL)  {
		fprintf(stderr,"addto: can't open %s for append.\n", filename);
		exit(1);
		}
	fprintf(tmpfile, keypending);
	fprintf(tmpfile, "\n");
/*
 * Add the goal to the next goal (type) file.
 */
	filename[0] = NULL;
	strcat(filename, type);
	strcat(filename, ".n");
	if (freopen(filename, "a", tmpfile) == NULL)  {
		fprintf(stderr,"addto: can't open %s for append.\n", filename);
		exit(1);
		}
	fprintf(stdout, "        ");
	fprintf(stdout, "%s %s ", argv[0], argv[1]);
	for (i = 2 ; i < argc ; i++)  {
		fprintf(tmpfile, argv[i]);
		fprintf(tmpfile, " ");
		fprintf(stdout, argv[i]);
		fprintf(stdout, " ");
		}
	fprintf(tmpfile, "\n");
	fprintf(stdout, "\n");
	exit(0);
}



