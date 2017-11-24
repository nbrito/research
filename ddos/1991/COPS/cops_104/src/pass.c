#include <stdio.h>
#include <pwd.h>
#include <ctype.h>

/* C2 stuff by Ole H. Nielsen */
#ifdef C2
#include <sys/label.h>
#include <sys/audit.h>
#include <pwdadj.h>
#endif C2

/* number of words the dictionary can suck up */
#define ARB_CONST	32000

#ifndef lint
static char *rcsid = "$Header: pwchkr.c,v 1.1 85/09/10 16:00:56 root Exp $";
#endif

/*
 * Warning: this program burns a lot of cpu.
 */
/*
 * Insecure - find accounts with poor passwords
	Date: Tue, 29 Nov 83 18:19:32 pst
	From: leres%ucbarpa@Berkeley (Craig Leres)

	Insecure is something that Jef Poskanzer and I wrote to rid a
	local system of an overly persistent ankle-biting adolescent.
	It was a quick hack we whipped up in just a few minutes and was
	never intended to be publically distributed. Unfortunately, I
	made the mistake of giving a copy to an associate at UC
	Berkeley. Apparently, he incorporated it in a security package
	he later developed for use at Berkeley. Someone else
	distributed it outside Berkeley which explains why it's been
	publically distributed.


	    Modified by Seth Alford, Roger Southwick, Steve Dum, and
	    Rick Lindsley for Tektronix

      Bits and pieces hacked by me and others, 1/4/91... df
 */

/*
 *	$Log:	pwchkr.c,v $
 *	Revision 1.1  85/09/10  16:00:56  root
 *	Initial revision
 *	
 *
 * By default, this program only checks for accounts with passwords the same
 * as the login name. The following options add more extensive checking. (The
 * tradeoff is cpu time -- with all options enabled it can run into the 100's
 * of MINUTES.) Any argument that does not begin with a "-" is assumed to be
 * a file name. (A single '-' means stdin.) If no file name is given,
 * /etc/passwd is used.
 *
 * Options:
 *
 *		-v:	verbose -- list all guesses on stdout
 *		-u:	output the username on the line of the password file
 *			currently being checked. If the program stops
 *			abruptly you will then know how far it got.
 *		-w file: use the list of words contained in "file" as likely
 *			passwords. Words in the file are one to a line.
 *		-b: 	check all guesses backwards too
 *		-g:	use the Full Name portion of the gecos field to
 *			generate more guesses; also check .plan, .signature
 *			and .project files.
 *		-s:	check the single letters a-z, A-Z, 0-9 as passwords
 *		-c:	with each guess, check for all-lowercase and
 *			all-uppercase versions too.
 *		-d:     check the doubling of the username
 *		-n:	complain about null passwords (default is to keep quiet)
 *		-p:	print the password when guessed
 *		-P:	use alternate password file
 */

int verbose = 0, singles = 0, backwards = 0, checkgecos = 0, checkcase = 0,
    chknulls = 0, printit = 0, users = 0, chkwords = 0, checkdouble = 0;

char *my_index(), *reverse();
long atol();
FILE *fopen();
char *fgets();

/* char PASSWD[] = "/etc/passwd"; */
char PASSWD[256];

char EMPTY[] = "";
static FILE *pwf = NULL, *wlf = NULL;
char line[BUFSIZ+1];
struct passwd passwd;
char	*Curpw, *Wordlist = NULL;

main(argc, argv)
char **argv;
{
    register int i;
    register char *arg;
    int onedone = 0;

    /*
    You have to decide whether or not to include these lines....

    if (getuid()) {
	printf("Did you really think we would let you run this?\n");
	exit(1);
	}

    */
    strcpy(PASSWD, "/etc/passwd");

    for (i = 1; i < argc; i++)
	if ((arg = argv[i]) && *arg == '-')
	    while (*++arg) {
		switch (*arg) {
		    case 'n':
			/*
			 * complain about null passwords
			 */
			chknulls++;
			break;
		    case 'c':
			/*
			 * check cases
			 */
			checkcase++;
			break;
		    case 'g':
			/*
			 * use gecos
			 */
			checkgecos++;
			break;
		    case 'v':
			/*
			 * turn on motormouth
			 */
			verbose++;
			break;
		    case 'b':
			/*
			 * check all attempts forwards and backwards
			 */
			backwards++;
			break;
		    case 'd':
			/*
			* check the doubling of the username
			*/
			checkdouble++;
			break;
		    case 's':
			/*
			 * carry out a more intensive search, checking for
			 * single letter passwords
			 */
			singles++;
			break;
		    case 'p':
			/*
			 * print out the password when found
			 */
			printit++;
			break;
		    case 'u':
			/*
			 * print out users as testing
			 */
			users++;
			break;
		    case 'P':
			/*
			 * use alternate passwd file
			 */
			if (argv[i+1] == NULL) {
			    fprintf(stderr,
				"%s: No file supplied with -P option\n",
				argv[0]);
			    exit (1);
			    }
			strcpy(PASSWD, argv[i+1]);
			argv[i+1] = NULL;
			break;
		    case 'w':
			/*
			 * consult word list of likely passwords
			 */
			if ((Wordlist = argv[i+1]) == NULL) {
			    fprintf(stderr,
				"%s: No file supplied with -w option\n",
				argv[0]);
			    exit (1);
			    }
			argv[i+1] = NULL;
			break;
		    case '\0':
			/*
			 * read from stdin
			 */
			break;
		    default:
			fprintf(stderr,
			    "%s: unknown option '%c'. Options are:\n",argv[0],
			    *arg);
			/* FALL THRU */
		    case '-':
			fprintf(stderr,"-v:\t\tverbose -- list all guesses on stdout\n");
			fprintf(stderr,"-u:\t\toutput the username currently being checked\n");
			fprintf(stderr,"-w file:\tconsult the indicated file for words to check as passwords\n");
			fprintf(stderr,"-b:\t\tcheck all guesses forwards and backwards\n");
			fprintf(stderr,"-g:\t\tuse the Full name portion of the gecos field for more guesses\n");
			fprintf(stderr,"-s:\t\tcheck the single letters a-z, A-Z, 0-9 as passwords\n");
			fprintf(stderr,"-c:\t\tcheck the all-upper and all-lower case version of each guess\n");
			fprintf(stderr,"-d:\t\tcheck for double repetition of the username\n");
			fprintf(stderr,"-n:\t\tcomplain about null passwords\n");
			fprintf(stderr,"-p:\t\tprint the password when guessed\n");
			exit(1);
		    }
		argv[i] = NULL;
		}
    
#ifdef FCRYPT
init_des();
#endif

    for (i = 1; i < argc; i++) {
	if (argv[i] == NULL) continue;
	onedone++;
	if (*(argv[i]) == '-') {
	    /*
	     * read from stdin; we'll cheat and set pwf directly
	     */
	    pwf = stdin;
	    chkpw();
	    /*
	     * don't fclose stdin!
	     */
	    clearerr(stdin);
	    }
	else {
	    if ((pwf=fopen(argv[i],"r")) == NULL) {
		perror(argv[i]);
		continue;
		}
	    Curpw = argv[i];
	    chkpw();
	    end2pwent();
	    }
	}
    if (!onedone) {
	Curpw = NULL;
	chkpw();
	}
    exit(0);
}

/*
 * Added by Jacob Gore, March 12, 1987.
 *
 * Finds the pointer of the leftmost occurance within the character string
 * 'string' of any character found within the character string 'chars'.
 *
 * If none of the characters in 'chars' appear in 'string', NULL is retutned.
 *
 */
char *
indexm (string, chars)
    char *string, *chars;
{
    while (*string) {
	if (my_index(chars, *string) != NULL) {
	    return string;
	}
	string++;
    }
    return NULL;
}

chkpw()
{
#ifdef C2
    struct passwd_adjunct *pwdadj;
    struct passwd_adjunct *getpwanam();
#endif C2
    register char	*cp, *cp2;
    struct passwd	*pwd;
    struct passwd	*getpwent();
    char		guess[100];
    char		*wordarray[ARB_CONST];
    char		*malloc(), **wordptr, **endptr;
    int			done = 0;


    if (Wordlist) {
	if ((wlf = fopen(Wordlist,"r")) == NULL) {
	    perror(Wordlist);
	    exit(1);
	}

	wordptr = wordarray;
	/*
	 * note that endptr points to space OUTSIDE of wordarray
	 */
	endptr = wordarray + (sizeof(wordarray)/sizeof(char *));

/* printf("testing words...\n"); */
	while (fscanf(wlf,"%[^\n]\n",guess) != EOF) {
int i;
/* printf("%d => %s\n", ++i, guess); */

	    if (wordptr == endptr) {
		fprintf(stderr,"Ran out of wordlist space. ARB_CONST %d must be too small.\n", ARB_CONST);
		exit(1);
	    }
	    if ((*wordptr = malloc(1+strlen(guess))) == NULL) {
		fprintf(stderr,"malloc: no more memory for wordlist\n");
		exit (1);
	    }
	    strcpy(*wordptr,guess);
	    wordptr++;
  /* SunOs 4.03 on a Sun 3/80 didn't work properly, needed this one line fix */
	    if (feof(wlf)) break;
	}
	*wordptr = NULL;
	fclose(wlf);
    }

    while ((pwd = getpwent()) != 0 ) {

        done = 0;
	if (verbose || users) {
	    if (Curpw == NULL)
		printf("\t%s \"%s\"\n", pwd->pw_name, pwd->pw_gecos);
	    else
		printf("%s -- \t%s \"%s\"\n", Curpw, pwd->pw_name,
		    pwd->pw_gecos);
	    fflush(stdout);
	    }
#ifdef C2
	(void) sprintf (guess, "##%s", pwd->pw_name);
	if (strcmp (guess, pwd->pw_passwd)) {
		/* Standard /etc/passwd entry */
		if (verbose || users) {
			if (*pwd->pw_passwd != '*' && *pwd->pw_passwd != '\0')
				printf ("\tC2 Warning!  user password %s is in the regular passwd file\n",
					pwd->pw_passwd);
			fflush(stdout);
		}
	} else {
		/* Entry in /etc/security/passwd.adjunct (C2 security) */
		/* Extract the C2 security password */
		if (Curpw == NULL)
			pwdadj = getpwanam(pwd->pw_name);
		else
			pwdadj = getpwanam(Curpw);
		if (pwdadj == (struct passwd_adjunct *)NULL) {
			fprintf (stderr, "Failed to get the C2 secure passwd for %s\n", pwd->pw_name);
			fflush(stderr);
			continue;
		} else
			/* Substitute the C2 secure password */
			pwd->pw_passwd = pwdadj->pwa_passwd;
	}
#endif C2

	if (*pwd->pw_passwd == '\0') {
	    if (chknulls) {
		if (Curpw == NULL)
		    printf("Warning!  Password Problem: null passwd:\t%s\tshell: %s\n",
			pwd->pw_name, pwd->pw_shell);
		else
		    printf("Warning!  %s -- Password Problem: null passwd:\t%s\tshell: %s\n",
			Curpw, pwd->pw_name, pwd->pw_shell);
		fflush(stdout);
		}
	    continue;
	}

	/* if (strlen(pwd->pw_passwd) != 13) { continue; } */
	/* common way of disabling account is a "*" in the first char of p/w */
	if (*pwd->pw_passwd == '*' || strlen(pwd->pw_passwd) < 13) continue;
	if (strlen(pwd->pw_passwd) > 13)
		 strncpy(pwd->pw_passwd, pwd->pw_passwd, 13);

	/*
	 * Try the user's login name
	 */
	if (uandltry(pwd,pwd->pw_name))
	    continue;

	if (checkdouble) {
		strcpy(guess,pwd->pw_name);
		strcat(guess,pwd->pw_name);
		if (uandltry(pwd,guess))
			continue;
		}

	/*
	 * Try names from the gecos field
	 */
	if (checkgecos) {
	    /* Check extra files as well */
	    if (srch_aux_files(pwd->pw_dir, pwd)) {
		done++;
		continue;
	    }
	    strcpy(guess, pwd->pw_gecos);
	    cp = guess;
	    if (*cp == '-') cp++;		/* special gecos field */
	    if ((cp2 = my_index(cp, ';')) != NULL)
		*cp2 = '\0';

	    for (;;) {
		/* use both ' ' and ',' as delimiters -- Jacob */
		if ((cp2 = indexm(cp, " ,")) == NULL) {
		    if (uandltry(pwd,cp))
			done++;
		    break;
		    }

		*cp2 = '\0';

		if (uandltry(pwd,cp)) {
		    done++;
		    break;
		    }
		cp = ++cp2;
		}
	    }
	    
	if (!done && Wordlist)
	{
	    /*
	     * try the words in the wordlist
	     */
	    wordptr = wordarray;
	    while (endptr != wordptr)
	    {
		if (*wordptr == NULL)
		    break;
		if (uandltry(pwd,*wordptr++))
		{
		    done++;
		    break;
		}
	    }
	}
	if (!done && singles) {
	    /*
	     * Try all single letters
	     * (try digits too .  --Seth)
	     */
	    guess[1] = '\0';
	    for (guess[0]='a'; guess[0] <= 'z'; guess[0]++)
		if (try(pwd,guess))
		    break;
	    for (guess[0]='A'; guess[0] <= 'Z'; guess[0]++)
		if (try(pwd,guess))
		    break;
	    for (guess[0]='0'; guess[0] <= '9'; guess[0]++)
		if (try(pwd,guess))
		    break;
	    }
    }
}

/*
 * Stands for "upper and lower" try.  Calls the "real" try, below,
 * with the supplied version of the password, and with
 * an upper and lowercase version of the password. If the user doesn't
 * want to try upper and lower case then we just return after the one
 * check.
*/

uandltry (pwd,guess)
char *guess;
struct passwd *pwd;
{
    register char *cp;
    char buf[100];
    int alllower, allupper;

    alllower = allupper = 1;

    if (try(pwd,guess) || (backwards && try(pwd,reverse(guess)))) return (1);

    if (!checkcase) return(0);

    strcpy (buf, guess);
    cp = buf-1;
    while (*++cp) {
	if (isupper(*cp))
	    alllower = 0;
	if (islower(*cp))
	    allupper = 0;
	}

    if (!allupper) {
	for ( cp=buf; *cp != '\0'; cp++)
	    if (islower (*cp))
		*cp += 'A' - 'a';

	if (try(pwd,buf) || (backwards && try(pwd,reverse(buf)))) return (1);
	}

    if (!alllower) {
	for ( cp = buf; *cp != '\0'; cp++)
	    if (isupper (*cp))
		*cp += 'a' - 'A';

	if (try(pwd,buf) || (backwards && try(pwd,reverse(buf)))) return (1);
	}
    return (0);
}

try(pwd,guess)
char *guess;
register struct passwd *pwd;
{
    register char  *cp;
    char   *crypt ();

    if (verbose) {
	if (Curpw == NULL)
	    printf ("Trying \"%s\" on %s\n", guess, pwd -> pw_name);
	else
	    printf ("%s -- Trying \"%s\" on %s\n", Curpw, guess,
		pwd -> pw_name);
	fflush (stdout);
	}
    if (! guess || ! *guess) return(0);
    cp = crypt (guess, pwd -> pw_passwd);

/* silly sun tries to fool us by adding extra chars in their passwd field! */
/* but laddie, we're too smart for 'em, eh?!?  Kudos to Bernard Wilson */
    if (strncmp (cp, pwd -> pw_passwd, 13))
	return (0);
    if (Curpw == NULL)
	if (printit)
	    printf ("Warning!  Password Problem: Guessed:\t%s\tshell: %s passwd: %s\n",
		pwd -> pw_name, pwd -> pw_shell, guess);
	else
	    printf ("Warning!  Password Problem: Guessed:\t%s\tshell: %s\n", pwd -> pw_name,
		pwd -> pw_shell);
    else
	if (printit)
	    printf ("Warning!  %s -- Password Problem: Guessed:\t%s\tshell: %s passwd: %s\n",
		Curpw, pwd -> pw_name, pwd -> pw_shell, guess);
	else
	    printf ("Warning!  %s -- Password Problem: Guessed:\t%s\tshell: %s\n",
		Curpw, pwd -> pw_name, pwd -> pw_shell);
    fflush (stdout);
    return (1);
}
/* end of PW guessing program */

#define MAXUID 0x7fff	/* added by tonyb 12/29/83 */
			/* altered to a reasonable number - mae 8/20/84 */

end2pwent()
{
    fclose(pwf);
    pwf = NULL;
}

char *
pwskip(p)
register char *p;
{
	while(*p && *p != ':' && *p != '\n')
		++p;
	if(*p == '\n')
		*p = '\0';
	else if(*p)
		*p++ = '\0';
	return(p);
}

struct passwd *
getpwent()
{
	register char *p;
	long	x;

	if(pwf == NULL)
	    if ((pwf = fopen(PASSWD,"r")) == NULL) {
		perror(PASSWD);
		return(NULL);
		}
	p = fgets(line, BUFSIZ, pwf);
	if(p == NULL)
		return(0);
	passwd.pw_name = p;
	p = pwskip(p);
	passwd.pw_passwd = p;
	p = pwskip(p);
	x = atol(p);	
	passwd.pw_uid = (x < 0 || x > MAXUID)? (MAXUID+1): x;
	p = pwskip(p);
	x = atol(p);
	passwd.pw_gid = (x < 0 || x > MAXUID)? (MAXUID+1): x;
/*	passwd.pw_comment = EMPTY; */
	p = pwskip(p);
	passwd.pw_gecos = p;
	p = pwskip(p);
	passwd.pw_dir = p;
	p = pwskip(p);
	passwd.pw_shell = p;
	(void) pwskip(p);

	p = passwd.pw_passwd;
 
	return(&passwd);

}


/*
 * reverse a string
 */
char *reverse(str)
char *str;

{
    register char *ptr;
    char	*malloc();
    static char buf[100];

    ptr = buf + strlen(str);
    *ptr = '\0';
    while (*str && (*--ptr = *str++))
	;
    return(ptr);

}


/* Guess passwords using additional files for guesses. Returns 1 (true) if
 * a match was found, otherwise 0 (false). The parameters to be passed to
 * this function are a character pointer to the directory in which the files
 * reside. This function access the "uandltry" routine from other 
 * sections of the code.
 */
#define MAXWORD 15		/* Maximum word length allow for guess */

#include <stdio.h>
#include <ctype.h>

static char *file[] = { "/.project",		/* These are the extra files */
			"/.plan",		/* to be searched for */
			"/.signature",		/* prospective passwords */
			"" };			/* Note the initial "/" */

int
srch_aux_files(dir, pwd)
	char *dir;	/* Directory in which to search */
	struct passwd *pwd;	/* Encrypted password */
{
	char path[100];		/* Complete path */
	FILE *fp;
	char *wp;
	char *getword();
	char **p;

	p = file;
	while (**p != NULL) {
		strcpy(path, dir);	/* Make complete path name */
		strcat(path, *p++);
		if ((fp = fopen(path, "r")) == NULL)
			continue;	/* If we can't open the file, skip it */
		while ((wp = getword(fp)) != NULL)
			if (uandltry(pwd, wp))
				return(1);
		fclose(fp);
	}
	return(0);
}

/* Get a word from a stream. Word separators are user definable in "is_sep".
 * Maximum word size is MAXWORD characters. If a word reaches it's maximum
 * limit, we choose not to flush the rest of the word. Returns NULL on EOF.
 */
char *
getword(fp)
	FILE *fp;
{
	static char word[MAXWORD + 1];
	char *p = word;
	int c;
	int is_sep();

	while ((c = fgetc(fp)) != EOF && !isalnum(c))
		;		/* Skip over word separators */
	if (c == EOF)
	       return(NULL);
	*p++ = c;
	while ((c = fgetc(fp)) != EOF && isalnum(c) && p != &(word[MAXWORD])) {
		*p++ = c;	/* Quit when a word separator is encountered
				 * or we reach maximum word length
				 */
	}
	*p = '\0';		/* Mustn't forget that word terminator */
	return ((c == EOF) ? NULL : word);
}
/* taken from comp.binaries.ibm.pc.d:
Some users have reported trouble compiling the freely distributable
uudecode I posted.  It seems that Berkeley moved the "index" function
to one of their system libraries and some systems don't have it.
Here is the missing "index" function, excerpted from an earlier freely
distributable uudecode.  Just add it on the end of the uudecode I posted.
*/
/*
--Keith Petersen
Maintainer of SIMTEL20's CP/M, MSDOS, & MISC archives [IP address 26.2.0.74]
Internet: w8sdz@WSMR-SIMTEL20.Army.Mil, w8sdz@brl.arpa  BITNET: w8sdz@NDSUVM1
Uucp: {ames,decwrl,harvard,rutgers,ucbvax,uunet}!wsmr-simtel20.army.mil!w8sdz
*/

/*
 * Return the ptr in sp at which the character c appears;
 * NULL if not found
 */

#define	NULL	0

char *
my_index(sp, c)
register char *sp, c;
{
	do {
		if (*sp == c)
			return(sp);
	} while (*sp++);
	return(NULL);
}


