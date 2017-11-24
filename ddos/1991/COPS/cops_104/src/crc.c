
/* updcrc(3), crc(1) - calculate crc polynomials
 *
 * Calculate, intelligently, the CRC of a dataset incrementally given a 
 * buffer full at a time.
 * 
 * Usage:
 * 	newcrc = updcrc( oldcrc, bufadr, buflen )
 * 		unsigned int oldcrc, buflen;
 * 		char *bufadr;
 *
 * Compiling with -DTEST creates a program to print the CRC of stdin to stdout.
 * Compile with -DMAKETAB to print values for crctab to stdout.  If you change
 *	the CRC polynomial parameters, be sure to do this and change
 *	crctab's initial value.
 *
 * Notes:
 *  Regards the data stream as an integer whose MSB is the MSB of the first
 *  byte recieved.  This number is 'divided' (using xor instead of subtraction)
 *  by the crc-polynomial P.
 *  XMODEM does things a little differently, essentially treating the LSB of
 * the first data byte as the MSB of the integer. Define SWAPPED to make
 * things behave in this manner.
 *
 * Author:	Mark G. Mendel, 7/86
 *		UUCP: ihnp4!umn-cs!hyper!mark, GEnie: mgm
 */

#define TEST

/* The CRC polynomial.
 * These 4 values define the crc-polynomial.
 * If you change them, you must change crctab[]'s initial value to what is
 * printed by initcrctab() [see 'compile with -DMAKETAB' above].
 */

/* Value used by:	    		CITT	XMODEM	ARC  	*/
#define	P	 0xA001	 /* the poly:	0x1021	0x1021	A001	*/
#define INIT_CRC 0L	 /* init value:	-1	0	0	*/
#define SWAPPED		 /* bit order:	undef	defined	defined */
#define W	16	 /* bits in CRC:16	16	16	*/

/* data type that holds a W-bit unsigned integer */
#if W <= 16
#  define WTYPE	unsigned short
#else
#  define WTYPE   unsigned long
#endif

/* the number of bits per char: don't change it. */
#define B	8

static WTYPE crctab[1<<B] = /* as calculated by initcrctab() */ {
   0x0,  0xc0c1,  0xc181,  0x140,  0xc301,  0x3c0,  0x280,  0xc241,
   0xc601,  0x6c0,  0x780,  0xc741,  0x500,  0xc5c1,  0xc481,  0x440,
   0xcc01,  0xcc0,  0xd80,  0xcd41,  0xf00,  0xcfc1,  0xce81,  0xe40,
   0xa00,  0xcac1,  0xcb81,  0xb40,  0xc901,  0x9c0,  0x880,  0xc841,
   0xd801,  0x18c0,  0x1980,  0xd941,  0x1b00,  0xdbc1,  0xda81,  0x1a40,
   0x1e00,  0xdec1,  0xdf81,  0x1f40,  0xdd01,  0x1dc0,  0x1c80,  0xdc41,
   0x1400,  0xd4c1,  0xd581,  0x1540,  0xd701,  0x17c0,  0x1680,  0xd641,
   0xd201,  0x12c0,  0x1380,  0xd341,  0x1100,  0xd1c1,  0xd081,  0x1040,
   0xf001,  0x30c0,  0x3180,  0xf141,  0x3300,  0xf3c1,  0xf281,  0x3240,
   0x3600,  0xf6c1,  0xf781,  0x3740,  0xf501,  0x35c0,  0x3480,  0xf441,
   0x3c00,  0xfcc1,  0xfd81,  0x3d40,  0xff01,  0x3fc0,  0x3e80,  0xfe41,
   0xfa01,  0x3ac0,  0x3b80,  0xfb41,  0x3900,  0xf9c1,  0xf881,  0x3840,
   0x2800,  0xe8c1,  0xe981,  0x2940,  0xeb01,  0x2bc0,  0x2a80,  0xea41,
   0xee01,  0x2ec0,  0x2f80,  0xef41,  0x2d00,  0xedc1,  0xec81,  0x2c40,
   0xe401,  0x24c0,  0x2580,  0xe541,  0x2700,  0xe7c1,  0xe681,  0x2640,
   0x2200,  0xe2c1,  0xe381,  0x2340,  0xe101,  0x21c0,  0x2080,  0xe041,
   0xa001,  0x60c0,  0x6180,  0xa141,  0x6300,  0xa3c1,  0xa281,  0x6240,
   0x6600,  0xa6c1,  0xa781,  0x6740,  0xa501,  0x65c0,  0x6480,  0xa441,
   0x6c00,  0xacc1,  0xad81,  0x6d40,  0xaf01,  0x6fc0,  0x6e80,  0xae41,
   0xaa01,  0x6ac0,  0x6b80,  0xab41,  0x6900,  0xa9c1,  0xa881,  0x6840,
   0x7800,  0xb8c1,  0xb981,  0x7940,  0xbb01,  0x7bc0,  0x7a80,  0xba41,
   0xbe01,  0x7ec0,  0x7f80,  0xbf41,  0x7d00,  0xbdc1,  0xbc81,  0x7c40,
   0xb401,  0x74c0,  0x7580,  0xb541,  0x7700,  0xb7c1,  0xb681,  0x7640,
   0x7200,  0xb2c1,  0xb381,  0x7340,  0xb101,  0x71c0,  0x7080,  0xb041,
   0x5000,  0x90c1,  0x9181,  0x5140,  0x9301,  0x53c0,  0x5280,  0x9241,
   0x9601,  0x56c0,  0x5780,  0x9741,  0x5500,  0x95c1,  0x9481,  0x5440,
   0x9c01,  0x5cc0,  0x5d80,  0x9d41,  0x5f00,  0x9fc1,  0x9e81,  0x5e40,
   0x5a00,  0x9ac1,  0x9b81,  0x5b40,  0x9901,  0x59c0,  0x5880,  0x9841,
   0x8801,  0x48c0,  0x4980,  0x8941,  0x4b00,  0x8bc1,  0x8a81,  0x4a40,
   0x4e00,  0x8ec1,  0x8f81,  0x4f40,  0x8d01,  0x4dc0,  0x4c80,  0x8c41,
   0x4400,  0x84c1,  0x8581,  0x4540,  0x8701,  0x47c0,  0x4680,  0x8641,
   0x8201,  0x42c0,  0x4380,  0x8341,  0x4100,  0x81c1,  0x8081,  0x4040,
};


void perror();
char *strcpy(); 
void exit();

WTYPE
updcrc( icrc, icp, icnt )
WTYPE icrc;
unsigned char	*icp;
int	icnt;
{
   register WTYPE crc = icrc;
   register unsigned char	*cp = icp;
   register int	cnt = icnt;

   while ( cnt--) {
#ifndef SWAPPED
      crc = (crc << B) ^ crctab[(crc>>(W-B)) ^ *cp++];
#else
      crc = (crc >> B) ^ crctab[(crc & ((1<<B)-1)) ^ *cp++];
#endif 
   }

   return( crc );
}


#ifdef MAKETAB

#include <stdio.h>
main()
{
   initcrctab();
}


initcrctab()
{
   register int	b, i;
   WTYPE v;


   for ( b = 0; b <= (1 << B) - 1; ++b ) {
#ifndef SWAPPED
      for ( v = b << (W - B), i = B; --i >= 0; )
         v = v & ((WTYPE)1 << (W - 1)) ? (v << 1) ^ P : v << 1;
#else
      for ( v = b, i = B; --i >= 0; )
         v = v & 1 ? (v >> 1) ^ P : v >> 1;
#endif	    
      crctab[b] = v;

      (void)  printf( "0x%lx,", v & ((1L << W) - 1L));
      if ( (b & 7) == 7 )
         (void)  printf("\n" );
      else
         (void)  printf("  ");
   }
}


#endif

#ifdef TEST

#include <stdio.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <pwd.h>
#include <grp.h>
#define MAXBUF	4096

#ifndef S_IRGRP
#define S_IRGRP	(S_IREAD >> 3)
#define S_IWGRP (S_IWRITE >> 3)
#define S_IXGRP (S_IEXEC >> 3)
#define S_IROTH (S_IREAD >> 6)
#define S_IWOTH (S_IWRITE >> 6)
#define S_IXOTH (S_IEXEC >> 6)
#endif

struct stat stat_buf;
int	initial_crc = INIT_CRC;

extern char	*optarg;
extern int	optind;
extern int	opterr;

main( argc, argv )
int	argc;
char	**argv;
{
   int	stats_flag = 0;

   int	c;

   if (argc == 1) {
      print_crc((char *)0, 0);
      return 0;
   }

   /* process all arguments */

   while ((c = getopt(argc, argv, "VvI:i:")) != EOF) {

      switch (c) {

      case 'V':
      case 'v':
         stats_flag = 1;
         break;

      case 'I':
      case 'i':
         initial_crc = atoi(optarg);
         break;

      default:
         (void) fprintf(stderr, "crc:  -v (verbose listing)\n");
         (void) fprintf(stderr, "      -i value (initial crc value)\n");
         exit(1);
      }
   }

   for (; optind < argc ; optind++)
      print_crc(argv[optind], stats_flag);

   return 0;
}


print_crc(name, stat_flag)
char	*name;
int	stat_flag;
{
   int	fd;
   int	nr;
   unsigned char	buf[MAXBUF];
   WTYPE crc;
#ifdef MAGICCHECK
   WTYPE crc2;
#endif

   fd = 0;

   /* quietly ignore files we can't stat */

   if (name != NULL && stat(name, &stat_buf) != 0)
      return;

   /* don't do a crc on strange files */

   crc = nr = 0;

   if (name == NULL || (stat_buf.st_mode & S_IFMT) == S_IFREG) {

      /* open the file and do a crc on it */

      if (name != NULL && (fd = open( name, O_RDONLY )) < 0 ) {
         perror( name );
         exit( -1 );
      }
#ifdef MAGICCHECK
      crc2 = 
#endif
      crc = initial_crc;

      while ( (nr = read( fd, (char *)buf, MAXBUF )) > 0 ) {
         crc = updcrc(crc, buf, nr );
      }
      (void) close(fd);

   }
   if ( nr != 0 ) {
      perror( "read error" );
   } else {
      (void)  printf("%4.4x", (unsigned) crc );
      if (stat_flag)
         stats(name);
      else
         (void)  printf("\n");

   }

#ifdef MAGICCHECK
   /* tack one's complement of crc onto data stream, and
       continue crc calculation.  Should get a constant (magic number)
       dependent only on P, not the data.
     */
   crc2 = crc ^ -1L;
   for ( nr = W - B; nr >= 0; nr -= B ) {
      buf[0] = (crc2 >> nr);
      crc = updcrc(crc, buf, 1);
   }

   /* crc should now equal magic */
   buf[0] = buf[1] = buf[2] = buf[3] = 0;
   (void)  printf( "magic test: %lx =?= %lx\n", crc, updcrc((WTYPE) - 1, buf, W / B));
#endif 


}


stats(name)
char	*name;
{

   struct passwd *entry;
   struct group *group_entry;
   static char	owner[20];
   static char	group[20];
   char	a_time[50];

   struct passwd *getpwuid();
   struct group *getgrgid();
   char	*ctime();

   static int	prev_uid = -9999;
   static int	prev_gid = -9999;

   if (stat_buf.st_uid != prev_uid) {
      entry = getpwuid((int)stat_buf.st_uid);
      if (entry)
         (void) strcpy(owner, entry->pw_name);
      else
         (void) sprintf(owner, "%d", stat_buf.st_uid);
      prev_uid = stat_buf.st_uid;
   }
   if (stat_buf.st_gid != prev_gid) {
      group_entry = getgrgid((int)stat_buf.st_gid);
      if (group_entry)
         (void) strcpy(group, group_entry->gr_name);
      else
         (void) sprintf(group, "%d", stat_buf.st_gid);
      prev_gid = stat_buf.st_gid;
   }

   (void) strcpy(a_time, ctime(&stat_buf.st_mtime));
   a_time[24] = '\0';

   print_perm(stat_buf.st_mode);

   (void)  printf(" %s\t%s\t%s %s\n", owner, group, a_time + 4, name);

}


print_perm(perm)
unsigned int	perm;
{

   char	string[20];
   (void) strcpy(string, "----------");

   switch (perm & S_IFMT) {

   case S_IFDIR:
      string[0] = 'd';
      break;

   case S_IFBLK:
      string[0] = 'b';
      break;

   case S_IFCHR:
      string[0] = 'c';
      break;

   case S_IFIFO:
      string[0] = 'p';
      break;
   }
   if (perm & S_IREAD)
      string[1] = 'r';
   if (perm & S_IWRITE)
      string[2] = 'w';
   if (perm & S_ISUID && perm & S_IEXEC)
      string[3] = 's';
   else if (perm & S_IEXEC)
      string[3] = 'x';
   else if (perm & S_ISUID)
      string[3] = 'S';

   if (perm & S_IRGRP)
      string[4] = 'r';
   if (perm & S_IWGRP)
      string[5] = 'w';
   if (perm & S_ISUID && perm & S_IXGRP)
      string[6] = 's';
   else if (perm & S_IXGRP)
      string[6] = 'x';
   else if (perm & S_ISUID)
      string[6] = 'l';

   if (perm & S_IROTH)
      string[7] = 'r';
   if (perm & S_IWOTH)
      string[8] = 'w';
   if (perm & S_ISVTX && perm & S_IXOTH)
      string[9] = 't';
   else if (perm & S_IXOTH)
      string[9] = 'x';
   else if (perm & S_ISVTX)
      string[9] = 'T';

   (void) printf(" %s", string);
}

#endif


