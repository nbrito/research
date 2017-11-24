/*
    This progam will compare two crc lists and report the differences.
    
    By Jon Zeeff (zeeff@b-tech.ann-arbor.mi.us)

    Permission is granted to use this in any manner provided that    
    1) the copyright notice is left intact, 
    2) you don't hold me responsible for any bugs and 
    3) you mail me any improvements that you make.  


    report:
         corrupt	-	crc changed w/o date change
         replaced	-	crc + date changed
         perm		-	permissions changed
         own/grp	-	owner or group changed
	 removed	-	
	 added		-

Print the info for the new file except for deleted.

Use:

find / -print | sort | xargs crc -v > crc_file

to generate a crc list (crc.c should accompany this source).

Assume that no files have tabs or spaces in the name.

*/

/*
 sequent stuff -- may or may not need it?  Worked fine without it
on a sequent I had, but others claim they need it.  Go figure.

#ifdef sequent
#define strrchr(s, c)	rindex(s,c)
#endif

*/

/* max size of line */

#define BUF_SIZE 1124

#include <stdio.h>

char	*strrchr();
void    exit();

char	new_line[BUF_SIZE];
char	old_line[BUF_SIZE];

FILE *new_file;
FILE *old_file;

main(argc, argv)
int	argc;
char	**argv;
{
   /*

           If line =, read new line from each file
           else
           If date/perm/crc change, report and read new line from each file
           else
           If old_line < new_line, report file removed, read old line
           else
              report new line as added
              read new_line
        loop
*/

   char	*new_ptr;
   char	*old_ptr;

   if (argc != 3) {
      (void) printf("wrong number of arguments\n");
      (void) printf("crc_check old_crc_file new_crc_file\n");
      exit(1);
   }
   new_file = fopen(argv[2], "r");
   old_file = fopen(argv[1], "r");

   if (new_file == NULL || old_file == NULL) {
      (void) printf("can't open input files\n");
      (void) printf("crc_check old_crc_file new_crc_file\n");
      exit(1);
   }

   get_line(new_line);
   get_line(old_line);

   for (; ; ) {

      check_eof();

      /* If equal, print nothing and get new lines */

      if (strcmp(old_line, new_line) == 0) {
         get_line(new_line);
         get_line(old_line);
         continue;
      }

      /* Compare just the file names */

      new_ptr = strrchr(new_line, ' ');
      old_ptr = strrchr(old_line, ' ');

      if (new_ptr == NULL || old_ptr == NULL) {
         (void) printf("Error in input data\n");
         exit(1);
      }

      if (strcmp(old_ptr, new_ptr) == 0) {

         new_ptr = strrchr(new_line, '\t');
         old_ptr = strrchr(old_line, '\t');

         if (new_ptr == NULL || old_ptr == NULL) {
            (void) printf("Error in input data\n");
            exit(1);
         }

         /* check crc change */

         if (strncmp(new_line, old_line, 4) != 0)
            if (strcmp(new_ptr, old_ptr) == 0)
               (void) printf("corrupt  %s", new_line + 5);
            else
               (void) printf("replaced %s", new_line + 5);


         /* check permission chenage */

         if (strncmp(new_line + 5, old_line + 5, 11) != 0)
            (void) printf("permiss  %s", new_line + 5);

         /* check  owner/group */

         if (strncmp(new_line+16, old_line+16, new_ptr - new_line - 15) != 0)
            (void) printf("own/grp  %s", new_line + 5);

         get_line(new_line);
         get_line(old_line);
         continue;
      }


      if (strcmp(old_ptr, new_ptr) < 0) {
         (void) printf("removed  %s", old_line + 5);
         get_line(old_line);
         continue;
      }

      (void) printf("added    %s", new_line + 5);
      get_line(new_line);

   }

}


get_line(string)
char	*string;
{
   if (string == new_line)
      (void) fgets(string, BUF_SIZE, new_file);
   else
      (void) fgets(string, BUF_SIZE, old_file);

}


check_eof()
{

   if (feof(new_file)) {

      while (!feof(old_file)) {
         (void) printf("removed  %s", old_line + 5);
         (void) fgets(old_line, BUF_SIZE, old_file);
      }
      exit(0);
   } else if (feof(old_file)) {
      while (!feof(new_file)) {
         (void) printf("added    %s", new_line + 5);
         (void) fgets(new_line, BUF_SIZE, new_file);
      }
      exit(0);
   }

}



