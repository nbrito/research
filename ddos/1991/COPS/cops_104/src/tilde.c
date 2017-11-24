#include <pwd.h>
#include <sys/types.h>
#include <sys/stat.h>

main(argc,argv)
int argc;
char **argv;
{
struct passwd *pp;

if (argc != 2) {
	printf("Usage: %s\n",argv[0]);
	exit(1);
}

/* print directory of user, else "Error"  -- need to print
  something, or kuang won't parse dir correctly */
if ((pp = getpwnam(argv[1])) != (struct passwd *)0)
	printf("%s", pp->pw_dir);
else
	printf("Error");

}
