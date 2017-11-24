
  This file covers the configuration and execution of the shell/C
version of COPS.  As a rough time estimate, it took about 6.5 minutes on
my host (a SPARCstation 2) to make the programs and generate a report
(not including the SUID checker, which does a find on "/").

1) How to Configure COPS
-------------------------

  System V users, other Non-BSD systems, or sites with commands in
strange places may have to run a shell script called "reconfig" to
change the pathnames of the executable programs called when using COPS.
In general, if your system does not use the paths listed in the shell
scripts, try running "reconfig".  COPS should run fine then, if it can
find all of the commands (reconfig will tell you if it cannot).  If
trouble persists, you will have to change the paths to your executable
files (awk, sed, etc) by hand.  A drag, I know.  If in doubt, run the
shell script.  It can't hurt.  Or at least shouldn't.  If it does hurt,
you're probably in trouble anyway.

  With all the varieties of unix, there are a few types that may need
extra help to run the system.  There are "readme" files for several
systems in the distribution (see the files "readme.*" in the "docs"
directory).  If you have any troubles, drop me a line and I'll see what
I can do about working out a patch/fix/workaround with you.  Some
problems might arise with some SYSV machines (heck, or any machine :-)),
due to weird files and names for stuff.  What can I say?  Portability
is a problem.

  C2 (as in NCSC standards -- B1, C2, etc.), NIS/YP, or shadow password
users can also look at "readme.*" files for suggestions on how to best
run/utilize COPS.

2) Running COPS for the First Time
-----------------------------------

   Since most of COPS was written and tested on just a few machines (at
least compared to the total number out there!), you may have significant
differences that were not anticipated -- unfortunately (or fortunately)
UNIX is not quite standardized yet.  However, I haven't run into a UNIX
that I haven't been able to get it running on, with just a small amount
of change (at least for the shell version -- perl is another story :-(
), so feel free to mail to me for help.  Note that the following info is
for the shell version only -- read "README.perl" for information on how
to install and run the perl version.

   COPS is run by simply typing "cops".  "cops" is a Bourne shell script
that runs each of the programs, accumulates the output, and then either
mails any results or stores them in a file.  "suid.chk" (and possibly
"crc.chk") is the only package that is meant to be run separately, both
because it can take a long time to run and because it needs a privileged
account (i.e. root) to run it; look at "suid.man" for more information.
By all means, however, do not ignore the SUID checker!  Run it at least
once a week, more (daily?) if possible; intruders often leave SUID files
to gain privileges later.  You should also run "crc.chk".  It can either
be run as a standalone program (preferred), or as part of the COPS
package; read the file "CRC.README" and the man page for more
information.

   To run COPS for the first time, follow these steps:

   -- Look at the disclaimer, file "disclaimer".  Don't sue me.

   -- Type "make" to compile the C programs and to make the shell programs
      executable, "make man" to create the formatted manual pages, or "make
      all" to make both the programs and documentation.

      A couple of potential (hopefully minor problems), probably only
      for SysV based machines:

      If you don't have the "-ms" package for nroff (i.e. you, get an
      error message about it after typing "make"), just remove the "-ms"
      flag -- change line 15 of the "docs/makefile" file, from:

      ROFFLAGS   = -ms
        to
      ROFFLAGS   =

      The password checking program may fail to compile.  If so, try 
      uncommenting line 29 in "makefile" -- this will enable the
      "BRAINDEADFLAGS = -lcrypt" flag.  If this doesn't work, you can
      either work it out (and tell me about your solution) or e-mail me,
      and we'll work it together.

   -- Read the technical report (in the "docs" directory) to understand
      what COPS is doing and what is going on -- "COPS.report".  Although
      this is out of date, this does give a look at the philosophies,
      design, and general outlay of the COPS system and UNIX security.
      This can be forsaken by those who just want to get to the results/see
      some action (people like me), but it might prove interesting to some. 

   -- Change lines 93 and 94 in the "cops" shell file.  They are
      originally:

        SECURE=/usr/foo/bar
        SECURE_USERS="foo@bar.edu"

      SECURE should be the same directory as the directory that contains 
      the COPS programs, and SECURE_USERS should be your own login id,
      or whomever you designate as the recipient of the output.

      Alternately, you can use the "-s" flag to "cops" to specify the
      secure directory, and the "-m" flag will make cops both mail the
      report (see next item) and specify the user to be mailed to.

   -- Set "MMAIL=NO" in the "cops" shell file (line 42; it is this by
      default).  This will prevent a large mail file of warnings from
      choking the mailer.  All of the output will be put into a file
      called "year_month_day" (obviously, that's like: "1991_Dec_31",
      not actually the words, "year_month_day" :-)), which is
      automatically placed by COPS in a directory that has the same name
      as the host it was run on (e.g., your own hostname.)  Hence, the
      final report will be in "./hostname/year_month_day".

      If you prefer to have the report mailed (don't do this the first
      time) set this variable to YES and the report will be mailed to
      $SECURE_USERS, or use the "-m" flag and specify the user on the
      command line.

   -- Look at the directory and file configuration file, "is_able.lst" 
      This contains critical files that COPS checks for group- and
      world-writability and readability.  Add or delete whatever files
      or directories you wish; if a file doesn't exist, COPS will ignore
      it. (If you don't know or are uncertain what files/directories are 
      important, what is given there is a good set to start with on most
      systems.)

   -- If you allow anonymous ftp access to your system, add a "-a" flag
      to "ftp.chk" on line 193 of "cops".  Right now, it is set up so
      that key files and directories are expected to be owned by root;
      however, it has provisions for two owners, $primary and $secondary
      -- some may wish to change the second to "ftp", or some other
      user. Read the man page for ftp.chk or look at "ftp.chk" for
      further notes. 

   -- You may wish to comment out the password checker (line 200 in the 
      "cops" shell file), for immediate gratification.  However, it is 
      generally a very bad idea to do this unless you plan to use
      another password cracker, such as "crack" (see the "extensions"
      directory for more info).  If you are using yellow pages/NIS, read
      "readme.yp" for tips on how to check passwords with it; if you are
      using shadow passwords, read "readme.shadow".

   -- Uncomment out the crc checker, "crc.chk" (lines 218-220 and
      224-226), if you desire to run it as part of the normal COPS run --
      highly recommended!

   You should be ready to roll.  COPS is run by simply typing "cops"
(you may wish to put it in the background).  If you followed my advice
and set "MMAIL=NO" in the "cops" shell file, after COPS is finished
there will be a report file created ("year_month_day") that includes the
time and machine it was created on.  Otherwise, COPS will mail the
report to the user(s) listed on the line 'SECURE_USERS="foo@bar.edu"'
(or by the -m flag.)  There is a file called "warnings" which contains most
of the warning messages that COPS uses, a brief explanation of how the
message might pertain to your system, and finally a suggestion as how to
"fix" any problem.

WARNING NOTE: Change the shell script "cops" to reflect who you want the
output sent to and where the location of the program is BEFORE running the
program!
