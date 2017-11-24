
  This file covers the configuration and execution of the perl version
of COPS (or p-COPS).  It requires a version of perl > 3.18 to work.  For
a rough time estimate, it took about 1.25 minutes on my host (a
SPARCstation 2) to generate a report (not including the SUID checker,
which does a find on "/").  p-COPS is roughly functionally equivalent to
the shell/C version (sans the CRC checker), but has some important
differences:

Advantages:

o  Perl is a real language (not that C isn't -- I'm comparing it mostly 
   to shell programming.)  It has almost no arbitrary limitations,
   unlike shell (amount of data a variable can hold, etc.)  All the
   information that COPS finds (especially from the password file, which
   is a major source of the security problems in a UN*X system) can be
   easily passed between modules.  As a result, the programs are more
   modular, easier to debug, and a lot more fun to write.

o  Perl is faster (even though the "hard" things are done mostly in C in
   the shell/C version, a lot of time is wasted due to the fact that
   almost no data sharing is done) and doesn't require any compilation
   (aside from the perl interpreter itself.)  This last point is  
   particularily nice for sites with multiple architectures.

o  p-COPS has a pair of very nice features -- the configuration file and 
   the recursive searching for writable files.  The config file is a big
   win: no more digging through code, trying to change some variable
   value and it gives control over which modules are run and many other
   important options. 

Disadvantages:
o  Perl.  It's a relatively new language that is changing frequently.
   The code, greatly boosted in complexity and efficiency by tom 
   christiansen's hard work, can cause core dumps and other problems
   on some platforms.  On others, it works fine.  Also, since perl is
   changing, future versions of perl might break previously working
   code.  It all rests in larry wall's capable hands.  Caveat Usor. 

o  p-COPS has not been tested thoroughly.  It seems to work, on some
   machines, but is sure to contain more bugs than the simpler shell/C
   version. 

  Ok -- now you're warned.  I highly suggest giving it a try -- here's
how to use p-COPS:

1) How to Configure p-COPS
---------------------------

  Although most of the programs in p-COPS are written entirely in perl,
some shell programs are used for simplicity (diff, ypcat, etc.)  This
shouldn't be a problem, but System V users, other Non-BSD systems, or
sites with commands in strange places should run a program called
"reconfig.pl" to change the pathnames of the executable programs called
when using COPS.  If your system does not use the paths listed in the
perl programs, try running it; COPS should run fine then, if it can find
all of the commands (reconfig should tell you if it cannot). If trouble
persists, you will have to edit the configuration file "cops.cf" to
change the paths to your executable files by hand.  A drag, I know.  If
in doubt, run reconfig.pl.  It can't hurt.  Or at least shouldn't.  If
it does hurt, you're probably in touble anyway.

2) Running p-COPS for the 1st Time
---------------------------------

   Since most of p-COPS was written and tested mostly on just a few
machines (at least compared to the total number out there!), you may
have significant differences that were not anticipated -- unfortunately
(or fortunately) perl and UNIX are not quite standardized yet.

   p-COPS is run by going into the "perl" subdirectory and typing
"cops".  "cops" is a perl program that looks inside the configuration
file ("cops.cf"), runs each of the programs listed there, accumulates
the output, and then either mails any results or stores them in a file.
"suid.chk" is the only package that is usually meant to be run
separately (although it can be run via the config file), simply because
it can take a long time to run, and because it needs a privileged
account to run it; look at "suid.man" for more information.  By all
means, however, do not ignore the SUID checker!  Run it at least once a
week, if possible more (daily?); intruders into a system often leave
SUID files to gain privileges later.  The program "crc.chk" (part of the
shell/C version of COPS) should also be run; read the file "CRC.README",
and the man page for more information.

   -- Read the technical report to understand what COPS is doing and
      what is going on -- "cops.report".  This gives a look at the 
      philosophies, design, and general outlay of the COPS system and
      UNIX security.  This can be forsaken by those who just want to get
      to the results/see some action (people like me), but it might
      prove interesting to some.

   -- On line 12 in the configuration file, "cops.cf":

        $SECURE_USERS="foo@bar.edu";

      $SECURE_USERS should be your own login id, or that of whomever
      you designate as the recipient of the output.

   -- Set "$MMAIL=0" in the "cops.cf" file (line 10; this is the default).
      This will prevent a large mail file from choking the mailer.  All of
      the output will be put into a file called "year_month_day" (obviously,
      that's like: "1992_Dec_31", not actually the words,
      "year_month_day" :-)), which is automatically placed by COPS
      in a directory that has the same name as the host it was run on
      (e.g., your own hostname).  Hence, the final report will be in
      "./hostname/year_month_day".  Setting this variable to 1 will
      cause the report to be mailed to $SECURE_USERS.

   -- Look at the directory and file configuration file, "is_able.lst" 
      This contains critical files that COPS checks for group and world 
      writability and readability.  Add or delete whatever files/
      directories you wish; if a file doesn't exist, COPS will
      effectively ignore it.  (If you don't know or are uncertain what
      files/directories are important, what is given there is a good set
      to start with on most systems.)

   -- If you allow anonymous ftp access to your system, add a "-a" flag 
      to "ftp.chk" on line 83 of "cops.cf".  Right now, it is set up so 
      that key files and directories are expected to be owned by root; 
      however, it has provisions for two owners, $primary and $secondary
      -- you may wish to change the second to "ftp", or some other user. 
      Read the man page for ftp.chk, or look at "ftp.chk" for further
      notes. 

   -- You may wish to comment out the password checker (line 72 in the 
      "cops.cf" file), if you wish for immediate gratification.
      However, it is an abysmal idea to do this in general (unless you
      use another password cracker, like "crack" (see the "extensions"
      directory for more info.)  If you are using yellow pages/NIS, read
      "readme.yp" for tips on how to check passwords with it; if you are
      using shadow passwords, read "readme.shadow".

   -- Run the crc checker, "crc.chk" if you desire; unfortunately, this
      hasn't been ported to perl yet, so you'll have to either use the
      shell version or wait for the port (or write it and send it to me...)

  You should be ready to roll.  COPS is run by simply typing "cops" (you
may wish to put it in the background).  If you followed my advice and
set "$MMAIL=0" in the "cops.cf" configuration file, after COPS is
finished there will be a report file created ("year_month_day") that
lists the time and machine it was created on.  Otherwise, COPS mails the
report to the user(s) listed on the line '$SECURE_USERS="foo@bar.edu"'.
There is a file "warnings" (in the "../docs" directory), which contains
the warning messages COPS uses, as well as a brief explanation of how
the message might pertain to your system and finally a suggestion as
how to "fix" any problem.

   WARNING NOTE: Change the configuration file "cops.cf" to reflect who
you want the output sent to and where the location of the program is
BEFORE running the program.


2) Further notes and use of p-COPS, plus things for "perl literates"
---------------------------------------------------------------------

   The only important thing you have to set in the "cops" main file (or
via the "-s" flag) is the secure directory, which by default is ".".
This is where COPS will look for the config file and all the programs.
Also, if something is flagged as world-writable, and the file itself is
not writable but the parent directory is, then there will be an asterix
after the warning (e.g. /usr/foo/bar is World Writable! (*).)

As said in the config file -- "cops.cf" (a "#" sign denotes comments):

# anything beginning with /^\s*[$@%&]/ will be eval'd

  In general, you can put variables and programs that will be run inside
the config file.  Variables look startlingly like they do in normal perl
(look at the "PROGRAMS" section below for more on running programs);
e.g.:

$MMAIL 		= 0; 		# send mail instead of generating reports
$ONLY_DIFF 	= 0;  		# only send diff from last time
$SECURE_USERS   = "root"; 	# user to receive mailed report

   Setting something to "0" (without quotes is fine) generally means
that the option is not used.  "1" (or non-zero values, if you feel
gutsy) is used for a positive/true/whatever value.  The variables in
general should be very similar to their normal COPS counterparts; in
this case, setting $MMAIL to 1 would mean to mail info to the user listed
in SECURE_USERS.  If $ONLY_DIFF is 1, it will only mail reports if change
has occurred.

  In general, variables in the main package are for COPS itself, whereas
those with package qualifiers are for a particular routine or for
auxiliary routines.  For instance, the following lines:

# this one says to ignore warnings about paths matching these regexps
@chk_strings'ignores = ( '^/tmp/?', '^/(var|usr)/tmp/?' );

  "chk_strings" is a routine that checks for writable programs within
other programs, usually executed by root, such as /etc/rc and crontab.
This line says to ignore any files that start with a "/tmp", "/var/tmp",
or "/usr/tmp".  If you have a file or set of files that always are
returning writable that are inside your rc and cron files, then you can
put exceptions here.  One possibility is that you don't care about files
created by other programs, so that anything after a ">" should be
ignored.  You might add something like '>.*' to ignore files like
"/usr/bar/snowcone", in a line like "/foo/bar/command >
/usr/bar/snowcone".

   Next, there is a nifty option that does recursive searching inside
the files chk_strings looks at.  This is neat... get it working by
setting this to 1:

$chk_strings'recurse = 1;

  So, if you have a line like this in /etc/rc:

/usr/bin/foo > /dev/console

  It will examine "/usr/bin/foo" for programs inside of it -- and it
will keep going until it has exhausted all possibilities.  So you can
get warning messages like:

Warning!  File /foo/bar (inside /usr/local/X11R4/bin/X inside
/usr/local/X11R4/bin/xdm inside /etc/rc.local) is _World_ writable!

  Fun stuff.  No one can hide, now...

PROGRAMS
=========

  Running a program within p-COPS is easy; you just have the program
with any options by itself on a line.  Semi-colons are not welcome here.
E.g.:

# first test the security of the root account
root.chk

  Some variables specific to the various programs are here as well, e.g.:

# now of the various devices.  -g means to check group writability, too
$MTAB    = '/etc/fstab';
$EXPORTS = '/etc/exports';
$TAB_STYLE = 'new';
dev.chk -g 

  This is specifying the export files, etc., and saying that you should
use the "new" format style in the exports file.  Ultrix, etc. uses the
old style.  Suid.chk eats up time -- consider the "-n" flag for systems
that have big NFS mounted disks.  And that's it -- the rest should be
similar to the shell version of cops, and theoretically should give you
similar or the same results.

  Good luck!  Send bugs, flames, etc. to zen@death.corp.sun.com

 -- dan
