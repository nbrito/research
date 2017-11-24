undefine(eval)dnl()
changequote(%,^)dnl()
dnl()
dnl() At some sites, a group is given to each user, rendering group
dnl()	permissions somewhat moot.  If your site is like this, then you
dnl()	want to tell chkacct to act as if group permissions don't matter.
dnl()   To do this, set smallgroups to be 1
dnl()
define(SmallGroups,%1^)dnl()
define(FindPermRead,
	ifelse(SmallGroups, %0^, %-perm -4 -o -perm -40^, %-perm -4^))dnl()
define(FindPermWrite,
	ifelse(SmallGroups, %0^, %-perm -2 -o -perm -20^, %-perm -2^))dnl()
define(ChmodPermSymbol,
	ifelse(SmallGroups, %0^, %go^, %o^))dnl()
define(FindPermSuid,
	ifelse(SmallGroups, %0^, %-perm -2000 -o -perm -4000^, %-perm -4000^))dnl()
define(ChmodPermSuidSymbol,
	ifelse(SmallGroups, %0^, %ug^, %u^))dnl()
dnl()
dnl()
dnl() Set cshpath() to be the tail end of whatever it takes to pipe standard
dnl() input to the shell.  It will be used in the following way:
dnl()		HOMEDIR=`echo "echo ~${USERID}" | cshpath()`
dnl() On some bsd systems, cshpath() needs to be "/bin/csh -".  
dnl() On some sysV systems, cshpath() needs to be "/bin/csh".  
dnl()
define(perlpath,%/usr/unsup/bin/perl^)dnl()
define(catpath,%/bin/cat^)dnl()
define(cshpath,%/bin/csh^)dnl()
define(pagerpath,%"/usr/ucb/more"^)dnl()
define(gurudude,%"PUCC General Consultant"^)dnl()
define(installpath,%/usr/local/^)dnl()
define(echownl,%/bin/echo "^$1%\c"^)dnl()
define(lsopt,%^)dnl()
define(findopts,%^)dnl()
