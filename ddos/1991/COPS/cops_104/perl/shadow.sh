#!/bin/sh
#
#  Usage: shadow.stuff
#
#   Extracts the correct info from shadow pass to use for processing with
# the rest of the perl stuff
#
#   The way you use this is just to type "shadow.stuff > tempfile";
# this will create a file, "tempfile" (or whatever), that *should*
# be the equivalent to a normal password file.  Of course, you'll have
# to run this as root so that you can read the shadow password file.

shadow=/etc/shadow
passwd=/etc/passwd
foo_pass=./shadow.tmp.$$

# foo_pass=shadow.pass

cat $passwd $shadow | sort > $foo_pass

awk -F: '{parray[$1] = $0":"parray[$1]} END { \
	for (line in parray) { \
		nf=split(parray[line], pline, ":"); \
		if (pline[9] != "LOCKED" && nf == 13) {
			print pline[1]":"pline[9]":"pline[3]":"pline[4]":" \
			pline[5]":"pline[6]":"pline[7]; \
		      	} \
		      } \
		}' $foo_pass
rm $foo_pass

