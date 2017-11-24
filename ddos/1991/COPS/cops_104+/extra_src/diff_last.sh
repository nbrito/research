#!/bin/csh -f
#
# Now for the good news: below is yet another little COPS accessory
# script.  As you will recall, I keep a number of COPS reports around in
# a subdirectory named after the host.  This script will find the last
# two and do a diff on them.  I've wondered whether I should take this a
# step further and use something like this as the basis for the mailed
# report, but that might make it too easy to miss things.  Still, this
# script seems to be useful when I get a COPS report in the mail and I
# can't see that anything important has changed.  Enjoy.
# 
# -- Prentiss Riddle ("aprendiz de todo, maestro de nada") riddle@rice.edu
# -- Unix Systems Programmer, Office of Networking and Computing Systems
# -- Rice University, POB 1892, Houston, TX 77251 / Mudd 208 / 713-285-5327
# -- Opinions expressed are not necessarily those of my employer.
# 
#
#  difflast - do a diff on the last two COPS reports for a specific host
#
#  Usage:  difflast [host-directory]
#
#
#  History:
#  11/25/91  P.Riddle  Original version.
#
set AWK=/bin/awk
set DIFF=/bin/diff
set LS=/bin/ls

set DIR="$1"
if ( "x$DIR" == x ) then
	set DIR=.
endif
if ( ! -d "$DIR" ) then
	echo "difflast: directory \"$DIR\" not found."
	exit 1
endif
set FILES=`$LS -t ${DIR}/[0-9][0-9][0-9][0-9]_[A-Z][a-z][a-z]_[0-9]* | $AWK 'NR<=2'`
echo "$FILES"
$DIFF $FILES
exit 0
