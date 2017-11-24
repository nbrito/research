#! /bin/sh 
#  stop.make  1.0       Allen-Bradley D818 Michael Reynolds     9-17-91
#
#  Creates a stop file from the current suid and sgid programs on the system.
#  You need to be in the cops directory to run this.  
#
SECURE=`grep 'SECURE=' suid.chk | cut -f2 -d=`
STOPFILE=`grep 'STOP=' suid.chk | cut -f2 -d=`
SEARCH=`grep 'SEARCH=' suid.chk | cut -f2 -d=`
#

#
# Replace with any options you like, of course.... (dan)
#
find $SEARCH \( -perm -4000 -o -perm -2000 \) -fstype 4.2 ! -type d -exec /bin/ls -lgad {} \; > $STOPFILE
