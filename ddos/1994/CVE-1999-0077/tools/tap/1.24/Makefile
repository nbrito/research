# @(#)Makefile	1.24 3/22/92
###############################################################################
#
#      	--- kernel loadable-module tap streams-module/driver pseudo-device ---
#
# 	SEE ALSO
#		modload(8)
#		modunload(8)
#		modstat(8)
#		vd(4)
#
# TAPDEBUG  -to show the tap structure every time a modstat(8) is started 
#
# TAPVD     -indicates kernel-loadable version
#
# TAPVDDUAL -must be defined only if a driver is already linked to /vmunix
#            and a additional loadable-driver should be loaded w/o confusing
#	     duplicate module-names ( "tapc"/"tap" strings are changed
#	     to "tapcvd"/"tapvd" )
#
###############################################################################
#
# TAPCLONE  -WARNING define ONLY after you have read the BUGS section 
#            in the README file
#
###############################################################################

CFLAGS=	-O -DKERNEL -D`arch -k` -DTAPVD # -DTAPDEBUG ### -DTAPCLONE
INSDIR=	/usr/local/etc
FILES=	README INSTALL Makefile load unload tap.c tap.h tapmon.c streams.c
MIDF=	/tmp/MODULE_ID 			# removed by reboot(8) and ./unload

all:	EXECS $(FILES) streams tapmon module

module:	tap.o  
	if( test -f $(MIDF) ) then \
		./unload ; \
	fi
	modload -exec ./load tap.o
	modstat

tap.c:	tap.h

EXECS:	load unload
	chmod a+x load unload
	touch $@ 				# WELCOME TO WATER-WORKS ...

edit:
	sccs edit $(FILES)
	chmod a+x load unload

delta:
	sccs delta $(FILES)

install:streams tapmon
	install -s -m 755 -o bin -g bin streams $(INSDIR)
	install -s -m 755 -o bin -g bin tapmon $(INSDIR)

clean:
	rm -f 	EXECS tap.o tap tapmon streams

shar:	$(FILES)
	shar -c $(FILES) > tap1.24.shar

