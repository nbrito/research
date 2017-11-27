# @(#)Makefile	1.5 3/19/92
#
#     --- kernel loadable-module tap streams-module/driver ---
#
# SEE ALSO
#	modload(8)
#	modunload(8)
#	modstat(8)
#	vd(4)
#
# TAPVD should be undefined if the driver is linked to /vmunix
# TAPVDDUAL must be defined only if a driver is already linked to /vmunix
#           and a additional loadable-driver should be loaded w/o confusing
#	    duplicate module-names ( "tapc"/"tap" strings are changed
#	    to "tapcvd"/"tapvd" )

INSDIR=		/usr/local/bin

FILES=		README INSTALL Makefile \
		load unload tap.c tap.h tapmon.c streams.c

CFLAGS=		-O -DKERNEL -DTAPVD 

all:		execs $(FILES) streams tapmon module

module:		tap.o  
		modload -exec ./load tap.o
		modstat

tap.c:		tap.h

execs:		load unload
		chmod a+x load unload
		> execs

edit:
		sccs edit $(FILES)
		chmod a+x load unload

delta:
		sccs delta $(FILES)

install:	streams tapmon
		install -s -m 755 -o bin -g bin streams $(INSDIR)
		install -s -m 755 -o bin -g bin tapmon $(INSDIR)

clean:
		rm -f 	execs tap.o tap tapmon streams

shar:		$(FILES)
		shar -c $(FILES) > tap.shar

