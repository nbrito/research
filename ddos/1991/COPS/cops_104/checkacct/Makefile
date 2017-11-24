#	$Id: Makefile,v 1.1 91/12/04 13:43:49 shabby Exp Locker: shabby $
#
#	Makefile for chkacct
#

DESTDIR=	/usr/local
PROG=	chkacct
BIN=	${DESTDIR}/bin
LIB=	${DESTDIR}/lib/chkacct
DOC=	${DESTDIR}/man

INSTALLFLAGSLIB=	-r -D -cm 0444
INSTALLFLAGSBIN=	-r -D -cm 0755

SRCs=	ca.src
M4SRC=	defines.m4
MAN=	chkacct.1l
PERLSRC=	rhosts.pl
OTHER=	README
SRCl=	dotwrite effect.dotwrit effect.owners effect.read effect.rhosts\
	effect.setuid effect.write Intro owners readable rhosts setuid write\
	prompt.help Article

SOURCE=	Makefile ${M4SRC} ${OTHER} ${MAN} ${SRCl} ${SRCs} ${PERLSRC}

all: ${SRCl} ${PROG}

${PROG}: ${SRCs}
	m4 ${M4SRC} ${SRCs} > $@
	chmod 755 $@

${M4SRC}:	
	echo "Remember to get a copy of the right m4 file.!";

clean: FRC
	rm -f Makefile.bak ${PROG} a.out core errs lint.out tags

depend: FRC

install: all FRC
	install ${INSTALLFLAGSLIB} ${SRCl} ${LIB}
	install ${INSTALLFLAGSBIN} ${PERLSRC} ${LIB}
	install ${INSTALLFLAGSBIN} ${PROG} ${BIN}

lint: FRC

mkcat: ${MAN} ${DOC} FRC
	mkcat -r${DOC} ${MAN}

print: source FRC
	lpr -J'${PROG} source' ${SOURCE}

source: ${SOURCE}

spotless: clean
	rcsclean ${SOURCE}

tags: FRC

${SOURCE}:
	co -q $@

FRC:

# DO NOT DELETE THIS LINE - make depend DEPENDS ON IT

# *** Do not add anything here - It will go away. ***
