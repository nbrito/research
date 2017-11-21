# IRPAS release code Makefile

CLIBS= -lpcap 
CFLAGS=-Wall -g -Wunused -Wmissing-prototypes -I. -L. 
CC=gcc
RM=rm
AR= ar rcs

OBJECTS= packets.o cdp.o igrp.o ass_v1.o irdp.o irdpresponder.o \
	itrace.o tctrace.o protos.o netmask.o file2cable.o netenum.o \
	hsrp.o icmp_redirect.o
PROGRAMS=cdp igrp ass irdp irdpresponder itrace tctrace protos \
	netmask file2cable netenum hsrp icmp_redirect
SOURCES=protocols.h packets.h packets.c \
	cdp.c igrp.c ass_v1.c irdp.c irdpresponder.c \
	itrace.c tctrace.c protos.c netmask.c file2cable.c \
	netenum.c hsrp.c icmp_redirect.c

all: ${PROGRAMS} 

# programs

netenum: netenum.o libpackets.a
	${CC} ${CFLAGS} -o netenum netenum.o -lpackets
netenum.o: netenum.c packets.h protocols.h enum.h 
	${CC} ${CFLAGS} -c netenum.c

hsrp: hsrp.o libpackets.a
	${CC} ${CFLAGS} -o hsrp hsrp.o -lpackets
hsrp.o: hsrp.c packets.h protocols.h 
	${CC} ${CFLAGS} -c hsrp.c

file2cable: file2cable.o libpackets.a
	${CC} ${CFLAGS} -o file2cable file2cable.o -lpackets
file2cable.o: file2cable.c packets.h protocols.h 
	${CC} ${CFLAGS} -c file2cable.c

cdp: cdp.o libpackets.a
	${CC} ${CFLAGS} -o cdp cdp.o -lpackets
cdp.o: cdp.c packets.h protocols.h 
	${CC} ${CFLAGS} -c cdp.c

igrp: igrp.o libpackets.a
	${CC} ${CFLAGS} -o igrp igrp.o -lpackets
igrp.o: igrp.c packets.h protocols.h 
	${CC} ${CFLAGS} -c igrp.c

netmask: netmask.o libpackets.a
	${CC} ${CFLAGS} -o netmask netmask.o -lpackets
netmask.o: netmask.c packets.h protocols.h 
	${CC} ${CFLAGS} -c netmask.c

itrace: itrace.o libpackets.a
	${CC} ${CFLAGS} -o itrace itrace.o -lpackets
itrace.o: itrace.c packets.h protocols.h 
	${CC} ${CFLAGS} -c itrace.c

tctrace: tctrace.o libpackets.a
	${CC} ${CFLAGS} -o tctrace tctrace.o -lpackets
tctrace.o: tctrace.c packets.h protocols.h 
	${CC} ${CFLAGS} -c tctrace.c

protos: protos.o libpackets.a
	${CC} ${CFLAGS} -o protos protos.o -lpackets
protos.o: protos.c packets.h protocols.h protocol-numbers.h 
	${CC} ${CFLAGS} -c protos.c

irdp: irdp.o libpackets.a
	${CC} ${CFLAGS} -o irdp irdp.o -lpackets
irdp.o: irdp.c packets.h protocols.h 
	${CC} ${CFLAGS} -c irdp.c

irdpresponder: irdpresponder.o libpackets.a
	${CC} ${CFLAGS} -o irdpresponder irdpresponder.o -lpackets ${CLIBS}
irdpresponder.o: irdpresponder.c packets.h protocols.h 
	${CC} ${CFLAGS} -c irdpresponder.c

icmp_redirect.o: icmp_redirect.c packets.h protocols.h 
	${CC} ${CFLAGS} -c icmp_redirect.c
icmp_redirect: icmp_redirect.o libpackets.a 
	${CC} ${CFLAGS} -o icmp_redirect icmp_redirect.o -lpackets ${CLIBS}

ass_v1.o: ass_v1.c packets.h protocols.h 
	${CC} ${CFLAGS} -c ass_v1.c
ass: ass_v1.o libpackets.a 
	${CC} ${CFLAGS} -o ass ass_v1.o -lpackets ${CLIBS}
assS: ass_v1.o libpackets.a
	${CC} ${CFLAGS} -o assS ass_v1.o -lpackets ${CLIBS} -static

libpackets.a: packets.o enum.o 
	$(AR) libpackets.a packets.o enum.o
packets.o: packets.c  protocols.h
	$(CC) ${CFLAGS} -c packets.c
enum.o: enum.h enum.c 
	$(CC) $(CFLAGS) -c enum.c


clean:
	${RM} -f ${OBJECTS}

realclean:
	${RM} -f ${OBJECTS} ${PROGRAMS} 
