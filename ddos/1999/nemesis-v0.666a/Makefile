# NEMESIS Packet Injection Suite [Makefile]
# Developed in FreeBSD 3.3
# Author-tested OS's: FreeBSD 3.x, OpenBSD 2.x 
# (c) 1999 obecian

CC = gcc
CFLAGS = -O2
TCP_TARGET = tcp
UDP_TARGET = udp
TCP_OBJS = tcp.o proto_tcp.o
UDP_OBJS = udp.o proto_udp.o

all: nemesis

nemesis:
	cd TCP; make
	cd UDP; make
	cd ICMP; make
	cd ARP; make
	cd OSPF; make

clean:
	cd TCP; make clean
	cd UDP; make clean
	cd ICMP; make clean
	cd ARP; make clean
	cd OSPF; make clean
