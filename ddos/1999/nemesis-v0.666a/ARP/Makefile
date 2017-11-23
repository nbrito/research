# NEMESIS Packet Injection Suite [ARP Makefile]
# (c) 1999 obecian

CC = gcc
CFLAGS = -O2
TARGET = arp
OBJS = arp.o proto_arp.o

arp: $(OBJS)
	$(CC) $(CFLAGS) -o $(TARGET) $(OBJS) -lnet

clean:
	rm $(TARGET) *.o
