# NEMESIS Packet Injection Suite [OSPF Makefile]
# (c) 1999 obecian

CC = gcc
CFLAGS = -O2
TARGET = ospf
OBJS = ospf.o proto_ospf.o

ospf: $(OBJS)
	$(CC) $(CFLAGS) -o $(TARGET) $(OBJS) -lnet

clean:
	rm $(TARGET) *.o
