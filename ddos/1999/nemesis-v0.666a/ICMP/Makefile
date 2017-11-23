# NEMESIS Packet Injection Suite [ICMP Makefile]
# (c) 1999 obecian

CC = gcc
CFLAGS = -O2
TARGET = icmp
OBJS = icmp.o proto_icmp.o

icmp: $(OBJS)
	$(CC) $(CFLAGS) -o $(TARGET) $(OBJS) -lnet

clean:
	rm $(TARGET) *.o
