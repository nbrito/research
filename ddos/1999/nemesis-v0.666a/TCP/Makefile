# NEMESIS Packet Injection Suite [TCP Makefile]
# (c) 1999 obecian

CC = gcc
CFLAGS = -O2
TARGET = tcp
OBJS = tcp.o proto_tcp.o

tcp: $(OBJS)
	$(CC) $(CFLAGS) -o $(TARGET) $(OBJS) -lnet

clean:
	rm $(TARGET) *.o
