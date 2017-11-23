# NEMESIS Packet Injection Suite [UDP Makefile]
# (c) 1999 obecian

CC = gcc
CFLAGS = -O2
TARGET = udp
OBJS = udp.o proto_udp.o

udp: $(OBJS)
	$(CC) $(CFLAGS) -o $(TARGET) $(OBJS) -lnet

clean:
	rm $(TARGET) *.o
