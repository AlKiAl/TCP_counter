CC=gcc
CFLAGS=-Wall -lpcap

all: tcp_counter

tcp_counter: main.o
	$(CC) -o tcp_counter main.o $(CFLAGS)

main.o: main.c
	$(CC) -c main.c $(CFLAGS)

clean:
	rm -f tcp_counter *.o

