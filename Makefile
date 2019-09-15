
CC = gcc
LDFLAGS = -lm
CFLAGS = -c -W -Iinc

ifdef D
CFLAGS += -DDEBUG
endif

vpath %.h inc
vpath %.c src

server: main.o logger.o util.o
	$(CC) $(LDFLAGS) $^ -o $@

main.o: main.c main.h
	$(CC) $(CFLAGS) $< -o $@

logger.o: logger.c logger.h
	$(CC) $(CFLAGS) $< -o $@

util.o: util.c util.h
	$(CC) $(CFLAGS) $< -o $@

clean:
	rm -f *.o
	rm -f server
