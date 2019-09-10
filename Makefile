
CC = gcc
LDFLAGS = -lm
CFLAGS = -c -W -Iinc

ifdef D
CFLAGS += -DDEBUG
endif

vpath %.h inc
vpath %.c src

server: main.o logger.o
	$(CC) $(LDFLAGS) $^ -o $@

main.o: main.c main.h
	$(CC) $(CFLAGS) $< -o $@

logger.o: logger.c logger.h
	$(CC) $(CFLAGS) $< -o $@

clean:
	rm -f *.o server
