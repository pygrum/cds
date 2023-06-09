CC=gcc
LIBS=-lzip

build:
	$(CC) *.c $(LIBS)