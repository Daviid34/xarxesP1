all:
	gcc server.c -Wall -ansi -pedantic -std=c99 -pthread -o server

clean:
	-rm -fr server
