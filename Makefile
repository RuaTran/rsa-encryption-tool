CC = clang 
CFLAGS = -Wall -Wextra -Werror -Wpedantic -g $(shell pkg-config --cflags gmp)
LFLAGS = $(shell pkg-config --libs gmp) -lm

all: encrypt decrypt keygen

keygen: keygen.o randstate.o numtheory.o rsa.o
	$(CC) keygen.o randstate.o numtheory.o rsa.o -o keygen $(LFLAGS)

encrypt: encrypt.o randstate.o numtheory.o rsa.o
	$(CC) encrypt.o randstate.o numtheory.o rsa.o -o encrypt $(LFLAGS)

decrypt: decrypt.o randstate.o numtheory.o rsa.o
	$(CC) decrypt.o randstate.o numtheory.o rsa.o -o decrypt $(LFLAGS)

randstate.o: randstate.c
	$(CC) $(CFLAGS) -c randstate.c

numtheory.o: numtheory.c
	$(CC) $(CFLAGS) -c numtheory.c

rsa.o: rsa.c
	$(CC) $(CFLAGS) -c rsa.c

clean:
	rm -f keygen encrypt decrypt rsa.pub rsa.priv *.o 

format: 
	clang-format -i -style=file *.[ch] 
