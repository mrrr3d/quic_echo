CC = gcc
CFLAGS = -g
LIBS = -lev -lngtcp2 -lngtcp2_crypto_gnutls -lgnutls

all: quicserver quicclient

quicserver: quicserver.c
	$(CC) $(CFLAGS) $^ -o $@ $(LIBS)

quicclient: quicclient.c
	$(CC) $(CFLAGS) $^ -o $@ $(LIBS)

clean:
	rm -f quicserver quicclient

