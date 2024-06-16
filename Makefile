CC = gcc
CFLAGS = -g
LIBS = -lev -lngtcp2 -lngtcp2_crypto_gnutls -lgnutls

all: quicserver quicclient h3server h3client

quicserver: quicserver.c
	$(CC) $(CFLAGS) $^ -o $@ $(LIBS)

quicclient: quicclient.c
	$(CC) $(CFLAGS) $^ -o $@ $(LIBS)

h3server: h3server.c
	$(CC) $(CFLAGS) $^ -o $@ $(LIBS) -lnghttp3

h3client: h3client.c
	$(CC) $(CFLAGS) $^ -o $@ $(LIBS) -lnghttp3

clean:
	rm -f quicserver quicclient

