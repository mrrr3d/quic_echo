#include <stdio.h>
#include <arpa/inet.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <ev.h>

#include <ngtcp2/ngtcp2.h>
#include <ngtcp2/ngtcp2_crypto.h>
#include <ngtcp2/ngtcp2_crypto_gnutls.h>

#include <gnutls/crypto.h>
#include <gnutls/gnutls.h>

#define LOCAL_HOST "127.0.0.1"
#define LOCAL_PORT "5556"

struct connection
{
  ngtcp2_conn *conn;
  gnutls_session_t session;
  struct sockaddr client_addr;
  socklen_t client_addrlen;
  int fd;

  struct
  {
    int64_t stream_id;
    const uint8_t *data;
    size_t datalen;
    size_t nwrite;
  } stream;

};

struct server
{
  struct sockaddr local_addr;
  socklen_t local_addrlen;
  gnutls_certificate_credentials_t cred;
  int fd;
  struct connection connections[10];

};

int
server_gnutls_init (struct server *s)
{
  gnutls_certificate_credentials_t cred = NULL;
  gnutls_certificate_allocate_credentials (&cred);
  gnutls_certificate_set_x509_key_file (cred, )
}


int
server_init (struct server *s)
{
  memset (s, 0, sizeof(*s));
  struct sockaddr_in local_addr;
  socklen_t local_addrlen;
  int ret;

  local_addr.sin_addr.s_addr = inet_addr (LOCAL_HOST);
  local_addr.sin_family = AF_INET;
  local_addr.sin_port = htons (atoi (LOCAL_PORT));

  s->fd = socket (AF_INET, SOCK_DGRAM, 0);
  ret = bind (s->fd, (struct sockaddr *) &local_addr, sizeof(local_addr));
  local_addrlen = sizeof(local_addr);

  memcpy (&s->local_addr, &local_addr, local_addrlen);


  return 0;
}


int
main ()
{
  struct server s;

  int ret;
  ret = server_init (&s);

  return 0;
}