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

struct server;
struct connection
{
  ngtcp2_conn *conn;
  gnutls_session_t session;
  struct sockaddr client_addr;
  socklen_t client_addrlen;
  struct sockaddr local_addr;
  socklen_t local_addrlen;
  int fd;
  ev_io wev;
  ev_timer timer;
  ngtcp2_ccerr last_error;
  ngtcp2_crypto_conn_ref conn_ref;
  struct server *server;
  struct connection *next;

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
  struct connection *connections;
  uint8_t num_connections;
  ngtcp2_settings settings;
  ev_io rev;

};

void
write_cb (struct ev_loop *loop, ev_io *w, int revents);

uint64_t
timestamp (void)
{
  struct timespec tp;

  clock_gettime (CLOCK_MONOTONIC, &tp);

  return (uint64_t) tp.tv_sec * NGTCP2_SECONDS + (uint64_t) tp.tv_nsec;
}


void
dispaddr (struct sockaddr *addr, uint8_t *prestr)
{
  struct sockaddr_in *addr_in = (struct sockaddr_in*) addr;
  char ip_str[INET_ADDRSTRLEN];
  uint16_t port;
  inet_ntop (AF_INET, &addr_in->sin_addr, ip_str, INET_ADDRSTRLEN);
  port = ntohs (addr_in->sin_port);
  printf ("%s: %s:%u\n", prestr, ip_str, port);
}


int
server_gnutls_init (struct server *s)
{
  s->cred = NULL;
  gnutls_certificate_allocate_credentials (&s->cred);
  gnutls_certificate_set_x509_key_file (s->cred,
                                        "credentials/server.pem",
                                        "credentials/server-key.pem",
                                        GNUTLS_X509_FMT_PEM);

}


ssize_t
recv_pkt (int fd, uint8_t *data, size_t datalen,
          struct sockaddr *remote_addr, socklen_t *remote_addrlen)
{
  struct iovec iov;
  iov.iov_base = data;
  iov.iov_len = datalen;

  struct msghdr msg;
  memset (&msg, 0, sizeof(msg));

  msg.msg_name = remote_addr;
  msg.msg_namelen = *remote_addrlen;
  msg.msg_iov = &iov;
  msg.msg_iovlen = 1;

  ssize_t ret;
  do {
    ret = recvmsg (fd, &msg, 0);
  }
  while (ret < 0 && errno == EINTR);
  *remote_addrlen = msg.msg_namelen;

  return ret;
}


void
dispcid (const uint8_t *cid, size_t cidlen)
{
  int i;
  for (i = 0; i < cidlen; i++)
  {
    printf ("%x", cid[i]);
  }
  printf ("\n");
}


struct connection*
find_connection (struct server *s, const uint8_t *dcid, size_t dcidlen)
{
  struct connection *connection = s->connections;
  while (NULL != connection)
  {
    ngtcp2_conn *conn = connection->conn;
    size_t num_scids = ngtcp2_conn_get_scid (conn, NULL);
    ngtcp2_cid scids[9];
    memcpy (&scids[0], ngtcp2_conn_get_client_initial_dcid (conn),
            sizeof (ngtcp2_cid));
    ngtcp2_conn_get_scid (conn, scids + 1);
    int j;
    for (j = 0; j < num_scids + 1; j++)
    {
      if (scids[j].datalen == dcidlen &&
          0 == memcmp (scids[j].data, dcid, dcidlen))
      {
        return connection;
      }
    }
    connection = connection->next;
  }

  return NULL;
}


int
get_random_cid (ngtcp2_cid *cid)
{
  uint8_t buf[NGTCP2_MAX_CIDLEN];
  int ret;

  ret = gnutls_rnd (GNUTLS_RND_RANDOM, buf, sizeof(buf));
  if (ret < 0)
  {
    return -1;
  }
  ngtcp2_cid_init (cid, buf, sizeof(buf));
  return 0;
}


void
rand_cb (uint8_t *dest, size_t destlen,
         const ngtcp2_rand_ctx *rand_ctx)
{
  (void) rand_ctx;

  (void) gnutls_rnd (GNUTLS_RND_RANDOM, dest, destlen);
}


int
get_new_connection_id_cb (ngtcp2_conn *conn, ngtcp2_cid *cid,
                          uint8_t *token, size_t cidlen,
                          void *user_data)
{
  (void) conn;
  (void) user_data;

  if (gnutls_rnd (GNUTLS_RND_RANDOM, cid->data, cidlen) != 0)
  {
    return NGTCP2_ERR_CALLBACK_FAILURE;
  }

  cid->datalen = cidlen;

  if (gnutls_rnd (GNUTLS_RND_RANDOM, token, NGTCP2_STATELESS_RESET_TOKENLEN) !=
      0)
  {
    return NGTCP2_ERR_CALLBACK_FAILURE;
  }

  return 0;
}


int
remove_connection_id (ngtcp2_conn *conn, const ngtcp2_cid *cid,
                      void *user_data)
{
  printf ("======remove_connection_cb:");
  dispcid (cid->data, cid->datalen);
  return 0;
}

int
connection_write (struct connection *connection);


int
recv_stream_data_cb (ngtcp2_conn *conn, uint32_t flags, int64_t stream_id,
                     uint64_t offset, const uint8_t *data, size_t datalen,
                     void *user_data,
                     void *stream_user_data)
{
  struct connection *c = (struct connection*) user_data;
  char buf[256] = "recv_data:";
  memcpy (buf + 10, data, datalen);
  buf[10 + datalen] = 0;
  write (1, buf, 10 + datalen);

  memcpy (buf, data, datalen);
  char suffix[] = "-----server_side\n";
  memcpy (buf + datalen, suffix, sizeof (suffix));
  c->stream.data = buf;
  c->stream.datalen = datalen + sizeof (suffix);
  c->stream.stream_id = stream_id;
  c->stream.nwrite = 0;
  connection_write (c);
  return 0;
}


ngtcp2_callbacks callbacks = {
  // .client_initial
  .recv_client_initial = ngtcp2_crypto_recv_client_initial_cb,
  .recv_crypto_data = ngtcp2_crypto_recv_crypto_data_cb,
  .encrypt = ngtcp2_crypto_encrypt_cb,
  .decrypt = ngtcp2_crypto_decrypt_cb,
  .hp_mask = ngtcp2_crypto_hp_mask_cb,
  // .recv_retry = ngtcp2_crypto_recv_retry_cb,
  .update_key = ngtcp2_crypto_update_key_cb,
  .delete_crypto_aead_ctx = ngtcp2_crypto_delete_crypto_aead_ctx_cb,
  .delete_crypto_cipher_ctx = ngtcp2_crypto_delete_crypto_cipher_ctx_cb,
  .get_path_challenge_data = ngtcp2_crypto_get_path_challenge_data_cb,
  .version_negotiation = ngtcp2_crypto_version_negotiation_cb,

  // .acked_stream_data_offset = acked_stream_data_offset_cb,
  // .recv_stream_data = recv_stream_data_cb,
  // .stream_open = stream_open_cb,
  .rand = rand_cb,
  .get_new_connection_id = get_new_connection_id_cb,
  .recv_stream_data = recv_stream_data_cb,
  .remove_connection_id = remove_connection_id,
};

ngtcp2_conn*
get_conn (ngtcp2_crypto_conn_ref *ref)
{
  return ((struct connection*) (ref->user_data))->conn;
}


#define PRIO "NORMAL:-VERS-ALL:+VERS-TLS1.3:" \
        "-CIPHER-ALL:+AES-128-GCM:+AES-256-GCM:+CHACHA20-POLY1305:+AES-128-CCM:" \
        "-GROUP-ALL:+GROUP-SECP256R1:+GROUP-X25519:+GROUP-SECP384R1:+GROUP-SECP521R1:" \
        "%DISABLE_TLS13_COMPAT_MODE"

struct connection*
accept_connection (struct server *s, struct sockaddr *remote_addr,
                   socklen_t remote_addrlen, uint8_t *data,
                   size_t datalen)
{
  ngtcp2_pkt_hd header;
  int ret;

  ret = ngtcp2_accept (&header, data, datalen);
  if (ret < 0)
  {
    printf ("ngtcp2_accept error ret = %d %s\n", ret, ngtcp2_strerror (ret));
    return NULL;
  }
  struct connection *new_connection;
  new_connection = (struct connection*) malloc (sizeof (struct connection));
  memset (new_connection, 0, sizeof(new_connection));
  new_connection->next = s->connections;
  s->connections = new_connection;

  s->num_connections += 1;
  gnutls_init (&new_connection->session, GNUTLS_SERVER
               | GNUTLS_ENABLE_EARLY_DATA
               | GNUTLS_NO_END_OF_EARLY_DATA);
  gnutls_priority_set_direct (new_connection->session,
                              PRIO, NULL);
  gnutls_credentials_set (new_connection->session,
                          GNUTLS_CRD_CERTIFICATE, s->cred);

  new_connection->fd = s->fd;
  ngtcp2_path path = {
    .local = {
      .addr = (struct sockaddr*) &s->local_addr,
      .addrlen = s->local_addrlen,
    },
    .remote = {
      .addr = remote_addr,
      .addrlen = remote_addrlen,
    },
  };

  ngtcp2_transport_params params;
  ngtcp2_transport_params_default (&params);
  params.initial_max_streams_uni = 3;
  params.initial_max_streams_bidi = 3;
  params.initial_max_stream_data_bidi_local = 128 * 1024;
  params.initial_max_stream_data_bidi_remote = 128 * 1024;
  params.initial_max_data = 1024 * 1024;
  params.original_dcid_present = 1;
  params.max_idle_timeout = 30 * NGTCP2_SECONDS;
  memcpy (&params.original_dcid, &header.dcid,
          sizeof (params.original_dcid));
  ngtcp2_cid scid;
  get_random_cid (&scid);
  ngtcp2_conn *conn = NULL;

  ret = ngtcp2_conn_server_new (&conn, &header.scid, &scid,
                                &path, header.version, &callbacks,
                                &s->settings, &params, NULL, new_connection);
  if (ret < 0)
  {
    fprintf (stderr, "ngtcp2_conn_server_new error!\n");
    return NULL;
  }
  new_connection->conn = conn;

  memcpy (&new_connection->local_addr, &s->local_addr, s->local_addrlen);
  new_connection->local_addrlen = s->local_addrlen;

  memcpy (&new_connection->client_addr, remote_addr, remote_addrlen);
  new_connection->client_addrlen = remote_addrlen;

  ngtcp2_crypto_gnutls_configure_server_session (new_connection->session);
  ngtcp2_conn_set_tls_native_handle (new_connection->conn,
                                     new_connection->session);
  gnutls_session_set_ptr (new_connection->session, &new_connection->conn_ref);
  new_connection->conn_ref.get_conn = get_conn;
  new_connection->conn_ref.user_data = new_connection;
  new_connection->stream.stream_id = -1;
  new_connection->server = s;

  return new_connection;
}


void
connection_close (struct connection *connection);



void
server_remove_connection (struct connection *connection)
{
  struct server *s = connection->server;
  struct connection *curr = s->connections;
  if (NULL == s->connections)
    return;
  s->num_connections -= 1;
  if (connection == s->connections)
  {
    s->connections = connection->next;
    ev_timer_stop (EV_DEFAULT, &connection->timer);
    ev_io_stop (EV_DEFAULT, &connection->wev);
    free (connection);
    return;
  }

  while (NULL != curr->next &&
         curr->next != connection)
  {
    curr = curr->next;
  }
  if (curr->next == connection)
  {
    curr->next = connection->next;
    ev_timer_stop (EV_DEFAULT, &connection->timer);
    ev_io_stop (EV_DEFAULT, &connection->wev);
    free (connection);
  }

  return;
}


void
timer_cb (struct ev_loop *loop, ev_timer *w, int revents)
{

  printf ("=====in timer_cb\n");
  struct connection *c = w->data;

  int ret = ngtcp2_conn_handle_expiry (c->conn, timestamp ());
  if (ret != 0)
  {
    printf ("ngtcp2_conn_handle_expiry ret = %s\n", ngtcp2_strerror (ret));
    // connection_close (c);
    server_remove_connection (c);
    return;
  }
  if (connection_write (c) != 0)
  {
    // fprintf (stdout, "client_write!=0\n");
    // connection_close (c);
    server_remove_connection (c);
  }
}


int
handle_incoming (struct server *s)
{
  uint8_t buf[1280];
  ssize_t n_read;
  struct sockaddr_in remote_addr;
  socklen_t remote_addrlen;
  int ret;

  for (;;)
  {
    remote_addrlen = sizeof (remote_addr);
    n_read = recv_pkt (s->fd, buf, 1280,
                       (struct sockaddr*) &remote_addr,
                       &remote_addrlen);
    if (n_read < 0)
    {
      fprintf (stderr, "recv_pkt error!\n");
      return -1;
    }
    dispaddr ((struct sockaddr*) &remote_addr, "client");

    ngtcp2_version_cid version_cid;

    ret = ngtcp2_pkt_decode_version_cid (&version_cid, buf, n_read, 20);
    if (ret < 0)
    {
      fprintf (stderr, "ngtcp2_pkt_decode_version_cid error!\n");
      return -1;
    }

    struct connection *connection = NULL;
    connection = find_connection (s, version_cid.dcid, version_cid.dcidlen);

    if (NULL == connection)
    {
      connection = accept_connection (s,
                                      (struct sockaddr*) &remote_addr,
                                      remote_addrlen, buf, n_read);
      if (NULL == connection)
      {
        fprintf (stderr, "accept_connection error!\n");
        return -1;
      }
      ev_io_init (&connection->wev, write_cb, connection->fd, EV_WRITE);
      connection->wev.data = s;
      ev_timer_init (&connection->timer, timer_cb, 0., 0.);
      connection->timer.data = connection;
      // ev_io_start (EV_DEFAULT, &connection->wev);
    }

    ngtcp2_conn *conn = connection->conn;
    ngtcp2_path path;
    ngtcp2_pkt_info pi;
    memcpy (&path, ngtcp2_conn_get_path (conn), sizeof(path));
    path.remote.addr = (struct sockaddr*) &remote_addr;
    path.remote.addrlen = remote_addrlen;
    memset (&pi, 0, sizeof(pi));

    ret = ngtcp2_conn_read_pkt (conn, &path, &pi,
                                buf, n_read, timestamp ());
    if (ret < 0)
    {
      fprintf (stderr, "ret = %d, ngtcp2_conn_read_pkt: %s\n", ret,
               ngtcp2_strerror (ret));
      return -1;
    }
    return 0;
  }
}


int
server_send_pkt (struct connection *connection,
                 uint8_t *data, size_t datalen,
                 struct sockaddr *remote_addr,
                 socklen_t remotea_addrlen)
{
  struct iovec iov = {data, datalen};
  struct msghdr msg = {0};
  ssize_t nwrite;

  msg.msg_iov = &iov;
  msg.msg_iovlen = 1;
  msg.msg_name = remote_addr;
  msg.msg_namelen = remotea_addrlen;
  do {
    nwrite = sendmsg (connection->fd, &msg, 0);
  } while (nwrite == -1 && errno == EINTR);

  if (nwrite == -1)
  {
    return -1;
  }
  return 0;
}


int
write_to_stream (struct connection *connection)
{
  uint8_t buf[1280];
  ngtcp2_tstamp ts = timestamp ();
  ngtcp2_path_storage ps;
  int64_t stream_id;
  uint32_t flags;
  ngtcp2_vec datav;
  size_t datavcnt;
  ngtcp2_ssize nwrite;
  ngtcp2_ssize wdatalen;
  ngtcp2_pkt_info pi;
  int fin;

  ngtcp2_path_storage_zero (&ps);

  for (;;)
  {
    if (-1 != connection->stream.stream_id &&
        connection->stream.nwrite < connection->stream.datalen)
    {
      stream_id = connection->stream.stream_id;
      fin = 0;
      datav.base = (uint8_t *) connection->stream.data
                   + connection->stream.nwrite;
      datav.len = connection->stream.datalen
                  - connection->stream.nwrite;
      datavcnt = 1;
    }
    else
    {
      stream_id = -1;
      fin = 0;
      datav.base = NULL;
      datav.len = 0;
      datavcnt = 0;
    }

    flags = NGTCP2_WRITE_STREAM_FLAG_MORE;
    if (fin)
      flags |= NGTCP2_WRITE_STREAM_FLAG_FIN;

    nwrite = ngtcp2_conn_writev_stream (connection->conn, &ps.path, &pi, buf,
                                        sizeof(buf),
                                        &wdatalen, flags, stream_id, &datav,
                                        datavcnt, ts);
    if (nwrite < 0)
    {
      switch (nwrite)
      {
      case NGTCP2_ERR_WRITE_MORE:
        connection->stream.nwrite += (size_t) wdatalen;
        continue;
      default:
        fprintf (stderr, "ngtcp2_conn_writev_stream: %s\n",
                 ngtcp2_strerror ((int) nwrite));
        ngtcp2_ccerr_set_liberr (&connection->last_error, (int) nwrite, NULL, 0)
        ;
        return -1;
      }
    }
    if (nwrite == 0)
    {
      return 0;
    }
    if (wdatalen > 0)
    {
      connection->stream.nwrite += (size_t) wdatalen;
    }
    if (0 != server_send_pkt (connection, buf, (size_t) nwrite,
                              &connection->client_addr,
                              connection->client_addrlen))
      break;
  }
  return 0;
}


int
connection_write (struct connection *connection)
{
  printf ("in connection_write!\n");
  ngtcp2_tstamp expiry, now;
  ev_tstamp t;
  if (0 != write_to_stream (connection))
  {
    return -1;
  }
  expiry = ngtcp2_conn_get_expiry (connection->conn);
  now = timestamp ();

  t = expiry < now ? 1e-9 : (ev_tstamp) (expiry - now) / NGTCP2_SECONDS;

  // printf("t=%lf\n", t);
  connection->timer.repeat = t;
  ev_timer_again (EV_DEFAULT, &connection->timer);

  return 0;
}


void
connection_close (struct connection *connection)
{
  printf ("in connection_close!\n");
  ngtcp2_ssize nwrite;
  ngtcp2_pkt_info pi;
  ngtcp2_path_storage ps;
  uint8_t buf[1280];

  if (ngtcp2_conn_in_closing_period (connection->conn) ||
      ngtcp2_conn_in_draining_period (connection->conn))
  {
    goto fin;
  }

  ngtcp2_path_storage_zero (&ps);

  nwrite = ngtcp2_conn_write_connection_close (
    connection->conn, &ps.path, &pi, buf, sizeof(buf), &connection->last_error,
    timestamp ());
  if (nwrite < 0)
  {
    fprintf (stderr, "ngtcp2_conn_write_connection_close: %s\n",
             ngtcp2_strerror ((int) nwrite));
    goto fin;
  }

  server_send_pkt (connection, buf, (size_t) nwrite,
                   &connection->client_addr, connection->client_addrlen);
fin:
  // ev_break (EV_DEFAULT, EVBREAK_ALL);
}


void
read_cb (struct ev_loop *loop, ev_io *w, int revents)
{
  struct server *s = w->data;
  int ret;
  printf ("num_connections = %d\n", s->num_connections);
  ret = handle_incoming (s);
  if (0 != ret)
  {
    printf ("handle_incoming error!\n");
    return;
  }
  struct connection *connection;
  int i;
  connection = s->connections;
  while (NULL != connection)
  {
    ret = connection_write (connection);
    connection = connection->next;
  }
}


void
write_cb (struct ev_loop *loop, ev_io *w, int revents)
{
  struct server *s = w->data;
  struct connection *connection;
  int ret;
  connection = s->connections;
  while (NULL != connection)
  {
    ret = connection_write (connection);
    connection = connection->next;
  }
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
  s->local_addrlen = local_addrlen;

  server_gnutls_init (s);

  ngtcp2_settings_default (&s->settings);
  s->settings.initial_ts = timestamp ();

  ev_io_init (&s->rev, read_cb, s->fd, EV_READ);
  s->rev.data = s;
  // ev_io_set (&s->rev, s->fd, EV_READ);
  ev_io_start (EV_DEFAULT, &s->rev);


  return 0;
}


int
server_run (struct server *s)
{

  ev_run (EV_DEFAULT, 0);
  return 0;
}


void
connection_free (struct connection *c)
{
  if (NULL == c)
    return;
  if (c->session)
    gnutls_deinit (c->session);
  if (c->conn)
    ngtcp2_conn_del (c->conn);
  if (c->fd >= 0)
    close (c->fd);
}


void
server_free (struct server *s)
{
  gnutls_certificate_free_credentials (s->cred);
  struct connection *tmp, *curr;
  curr = s->connections;
  while (NULL != curr)
  {
    tmp = curr;
    curr = curr->next;
    free (curr);
  }
  s->num_connections = 0;
}


int
main ()
{
  struct server s;

  int ret;
  ret = server_init (&s);
  // printf ("server_init: %d\n", ret);

  ret = server_run (&s);

  server_free (&s);
  return 0;
}