#include <stdint.h>
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


#define REMOTE_HOST "127.0.0.1"
#define REMOTE_PORT "5556"
#define ALPN "hq-interop"

uint64_t
timestamp (void)
{
  struct timespec tp;

  clock_gettime (CLOCK_MONOTONIC, &tp);

  return (uint64_t) tp.tv_sec * NGTCP2_SECONDS + (uint64_t) tp.tv_nsec;
}


struct Stream
{

  int64_t stream_id;

  uint8_t *data;
  uint64_t datalen;

  uint32_t sent_offset;
  uint32_t ack_offset;

  struct Stream *next;
};


struct client
{
  gnutls_session_t session;
  gnutls_certificate_credentials_t cred;
  int fd;
  struct sockaddr client_addr;
  socklen_t client_addrlen;
  ngtcp2_crypto_conn_ref conn_ref;
  ngtcp2_conn *conn;
  struct Stream *streams;

  ngtcp2_ccerr last_error;
  ev_timer timer;
  ev_io rev;
  ev_io input;
};

static const char priority[] =
  "NORMAL:-VERS-ALL:+VERS-TLS1.3:-CIPHER-ALL:+AES-128-GCM:+AES-256-GCM:"
  "+CHACHA20-POLY1305:+AES-128-CCM:-GROUP-ALL:+GROUP-SECP256R1:+GROUP-X25519:"
  "+GROUP-SECP384R1:"
  "+GROUP-SECP521R1:%DISABLE_TLS13_COMPAT_MODE";

int
client_gnutls_init (struct client *c)
{
  gnutls_certificate_allocate_credentials (&c->cred);
  gnutls_certificate_set_x509_system_trust (c->cred);
  gnutls_init (&c->session, GNUTLS_CLIENT | GNUTLS_ENABLE_EARLY_DATA
               | GNUTLS_NO_END_OF_EARLY_DATA);
// 这个和quic-echo中的 setup_gnutls_for_quic函数应该是相同的作用
// 用在server的也有，函数名不一样
  ngtcp2_crypto_gnutls_configure_client_session (c->session);

  gnutls_priority_set_direct (c->session, priority, NULL);
  gnutls_session_set_ptr (c->session, &c->conn_ref);
  gnutls_credentials_set (c->session, GNUTLS_CRD_CERTIFICATE, c->cred);

  gnutls_server_name_set (c->session, GNUTLS_NAME_DNS,
                          "localhost", strlen ("localhost"));
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


void
client_close (struct client *c);

int
client_write (struct client *c);

int
client_send_pkt (struct client *c, unsigned char *data, size_t datalen);


int
handle_error (struct client *c)
{
  uint8_t buf[1200];
  ngtcp2_path_storage ps;
  ngtcp2_pkt_info pi;
  ngtcp2_ssize nwrite;
  int rv;

  if (! c->conn ||
      ngtcp2_conn_in_closing_period (c->conn) ||
      ngtcp2_conn_in_draining_period (c->conn))
  {
    return 0;
  }

  ngtcp2_path_storage_zero (&ps);
  nwrite = ngtcp2_conn_write_connection_close (c->conn,
                                               &ps.path,
                                               &pi,
                                               buf,
                                               1200,
                                               &c->last_error,
                                               timestamp ());
  if (nwrite < 0)
  {
    fprintf (stderr, "ngtcp2_conn_write_connection_close: %s\n",
             ngtcp2_strerror (nwrite));
    return -1;
  }
  if (0 == nwrite)
  {
    return 0;
  }
  rv = client_send_pkt (c, buf, nwrite);
  return rv;
}


void
client_disconnect (struct client*c)
{
  handle_error (c);

  ev_timer_stop (EV_DEFAULT, &c->timer);
  ev_io_stop (EV_DEFAULT, &c->rev);
  ev_io_stop (EV_DEFAULT, &c->input);
}


struct Stream*
create_stream (struct client *c, int64_t id)
{
  struct Stream *new_stream = NULL;
  new_stream = (struct Stream*) malloc (sizeof (struct Stream));
  memset (new_stream, 0, sizeof (struct Stream));
  new_stream->stream_id = id;
  new_stream->next = c->streams;
  c->streams = new_stream;
  return new_stream;
}


void
stream_free (struct client *c)
{
  struct Stream *tmp, *curr;
  curr = c->streams;
  while (NULL != curr)
  {
    tmp = curr;
    curr = curr->next;
    free (curr);
  }
}


void
stdin_cb (struct ev_loop *loop, ev_io *w, int revents)
{
  // printf ("getstdin!\n");

  struct client *c = w->data;
  char buf[1024];
  ssize_t nread = 0;
  struct Stream *stream;

  stream = create_stream (c, -1);
  nread = read (0, buf, sizeof(buf));

  ngtcp2_conn_open_bidi_stream (c->conn, &stream->stream_id, NULL);
  stream->data = (uint8_t *) buf;
  stream->datalen = nread;

  // if (c->stream.stream_id == -1)
  // {
  //   int64_t stream_id;
  //   ngtcp2_conn_open_bidi_stream (c->conn, &stream_id, NULL);
  //   c->stream.stream_id = stream_id;
  // }

  // c->stream.data = buf;
  // c->stream.datalen = nread;
  // c->stream.nwrite = 0;
  client_write (c);

  return;
}


int
handshake_completed_cb (ngtcp2_conn *conn, void *user_data)
{
  printf ("=====handshake_ok!=====\n");
  struct client *c = user_data;
  ev_io_init (&c->input, stdin_cb, 0, EV_READ);
  c->input.data = c;
  ev_io_start (EV_DEFAULT, &c->input);
  return 0;
}


int
recv_stream_data_cb (ngtcp2_conn *conn, uint32_t flags, int64_t stream_id,
                     uint64_t offset, const uint8_t *data, size_t datalen,
                     void *user_data,
                     void *stream_user_data)
{

  ngtcp2_conn_extend_max_stream_offset (conn, stream_id, datalen);
  ngtcp2_conn_extend_max_offset (conn, datalen);
  char buf[256] = "recv_data:";
  memcpy (buf + 10, data, datalen);
  buf[10 + datalen] = 0;
  write (1, buf, 10 + datalen);

  return 0;
}


void
connection_remove_stream (struct client *c, int64_t stream_id)
{
  struct Stream *curr = c->streams;
  struct Stream *tmp;
  if (NULL == curr)
    return;
  if (curr->stream_id == stream_id)
  {
    c->streams = curr->next;
    free (curr);
    return;
  }
  while (NULL != curr)
  {
    if (curr->stream_id == stream_id)
    {
      tmp->next = curr->next;
      free (curr);
      return;
    }
    tmp = curr;
    curr = curr->next;
  }
}


int
stream_close_cb (ngtcp2_conn *conn, uint32_t flags, int64_t stream_id,
                 uint64_t app_error_code, void *user_data,
                 void *stream_user_data)
{
  printf ("stream_close id = %ld\n", stream_id);
  struct client *c = user_data;
  connection_remove_stream (c, stream_id);
  int i = 0;
  struct Stream *s;
  for (s = c->streams; s; s = s->next)
  {
    i += 1;
  }
  printf ("streams cnt = %d\n", i);
  return 0;
}


void
log_printf (void *user_data, const char *fmt, ...)
{
  va_list ap;
  (void) user_data;

  va_start (ap, fmt);
  vfprintf (stderr, fmt, ap);
  va_end (ap);

  fprintf (stderr, "\n");
}


int
client_quic_init (struct client *c, struct sockaddr *client_addr,
                  socklen_t client_addrlen,struct sockaddr *server_addr,
                  socklen_t server_addrlen)
{
  ngtcp2_path path = {
    {(struct sockaddr*) client_addr, client_addrlen},
    {(struct sockaddr*) server_addr, server_addrlen},
    NULL,
  };
  ngtcp2_callbacks callbacks = {
    .client_initial = ngtcp2_crypto_client_initial_cb,
    .recv_crypto_data = ngtcp2_crypto_recv_crypto_data_cb,
    .encrypt = ngtcp2_crypto_encrypt_cb,
    .decrypt = ngtcp2_crypto_decrypt_cb,
    .hp_mask = ngtcp2_crypto_hp_mask_cb,
    .recv_retry = ngtcp2_crypto_recv_retry_cb,
    .update_key = ngtcp2_crypto_update_key_cb,
    .delete_crypto_aead_ctx = ngtcp2_crypto_delete_crypto_aead_ctx_cb,
    .delete_crypto_cipher_ctx = ngtcp2_crypto_delete_crypto_cipher_ctx_cb,
    .get_path_challenge_data = ngtcp2_crypto_get_path_challenge_data_cb,
    .version_negotiation = ngtcp2_crypto_version_negotiation_cb,

    // .acked_stream_data_offset = acked_stream_data_offset_cb,
    .recv_stream_data = recv_stream_data_cb,
    .rand = rand_cb,
    .get_new_connection_id = get_new_connection_id_cb,
    .handshake_completed = handshake_completed_cb,
    .stream_close = stream_close_cb,
    // .extend_max_local_streams_bidi = extend_max_local_streams_bidi,
  };

  ngtcp2_cid dcid, scid;
  ngtcp2_settings settings;
  ngtcp2_transport_params params;

  unsigned char buf[NGTCP2_MAX_CIDLEN];
  gnutls_rnd (GNUTLS_RND_RANDOM, buf, sizeof(buf));
  ngtcp2_cid_init (&dcid, buf, sizeof(buf));

  gnutls_rnd (GNUTLS_RND_RANDOM, buf, sizeof(buf));
  ngtcp2_cid_init (&scid, buf, sizeof(buf));

  ngtcp2_settings_default (&settings);
  settings.initial_ts = timestamp ();
  // printf("max_tx_udp_payload_size=%ld\n", settings.max_tx_udp_payload_size);
  // settings.log_printf = log_printf;

  ngtcp2_transport_params_default (&params);
  params.initial_max_streams_uni = 3;
  params.initial_max_stream_data_bidi_local = 128 * 1024;
  params.initial_max_data = 1024 * 1024;

  ngtcp2_conn_client_new (&c->conn, &dcid, &scid, &path, NGTCP2_PROTO_VER_V1,
                          &callbacks, &settings, &params, NULL, c);

  ngtcp2_conn_set_tls_native_handle (c->conn, c->session);

  return 0;
}


ngtcp2_conn*
get_conn (ngtcp2_crypto_conn_ref *ref)
{
  return ((struct client*) (ref->user_data))->conn;
}


int
client_send_pkt (struct client *c, unsigned char *data, size_t datalen)
{
  struct iovec iov = {data, datalen};
  struct msghdr msg = {0};
  ssize_t nwrite;

  msg.msg_iov = &iov;
  msg.msg_iovlen = 1;
  do {
    nwrite = sendmsg (c->fd, &msg, 0);
  } while (nwrite == -1 && errno == EINTR);

  if (nwrite == -1)
  {
    return -1;
  }
  return 0;
}


int
client_read (struct client *c)
{
  struct msghdr msg = {0};
  struct sockaddr_storage addr;
  unsigned char buf[65536];
  struct iovec iov = {buf, sizeof(buf)};
  ssize_t nread;
  ngtcp2_path path;
  ngtcp2_pkt_info pi = {0};

  msg.msg_name = &addr;
  msg.msg_iov = &iov;
  msg.msg_iovlen = 1;

  for (;;)
  {
    msg.msg_namelen = sizeof(addr);
    nread = recvmsg (c->fd, &msg, MSG_DONTWAIT);
    if (nread == -1)
    {
      if (errno != EAGAIN && errno != EWOULDBLOCK)
      {
        fprintf (stderr, "recvmsg: %s\n", strerror (errno));
      }
      break;
    }

    path.local.addr = &c->client_addr;
    path.local.addrlen = c->client_addrlen;
    path.remote.addr = msg.msg_name;
    path.remote.addrlen = msg.msg_namelen;

    int ret;
    ret = ngtcp2_conn_read_pkt (c->conn, &path, &pi, buf, nread, timestamp ());
    if (ret != 0)
    {
      fprintf (stderr, "ngtcp2_conn_read_pkt: %s\n", ngtcp2_strerror (ret));
      if (! c->last_error.error_code)
      {
        if (ret == NGTCP2_ERR_CRYPTO)
        {
          ngtcp2_ccerr_set_tls_alert (
            &c->last_error, ngtcp2_conn_get_tls_alert (c->conn), NULL, 0);
        }
        else
        {
          ngtcp2_ccerr_set_liberr (&c->last_error, ret, NULL, 0);
        }
      }
      client_disconnect (c);
      return -1;
    }

  }
  return 0;
}


int
client_write_streams (struct client *c, struct Stream *stream)
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
    if (NULL != stream &&
        stream->sent_offset < stream->datalen)
    {
      stream_id = stream->stream_id;
      fin = 1;
      datav.base = (uint8_t *) stream->data + stream->sent_offset;
      datav.len = stream->datalen - stream->sent_offset;
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
    // if (c->stream.stream_id != -1 &&
    //     c->stream.nwrite < c->stream.datalen)
    // {
    //   stream_id = c->stream.stream_id;
    //   fin = 0;
    //   datav.base = (uint8_t *) c->stream.data + c->stream.nwrite;
    //   datav.len = c->stream.datalen - c->stream.nwrite;
    //   datavcnt = 1;
    // }
    // else
    // {
    //   stream_id = -1;
    //   fin = 0;
    //   datav.base = NULL;
    //   datav.len = 0;
    //   datavcnt = 0;
    // }

    flags = NGTCP2_WRITE_STREAM_FLAG_MORE;
    if (fin)
      flags |= NGTCP2_WRITE_STREAM_FLAG_FIN;

    // printf ("data_left: %lu\n",
    //         ngtcp2_conn_get_max_stream_data_left (c->conn, stream_id));
    // printf ("stream_bidi_left: %lu\n",
    //         ngtcp2_conn_get_streams_bidi_left (c->conn));
    // printf ("connection_data_left: %lu\n",
    //         ngtcp2_conn_get_max_data_left (c->conn));
    nwrite = ngtcp2_conn_writev_stream (c->conn, &ps.path, &pi, buf,
                                        sizeof(buf),
                                        &wdatalen, flags, stream_id, &datav,
                                        datavcnt, ts);

    if (nwrite < 0)
    {
      switch (nwrite)
      {
      case NGTCP2_ERR_STREAM_DATA_BLOCKED:
        // add nghttp3 block stream
        continue;
      case NGTCP2_ERR_STREAM_SHUT_WR:
        // add nghttp3 shutdown stream write
        continue;
      case NGTCP2_ERR_WRITE_MORE:
        // nghttp3 write offset
        // ngtcp2 set application error
        stream->sent_offset += (size_t) wdatalen;
        continue;
      }
      // switch (nwrite)
      // {
      // case NGTCP2_ERR_WRITE_MORE:
      //   // c->stream.nwrite += (size_t) wdatalen;
      //   stream->sent_offset += (size_t) wdatalen;
      //   continue;
      // default:
      //   fprintf (stderr, "ngtcp2_conn_writev_stream: %s\n",
      //            ngtcp2_strerror ((int) nwrite));
      //   ngtcp2_ccerr_set_liberr (&c->last_error, (int) nwrite, NULL, 0);
      //   return -1;
      // }
      printf ("ngtcp2_conn_writev_stream: %s\n",
              ngtcp2_strerror (nwrite));
      ngtcp2_ccerr_set_liberr (&c->last_error,
                               nwrite,
                               NULL,
                               0);
      client_disconnect (c);
      return -1;
    }
    if (nwrite == 0)
    {
      return 0;
    }
    if (wdatalen > 0)
    {
      // c->stream.nwrite += (size_t) wdatalen;
      stream->sent_offset += (size_t) wdatalen;
    }
    if (client_send_pkt (c, buf, (size_t) nwrite) != 0)
      break;
  }
  return 0;
}


int
client_write (struct client *c)
{
  // printf("client_write!\n");
  ngtcp2_tstamp expiry, now;
  ev_tstamp t;
  int rv;
  struct Stream *stream = c->streams;
  if (NULL == stream)
  {
    rv = client_write_streams (c, NULL);
    if (0 != rv)
    {
      return -1;
    }
  }
  for (; stream; stream = stream->next)
  {
    rv = client_write_streams (c, stream);
    if (0 != rv)
    {
      return -1;
    }
  }
  // if (client_write_streams (c) != 0)
  // {
  //   return -1;
  // }
  expiry = ngtcp2_conn_get_expiry (c->conn);
  now = timestamp ();

  t = expiry < now ? 1e-9 : (ev_tstamp) (expiry - now) / NGTCP2_SECONDS;

  // printf("t=%lf\n", t);
  c->timer.repeat = t;
  ev_timer_again (EV_DEFAULT, &c->timer);

  return 0;
}


void
client_close (struct client *c)
{
  // printf ("client_close!\n");
  ngtcp2_ssize nwrite;
  ngtcp2_pkt_info pi;
  ngtcp2_path_storage ps;
  uint8_t buf[1280];

  if (ngtcp2_conn_in_closing_period (c->conn) ||
      ngtcp2_conn_in_draining_period (c->conn))
  {
    goto fin;
  }

  ngtcp2_path_storage_zero (&ps);

  nwrite = ngtcp2_conn_write_connection_close (
    c->conn, &ps.path, &pi, buf, sizeof(buf), &c->last_error, timestamp ());
  if (nwrite < 0)
  {
    fprintf (stderr, "ngtcp2_conn_write_connection_close: %s\n",
             ngtcp2_strerror ((int) nwrite));
    goto fin;
  }

  client_send_pkt (c, buf, (size_t) nwrite);
fin:
  ev_break (EV_DEFAULT, EVBREAK_ALL);
}


void
read_cb (struct ev_loop *loop, ev_io *w, int revents)
{
  // fprintf (stdout, "read_cb\n");
  struct client *c = w->data;
  if (client_read (c) != 0)
  {
    // fprintf (stdout, "client_read!=0\n");
    client_close (c);
    return;
  }
  if (client_write (c) != 0)
  {
    // fprintf (stdout, "client_write!=0\n");
    client_close (c);
  }
}


int
handle_expiry (struct client *c)
{
  ngtcp2_tstamp now;
  int rv;

  now = timestamp ();
  rv = ngtcp2_conn_handle_expiry (c->conn, now);
  if (0 != rv)
  {
    fprintf (stderr, "ngtcp2_conn_handle_expiry: %s\n",
             ngtcp2_strerror (rv));
    ngtcp2_ccerr_set_liberr (&c->last_error, rv, NULL, 0);
    client_disconnect (c);
    return -1;
  }
  return 0;
}


void
timer_cb (struct ev_loop *loop, ev_timer *w, int revents)
{
  // fprintf (stdout, "timer_cb\n");
  struct client *c = w->data;
  int rv;

  rv = handle_expiry (c);
  if (0 != rv)
  {
    // fprintf (stdout, "ngtcp2_conn_handle_expiry!=0\n");
    // client_close (c);
    return;
  }
  if (client_write (c) != 0)
  {
    // fprintf (stdout, "client_write!=0\n");
    // client_close (c);
  }
}


int
client_init (struct client *c)
{
  struct sockaddr_in server_addr, client_addr;
  int ret;
  memset (c, 0, sizeof(*c));
  c->fd = socket (AF_INET, SOCK_DGRAM, 0);
  if (c->fd == -1)
  {
    return -1;
  }
  server_addr.sin_family = AF_INET;
  server_addr.sin_addr.s_addr = inet_addr (REMOTE_HOST);
  server_addr.sin_port = htons (atoi (REMOTE_PORT));

  ret = connect (c->fd, (struct sockaddr*) &server_addr, sizeof(server_addr));
  if (ret != 0)
  {
    return -1;
  }

  /* len 需要先赋值，要不getsockname获取不到 */
  socklen_t len = sizeof(client_addr);
  ret = getsockname (c->fd, (struct sockaddr*) &client_addr, &len);
  // printf("getsockname:ret=%d\n", ret);
  memcpy (&c->client_addr, &client_addr, len);
  c->client_addrlen = len;

  ret = client_gnutls_init (c);
  // printf ("client_gnutls_init:ret=%d\n", ret);

  ret = client_quic_init (c, (struct sockaddr*) &client_addr,
                          sizeof(client_addr),
                          (struct sockaddr*) &server_addr, sizeof(server_addr));
  // printf ("client_quic_init:ret=%d\n", ret);

  // c->stream.stream_id = -1;
  c->streams = NULL;

  c->conn_ref.user_data = c;
  c->conn_ref.get_conn = get_conn;


  ev_io_init (&c->rev, read_cb, c->fd, EV_READ);
  c->rev.data = c;
  ev_io_start (EV_DEFAULT, &c->rev);


  ev_timer_init (&c->timer, timer_cb, 0., 0.);
  c->timer.data = c;

  return 0;
}


void
client_free (struct client *c)
{
  stream_free (c);
  ngtcp2_conn_del (c->conn);
  gnutls_deinit (c->session);
  gnutls_certificate_free_credentials (c->cred);
  client_disconnect (c);
}


int
main (int argc, char **argv)
{
  struct client c;
  int ret;
  ret = client_init (&c);
  // printf ("init_ret=%d\n", ret);

  ret = client_write (&c);
  // printf ("write_ret=%d\n", ret);

  ev_run (EV_DEFAULT, 0);

  client_free (&c);
  return 0;
}