#include <stdint.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <time.h>
#include <unistd.h>
#include <ev.h>

#include <ngtcp2/ngtcp2.h>
#include <ngtcp2/ngtcp2_crypto.h>
#include <ngtcp2/ngtcp2_crypto_gnutls.h>
#include <nghttp3/nghttp3.h>

#include <gnutls/crypto.h>
#include <gnutls/gnutls.h>


#define REMOTE_HOST "127.0.0.1"
#define REMOTE_PORT "5556"
// #define REMOTE_HOST "139.162.123.134"
// #define REMOTE_PORT "4433"
#define ALPN "h3"
// #define ALPN "hq-interop"

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
  nghttp3_conn *h3conn;
  struct Stream *streams;
  size_t nstreams_done_;
  size_t nstreams_;

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
  const gnutls_datum_t alpn = {
    (uint8_t *) ALPN,
    sizeof (ALPN) - 1
  };
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

  gnutls_alpn_set_protocols (c->session, &alpn, 1, GNUTLS_ALPN_MANDATORY);
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

void
connection_remove_stream (struct client *c, int64_t stream_id);

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
client_disconnect (struct client *c)
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


struct Stream*
find_stream (struct client *c, int64_t stream_id)
{
  struct Stream *curr;
  curr = c->streams;
  while (NULL != curr)
  {
    if (curr->stream_id == stream_id)
    {
      return curr;
    }
    curr = curr->next;
  }
  return NULL;
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


  client_write (c);

  return;
}


void
http_consume (struct client *c, int64_t stream_id, size_t consumed)
{
  ngtcp2_conn_extend_max_stream_offset (c->conn, stream_id, consumed);
  ngtcp2_conn_extend_max_offset (c->conn, consumed);
}


int
http_stream_close (nghttp3_conn *conn, int64_t stream_id,
                   uint64_t app_error_code, void *conn_user_data,
                   void *stream_user_data)
{
  struct client *c = conn_user_data;

  if (! ngtcp2_is_bidi_stream (stream_id))
  {
    ngtcp2_conn_extend_max_streams_uni (c->conn, 1);
  }
  else
  {
    // increase closed stream cnt
  }

  if (NULL != find_stream (c, stream_id))
  {
    connection_remove_stream (c, stream_id);
  }

  return 0;
}


int
http_recv_data (nghttp3_conn *conn, int64_t stream_id, const uint8_t *data,
                size_t datalen, void *user_data, void *stream_user_data)
{
  fprintf (stdout, "http_recv_data\n");
  struct client *c = user_data;
  printf ("datalen = %lu\n", datalen);
  char *str = (char *) malloc (datalen + 1);
  memcpy (str, data, datalen);
  str[datalen] = 0;
  printf ("%s\n", str);
  http_consume (c, stream_id, datalen);
  // write data to file.

  return 0;
}


int
http_deferred_consume (nghttp3_conn *conn, int64_t stream_id,
                       size_t nconsumed, void *user_data,
                       void *stream_user_data)
{
  struct client *c = user_data;
  http_consume (c, stream_id, nconsumed);

  return 0;
}


int
http_stop_sending (nghttp3_conn *conn, int64_t stream_id,
                   uint64_t app_error_code, void *user_data,
                   void *stream_user_data)
{
  struct client *c = user_data;
  int rv;

  rv = ngtcp2_conn_shutdown_stream_read (c->conn, 0, stream_id, app_error_code);
  if (0 != rv)
  {
    fprintf (stderr, "ngtcp2_conn_shutdown_stream_read: %s\n",
             ngtcp2_strerror (rv));
    return NGHTTP3_ERR_CALLBACK_FAILURE;
  }
  return 0;
}


int
http_reset_stream (nghttp3_conn *conn, int64_t stream_id,
                   uint64_t app_error_code, void *user_data,
                   void *stream_user_data)
{
  struct client *c = user_data;
  int rv;

  rv = ngtcp2_conn_shutdown_stream_write (c->conn, 0, stream_id,
                                          app_error_code);
  if (0 != rv)
  {
    fprintf (stderr, "ngtcp2_conn_shutdown_stream_write: %s\n",
             ngtcp2_strerror (rv));
    return NGHTTP3_ERR_CALLBACK_FAILURE;
  }
  return 0;
}


int
http_recv_header (nghttp3_conn *conn, int64_t stream_id, int32_t token,
                  nghttp3_rcbuf *name, nghttp3_rcbuf *value, uint8_t flags,
                  void *user_data, void *stream_user_data)
{
  nghttp3_vec namebuf = nghttp3_rcbuf_get_buf (name);
  nghttp3_vec valbuf = nghttp3_rcbuf_get_buf (value);

  fprintf (stdout, "http header: [%.*s: %.*s]\n",
           (int) namebuf.len, namebuf.base, (int) valbuf.len, valbuf.base);

  return 0;
}


int
setup_httpconn (struct client *c)
{
  if (NULL != c->h3conn)
  {
    return 0;
  }

  if (ngtcp2_conn_get_streams_uni_left (c->conn) < 3)
  {
    fprintf (stderr, "uni stream left less than 3!\n");
    return -1;
  }

  nghttp3_callbacks callbacks = {
    .stream_close = http_stream_close,
    .recv_data = http_recv_data,
    .deferred_consume = http_deferred_consume,
    .stop_sending = http_stop_sending,
    .reset_stream = http_reset_stream,
    .recv_header = http_recv_header,
  };
  nghttp3_settings settings;
  const nghttp3_mem *mem = nghttp3_mem_default ();
  int64_t ctrl_stream_id;
  int64_t enc_stream_id;
  int64_t dec_stream_id;
  int rv;

  nghttp3_settings_default (&settings);
  settings.qpack_max_dtable_capacity = 4096;
  settings.qpack_blocked_streams = 100;

  rv = nghttp3_conn_client_new (&c->h3conn, &callbacks, &settings, mem, c);
  if (0 != rv)
  {
    fprintf (stderr, "nghttp3_conn_client_new: %s\n", nghttp3_strerror (rv));
    return -1;
  }

  rv = ngtcp2_conn_open_uni_stream (c->conn, &ctrl_stream_id, NULL);
  if (0 != rv)
  {
    fprintf (stderr, "ngtcp2_conn_open_uni_stream: %s\n", ngtcp2_strerror (rv));
    return -1;
  }

  rv = nghttp3_conn_bind_control_stream (c->h3conn, ctrl_stream_id);
  if (0 != rv)
  {
    fprintf (stderr, "nghttp3_conn_bind_control_stream: %s\n",
             nghttp3_strerror (rv));
    return -1;
  }

  rv = ngtcp2_conn_open_uni_stream (c->conn, &enc_stream_id, NULL);
  if (0 != rv)
  {
    fprintf (stderr, "ngtcp2_conn_open_uni_stream: %s\n", ngtcp2_strerror (rv));
    return -1;
  }

  rv = ngtcp2_conn_open_uni_stream (c->conn, &dec_stream_id, NULL);
  if (0 != rv)
  {
    fprintf (stderr, "ngtcp2_conn_open_uni_stream: %s\n", ngtcp2_strerror (rv));
    return -1;
  }

  rv = nghttp3_conn_bind_qpack_streams (c->h3conn,
                                        enc_stream_id, dec_stream_id);
  if (0 != rv)
  {
    fprintf (stderr, "nghttp3_conn_bind_qpack_streams: %s\n",
             nghttp3_strerror (rv));
    return -1;
  }

  fprintf (stdout, "ctrl stream: %ld, enc stream: %ld, dec stream: %ld\n",
           ctrl_stream_id, enc_stream_id, dec_stream_id);
  return 0;
}


int
client_submit_requests (struct client *c, int64_t stream_id);


int
handshake_completed_cb (ngtcp2_conn *conn, void *user_data)
{
  printf ("=====handshake_ok!=====\n");
  return 0;
}


int
extend_max_local_streams_bidi_cb (ngtcp2_conn *conn, uint64_t max_streams,
                                  void *user_data)
{
  struct client *c = user_data;
  struct Stream *stream;

  for (; c->nstreams_done_ < c->nstreams_; c->nstreams_done_ += 1)
  {
    stream = create_stream (c, -1);
    ngtcp2_conn_open_bidi_stream (c->conn, &stream->stream_id, NULL);
    client_submit_requests (c, stream->stream_id);
  }
  return 0;
}


int
recv_rx_key_cb (ngtcp2_conn *conn, ngtcp2_encryption_level level,
                void *user_data)
{
  if (NGTCP2_ENCRYPTION_LEVEL_1RTT != level)
  {
    return 0;
  }

  struct client *c = user_data;
  int rv;

  rv = setup_httpconn (c);
  if (0 != rv)
  {
    return NGTCP2_ERR_CALLBACK_FAILURE;
  }
  return 0;
}


int
recv_stream_data_cb (ngtcp2_conn *conn, uint32_t flags, int64_t stream_id,
                     uint64_t offset, const uint8_t *data, size_t datalen,
                     void *user_data,
                     void *stream_user_data)
{
  nghttp3_ssize nconsumed;
  struct client *c = user_data;

  nconsumed = nghttp3_conn_read_stream (c->h3conn, stream_id, data, datalen,
                                        flags & NGTCP2_STREAM_DATA_FLAG_FIN);
  printf ("recv_stream_data_cb: id = %ld, len = %lu, consumed = %ld\n",
          stream_id, datalen, nconsumed);
  if (nconsumed < 0)
  {
    fprintf (stderr, "nghttp3_conn_read_stream: %s\n",
             nghttp3_strerror (nconsumed));
    ngtcp2_ccerr_set_application_error (
      &c->last_error,
      nghttp3_err_infer_quic_app_error_code (nconsumed), NULL, 0);
    return NGTCP2_ERR_CALLBACK_FAILURE;
  }

  http_consume (c, stream_id, nconsumed);

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
extend_max_stream_data_cb (ngtcp2_conn *conn, int64_t stream_id,
                           uint64_t max_data, void *user_data,
                           void *stream_user_data)
{
  struct client *c = user_data;
  int rv;

  rv = nghttp3_conn_unblock_stream (c->h3conn, stream_id);
  if (0 != rv)
  {
    fprintf (stderr, "nghttp3_conn_unblock_stream: %s\n",
             nghttp3_strerror (rv));
    return NGTCP2_ERR_CALLBACK_FAILURE;
  }
  return 0;
}


int
stream_reset_cb (ngtcp2_conn *conn, int64_t stream_id, uint64_t final_size,
                 uint64_t app_error_code, void *user_data,
                 void *stream_user_data)
{
  struct client *c = user_data;
  int rv;

  if (c->h3conn)
  {
    rv = nghttp3_conn_shutdown_stream_read (c->h3conn, stream_id);
    if (0 != rv)
    {
      fprintf (stderr, "nghttp3_conn_shutdown_stream_read: %s\n",
               nghttp3_strerror (rv));
      return NGTCP2_ERR_CALLBACK_FAILURE;
    }
  }
  return 0;
}


int
stream_stop_sending_cb (ngtcp2_conn *conn, int64_t stream_id,
                        uint64_t app_error_code, void *user_data,
                        void *stream_user_data)
{
  struct client *c = user_data;
  int rv;

  if (c->h3conn)
  {
    rv = nghttp3_conn_shutdown_stream_read (c->h3conn, stream_id);
    if (0 != rv)
    {
      fprintf (stderr, "nghttp3_conn_shutdown_stream_read: %s\n",
               nghttp3_strerror (rv));
      return NGTCP2_ERR_CALLBACK_FAILURE;
    }
  }
  return 0;
}


int
acked_stream_data_offset_cb (ngtcp2_conn *conn, int64_t stream_id,
                             uint64_t offset, uint64_t datalen, void *user_data,
                             void *stream_user_data)
{
  struct client *c = user_data;
  int rv;

  rv = nghttp3_conn_add_ack_offset (c->h3conn, stream_id, datalen);
  if (0 != rv)
  {
    fprintf (stderr, "nghttp3_conn_add_ack_offset: %s\n",
             nghttp3_strerror (rv));
    return NGTCP2_ERR_CALLBACK_FAILURE;
  }
  return 0;
}


int
client_on_stream_close (struct client *c, int64_t stream_id,
                        uint64_t app_error_code)
{
  int rv;

  if (c->h3conn)
  {
    if (0 == app_error_code)
    {
      app_error_code = NGHTTP3_H3_NO_ERROR;
    }
    rv = nghttp3_conn_close_stream (c->h3conn, stream_id, app_error_code);
    switch (rv)
    {
    case 0:
      break;
    case NGHTTP3_ERR_STREAM_NOT_FOUND:
      if (! ngtcp2_is_bidi_stream (stream_id))
      {
        ngtcp2_conn_extend_max_streams_uni (c->conn, 1);
      }
      break;
    default:
      fprintf (stderr, "nghttp3_conn_close_stream: %s\n",
               nghttp3_strerror (rv));
      ngtcp2_ccerr_set_application_error (
        &c->last_error,
        nghttp3_err_infer_quic_app_error_code (rv),
        NULL, 0);
      return -1;
    }
  }

  return 0;
}


int
stream_close_cb (ngtcp2_conn *conn, uint32_t flags, int64_t stream_id,
                 uint64_t app_error_code, void *user_data,
                 void *stream_user_data)
{
  printf ("stream_close id = %ld\n", stream_id);
  struct client *c = user_data;
  int rv;

  if (! (flags & NGTCP2_STREAM_CLOSE_FLAG_APP_ERROR_CODE_SET))
  {
    app_error_code = NGHTTP3_H3_NO_ERROR;
  }
  rv = client_on_stream_close (c, stream_id, app_error_code);
  if (0 != rv)
  {
    return NGTCP2_ERR_CALLBACK_FAILURE;
  }
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

    .acked_stream_data_offset = acked_stream_data_offset_cb,
    .recv_stream_data = recv_stream_data_cb,
    .rand = rand_cb,
    .get_new_connection_id = get_new_connection_id_cb,
    .handshake_completed = handshake_completed_cb,
    .stream_close = stream_close_cb,
    .extend_max_local_streams_bidi = extend_max_local_streams_bidi_cb,
    .extend_max_stream_data = extend_max_stream_data_cb,
    .stream_reset = stream_reset_cb,
    .stream_stop_sending = stream_stop_sending_cb,
    .recv_rx_key = recv_rx_key_cb,
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
  // settings.log_printf = log_printf;

  ngtcp2_transport_params_default (&params);
  params.initial_max_streams_uni = 100;
  params.initial_max_stream_data_bidi_local = 6291456;
  params.initial_max_data = 15728640;
  params.initial_max_stream_data_bidi_remote = 0;
  params.initial_max_stream_data_uni = 6291456;
  params.initial_max_streams_bidi = 0;
  params.max_idle_timeout = 30 * NGTCP2_SECONDS;
  params.active_connection_id_limit = 7;
  params.grease_quic_bit = 1;

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
feed_data (struct client *c, struct sockaddr *sa, socklen_t salen,
           const ngtcp2_pkt_info *pi, const uint8_t *data, size_t datalen)
{
  ngtcp2_path path;
  int rv;

  path.local.addr = &c->client_addr;
  path.local.addrlen = c->client_addrlen;
  path.remote.addr = sa;
  path.remote.addrlen = salen;

  rv = ngtcp2_conn_read_pkt (c->conn, &path, pi, data, datalen, timestamp ());
  if (0 != rv)
  {
    fprintf (stderr, "ngtcp2_conn_read_pkt: %s\n",
             ngtcp2_strerror (rv));
    if (! c->last_error.error_code)
    {
      if (NGTCP2_ERR_CRYPTO == rv)
      {
        ngtcp2_ccerr_set_tls_alert (
          &c->last_error, ngtcp2_conn_get_tls_alert (c->conn), NULL, 0);
      }
      else
      {
        ngtcp2_ccerr_set_liberr (&c->last_error, rv, NULL, 0);
      }
    }
    client_disconnect (c);
    return -1;
  }
  return 0;
}


void
update_timer (struct client *c)
{
  ngtcp2_tstamp expiry;
  ngtcp2_tstamp now;
  ev_tstamp t;

  expiry = ngtcp2_conn_get_expiry (c->conn);
  now = timestamp ();
  if (expiry <= now)
  {
    t = (ev_tstamp) (now - expiry) / NGTCP2_SECONDS;
    fprintf (stderr, "Timer expired: %lfs\n", t);

    ev_feed_event (EV_DEFAULT, &c->timer, EV_TIMER);
    return;
  }
  t = (ev_tstamp) (expiry - now) / NGTCP2_SECONDS;
  fprintf (stderr, "Set timer = %lfs\n", t);
  c->timer.repeat = t;
  ev_timer_again (EV_DEFAULT, &c->timer);
}


int
on_read (struct client *c)
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

    int ret;
    ret = feed_data (c, (struct sockaddr *) msg.msg_name, msg.msg_namelen, &pi,
                     buf, nread);
    if (0 != ret)
    {
      return -1;
    }

  }
  update_timer (c);
  return 0;
}


nghttp3_nv
make_nv (const uint8_t *name, size_t namelen,
         const uint8_t *value, size_t valuelen,
         uint8_t flags)
{
  nghttp3_nv nv = {
    name, value, namelen, valuelen, flags
  };
  return nv;
}


int
client_submit_requests (struct client *c, int64_t stream_id)
{
  nghttp3_nv nva[6] = {
    make_nv ((const uint8_t *) ":method", sizeof (":method") - 1,
             (const uint8_t *) "GET", sizeof ("GET") - 1,
             NGHTTP3_NV_FLAG_NO_COPY_NAME | NGHTTP3_NV_FLAG_NO_COPY_VALUE),
    make_nv ((const uint8_t *) ":scheme", sizeof (":scheme") - 1,
             (const uint8_t *) "https", sizeof ("https") - 1,
             NGHTTP3_NV_FLAG_NO_COPY_NAME | NGHTTP3_NV_FLAG_NO_COPY_VALUE),
    make_nv ((const uint8_t *) ":authority", sizeof (":authority") - 1,
             (const uint8_t *) "127.0.0.1:5556", sizeof ("127.0.0.1:5556") - 1,
             //  (const uint8_t *) "nghttp2.org", sizeof ("nghttp2.org") - 1,
             NGHTTP3_NV_FLAG_NO_COPY_NAME | NGHTTP3_NV_FLAG_NO_COPY_VALUE),
    make_nv ((const uint8_t *) ":path", sizeof (":path") - 1,
             (const uint8_t *) "/", sizeof ("/") - 1,
             NGHTTP3_NV_FLAG_NO_COPY_NAME | NGHTTP3_NV_FLAG_NO_COPY_VALUE),
    make_nv ((const uint8_t *) "user-agent", sizeof ("user-agent") - 1,
             (const uint8_t *) "nghttp3/ngtcp2 client",
             sizeof ("nghttp3/ngtcp2 client") - 1,
             NGHTTP3_NV_FLAG_NO_COPY_NAME | NGHTTP3_NV_FLAG_NO_COPY_VALUE),
  };
  int rv;

  rv = nghttp3_conn_submit_request (c->h3conn, stream_id, nva, 5, NULL, NULL);
  if (0 != rv)
  {
    fprintf (stderr, "nghttp3_conn_submit_request: %s\n",
             nghttp3_strerror (rv));
    return -1;
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
  ngtcp2_ssize nwrite;
  ngtcp2_ssize wdatalen;
  ngtcp2_pkt_info pi;
  nghttp3_vec vec[16];
  nghttp3_ssize sveccnt;
  int fin;
  int rv;

  ngtcp2_path_storage_zero (&ps);

  for (;;)
  {
    stream_id = -1;
    fin = 0;
    sveccnt = 0;
    if (c->h3conn && ngtcp2_conn_get_max_data_left (c->conn))
    {
      sveccnt = nghttp3_conn_writev_stream (c->h3conn,
                                            &stream_id, &fin, vec, 16);
      if (sveccnt < 0)
      {
        fprintf (stderr, "nghttp3_conn_writev_stream: %s\n",
                 nghttp3_strerror (sveccnt));
        ngtcp2_ccerr_set_application_error (
          &c->last_error,
          nghttp3_err_infer_quic_app_error_code (sveccnt),
          NULL, 0);
        client_disconnect (c);
        return -1;
      }
    }

    flags = NGTCP2_WRITE_STREAM_FLAG_MORE;
    if (fin)
      flags |= NGTCP2_WRITE_STREAM_FLAG_FIN;

    nwrite = ngtcp2_conn_writev_stream (c->conn, &ps.path, &pi, buf,
                                        sizeof(buf),
                                        &wdatalen, flags, stream_id,
                                        (ngtcp2_vec *) vec,
                                        (size_t) sveccnt, ts);

    if (nwrite < 0)
    {
      switch (nwrite)
      {
      case NGTCP2_ERR_STREAM_DATA_BLOCKED:
        nghttp3_conn_block_stream (c->h3conn, stream_id);
        continue;
      case NGTCP2_ERR_STREAM_SHUT_WR:
        nghttp3_conn_shutdown_stream_write (c->h3conn, stream_id);
        continue;
      case NGTCP2_ERR_WRITE_MORE:
        // nghttp3 write offset
        // ngtcp2 set application error
        // stream->sent_offset += (size_t) wdatalen;
        rv = nghttp3_conn_add_write_offset (c->h3conn, stream_id, wdatalen);
        if (0 != rv)
        {
          fprintf (stderr, "nghttp3_conn_add_write_offset: %s\n",
                   nghttp3_strerror (rv));
          ngtcp2_ccerr_set_application_error (
            &c->last_error, nghttp3_err_infer_quic_app_error_code (rv),
            NULL, 0);
          client_disconnect (c);
          return -1;
        }
        continue;
      }

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
      // stream->sent_offset += (size_t) wdatalen;
      rv = nghttp3_conn_add_write_offset (c->h3conn, stream_id, wdatalen);
      if (0 != rv)
      {
        fprintf (stderr, "nghttp3_conn_add_write_offset: %s\n",
                 nghttp3_strerror (rv));
        ngtcp2_ccerr_set_application_error (
          &c->last_error,
          nghttp3_err_infer_quic_app_error_code (rv),
          NULL, 0);
        client_disconnect (c);
        return -1;
      }
    }
    if (client_send_pkt (c, buf, (size_t) nwrite) != 0)
      break;
  }
  return 0;
}


int
client_write (struct client *c)
{
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

  update_timer (c);

  return 0;
}


void
client_close (struct client *c)
{
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
  struct client *c = w->data;
  int rv;

  rv = on_read (c);
  if (0 != rv)
  {
    return;
  }
  if (client_write (c) != 0)
  {
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
  struct client *c = w->data;
  int rv;

  rv = handle_expiry (c);
  if (0 != rv)
  {
    return;
  }
  client_write (c);
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
  memcpy (&c->client_addr, &client_addr, len);
  c->client_addrlen = len;

  ret = client_gnutls_init (c);

  ret = client_quic_init (c, (struct sockaddr*) &client_addr,
                          sizeof(client_addr),
                          (struct sockaddr*) &server_addr, sizeof(server_addr));

  c->streams = NULL;

  c->conn_ref.user_data = c;
  c->conn_ref.get_conn = get_conn;


  ev_io_init (&c->rev, read_cb, c->fd, EV_READ);
  c->rev.data = c;
  ev_io_start (EV_DEFAULT, &c->rev);


  ev_timer_init (&c->timer, timer_cb, 0., 0.);
  c->timer.data = c;
  c->nstreams_ = 1;
  c->nstreams_done_ = 0;

  return 0;
}


void
client_free (struct client *c)
{
  stream_free (c);
  ngtcp2_conn_del (c->conn);
  nghttp3_conn_del (c->h3conn);
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

  ret = client_write (&c);

  ev_run (EV_DEFAULT, 0);

  client_free (&c);
  return 0;
}