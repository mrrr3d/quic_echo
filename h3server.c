#include <bits/types/struct_iovec.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>
#include <ev.h>

#include <ngtcp2/ngtcp2.h>
#include <ngtcp2/ngtcp2_crypto.h>
#include <ngtcp2/ngtcp2_crypto_gnutls.h>
#include <nghttp3/nghttp3.h>

#include <gnutls/crypto.h>
#include <gnutls/gnutls.h>

#define LOCAL_HOST "127.0.0.1"
#define LOCAL_PORT "5556"
#define NGTCP2_SERVER "nghttp3/ngtcp2 server"

struct server;
struct connection;

struct Stream
{

  int64_t stream_id;

  uint8_t *data;
  uint64_t datalen;

  uint32_t sent_offset;
  uint32_t ack_offset;

  struct Stream *next;
  struct connection *connection;

  uint8_t *uri;
  size_t urilen;
  uint8_t *method;
  size_t methodlen;
  uint8_t *authority;
  size_t authoritylen;
  uint8_t *status_resp_body;
  size_t status_resp_bodylen;
};

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
  nghttp3_conn *h3conn;

  struct Stream *streams;
  uint8_t conn_close_buf[1280];
  ngtcp2_ssize conn_close_buflen;
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

enum network_error
{
  NETWORK_ERR_OK = 0,
  NETWORK_ERR_FATAL = -10,
  NETWORK_ERR_SEND_BLOCKED = -11,
  NETWORK_ERR_CLOSE_WAIT = -12,
  NETWORK_ERR_RETRY = -13,
  NETWORK_ERR_DROP_CONN = -14,
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


void
server_gnutls_init (struct server *s)
{
  s->cred = NULL;
  gnutls_certificate_allocate_credentials (&s->cred);
  gnutls_certificate_set_x509_key_file (s->cred,
                                        "credentials/server.pem",
                                        "credentials/server-key.pem",
                                        GNUTLS_X509_FMT_PEM);

}


struct Stream*
create_stream (struct connection *c, int64_t id)
{
  struct Stream *new_stream = NULL;
  new_stream = (struct Stream*) malloc (sizeof (struct Stream));
  memset (new_stream, 0, sizeof (struct Stream));
  new_stream->stream_id = id;
  new_stream->next = c->streams;
  c->streams = new_stream;
  new_stream->connection = c;
  return new_stream;
}


void
free_stream (struct Stream *stream)
{
  if (stream->uri)
  {
    free (stream->uri);
  }
  if (stream->method)
  {
    free (stream->method);
  }
  if (stream->authority)
  {
    free (stream->authority);
  }
  if (stream->status_resp_body)
  {
    free (stream->status_resp_body);
  }
}


void
connection_remove_all_streams (struct connection *c)
{
  struct Stream *tmp, *curr;
  curr = c->streams;
  while (NULL != curr)
  {
    tmp = curr;
    curr = curr->next;
    free_stream (tmp);
    free (tmp);
  }
}


struct Stream*
find_stream (struct connection *c, int64_t stream_id)
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


void
server_remove_connection (struct connection *connection);

void
close_waitcb (struct ev_loop *loop, ev_timer *w, int revents)
{
  struct connection *c = w->data;

  if (ngtcp2_conn_in_closing_period (c->conn))
  {
    printf ("closing period over\n");
    server_remove_connection (c);
    return;
  }
  if (ngtcp2_conn_in_draining_period (c->conn))
  {
    printf ("draining period over\n");
    server_remove_connection (c);
    return;
  }
}


void
start_draining_period (struct connection *c)
{
  ev_set_cb (&c->timer, close_waitcb);
  c->timer.repeat = (ev_tstamp)
                    (ngtcp2_conn_get_pto (c->conn))
                    / NGTCP2_SECONDS * 3;
  ev_timer_again (EV_DEFAULT, &c->timer);

  printf ("start draining!\n");
}


int
start_closing_period (struct connection *c)
{
  if (NULL == c->conn ||
      ngtcp2_conn_in_closing_period (c->conn) ||
      ngtcp2_conn_in_draining_period (c->conn))
  {
    return 0;
  }

  ev_set_cb (&c->timer, close_waitcb);
  c->timer.repeat = (ev_tstamp)
                    (ngtcp2_conn_get_pto (c->conn))
                    / NGTCP2_SECONDS * 3;
  ev_timer_again (EV_DEFAULT, &c->timer);

  printf ("start closing!\n");

  ngtcp2_path_storage ps;
  ngtcp2_pkt_info pi;
  ngtcp2_ssize nwrite;

  ngtcp2_path_storage_zero (&ps);
  nwrite = ngtcp2_conn_write_connection_close (c->conn,
                                               &ps.path,
                                               &pi,
                                               c->conn_close_buf,
                                               sizeof (c->conn_close_buf),
                                               &c->last_error,
                                               timestamp ());
  if (nwrite < 0)
  {
    printf ("ngtcp2_conn_write_connection_close: %s\n",
            ngtcp2_strerror (nwrite));
    return -1;
  }
  if (0 == nwrite)
  {
    return 0;
  }
  c->conn_close_buflen = nwrite;
  return 0;
}


int
server_send_pkt (struct connection *connection,
                 uint8_t *data, size_t datalen,
                 struct sockaddr *remote_addr,
                 socklen_t remotea_addrlen);


int
send_conn_close (struct connection *c)
{
  int rv;
  /**
   * TODO: we use ngtcp2_conn_get_path may be better.
   */
  printf ("closing period, send CONNECTION_CLOSE\n");
  rv = server_send_pkt (c,
                        c->conn_close_buf,
                        c->conn_close_buflen,
                        &c->client_addr,
                        c->client_addrlen);
  return rv;
}


int
handle_error (struct connection *c)
{
  printf ("handle_error called\n");
  int rv;
  if (NGTCP2_CCERR_TYPE_IDLE_CLOSE == c->last_error.type)
  {
    return -1;
  }

  if (0 != start_closing_period (c))
  {
    return -1;
  }

  if (ngtcp2_conn_in_draining_period (c->conn))
  {
    return NETWORK_ERR_CLOSE_WAIT;
  }

  rv = send_conn_close (c);
  if (NETWORK_ERR_OK != rv)
  {
    return rv;
  }

  return NETWORK_ERR_CLOSE_WAIT;
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

void
http_consume (struct connection *c, int64_t stream_id, size_t consumed)
{
  ngtcp2_conn_extend_max_stream_offset (c->conn, stream_id, consumed);
  ngtcp2_conn_extend_max_offset (c->conn, consumed);
}


int
recv_stream_data_cb (ngtcp2_conn *conn, uint32_t flags, int64_t stream_id,
                     uint64_t offset, const uint8_t *data, size_t datalen,
                     void *user_data,
                     void *stream_user_data)
{
  struct connection *c = (struct connection*) user_data;
  nghttp3_ssize nconsumed;

  if (NULL == c->h3conn)
  {
    return 0;
  }
  nconsumed = nghttp3_conn_read_stream (c->h3conn, stream_id, data, datalen,
                                        flags & NGTCP2_STREAM_DATA_FLAG_FIN);
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
connection_remove_stream (struct connection *c, int64_t stream_id)
{
  struct Stream *curr = c->streams;
  struct Stream *tmp;
  if (NULL == curr)
    return;
  if (curr->stream_id == stream_id)
  {
    c->streams = curr->next;
    free_stream (curr);
    free (curr);
    return;
  }
  while (NULL != curr)
  {
    if (curr->stream_id == stream_id)
    {
      tmp->next = curr->next;
      free_stream (curr);
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
  printf ("stream_close id = %ld, err_code = %lu\n", stream_id, app_error_code);
  struct connection *c = user_data;
  int rv;

  if (! (flags & NGTCP2_STREAM_CLOSE_FLAG_APP_ERROR_CODE_SET))
  {
    app_error_code = NGHTTP3_H3_NO_ERROR;
  }

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
      if (ngtcp2_is_bidi_stream (stream_id))
      {
        ngtcp2_conn_extend_max_streams_bidi (c->conn, 1);
      }
      break;
    default:
      fprintf (stderr, "nghttp3_conn_close_stream: %s\n",
               nghttp3_strerror (rv));
      ngtcp2_ccerr_set_application_error (
        &c->last_error,
        nghttp3_err_infer_quic_app_error_code (rv),
        NULL, 0);
      return NGTCP2_ERR_CALLBACK_FAILURE;
    }
  }
  return 0;
}


const char *
get_reason_phrase (unsigned int status_code)
{
  switch (status_code)
  {
  case 100:
    return "Continue";
  case 101:
    return "Switching Protocols";
  case 200:
    return "OK";
  case 201:
    return "Created";
  case 202:
    return "Accepted";
  case 203:
    return "Non-Authoritative Information";
  case 204:
    return "No Content";
  case 205:
    return "Reset Content";
  case 206:
    return "Partial Content";
  case 300:
    return "Multiple Choices";
  case 301:
    return "Moved Permanently";
  case 302:
    return "Found";
  case 303:
    return "See Other";
  case 304:
    return "Not Modified";
  case 305:
    return "Use Proxy";
  // case 306: return "(Unused)";
  case 307:
    return "Temporary Redirect";
  case 308:
    return "Permanent Redirect";
  case 400:
    return "Bad Request";
  case 401:
    return "Unauthorized";
  case 402:
    return "Payment Required";
  case 403:
    return "Forbidden";
  case 404:
    return "Not Found";
  case 405:
    return "Method Not Allowed";
  case 406:
    return "Not Acceptable";
  case 407:
    return "Proxy Authentication Required";
  case 408:
    return "Request Timeout";
  case 409:
    return "Conflict";
  case 410:
    return "Gone";
  case 411:
    return "Length Required";
  case 412:
    return "Precondition Failed";
  case 413:
    return "Payload Too Large";
  case 414:
    return "URI Too Long";
  case 415:
    return "Unsupported Media Type";
  case 416:
    return "Requested Range Not Satisfiable";
  case 417:
    return "Expectation Failed";
  case 421:
    return "Misdirected Request";
  case 426:
    return "Upgrade Required";
  case 428:
    return "Precondition Required";
  case 429:
    return "Too Many Requests";
  case 431:
    return "Request Header Fields Too Large";
  case 451:
    return "Unavailable For Legal Reasons";
  case 500:
    return "Internal Server Error";
  case 501:
    return "Not Implemented";
  case 502:
    return "Bad Gateway";
  case 503:
    return "Service Unavailable";
  case 504:
    return "Gateway Timeout";
  case 505:
    return "HTTP Version Not Supported";
  case 511:
    return "Network Authentication Required";
  default:
    return "";
  }
}


char*
make_status_body (unsigned int status_code)
{
  const char *reason_phrase = get_reason_phrase (status_code);

  size_t body_size = strlen ("<html><head><title>") + 3
                     + strlen (" ") + strlen (reason_phrase)
                     + strlen ("</title></head><body><h1>")
                     + 3 + strlen (" ")
                     + strlen (reason_phrase)
                     + strlen ("</h1><hr><address>")
                     + strlen (NGTCP2_SERVER)
                     + strlen (" at port ")
                     + strlen (LOCAL_PORT)
                     + strlen ("</address></body></html>") + 1;

  char *body = (char*) malloc (body_size);
  if (NULL == body)
  {
    return NULL;
  }

  snprintf (body, body_size,
            "<html><head><title>%u %s</title></head><body><h1>%u %s</h1><hr><address>%s at port %s</address></body></html>",
            status_code, reason_phrase, status_code, reason_phrase,
            NGTCP2_SERVER, LOCAL_PORT);
  return body;
}


nghttp3_nv
make_nv (const char *name, const char *value, uint8_t flag)
{
  nghttp3_nv nv;
  nv.name = (const uint8_t *) name;
  nv.namelen = strlen (name);
  nv.value = (const uint8_t *) value;
  nv.valuelen = strlen (value);
  nv.flags = flag;

  return nv;
}


nghttp3_ssize
read_data (nghttp3_conn *conn, int64_t stream_id, nghttp3_vec *vec,
           size_t veccnt, uint32_t *pflags, void *user_data,
           void *stream_user_data)
{
  struct Stream *stream = stream_user_data;

  vec[0].base = stream->data;
  vec[0].len = stream->datalen;
  *pflags |= NGHTTP3_DATA_FLAG_EOF;

  return 1;
}


int
stream_send_status_response (struct Stream *stream, nghttp3_conn *httpconn,
                             unsigned int status_code,
                             const char *path)
{
  char status_code_str[4];
  char content_length_str[4];
  nghttp3_nv nva[5];
  size_t nvalen = 4;
  nghttp3_data_reader dr = {};
  int rv;

  stream->status_resp_body = (uint8_t *) make_status_body (status_code);
  snprintf (status_code_str, 4, "%u", status_code);
  snprintf (content_length_str, 4, "%lu",
            strlen ((const char *) stream->status_resp_body));

  nva[0] = make_nv (":status", status_code_str, NGHTTP3_NV_FLAG_NO_COPY_NAME);
  nva[1] = make_nv ("server", NGTCP2_SERVER,
                    NGHTTP3_NV_FLAG_NO_COPY_NAME
                    | NGHTTP3_NV_FLAG_NO_COPY_VALUE);
  nva[2] = make_nv ("content-type", "text/html; charset=utf-8",
                    NGHTTP3_NV_FLAG_NO_COPY_NAME
                    | NGHTTP3_NV_FLAG_NO_COPY_VALUE);
  nva[3] = make_nv ("content-length", content_length_str,
                    NGHTTP3_NV_FLAG_NO_COPY_NAME);
  if (NULL != path)
  {
    nva[4] = make_nv ("location", path, NGHTTP3_NV_FLAG_NONE);
    nvalen += 1;
  }

  stream->data = (uint8_t *) stream->status_resp_body;
  stream->datalen = strlen ((const char *) stream->status_resp_body);
  dr.read_data = read_data;
  rv = nghttp3_conn_submit_response (httpconn, stream->stream_id,
                                     nva, nvalen, &dr);
  if (0 != rv)
  {
    fprintf (stderr, "nghttp3_conn_submit_response: %s\n",
             nghttp3_strerror (rv));
    return -1;
  }

  ngtcp2_conn_shutdown_stream_read (stream->connection->conn, 0,
                                    stream->stream_id, NGHTTP3_H3_NO_ERROR);
  return 0;
}


int
stream_start_response (struct Stream *stream, nghttp3_conn *http_conn)
{
  stream_send_status_response (stream, http_conn, 404, NULL);
  return 0;
  if (NULL == stream->uri || NULL == stream->method)
  {
    return stream_send_status_response (stream, http_conn, 400, NULL);
  }

  nghttp3_nv nva[5];
  size_t nvlen;
  nghttp3_data_reader dr = {};
  int rv;

  nva[0] = make_nv (":status", "200",
                    NGHTTP3_NV_FLAG_NO_COPY_NAME
                    | NGHTTP3_NV_FLAG_NO_COPY_VALUE);
  nva[1] = make_nv ("server", NGTCP2_SERVER,
                    NGHTTP3_NV_FLAG_NO_COPY_NAME
                    | NGHTTP3_NV_FLAG_NO_COPY_VALUE);
  nva[2] = make_nv ("content-type", "text/plain",
                    NGHTTP3_NV_FLAG_NO_COPY_NAME
                    | NGHTTP3_NV_FLAG_NO_COPY_VALUE);
  nva[3] = make_nv ("cotent-length", "0",
                    NGHTTP3_NV_FLAG_NO_COPY_NAME);
  nvlen = 4;
}


int
http_acked_stream_data (nghttp3_conn *conn, int64_t stream_id,
                        uint64_t datalen, void *user_data,
                        void *stream_user_data)
{
  return 0;
}


int
http_stream_close (nghttp3_conn *conn, int64_t stream_id,
                   uint64_t app_error_code, void *conn_user_data,
                   void *stream_user_data)
{
  struct connection *c = conn_user_data;

  connection_remove_stream (c, stream_id);
  fprintf (stderr, "HTTP stream %ld closed\n", stream_id);
  if (ngtcp2_is_bidi_stream (stream_id))
  {
    ngtcp2_conn_extend_max_streams_bidi (c->conn, 1);
  }
  return 0;
}


int
http_recv_data (nghttp3_conn *conn, int64_t stream_id, const uint8_t *data,
                size_t datalen, void *user_data, void *stream_user_data)
{
  printf ("http_recv_data\n");
  struct connection *c = user_data;
  http_consume (c, stream_id, datalen);
  return 0;
}


int
http_deferred_consume (nghttp3_conn *conn, int64_t stream_id,
                       size_t nconsumed, void *user_data,
                       void *stream_user_data)
{
  struct connection *c = user_data;
  http_consume (c, stream_id, nconsumed);

  return 0;
}


int
http_begin_request_headers (nghttp3_conn *conn, int64_t stream_id,
                            void *user_data, void *stream_user_data)
{
  printf ("http_begin_header! stream_id = %ld\n", stream_id);
  struct connection *c = user_data;
  struct Stream *stream;

  stream = find_stream (c, stream_id);
  if (NULL == stream)
  {
    return NGHTTP3_ERR_CALLBACK_FAILURE;
  }
  nghttp3_conn_set_stream_user_data (c->h3conn, stream_id, stream);

  return 0;
}


int
http_recv_request_header (nghttp3_conn *conn, int64_t stream_id, int32_t token,
                          nghttp3_rcbuf *name, nghttp3_rcbuf *value,
                          uint8_t flags,
                          void *user_data, void *stream_user_data)
{
  nghttp3_vec namebuf = nghttp3_rcbuf_get_buf (name);
  nghttp3_vec valbuf = nghttp3_rcbuf_get_buf (value);
  struct Stream *stream = stream_user_data;

  fprintf (stdout, "http header: [%.*s: %.*s]\n",
           (int) namebuf.len, namebuf.base, (int) valbuf.len, valbuf.base);

  switch (token)
  {
  case NGHTTP3_QPACK_TOKEN__PATH:
    stream->urilen = valbuf.len;
    stream->uri = (uint8_t *) malloc (valbuf.len);
    memcpy (stream->uri, valbuf.base, valbuf.len);
    break;
  case NGHTTP3_QPACK_TOKEN__METHOD:
    stream->methodlen = valbuf.len;
    stream->method = (uint8_t *) malloc (valbuf.len);
    memcpy (stream->method, valbuf.base, valbuf.len);
    break;
  case NGHTTP3_QPACK_TOKEN__AUTHORITY:
    stream->authoritylen = valbuf.len;
    stream->authority = (uint8_t *) malloc (valbuf.len);
    memcpy (stream->authority, valbuf.base, valbuf.len);
    break;
  }
  return 0;
}


int
http_stop_sending (nghttp3_conn *conn, int64_t stream_id,
                   uint64_t app_error_code, void *user_data,
                   void *stream_user_data)
{
  struct connection *c = user_data;
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
http_end_stream (nghttp3_conn *conn, int64_t stream_id, void *user_data,
                 void *stream_user_data)
{
  struct Stream *stream = stream_user_data;
  int rv;

  rv = stream_start_response (stream, conn);
  if (0 != rv)
  {
    return NGHTTP3_ERR_CALLBACK_FAILURE;
  }
  return 0;
}


int
http_reset_stream (nghttp3_conn *conn, int64_t stream_id,
                   uint64_t app_error_code, void *user_data,
                   void *stream_user_data)
{
  struct connection *c = user_data;
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
setup_httpconn (struct connection *c)
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
    .acked_stream_data = http_acked_stream_data,
    .stream_close = http_stream_close,
    .recv_data = http_recv_data,
    .deferred_consume = http_deferred_consume,
    .begin_headers = http_begin_request_headers,
    .recv_header = http_recv_request_header,
    .stop_sending = http_stop_sending,
    .end_stream = http_end_stream,
    .reset_stream = http_reset_stream,
  };
  nghttp3_settings settings;
  const nghttp3_mem *mem = nghttp3_mem_default ();
  const ngtcp2_transport_params *params =
    ngtcp2_conn_get_local_transport_params (c->conn);
  int64_t ctrl_stream_id;
  int64_t enc_stream_id;
  int64_t dec_stream_id;
  int rv;

  nghttp3_settings_default (&settings);
  settings.qpack_blocked_streams = 100;
  settings.qpack_encoder_max_dtable_capacity = 4096;

  rv = nghttp3_conn_server_new (&c->h3conn, &callbacks, &settings, mem, c);
  if (0 != rv)
  {
    fprintf (stderr, "nghttp3_conn_server_new: %s\n",
             nghttp3_strerror (rv));
    return -1;
  }
  nghttp3_conn_set_max_client_streams_bidi (c->h3conn,
                                            params->initial_max_streams_bidi);

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
stream_open_cb (ngtcp2_conn *conn, int64_t stream_id, void *user_data)
{
  struct connection *c = user_data;
  if (! ngtcp2_is_bidi_stream (stream_id))
  {
    return 0;
  }
  create_stream (c, stream_id);
  return 0;
}


int
acked_stream_data_offset_cb (ngtcp2_conn *conn, int64_t stream_id,
                             uint64_t offset, uint64_t datalen, void *user_data,
                             void *stream_user_data)
{
  struct connection *c = user_data;
  int rv;

  if (NULL == c->h3conn)
  {
    return 0;
  }

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
extend_max_remote_streams_bidi_cb (ngtcp2_conn *conn, uint64_t max_streams,
                                   void *user_data)
{
  struct connection *c = user_data;
  if (NULL == c->h3conn)
  {
    return 0;
  }
  nghttp3_conn_set_max_client_streams_bidi (c->h3conn, max_streams);
  return 0;
}


int
stream_stop_sending_cb (ngtcp2_conn *conn, int64_t stream_id,
                        uint64_t app_error_code, void *user_data,
                        void *stream_user_data)
{
  struct connection *c = user_data;
  int rv;

  if (NULL == c->h3conn)
  {
    return 0;
  }
  rv = nghttp3_conn_shutdown_stream_read (c->h3conn, stream_id);
  if (0 != rv)
  {
    fprintf (stderr, "nghttp3_conn_shutdown_stream_read: %s\n",
             nghttp3_strerror (rv));
    return NGTCP2_ERR_CALLBACK_FAILURE;
  }

  return 0;
}


int
extend_max_stream_data_cb (ngtcp2_conn *conn, int64_t stream_id,
                           uint64_t max_data, void *user_data,
                           void *stream_user_data)
{
  struct connection *c = user_data;
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
recv_tx_key_cb (ngtcp2_conn *conn, ngtcp2_encryption_level level,
                void *user_data)
{
  if (NGTCP2_ENCRYPTION_LEVEL_1RTT != level)
  {
    return 0;
  }

  struct connection *c = user_data;
  int rv;

  rv = setup_httpconn (c);
  if (0 != rv)
  {
    return NGTCP2_ERR_CALLBACK_FAILURE;
  }

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

  .acked_stream_data_offset = acked_stream_data_offset_cb,
  .stream_open = stream_open_cb,
  .rand = rand_cb,
  .get_new_connection_id = get_new_connection_id_cb,
  .recv_stream_data = recv_stream_data_cb,
  .remove_connection_id = remove_connection_id,
  .stream_close = stream_close_cb,
  .extend_max_remote_streams_bidi = extend_max_remote_streams_bidi_cb,
  .stream_stop_sending = stream_stop_sending_cb,
  .extend_max_stream_data = extend_max_stream_data_cb,
  .recv_tx_key = recv_tx_key_cb,
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
  memset (new_connection, 0, sizeof (struct connection));
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
  params.initial_max_streams_bidi = 100;
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
  // new_connection->stream.stream_id = -1;
  new_connection->streams = NULL;
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
    ngtcp2_conn_del (connection->conn);
    if (connection->h3conn)
    {
      nghttp3_conn_del (connection->h3conn);
    }
    connection_remove_all_streams (connection);
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
    ngtcp2_conn_del (connection->conn);
    if (connection->h3conn)
    {
      nghttp3_conn_del (connection->h3conn);
    }
    connection_remove_all_streams (connection);
    free (connection);
  }

  return;
}


int
handle_expiry (struct connection *c)
{
  ngtcp2_tstamp now;
  int rv;

  now = timestamp ();
  rv = ngtcp2_conn_handle_expiry (c->conn, now);
  if (0 != rv)
  {
    printf ("ngtcp2_conn_handle_expiry: %s\n",
            ngtcp2_strerror (rv));
    ngtcp2_ccerr_set_liberr (&c->last_error, rv, NULL, 0);
    return handle_error (c);
  }
  return 0;
}


void
timer_cb (struct ev_loop *loop, ev_timer *w, int revents)
{

  printf ("=====in timer_cb\n");
  struct connection *c = w->data;
  int ret;
  ret = handle_expiry (c);
  if (0 != ret)
  {
    switch (ret)
    {
    case NETWORK_ERR_CLOSE_WAIT:
      ev_timer_stop (EV_DEFAULT, w);
      return;
    default:
      server_remove_connection (c);
      return;
    }
  }
  ret = connection_write (c);
  if (0 != ret)
  {
    switch (ret)
    {
    case NETWORK_ERR_CLOSE_WAIT:
      ev_timer_stop (EV_DEFAULT, w);
      return;
    default:
      server_remove_connection (c);
      return;
    }
  }
}


struct connection *
connection_init (struct server *s,
                 const struct sockaddr *sa, socklen_t salen,
                 const ngtcp2_cid *dcid, const ngtcp2_cid *scid,
                 uint32_t version)
{
  struct connection *new_connection;
  ngtcp2_path path;
  ngtcp2_transport_params params;
  ngtcp2_cid scid_;
  ngtcp2_conn *conn = NULL;
  int rv;

  new_connection = (struct connection *) malloc (sizeof(struct connection));
  memset (new_connection, 0, sizeof(struct connection));
  new_connection->next = s->connections;
  s->connections = new_connection;
  s->num_connections += 1;

  gnutls_init (&new_connection->session,
               GNUTLS_SERVER
               | GNUTLS_ENABLE_EARLY_DATA
               | GNUTLS_NO_END_OF_EARLY_DATA);
  gnutls_priority_set_direct (new_connection->session, PRIO, NULL);
  gnutls_credentials_set (new_connection->session,
                          GNUTLS_CRD_CERTIFICATE,
                          s->cred);
  new_connection->fd = s->fd;

  path.local.addr = (struct sockaddr *) &s->local_addr;
  path.local.addrlen = s->local_addrlen;
  path.remote.addr = (struct sockaddr*) sa;
  path.remote.addrlen = salen;

  ngtcp2_transport_params_default (&params);
  params.initial_max_streams_uni = 3;
  params.initial_max_streams_bidi = 3;
  params.initial_max_stream_data_bidi_local = 128 * 1024;
  params.initial_max_stream_data_bidi_remote = 128 * 1024;
  params.initial_max_data = 1024 * 1024;
  params.original_dcid_present = 1;
  params.max_idle_timeout = 30 * NGTCP2_SECONDS;
  params.original_dcid = *scid;

  get_random_cid (&scid_);

  rv = ngtcp2_conn_server_new (&conn,
                               dcid,
                               &scid_,
                               &path,
                               version,
                               &callbacks,
                               &s->settings,
                               &params,
                               NULL, new_connection);
  if (rv < 0)
  {
    fprintf (stderr, "ngtcp2_conn_server_new error!\n");
    return NULL;
  }

  new_connection->conn = conn;
  memcpy (&new_connection->local_addr, &s->local_addr, s->local_addrlen);
  new_connection->local_addrlen = s->local_addrlen;

  memcpy (&new_connection->client_addr, sa, salen);
  new_connection->client_addrlen = salen;

  ngtcp2_crypto_gnutls_configure_server_session (new_connection->session);
  ngtcp2_conn_set_tls_native_handle (new_connection->conn,
                                     new_connection->session);
  gnutls_session_set_ptr (new_connection->session, &new_connection->conn_ref);
  new_connection->conn_ref.get_conn = get_conn;
  new_connection->conn_ref.user_data = new_connection;
  new_connection->streams = NULL;
  new_connection->server = s;

  ev_io_init (&new_connection->wev, write_cb, new_connection->fd, EV_WRITE);
  new_connection->wev.data = s;
  ev_timer_init (&new_connection->timer, timer_cb, 0., 0.);
  new_connection->timer.data = new_connection;

  return new_connection;
}


int
connection_feed_data (struct connection *c, struct sockaddr *sa,
                      socklen_t salen, const ngtcp2_pkt_info *pi,
                      const uint8_t *data, size_t datalen)
{
  ngtcp2_path path;
  int rv;

  path.local.addr = &c->local_addr;
  path.local.addrlen = c->local_addrlen;
  path.remote.addr = sa;
  path.remote.addrlen = salen;

  rv = ngtcp2_conn_read_pkt (c->conn, &path, pi, data, datalen, timestamp ());
  if (0 != rv)
  {
    fprintf (stderr, "ngtcp2_conn_read_pkt: %s\n", ngtcp2_strerror (rv));
    switch (rv)
    {
    case NGTCP2_ERR_DRAINING:
      start_draining_period (c);
      return NETWORK_ERR_CLOSE_WAIT;
    case NGTCP2_ERR_RETRY:
      return NETWORK_ERR_RETRY;
    case NGTCP2_ERR_DROP_CONN:
      return NETWORK_ERR_DROP_CONN;
    case NGTCP2_ERR_CRYPTO:
      if (! c->last_error.error_code)
      {
        ngtcp2_ccerr_set_tls_alert (
          &c->last_error, ngtcp2_conn_get_tls_alert (c->conn), NULL, 0);
      }
      break;
    default:
      if (! c->last_error.error_code)
      {
        ngtcp2_ccerr_set_liberr (&c->last_error, rv, NULL, 0);
      }
    }
    return handle_error (c);
  }
  return 0;
}


void
update_timer (struct connection *c)
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
connection_on_read (struct connection *c, struct sockaddr *sa,
                    socklen_t salen, const ngtcp2_pkt_info *pi,
                    const uint8_t *data, size_t datalen)
{
  int rv;
  rv = connection_feed_data (c, sa, salen, pi, data, datalen);
  if (0 != rv)
  {
    return rv;
  }

  // update_timer here.
  update_timer (c);
  return 0;
}


void
server_read_pkt (struct server *s,
                 struct sockaddr *remote_addr, socklen_t remote_addrlen,
                 const ngtcp2_pkt_info *pi,
                 const uint8_t *data, size_t datalen)
{
  ngtcp2_version_cid version_cid;
  struct connection *connection;
  int rv;

  rv = ngtcp2_pkt_decode_version_cid (&version_cid, data, datalen,
                                      NGTCP2_MAX_CIDLEN);
  switch (rv)
  {
  case 0:
    break;
  case NGTCP2_ERR_VERSION_NEGOTIATION:
    // TODO: send version negotiation.
    return;
  default:
    fprintf (stderr, "can't decode version and CID: %s",
             ngtcp2_strerror (rv));
    return;
  }

  connection = find_connection (s, version_cid.dcid, version_cid.dcidlen);
  if (NULL == connection)
  {
    ngtcp2_pkt_hd header;
    rv = ngtcp2_accept (&header, data, datalen);
    if (0 != rv)
    {
      fprintf (stderr, "ngtcp2_accept: %s",
               ngtcp2_strerror (rv));
      return;
    }


    // TODO: handle the stateless reset token.

    connection = connection_init (s, remote_addr, remote_addrlen, &header.scid,
                                  &header.dcid, header.version);
    if (NULL == connection)
    {
      return;
    }

    rv = connection_on_read (connection, remote_addr, remote_addrlen, pi, data,
                             datalen);
    switch (rv)
    {
    case 0:
      break;
    case NETWORK_ERR_RETRY:
      // send retry
      return;
    default:
      return;
    }

    rv = connection_write (connection);
    if (0 != rv)
    {
      return;
    }

    // deal with cid map

    return;
  }

  if (ngtcp2_conn_in_closing_period (connection->conn))
  {
    rv = send_conn_close (connection);
    if (0 != rv)
    {
      server_remove_connection (connection);
    }
    return;
  }
  if (ngtcp2_conn_in_draining_period (connection->conn))
  {
    return;
  }

  rv = connection_on_read (connection, remote_addr, remote_addrlen, pi, data,
                           datalen);
  if (0 != rv)
  {
    if (rv != NETWORK_ERR_CLOSE_WAIT)
    {
      server_remove_connection (connection);
    }
    return;
  }

  connection_write (connection);
}


int
server_on_read (struct server *s)
{
  struct sockaddr_storage addr;
  socklen_t addrlen;
  uint8_t buf[65535];
  ssize_t n_read;
  ngtcp2_pkt_info pi;
  struct iovec iov = {buf, sizeof (buf)};
  struct msghdr msg = {0};
  int rv;

  msg.msg_name = &addr;
  msg.msg_iov = &iov;
  msg.msg_iovlen = 1;
  for (;;)
  {
    msg.msg_namelen = sizeof (addr);
    n_read = recvmsg (s->fd, &msg, 0);
    if (-1 == n_read)
    {
      if (errno != EAGAIN && errno != EWOULDBLOCK)
      {
        fprintf (stderr, "recvmsg: %s\n", strerror (errno));
      }
      return 0;
    }

    server_read_pkt (s, msg.msg_name, msg.msg_namelen, &pi, buf, n_read);
  }

  return 0;
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
    dispaddr ((struct sockaddr*) &remote_addr, (uint8_t *) "client");

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
      switch (ret)
      {
      case NGTCP2_ERR_DRAINING:
        start_draining_period (connection);
        return NETWORK_ERR_CLOSE_WAIT;
      case NGTCP2_ERR_RETRY:
        return NETWORK_ERR_RETRY;
      case NGTCP2_ERR_DROP_CONN:
        return NETWORK_ERR_DROP_CONN;
      case NGTCP2_ERR_CRYPTO:
        if (! connection->last_error.error_code)
        {
          ngtcp2_ccerr_set_tls_alert (&connection->last_error,
                                      ngtcp2_conn_get_tls_alert (
                                        connection->conn),
                                      NULL,
                                      0);
        }
        break;
      default:
        if (! connection->last_error.error_code)
        {
          ngtcp2_ccerr_set_liberr (&connection->last_error,
                                   ret,
                                   NULL,
                                   0);
        }
      }
      return handle_error (connection);
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
write_to_stream (struct connection *connection, struct Stream *stream)
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
      printf ("ngtcp2_conn_writev_stream: %s\n",
              ngtcp2_strerror (nwrite));
      ngtcp2_ccerr_set_liberr (&connection->last_error,
                               nwrite,
                               NULL,
                               0);
      return handle_error (connection);
    }
    if (nwrite == 0)
    {
      return 0;
    }
    if (wdatalen > 0)
    {
      // connection->stream.nwrite += (size_t) wdatalen;
      stream->sent_offset += (size_t) wdatalen;
    }
    if (0 != server_send_pkt (connection, buf, (size_t) nwrite,
                              &connection->client_addr,
                              connection->client_addrlen))
      break;
  }
  return 0;
}


int
write_streams (struct connection *c)
{
  uint8_t buf[1280];
  ngtcp2_tstamp ts = timestamp ();
  ngtcp2_path_storage ps;
  int64_t stream_id;
  uint32_t flags;


  ngtcp2_ssize nwrite;
  ngtcp2_ssize wdatalen;
  nghttp3_vec vec[16];
  nghttp3_ssize sveccnt;
  ngtcp2_pkt_info pi;
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
        return handle_error (c);
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
        // add nghttp3 block stream
        nghttp3_conn_block_stream (c->h3conn, stream_id);
        continue;
      case NGTCP2_ERR_STREAM_SHUT_WR:
        // add nghttp3 shutdown stream write
        nghttp3_conn_shutdown_stream_write (c->h3conn, stream_id);
        continue;
      case NGTCP2_ERR_WRITE_MORE:
        // nghttp3 write offset
        // ngtcp2 set application error
        rv = nghttp3_conn_add_write_offset (c->h3conn, stream_id, wdatalen);
        if (0 != rv)
        {
          fprintf (stderr, "nghttp3_conn_add_write_offset: %s\n",
                   nghttp3_strerror (rv));
          ngtcp2_ccerr_set_application_error (
            &c->last_error,
            nghttp3_err_infer_quic_app_error_code (rv),
            NULL, 0);
          return handle_error (c);
        }
        continue;
      }
      fprintf (stderr, "ngtcp2_conn_writev_stream: %s\n",
               ngtcp2_strerror (nwrite));
      ngtcp2_ccerr_set_liberr (&c->last_error,
                               nwrite,
                               NULL,
                               0);
      return handle_error (c);
    }
    if (nwrite == 0)
    {
      ngtcp2_conn_update_pkt_tx_time (c->conn, ts);
      return 0;
    }
    if (wdatalen > 0)
    {
      rv = nghttp3_conn_add_write_offset (c->h3conn, stream_id, wdatalen);
      if (0 != rv)
      {
        fprintf (stderr, "nghttp3_conn_add_write_offset: %s\n",
                 nghttp3_strerror (rv));
        ngtcp2_ccerr_set_application_error (
          &c->last_error,
          nghttp3_err_infer_quic_app_error_code (rv),
          NULL, 0);
        return handle_error (c);
      }
    }
    if (0 != server_send_pkt (c, buf, (size_t) nwrite,
                              &c->client_addr,
                              c->client_addrlen))
      break;
  }
  return 0;
}


int
connection_write (struct connection *connection)
{
  printf ("in connection_write!\n");
  int rv;

  if (ngtcp2_conn_in_closing_period (connection->conn) ||
      ngtcp2_conn_in_draining_period (connection->conn))
  {
    return 0;
  }
  rv = write_streams (connection);
  if (0 != rv)
  {
    return rv;
  }
  update_timer (connection);
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
  return;
}


void
read_cb (struct ev_loop *loop, ev_io *w, int revents)
{
  struct server *s = w->data;
  int ret;
  printf ("num_connections = %d\n", s->num_connections);
  // ret = handle_incoming (s);
  ret = server_on_read (s);
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
server_free (struct server *s)
{
  gnutls_certificate_free_credentials (s->cred);
  struct connection *tmp, *curr;
  curr = s->connections;
  while (NULL != curr)
  {
    tmp = curr;
    curr = curr->next;
    free (tmp);
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