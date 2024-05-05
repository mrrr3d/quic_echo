#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <gnutls/gnutls.h>

#define SERVER_PORT 4433
#define BUFFER_SIZE 1024
#define LOOP_CHECK(rval, cmd) \
  do {                  \
    rval = cmd;   \
  } while (rval == GNUTLS_E_AGAIN || rval == GNUTLS_E_INTERRUPTED)


int
main ()
{
  int server_socket, client_socket;
  struct sockaddr_in server_address, client_address;
  char buffer[BUFFER_SIZE];

  // 创建服务器套接字
  server_socket = socket (AF_INET, SOCK_STREAM, 0);
  if (server_socket < 0)
  {
    perror ("Socket creation failed");
    exit (EXIT_FAILURE);
  }

  // 设置服务器地址
  server_address.sin_family = AF_INET;
  server_address.sin_addr.s_addr = INADDR_ANY;
  server_address.sin_port = htons (SERVER_PORT);

  // 绑定套接字
  if (bind (server_socket, (struct sockaddr *) &server_address,
            sizeof(server_address)) < 0)
  {
    perror ("Binding failed");
    exit (EXIT_FAILURE);
  }

  // 监听连接
  if (listen (server_socket, 5) < 0)
  {
    perror ("Listening failed");
    exit (EXIT_FAILURE);
  }

  printf ("Server listening on port %d...\n", SERVER_PORT);

  const char *ca_crt = "../Documents/ca.crt";
  const char *server_crt = "../Documents/server.crt";
  const char *server_key = "../Documents/server.key";
  gnutls_certificate_credentials_t x509_cred;
  gnutls_priority_t priority_cache;
  gnutls_session_t session;
  gnutls_priority_t pri_cache;
  gnutls_global_init ();
  gnutls_certificate_allocate_credentials (&x509_cred);
  // gnutls_certificate_set_x509_trust_file (x509_cred, ca_crt, GNUTLS_X509_FMT_PEM);
  // gnutls_certificate_set_x509_system_trust(x509_cred);
  // crl_file didn't set
  gnutls_certificate_set_x509_key_file (x509_cred, server_crt, server_key,
                                        GNUTLS_X509_FMT_PEM);
  // ocsp status didn't set
  gnutls_priority_init (&pri_cache, NULL, NULL);
  gnutls_certificate_set_known_dh_params (x509_cred, GNUTLS_SEC_PARAM_MEDIUM);

  while (1)
  {
    gnutls_init (&session, GNUTLS_SERVER);
    gnutls_priority_set (session, pri_cache);
    gnutls_credentials_set (session, GNUTLS_CRD_CERTIFICATE, x509_cred);
    gnutls_certificate_server_set_request (session, GNUTLS_CERT_IGNORE);
    gnutls_handshake_set_timeout (session, GNUTLS_DEFAULT_HANDSHAKE_TIMEOUT);


    // 等待客户端连接
    socklen_t client_address_len = sizeof(client_address);
    client_socket = accept (server_socket, (struct sockaddr *) &client_address,
                            &client_address_len);
    if (client_socket < 0)
    {
      perror ("Acceptance failed");
      exit (EXIT_FAILURE);
    }
    printf ("Connection accepted from %s:%d\n",
            inet_ntoa (client_address.sin_addr),
            ntohs (client_address.sin_port));

    gnutls_transport_set_int (session, client_socket);
    int ret;
    LOOP_CHECK (ret, gnutls_handshake (session));
    if (ret < 0)
    {
      close (client_socket);
      gnutls_deinit (session);
      fprintf (stderr, "*** Handshake has failed (%s)\n\n",
               gnutls_strerror (ret));
      continue;
    }

    // 接收数据并回显
    while (1)
    {
      // int bytes_received = recv(client_socket, buffer, BUFFER_SIZE, 0);
      int bytes_received = gnutls_record_recv (session, buffer, BUFFER_SIZE);
      if (bytes_received < 0)
      {
        perror ("Receiving failed");
        exit (EXIT_FAILURE);
      }
      if (bytes_received == 0)
      {
        printf ("Client disconnected\n");
        break;
      }

      printf ("rcv: %s", buffer);
      // 发送回显数据
      // send(client_socket, buffer, bytes_received, 0);
      gnutls_record_send (session, buffer, bytes_received);
    }
    gnutls_bye (session, GNUTLS_SHUT_WR);


    // 关闭客户端套接字
    close (client_socket);
    gnutls_deinit (session);
  }

  // 关闭服务器套接字
  close (server_socket);
  gnutls_certificate_free_credentials (x509_cred);
  gnutls_priority_deinit (pri_cache);

  gnutls_global_deinit ();

  return 0;
}
