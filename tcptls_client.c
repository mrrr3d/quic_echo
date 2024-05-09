#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <gnutls/gnutls.h>

#define SERVER_IP "127.0.0.1"
#define SERVER_PORT 4433
#define BUFFER_SIZE 1024

static const char priority[] =
    "NORMAL:-VERS-ALL:+VERS-TLS1.3:-CIPHER-ALL:+AES-128-GCM:+AES-256-GCM:"
    "+CHACHA20-POLY1305:+AES-128-CCM:-GROUP-ALL:+GROUP-SECP256R1:+GROUP-X25519:"
    "+GROUP-SECP384R1:"
    "+GROUP-SECP521R1:%DISABLE_TLS13_COMPAT_MODE";

int main() {
    int client_socket;
    struct sockaddr_in server_address;
    char buffer[BUFFER_SIZE];
    char *desc;

    

    // 创建客户端套接字
    client_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (client_socket < 0) {
        perror("Socket creation failed");
        exit(EXIT_FAILURE);
    }

    // 设置服务器地址
    server_address.sin_family = AF_INET;
    server_address.sin_addr.s_addr = inet_addr(SERVER_IP);
    server_address.sin_port = htons(SERVER_PORT);


    gnutls_session_t session;
    gnutls_certificate_credentials_t xcred;
    const char *ca_crt = "credentials/ca.pem";
    gnutls_global_init();
    gnutls_certificate_allocate_credentials(&xcred);
    // gnutls_certificate_set_x509_trust_file(xcred, ca_crt, GNUTLS_X509_FMT_PEM);
    gnutls_certificate_set_x509_system_trust(xcred);
    gnutls_init(&session, GNUTLS_CLIENT | GNUTLS_ENABLE_EARLY_DATA |
                                    GNUTLS_NO_END_OF_EARLY_DATA);
    gnutls_server_name_set(session, GNUTLS_NAME_DNS, "localhost", strlen("localhost"));
    gnutls_set_default_priority(session);
    gnutls_credentials_set(session, GNUTLS_CRD_CERTIFICATE, xcred);
//有这个才会验证证书！
    // gnutls_session_set_verify_cert(session, "localhost", 0);





    // 连接到服务器
    if (connect(client_socket, (struct sockaddr *)&server_address, sizeof(server_address)) < 0) {
        perror("Connection failed");
        exit(EXIT_FAILURE);
    }
    // 额应该就用这个描述符？对吗不知道....
    gnutls_transport_set_int(session, client_socket);
    gnutls_handshake_set_timeout(session, GNUTLS_DEFAULT_HANDSHAKE_TIMEOUT);
    
    printf("Connected to server on %s:%d\n", SERVER_IP, SERVER_PORT);

    int ret;
    int type;
    unsigned status;
    gnutls_datum_t out;
    do {
		ret = gnutls_handshake(session);
	} while (ret < 0 && gnutls_error_is_fatal(ret) == 0);
    if (ret < 0) {
		if (ret == GNUTLS_E_CERTIFICATE_VERIFICATION_ERROR) {
			/* check certificate verification status */
			type = gnutls_certificate_type_get(session);
			status = gnutls_session_get_verify_cert_status(session);
			gnutls_certificate_verification_status_print(status, type, &out, 0);
			printf("cert verify output: %s\n", out.data);
			gnutls_free(out.data);
		}
		fprintf(stderr, "*** Handshake failed: %s\n",
			gnutls_strerror(ret));
		goto end;
	} else {
		desc = gnutls_session_get_desc(session);
		printf("- Session info: %s\n", desc);
		gnutls_free(desc);
	}

    while (1) {
        // 输入要发送的消息
        printf("Enter message to send (press 'q' to quit): ");
        fgets(buffer, BUFFER_SIZE, stdin);

        // 发送消息到服务器
        // send(client_socket, buffer, strlen(buffer), 0);
        gnutls_record_send(session, buffer, strlen(buffer));

        // 接收服务器回显的消息
        // int bytes_received = recv(client_socket, buffer, BUFFER_SIZE, 0);
        int bytes_received = gnutls_record_recv(session, buffer, BUFFER_SIZE);

        if (bytes_received < 0) {
            perror("Receiving failed");
            exit(EXIT_FAILURE);
        }
        if (bytes_received == 0) {
            printf("Server disconnected\n");
            break;
        }

        buffer[bytes_received] = '\0';
        printf("Received: %s", buffer);

        // 如果用户输入'q'，则退出
        if (buffer[0] == 'q') {
            gnutls_bye(session, GNUTLS_SHUT_RDWR);
            break;
        }
    }

end:
    // 关闭客户端套接字
    close(client_socket);
    gnutls_deinit(session);
    gnutls_certificate_free_credentials(xcred);
    gnutls_global_deinit();

    return 0;
}
