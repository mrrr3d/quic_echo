#include <stdio.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <string.h>

int main () {
  int cli_socket;
  struct sockaddr_in serv_addr;

  serv_addr.sin_addr.s_addr = inet_addr("127.0.0.1");
  serv_addr.sin_family = AF_INET;
  serv_addr.sin_port = htons(9999);

  cli_socket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
  // connect (cli_socket, (struct sockaddr*)&serv_addr, sizeof(serv_addr));

  char buf[128] = "thisis udp!";
  sendto(cli_socket, buf, strlen(buf), 0, (struct sockaddr*)&serv_addr, sizeof(serv_addr));
  close(cli_socket);

  return 0;
}