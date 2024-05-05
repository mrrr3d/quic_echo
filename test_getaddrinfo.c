#include <stdio.h>
#include <unistd.h>
#include <netdb.h>
#include <arpa/inet.h>

int main () {
  struct addrinfo *res, *p;
  struct addrinfo hint = {0};
  int fd;
  hint.ai_socktype = SOCK_STREAM;
  hint.ai_family = AF_UNSPEC;

  getaddrinfo("bing.com", NULL, &hint, &res);
  for (p = res; p; p = p->ai_next) {
    char host[NI_MAXHOST];
    getnameinfo(p->ai_addr, p->ai_addrlen, host, NI_MAXHOST, NULL, 0, NI_NUMERICHOST);
    
    printf("ip: %s\n", host);
  }
  
  return 0;
}