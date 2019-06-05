#ifndef BEETLE_SOCKET_H
#define BEETLE_SOCKET_H

#include <sys/socket.h>

int sock_addr(const char* host, unsigned short port, struct sockaddr_storage *addr);
//没有dns查询    
int ip_to_address (const char *host, unsigned short port, struct sockaddr_storage *addr);
int write_data(int fd, uint8_t *bytes, int len);
int sock_nonblock(int fd, int set);

#endif
