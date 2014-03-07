#ifndef BEETLE_SOCKET_H
#define BEETLE_SOCKET_H

struct sockaddr_in sock_addr(const char* host, unsigned short port);
int write_data(int fd, uint8_t *bytes, int len);
int sock_nonblock(int fd, int set);

#endif
