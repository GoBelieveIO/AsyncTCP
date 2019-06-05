#ifndef BEETLE_SOCKET_H
#define BEETLE_SOCKET_H

struct sockaddr_in sock_addr(const char* host, unsigned short port);
//没有dns查询
int ipv4_to_address(const char *host, unsigned short port, struct sockaddr_in *addr);
int write_data(int fd, uint8_t *bytes, int len);
int sock_nonblock(int fd, int set);

#endif
