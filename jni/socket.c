#include <stdint.h>
#include "socket.h"

#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <limits.h> /* INT_MAX, PATH_MAX */
#include <sys/uio.h> /* writev */
#include <sys/ioctl.h>
#include <errno.h>
#include <netdb.h>
#include <strings.h>
#include <stdio.h>

struct sockaddr_in sock_addr(const char* host, unsigned short port) {
    char port_str[10] = {0};
    struct sockaddr_in addr;
    bzero(&addr, sizeof(addr));
    sprintf(port_str, "%hu", port);
    
    struct addrinfo hints, *res, *res0;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family   = PF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;
    
    int gai_error = getaddrinfo(host, port_str, &hints, &res0);
    
    if (gai_error) {
        return addr;
    }

    for(res = res0; res != NULL; res = res->ai_next) {
        if (res->ai_family == AF_INET) {
            memcpy(&addr, res->ai_addr, res->ai_addrlen);
            break;
        }
    }
    freeaddrinfo(res0);
    return addr;
}

int ipv4_to_address (const char *host, unsigned short port, struct sockaddr_in *addr) {
    int r;
    r = inet_pton(AF_INET, host, &(addr->sin_addr));
    if (r == 1) {
        addr->sin_family = AF_INET;
        addr->sin_port = htons(port);
        return 0;
    }
    return -1;
}

int sock_nonblock(int fd, int set) {
    int r;
    
    do
        r = ioctl(fd, FIONBIO, &set);
    while (r == -1 && errno == EINTR);
    
    return r;
}

int write_data(int fd, uint8_t *bytes, int len) {
    int n = 0;
    int err = 0;

    do {
        n = send(fd, bytes, len, 0);
    } while(n == -1 && errno == EINTR);
    if (n < 0) {
        if (errno != EAGAIN && errno != EWOULDBLOCK) {
            return -1;
        }
        return 0;
    } else {
        return n;
    }
}
