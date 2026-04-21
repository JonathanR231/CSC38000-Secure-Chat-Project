#include "net.h"
#include "util.h"
#include "common.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>

int create_server_socket(const char *port) {
    struct addrinfo hints, *res, *rp;
    int fd = -1;
    int opt = 1;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;

    int rc = getaddrinfo(NULL, port, &hints, &res);
    if (rc != 0) {
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(rc));
        return -1;
    }

    for (rp = res; rp; rp = rp->ai_next) {
        fd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (fd < 0) continue;
        setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
        if (bind(fd, rp->ai_addr, rp->ai_addrlen) == 0 && listen(fd, 1) == 0) {
            break;
        }
        close(fd);
        fd = -1;
    }

    freeaddrinfo(res);
    return fd;
}

int accept_client(int listen_fd) {
    struct sockaddr_storage ss;
    socklen_t slen = sizeof(ss);
    return accept(listen_fd, (struct sockaddr *)&ss, &slen);
}

int connect_to_server(const char *host, const char *port) {
    struct addrinfo hints, *res, *rp;
    int fd = -1;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    int rc = getaddrinfo(host, port, &hints, &res);
    if (rc != 0) {
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(rc));
        return -1;
    }

    for (rp = res; rp; rp = rp->ai_next) {
        fd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (fd < 0) continue;
        if (connect(fd, rp->ai_addr, rp->ai_addrlen) == 0) {
            break;
        }
        close(fd);
        fd = -1;
    }

    freeaddrinfo(res);
    return fd;
}

int send_frame(int fd, const uint8_t *buf, uint32_t len) {
    uint8_t hdr[4];
    if (len > SC_MAX_PACKET_LEN) return -1;
    store_u32_be(hdr, len);
    if (writen(fd, hdr, sizeof(hdr)) != (ssize_t)sizeof(hdr)) return -1;
    if (len > 0 && writen(fd, buf, len) != (ssize_t)len) return -1;
    return 0;
}

int recv_frame(int fd, uint8_t **buf, uint32_t *len) {
    uint8_t hdr[4];
    ssize_t r = readn(fd, hdr, sizeof(hdr));
    if (r == 0) return 0;
    if (r != (ssize_t)sizeof(hdr)) return -1;

    uint32_t n = load_u32_be(hdr);
    if (n == 0 || n > SC_MAX_PACKET_LEN) return -1;

    uint8_t *p = xmalloc(n);
    r = readn(fd, p, n);
    if (r != (ssize_t)n) {
        free(p);
        return -1;
    }

    *buf = p;
    *len = n;
    return 1;
}
