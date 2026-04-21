#ifndef NET_H
#define NET_H

#include <stdint.h>
#include <stddef.h>

int create_server_socket(const char *port);
int accept_client(int listen_fd);
int connect_to_server(const char *host, const char *port);

int send_frame(int fd, const uint8_t *buf, uint32_t len);
int recv_frame(int fd, uint8_t **buf, uint32_t *len);

#endif
