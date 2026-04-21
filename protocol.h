#ifndef PROTOCOL_H
#define PROTOCOL_H

#include "common.h"

int run_client_handshake(int fd, session_t *s);
int run_server_handshake(int fd, session_t *s);

int send_secure_message(int fd, session_t *s, const uint8_t *msg, size_t msg_len);
int recv_and_process_packet(int fd, session_t *s, uint8_t **msg, size_t *msg_len, int *is_close);
int send_close_packet(int fd, session_t *s);

#endif
