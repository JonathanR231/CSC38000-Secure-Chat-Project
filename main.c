#include "common.h"
#include "crypto.h"
#include "net.h"
#include "protocol.h"
#include "util.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <getopt.h>
#include <sys/select.h>

static void usage(const char *prog) {
    fprintf(stderr,
        "Usage:\n"
        "  %s -l <port> -k <my_private.pem> -p <peer_public.pem> [-n my_name]\n"
        "  %s -c <host> <port> -k <my_private.pem> -p <peer_public.pem> [-n my_name]\n",
        prog, prog);
}

static void cleanup_session(session_t *s) {
    EVP_PKEY_free(s->my_static_priv);
    EVP_PKEY_free(s->peer_static_pub);
    EVP_PKEY_free(s->my_eph_priv);
    secure_bzero(s, sizeof(*s));
}

static void print_prompt(const session_t *s) {
    printf("%s> ", s->my_name);
    fflush(stdout);
}

static int chat_loop(int fd, session_t *s) {
    char line[SC_MAX_MSG_LEN + 2];
    int stdin_open = 1;

    fprintf(stderr, "Secure session established with %s\n", s->peer_name);
    fprintf(stderr, "Type /quit to exit.\n");
    print_prompt(s);

    for (;;) {
        fd_set rfds;
        FD_ZERO(&rfds);
        FD_SET(fd, &rfds);
        int maxfd = fd + 1;
        if (stdin_open) {
            FD_SET(STDIN_FILENO, &rfds);
            if (STDIN_FILENO >= maxfd) maxfd = STDIN_FILENO + 1;
        }

        if (select(maxfd, &rfds, NULL, NULL, NULL) < 0) {
            perror("select");
            return 0;
        }

        if (stdin_open && FD_ISSET(STDIN_FILENO, &rfds)) {
            if (!fgets(line, sizeof(line), stdin)) {
                stdin_open = 0;
            } else {
                size_t len = strlen(line);
                if (len > 0 && line[len - 1] == '\n') {
                    line[--len] = '\0';
                }
                if (strcmp(line, "/quit") == 0) {
                    send_close_packet(fd, s);
                    return 1;
                }
                if (!send_secure_message(fd, s, (const uint8_t *)line, len)) {
                    fprintf(stderr, "send failed\n");
                    return 0;
                }
                print_prompt(s);
            }
        }

        if (FD_ISSET(fd, &rfds)) {
            uint8_t *msg = NULL;
            size_t msg_len = 0;
            int is_close = 0;

            if (!recv_and_process_packet(fd, s, &msg, &msg_len, &is_close)) {
                fprintf(stderr, "connection closed or invalid packet\n");
                free(msg);
                return 0;
            }
            if (is_close) {
                fprintf(stderr, "peer closed the chat\n");
                free(msg);
                return 1;
            }

            printf("\r%s: %.*s\n", s->peer_name, (int)msg_len, (char *)msg);
            fflush(stdout);
            print_prompt(s);
            free(msg);
        }
    }
}

int main(int argc, char **argv) {
    int opt;
    int listen_mode = 0;
    const char *host = NULL;
    const char *port = NULL;
    const char *my_priv_path = NULL;
    const char *peer_pub_path = NULL;
    const char *my_name = NULL;
    int fd = -1;
    int listen_fd = -1;
    session_t s;
    memset(&s, 0, sizeof(s));

    while ((opt = getopt(argc, argv, "l:c:k:p:n:")) != -1) {
        switch (opt) {
            case 'l':
                listen_mode = 1;
                port = optarg;
                break;
            case 'c':
                host = optarg;
                if (optind >= argc) {
                    usage(argv[0]);
                    return 1;
                }
                port = argv[optind++];
                break;
            case 'k':
                my_priv_path = optarg;
                break;
            case 'p':
                peer_pub_path = optarg;
                break;
            case 'n':
                my_name = optarg;
                break;
            default:
                usage(argv[0]);
                return 1;
        }
    }

    if (!port || !my_priv_path || !peer_pub_path || (!listen_mode && !host)) {
        usage(argv[0]);
        return 1;
    }

    s.is_server = listen_mode;
    strncpy(s.my_name, my_name ? my_name : (listen_mode ? "server" : "client"), SC_MAX_NAME_LEN);
    s.my_name[SC_MAX_NAME_LEN] = '\0';

    if (!crypto_init()) {
        fprintf(stderr, "crypto init failed\n");
        return 1;
    }

    s.my_static_priv = load_private_key_pem(my_priv_path);
    s.peer_static_pub = load_public_key_pem(peer_pub_path);
    if (!s.my_static_priv || !s.peer_static_pub) {
        fprintf(stderr, "failed to load keys\n");
        cleanup_session(&s);
        crypto_cleanup();
        return 1;
    }

    if (listen_mode) {
        listen_fd = create_server_socket(port);
        if (listen_fd < 0) die("create_server_socket");
        fprintf(stderr, "Listening on port %s...\n", port);
        fd = accept_client(listen_fd);
        if (fd < 0) die("accept_client");
        close(listen_fd);
        fprintf(stderr, "Client connected. Running handshake...\n");
        if (!run_server_handshake(fd, &s)) {
            fprintf(stderr, "server handshake failed\n");
            close(fd);
            cleanup_session(&s);
            crypto_cleanup();
            return 1;
        }
    } else {
        fd = connect_to_server(host, port);
        if (fd < 0) die("connect_to_server");
        fprintf(stderr, "Connected. Running handshake...\n");
        if (!run_client_handshake(fd, &s)) {
            fprintf(stderr, "client handshake failed\n");
            close(fd);
            cleanup_session(&s);
            crypto_cleanup();
            return 1;
        }
    }

    int ok = chat_loop(fd, &s);
    close(fd);
    cleanup_session(&s);
    crypto_cleanup();
    return ok ? 0 : 1;
}
