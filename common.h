#ifndef COMMON_H
#define COMMON_H

#include <stdint.h>
#include <stddef.h>

#define SC_PROTO_VERSION 1
#define SC_NONCE_LEN 32
#define SC_X25519_PUB_LEN 32
#define SC_ED25519_SIG_MAX 128
#define SC_MAC_LEN 32
#define SC_AES_KEY_LEN 32
#define SC_HMAC_KEY_LEN 32
#define SC_IV_LEN 16
#define SC_MAX_NAME_LEN 128
#define SC_MAX_PACKET_LEN 65536
#define SC_MAX_MSG_LEN 8192

enum packet_type {
    PKT_CLIENT_HELLO = 1,
    PKT_SERVER_HELLO = 2,
    PKT_CLIENT_AUTH  = 3,
    PKT_DATA         = 4
};

enum secure_content_type {
    SC_CONTENT_CHAT  = 1,
    SC_CONTENT_CLOSE = 2
};

typedef struct {
    char my_name[SC_MAX_NAME_LEN + 1];
    char peer_name[SC_MAX_NAME_LEN + 1];

    uint8_t my_nonce[SC_NONCE_LEN];
    uint8_t peer_nonce[SC_NONCE_LEN];

    uint8_t my_eph_pub[SC_X25519_PUB_LEN];
    uint8_t peer_eph_pub[SC_X25519_PUB_LEN];

    uint8_t transcript_hash[32];

    uint8_t c2s_enc[SC_AES_KEY_LEN];
    uint8_t s2c_enc[SC_AES_KEY_LEN];
    uint8_t c2s_mac[SC_HMAC_KEY_LEN];
    uint8_t s2c_mac[SC_HMAC_KEY_LEN];
    uint8_t c2s_iv_base[SC_IV_LEN];
    uint8_t s2c_iv_base[SC_IV_LEN];

    uint64_t send_seq;
    uint64_t recv_seq;
    int recv_seq_valid;

    int is_server;
    int established;

    struct evp_pkey_st *my_static_priv;
    struct evp_pkey_st *peer_static_pub;
    struct evp_pkey_st *my_eph_priv;
} session_t;

#endif
