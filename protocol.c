#include "protocol.h"
#include "crypto.h"
#include "net.h"
#include "util.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>

static int build_transcript_hash(session_t *s) {
    size_t c_len = strnlen(s->my_name, SC_MAX_NAME_LEN);
    size_t p_len = strnlen(s->peer_name, SC_MAX_NAME_LEN);
    if (c_len > SC_MAX_NAME_LEN || p_len > SC_MAX_NAME_LEN) return 0;

    size_t total = 4 + 2 + c_len + 2 + p_len + 32 + 32 + 32 + 32;
    uint8_t *buf = xmalloc(total);
    uint8_t *p = buf;

    memcpy(p, "SCv1", 4); p += 4;
    if (s->is_server) {
        store_u16_be(p, (uint16_t)p_len); p += 2;
        memcpy(p, s->peer_name, p_len); p += p_len;
        store_u16_be(p, (uint16_t)c_len); p += 2;
        memcpy(p, s->my_name, c_len); p += c_len;
        memcpy(p, s->peer_nonce, 32); p += 32;
        memcpy(p, s->my_nonce, 32); p += 32;
        memcpy(p, s->peer_eph_pub, 32); p += 32;
        memcpy(p, s->my_eph_pub, 32); p += 32;
    } else {
        store_u16_be(p, (uint16_t)c_len); p += 2;
        memcpy(p, s->my_name, c_len); p += c_len;
        store_u16_be(p, (uint16_t)p_len); p += 2;
        memcpy(p, s->peer_name, p_len); p += p_len;
        memcpy(p, s->my_nonce, 32); p += 32;
        memcpy(p, s->peer_nonce, 32); p += 32;
        memcpy(p, s->my_eph_pub, 32); p += 32;
        memcpy(p, s->peer_eph_pub, 32); p += 32;
    }

    int ok = sha256_bytes(buf, total, s->transcript_hash);
    free(buf);
    return ok;
}

static int make_sig_message(uint8_t role_byte, const uint8_t thash[32], uint8_t out[1 + 32]) {
    out[0] = role_byte;
    memcpy(out + 1, thash, 32);
    return 1;
}

static int derive_session_keys(session_t *s) {
    uint8_t *shared = NULL;
    size_t shared_len = 0;
    uint8_t material[128];
    const uint8_t info[] = "SCv1 session keys";
    int ok = 0;

    if (!x25519_derive(s->my_eph_priv, s->peer_eph_pub, &shared, &shared_len)) goto out;
    if (!hkdf_sha256(s->transcript_hash, 32, shared, shared_len, info, sizeof(info) - 1,
                     material, sizeof(material))) goto out;

    memcpy(s->c2s_enc, material, 32);
    memcpy(s->s2c_enc, material + 32, 32);
    memcpy(s->c2s_mac, material + 64, 32);
    memcpy(s->s2c_mac, material + 96, 32);
    memcpy(s->c2s_iv_base, material + 128 - 32, 16);
    memcpy(s->s2c_iv_base, material + 128 - 16, 16);

    s->send_seq = 0;
    s->recv_seq = 0;
    s->recv_seq_valid = 0;
    s->established = 1;
    ok = 1;
out:
    if (shared) {
        secure_bzero(shared, shared_len);
        free(shared);
    }
    secure_bzero(material, sizeof(material));
    return ok;
}

static void make_iv(const uint8_t base[16], uint64_t seq, uint8_t out[16]) {
    memcpy(out, base, 16);
    for (int i = 0; i < 8; i++) {
        out[15 - i] ^= (uint8_t)(seq & 0xff);
        seq >>= 8;
    }
}

static int send_client_hello(int fd, session_t *s) {
    size_t name_len = strnlen(s->my_name, SC_MAX_NAME_LEN);
    uint32_t len = 1 + 1 + 1 + 1 + 2 + 32 + 32 + (uint32_t)name_len;
    uint8_t *buf = xmalloc(len);
    uint8_t *p = buf;

    *p++ = PKT_CLIENT_HELLO;
    *p++ = SC_PROTO_VERSION;
    *p++ = 0;
    *p++ = 0;
    store_u16_be(p, (uint16_t)name_len); p += 2;
    memcpy(p, s->my_nonce, 32); p += 32;
    memcpy(p, s->my_eph_pub, 32); p += 32;
    memcpy(p, s->my_name, name_len);

    int rc = send_frame(fd, buf, len);
    free(buf);
    return rc == 0;
}

static int recv_client_hello(int fd, session_t *s) {
    uint8_t *buf = NULL;
    uint32_t len = 0;
    int rc = recv_frame(fd, &buf, &len);
    if (rc <= 0) return 0;

    if (len < 70 || buf[0] != PKT_CLIENT_HELLO || buf[1] != SC_PROTO_VERSION) {
        free(buf);
        return 0;
    }

    uint16_t name_len = load_u16_be(buf + 4);
    if (name_len == 0 || name_len > SC_MAX_NAME_LEN || (uint32_t)(70 + name_len) != len) {
        free(buf);
        return 0;
    }

    memcpy(s->peer_nonce, buf + 6, 32);
    memcpy(s->peer_eph_pub, buf + 38, 32);
    memcpy(s->peer_name, buf + 70, name_len);
    s->peer_name[name_len] = '\0';
    free(buf);
    return 1;
}

static int send_server_hello(int fd, session_t *s) {
    uint8_t sig_msg[33];
    uint8_t *sig = NULL;
    size_t sig_len = 0;
    size_t name_len = strnlen(s->my_name, SC_MAX_NAME_LEN);
    uint32_t len;
    uint8_t *buf = NULL;
    uint8_t *p;
    int ok = 0;

    make_sig_message('S', s->transcript_hash, sig_msg);
    if (!ed25519_sign(s->my_static_priv, sig_msg, sizeof(sig_msg), &sig, &sig_len)) goto out;
    len = 1 + 1 + 1 + 1 + 2 + 2 + 32 + 32 + (uint32_t)name_len + (uint32_t)sig_len;
    buf = xmalloc(len);
    p = buf;

    *p++ = PKT_SERVER_HELLO;
    *p++ = SC_PROTO_VERSION;
    *p++ = 1;
    *p++ = 0;
    store_u16_be(p, (uint16_t)name_len); p += 2;
    store_u16_be(p, (uint16_t)sig_len); p += 2;
    memcpy(p, s->my_nonce, 32); p += 32;
    memcpy(p, s->my_eph_pub, 32); p += 32;
    memcpy(p, s->my_name, name_len); p += name_len;
    memcpy(p, sig, sig_len);

    ok = send_frame(fd, buf, len) == 0;
out:
    free(sig);
    free(buf);
    return ok;
}

static int recv_server_hello(int fd, session_t *s) {
    uint8_t *buf = NULL;
    uint32_t len = 0;
    uint8_t sig_msg[33];
    int rc = recv_frame(fd, &buf, &len);
    if (rc <= 0) return 0;

    if (len < 72 || buf[0] != PKT_SERVER_HELLO || buf[1] != SC_PROTO_VERSION) {
        free(buf);
        return 0;
    }

    uint16_t name_len = load_u16_be(buf + 4);
    uint16_t sig_len = load_u16_be(buf + 6);
    if (name_len == 0 || name_len > SC_MAX_NAME_LEN || sig_len == 0 || sig_len > SC_ED25519_SIG_MAX) {
        free(buf);
        return 0;
    }
    if ((uint32_t)(72 + name_len + sig_len) != len) {
        free(buf);
        return 0;
    }

    memcpy(s->peer_nonce, buf + 8, 32);
    memcpy(s->peer_eph_pub, buf + 40, 32);
    memcpy(s->peer_name, buf + 72, name_len);
    s->peer_name[name_len] = '\0';

    if (!build_transcript_hash(s)) {
        free(buf);
        return 0;
    }
    make_sig_message('S', s->transcript_hash, sig_msg);
    if (!ed25519_verify(s->peer_static_pub, sig_msg, sizeof(sig_msg),
                        buf + 72 + name_len, sig_len)) {
        free(buf);
        return 0;
    }

    free(buf);
    return 1;
}

static int send_client_auth(int fd, session_t *s) {
    uint8_t sig_msg[33];
    uint8_t *sig = NULL;
    size_t sig_len = 0;
    uint32_t len;
    uint8_t *buf = NULL;
    uint8_t *p;
    int ok = 0;

    make_sig_message('C', s->transcript_hash, sig_msg);
    if (!ed25519_sign(s->my_static_priv, sig_msg, sizeof(sig_msg), &sig, &sig_len)) goto out;
    len = 1 + 2 + (uint32_t)sig_len;
    buf = xmalloc(len);
    p = buf;
    *p++ = PKT_CLIENT_AUTH;
    store_u16_be(p, (uint16_t)sig_len); p += 2;
    memcpy(p, sig, sig_len);
    ok = send_frame(fd, buf, len) == 0;
out:
    free(sig);
    free(buf);
    return ok;
}

static int recv_client_auth(int fd, session_t *s) {
    uint8_t *buf = NULL;
    uint32_t len = 0;
    uint8_t sig_msg[33];
    int rc = recv_frame(fd, &buf, &len);
    if (rc <= 0) return 0;
    if (len < 3 || buf[0] != PKT_CLIENT_AUTH) {
        free(buf);
        return 0;
    }

    uint16_t sig_len = load_u16_be(buf + 1);
    if (sig_len == 0 || sig_len > SC_ED25519_SIG_MAX || (uint32_t)(3 + sig_len) != len) {
        free(buf);
        return 0;
    }

    make_sig_message('C', s->transcript_hash, sig_msg);
    rc = ed25519_verify(s->peer_static_pub, sig_msg, sizeof(sig_msg), buf + 3, sig_len);
    free(buf);
    return rc;
}

int run_client_handshake(int fd, session_t *s) {
    if (!random_bytes(s->my_nonce, 32)) return 0;
    if (!x25519_generate(&s->my_eph_priv, s->my_eph_pub)) return 0;
    if (!send_client_hello(fd, s)) return 0;
    if (!recv_server_hello(fd, s)) return 0;
    if (!send_client_auth(fd, s)) return 0;
    if (!derive_session_keys(s)) return 0;
    return 1;
}

int run_server_handshake(int fd, session_t *s) {
    if (!random_bytes(s->my_nonce, 32)) return 0;
    if (!x25519_generate(&s->my_eph_priv, s->my_eph_pub)) return 0;
    if (!recv_client_hello(fd, s)) return 0;
    if (!build_transcript_hash(s)) return 0;
    if (!send_server_hello(fd, s)) return 0;
    if (!recv_client_auth(fd, s)) return 0;
    if (!derive_session_keys(s)) return 0;
    return 1;
}

int send_secure_message(int fd, session_t *s, const uint8_t *msg, size_t msg_len) {
    const uint8_t *enc_key = s->is_server ? s->s2c_enc : s->c2s_enc;
    const uint8_t *mac_key = s->is_server ? s->s2c_mac : s->c2s_mac;
    const uint8_t *iv_base = s->is_server ? s->s2c_iv_base : s->c2s_iv_base;
    uint8_t iv[16];
    uint8_t *ct = NULL;
    size_t ct_len = 0;
    uint8_t mac[32];
    uint8_t *buf = NULL;
    uint8_t *mp = NULL;
    uint32_t total_len;
    int ok = 0;

    if (msg_len > SC_MAX_MSG_LEN) return 0;

    make_iv(iv_base, s->send_seq, iv);
    if (!aes256ctr_crypt(enc_key, iv, msg, msg_len, &ct, &ct_len)) goto out;

    total_len = 1 + 8 + 16 + 4 + (uint32_t)ct_len + 32;
    buf = xmalloc(total_len);
    uint8_t *p = buf;
    *p++ = PKT_DATA;
    store_u64_be(p, s->send_seq); p += 8;
    memcpy(p, iv, 16); p += 16;
    store_u32_be(p, (uint32_t)ct_len); p += 4;
    memcpy(p, ct, ct_len); p += ct_len;
    mp = p;

    if (!hmac_sha256(mac_key, 32, buf, total_len - 32, mac)) goto out;
    memcpy(mp, mac, 32);
    if (send_frame(fd, buf, total_len) != 0) goto out;

    s->send_seq++;
    ok = 1;
out:
    free(ct);
    free(buf);
    return ok;
}

int send_close_packet(int fd) {
    uint8_t b = PKT_CLOSE;
    return send_frame(fd, &b, 1) == 0;
}

int recv_and_process_packet(int fd, session_t *s, uint8_t **msg, size_t *msg_len, int *is_close) {
    uint8_t *buf = NULL;
    uint32_t len = 0;
    int rc = recv_frame(fd, &buf, &len);
    if (rc <= 0) return 0;

    *is_close = 0;
    *msg = NULL;
    *msg_len = 0;

    if (buf[0] == PKT_CLOSE) {
        *is_close = 1;
        free(buf);
        return 1;
    }

    if (buf[0] != PKT_DATA || len < 1 + 8 + 16 + 4 + 32) {
        free(buf);
        return 0;
    }

    const uint8_t *enc_key = s->is_server ? s->c2s_enc : s->s2c_enc;
    const uint8_t *mac_key = s->is_server ? s->c2s_mac : s->s2c_mac;
    uint64_t seq = load_u64_be(buf + 1);
    uint32_t ct_len = load_u32_be(buf + 25);
    if ((uint32_t)(1 + 8 + 16 + 4 + ct_len + 32) != len || ct_len > SC_MAX_MSG_LEN + 16) {
        free(buf);
        return 0;
    }

    uint8_t calc_mac[32];
    if (!hmac_sha256(mac_key, 32, buf, len - 32, calc_mac)) {
        free(buf);
        return 0;
    }
    if (ct_memcmp(calc_mac, buf + len - 32, 32) != 0) {
        free(buf);
        return 0;
    }

    if (s->recv_seq_valid && seq <= s->recv_seq) {
        free(buf);
        return 0;
    }

    uint8_t *pt = NULL;
    size_t pt_len = 0;
    if (!aes256ctr_crypt(enc_key, buf + 9, buf + 29, ct_len, &pt, &pt_len)) {
        free(buf);
        return 0;
    }

    s->recv_seq = seq;
    s->recv_seq_valid = 1;
    *msg = pt;
    *msg_len = pt_len;
    free(buf);
    return 1;
}
