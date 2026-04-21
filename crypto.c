#include "crypto.h"
#include "util.h"

#include <stdio.h>
#include <string.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/hmac.h>
#include <openssl/sha.h>
#include <openssl/err.h>

int crypto_init(void) {
    ERR_load_crypto_strings();
    OpenSSL_add_all_algorithms();
    return 1;
}

void crypto_cleanup(void) {
    EVP_cleanup();
    ERR_free_strings();
}

static void print_ssl_errors(void) {
    unsigned long err;
    while ((err = ERR_get_error()) != 0) {
        fprintf(stderr, "OpenSSL: %s\n", ERR_error_string(err, NULL));
    }
}

EVP_PKEY *load_private_key_pem(const char *path) {
    FILE *f = fopen(path, "r");
    if (!f) return NULL;
    EVP_PKEY *p = PEM_read_PrivateKey(f, NULL, NULL, NULL);
    fclose(f);
    if (!p) print_ssl_errors();
    return p;
}

EVP_PKEY *load_public_key_pem(const char *path) {
    FILE *f = fopen(path, "r");
    if (!f) return NULL;
    EVP_PKEY *p = PEM_read_PUBKEY(f, NULL, NULL, NULL);
    fclose(f);
    if (!p) print_ssl_errors();
    return p;
}

int random_bytes(uint8_t *out, size_t len) {
    return RAND_bytes(out, (int)len) == 1;
}

int sha256_bytes(const uint8_t *in, size_t in_len, uint8_t out[32]) {
    return SHA256(in, in_len, out) != NULL;
}

int ed25519_sign(EVP_PKEY *priv, const uint8_t *msg, size_t msg_len,
                 uint8_t **sig, size_t *sig_len) {
    int ok = 0;
    EVP_MD_CTX *ctx = NULL;
    uint8_t *tmp = NULL;

    if (!priv || EVP_PKEY_base_id(priv) != EVP_PKEY_ED25519) {
        fprintf(stderr, "private key must be Ed25519\n");
        return 0;
    }

    ctx = EVP_MD_CTX_new();
    if (!ctx) goto out;
    if (EVP_DigestSignInit(ctx, NULL, NULL, NULL, priv) != 1) goto out;
    if (EVP_DigestSign(ctx, NULL, sig_len, msg, msg_len) != 1) goto out;
    tmp = xmalloc(*sig_len);
    if (EVP_DigestSign(ctx, tmp, sig_len, msg, msg_len) != 1) goto out;
    *sig = tmp;
    tmp = NULL;
    ok = 1;
out:
    if (!ok) print_ssl_errors();
    free(tmp);
    EVP_MD_CTX_free(ctx);
    return ok;
}

int ed25519_verify(EVP_PKEY *pub, const uint8_t *msg, size_t msg_len,
                   const uint8_t *sig, size_t sig_len) {
    EVP_MD_CTX *ctx = NULL;
    int rc = 0;

    if (!pub || EVP_PKEY_base_id(pub) != EVP_PKEY_ED25519) {
        fprintf(stderr, "public key must be Ed25519\n");
        return 0;
    }

    ctx = EVP_MD_CTX_new();
    if (!ctx) goto out;
    if (EVP_DigestVerifyInit(ctx, NULL, NULL, NULL, pub) != 1) goto out;
    rc = EVP_DigestVerify(ctx, sig, sig_len, msg, msg_len);
    if (rc != 1) {
        rc = 0;
        goto out;
    }
    rc = 1;
out:
    if (!rc) print_ssl_errors();
    EVP_MD_CTX_free(ctx);
    return rc;
}

int x25519_generate(EVP_PKEY **out_priv, uint8_t pub[32]) {
    int ok = 0;
    EVP_PKEY_CTX *pctx = NULL;
    EVP_PKEY *priv = NULL;
    size_t pub_len = 32;

    pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, NULL);
    if (!pctx) goto out;
    if (EVP_PKEY_keygen_init(pctx) != 1) goto out;
    if (EVP_PKEY_keygen(pctx, &priv) != 1) goto out;
    if (EVP_PKEY_get_raw_public_key(priv, pub, &pub_len) != 1) goto out;
    if (pub_len != 32) goto out;
    *out_priv = priv;
    priv = NULL;
    ok = 1;
out:
    if (!ok) print_ssl_errors();
    EVP_PKEY_free(priv);
    EVP_PKEY_CTX_free(pctx);
    return ok;
}

int x25519_derive(EVP_PKEY *priv, const uint8_t peer_pub[32],
                  uint8_t **secret, size_t *secret_len) {
    int ok = 0;
    EVP_PKEY *peer = NULL;
    EVP_PKEY_CTX *ctx = NULL;
    uint8_t *tmp = NULL;

    peer = EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, NULL, peer_pub, 32);
    if (!peer) goto out;

    ctx = EVP_PKEY_CTX_new(priv, NULL);
    if (!ctx) goto out;
    if (EVP_PKEY_derive_init(ctx) != 1) goto out;
    if (EVP_PKEY_derive_set_peer(ctx, peer) != 1) goto out;
    if (EVP_PKEY_derive(ctx, NULL, secret_len) != 1) goto out;
    tmp = xmalloc(*secret_len);
    if (EVP_PKEY_derive(ctx, tmp, secret_len) != 1) goto out;
    *secret = tmp;
    tmp = NULL;
    ok = 1;
out:
    if (!ok) print_ssl_errors();
    free(tmp);
    EVP_PKEY_free(peer);
    EVP_PKEY_CTX_free(ctx);
    return ok;
}

int hmac_sha256(const uint8_t *key, size_t key_len,
                const uint8_t *data, size_t data_len,
                uint8_t out[32]) {
    unsigned int out_len = 0;
    unsigned char *res = HMAC(EVP_sha256(), key, (int)key_len, data, data_len, out, &out_len);
    return res != NULL && out_len == 32;
}

int hkdf_sha256(const uint8_t *salt, size_t salt_len,
                const uint8_t *ikm, size_t ikm_len,
                const uint8_t *info, size_t info_len,
                uint8_t *out, size_t out_len) {
    uint8_t prk[32];
    uint8_t t[32];
    uint8_t ctr = 1;
    size_t produced = 0;
    size_t t_len = 0;
    unsigned int mac_len = 0;

    if (out_len > 255 * 32) return 0;
    if (!HMAC(EVP_sha256(), salt, (int)salt_len, ikm, ikm_len, prk, &mac_len) || mac_len != 32) {
        return 0;
    }

    while (produced < out_len) {
        size_t input_len = t_len + info_len + 1;
        uint8_t *input = xmalloc(input_len);
        if (t_len > 0) memcpy(input, t, t_len);
        if (info_len > 0) memcpy(input + t_len, info, info_len);
        input[input_len - 1] = ctr;

        if (!HMAC(EVP_sha256(), prk, 32, input, input_len, t, &mac_len) || mac_len != 32) {
            secure_bzero(input, input_len);
            free(input);
            secure_bzero(prk, sizeof(prk));
            secure_bzero(t, sizeof(t));
            return 0;
        }

        secure_bzero(input, input_len);
        free(input);
        t_len = 32;

        size_t chunk = (out_len - produced < t_len) ? (out_len - produced) : t_len;
        memcpy(out + produced, t, chunk);
        produced += chunk;
        ctr++;
    }

    secure_bzero(prk, sizeof(prk));
    secure_bzero(t, sizeof(t));
    return 1;
}

int aes256ctr_crypt(const uint8_t key[32], const uint8_t iv[16],
                    const uint8_t *in, size_t in_len,
                    uint8_t **out, size_t *out_len) {
    int ok = 0;
    int n1 = 0, n2 = 0;
    EVP_CIPHER_CTX *ctx = NULL;
    uint8_t *tmp = NULL;

    ctx = EVP_CIPHER_CTX_new();
    if (!ctx) goto out;
    tmp = xmalloc(in_len + 16);

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_ctr(), NULL, key, iv) != 1) goto out;
    if (EVP_EncryptUpdate(ctx, tmp, &n1, in, (int)in_len) != 1) goto out;
    if (EVP_EncryptFinal_ex(ctx, tmp + n1, &n2) != 1) goto out;

    *out = tmp;
    *out_len = (size_t)(n1 + n2);
    tmp = NULL;
    ok = 1;
out:
    if (!ok) print_ssl_errors();
    free(tmp);
    EVP_CIPHER_CTX_free(ctx);
    return ok;
}
