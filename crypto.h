#ifndef CRYPTO_H
#define CRYPTO_H

#include <stddef.h>
#include <stdint.h>
#include <openssl/evp.h>

int crypto_init(void);
void crypto_cleanup(void);

EVP_PKEY *load_private_key_pem(const char *path);
EVP_PKEY *load_public_key_pem(const char *path);

int random_bytes(uint8_t *out, size_t len);
int sha256_bytes(const uint8_t *in, size_t in_len, uint8_t out[32]);

int ed25519_sign(EVP_PKEY *priv, const uint8_t *msg, size_t msg_len,
                 uint8_t **sig, size_t *sig_len);
int ed25519_verify(EVP_PKEY *pub, const uint8_t *msg, size_t msg_len,
                   const uint8_t *sig, size_t sig_len);

int x25519_generate(EVP_PKEY **out_priv, uint8_t pub[32]);
int x25519_derive(EVP_PKEY *priv, const uint8_t peer_pub[32],
                  uint8_t **secret, size_t *secret_len);

int hkdf_sha256(const uint8_t *salt, size_t salt_len,
                const uint8_t *ikm, size_t ikm_len,
                const uint8_t *info, size_t info_len,
                uint8_t *out, size_t out_len);

int hmac_sha256(const uint8_t *key, size_t key_len,
                const uint8_t *data, size_t data_len,
                uint8_t out[32]);

int aes256ctr_crypt(const uint8_t key[32], const uint8_t iv[16],
                    const uint8_t *in, size_t in_len,
                    uint8_t **out, size_t *out_len);

#endif
