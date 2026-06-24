#ifndef UTILS_H
#define UTILS_H

#include <stdint.h>
#include <stddef.h>

/* Secure memory operations */
void secure_zero(void *ptr, size_t len);
int lock_sensitive(void *ptr, size_t len);
int ct_memcmp(const void *a, const void *b, size_t n);

/* Random bytes generation */
void random_bytes(uint8_t *buf, size_t len);

/* AES-256-GCM functions */
int aes256gcm_encrypt(const uint8_t *plain, size_t plain_len,
                      const uint8_t *key, const uint8_t *iv, size_t iv_len,
                      const uint8_t *aad, size_t aad_len,
                      uint8_t *cipher, uint8_t *tag);
int aes256gcm_decrypt(const uint8_t *cipher, size_t cipher_len,
                      const uint8_t *tag,
                      const uint8_t *key, const uint8_t *iv, size_t iv_len,
                      const uint8_t *aad, size_t aad_len,
                      uint8_t *plain);

/* Secure file operations */
int secure_shred_file(const char *path);

/* System security checks */
int check_swap_security(void);

/* Progress callback type */
typedef void (*progress_callback_t)(const char *label, size_t cur, size_t total, void *user_data);

#endif /* UTILS_H */
