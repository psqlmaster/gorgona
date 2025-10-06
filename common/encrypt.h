#ifndef ENCRYPT_H
#define ENCRYPT_H

#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <stddef.h>

#define PUBKEY_HASH_LEN 8
#define AES_BLOCK_SIZE 16
#define GCM_TAG_LEN 16

typedef struct {
    unsigned char hash[PUBKEY_HASH_LEN];
} RecipientHash;

/* Проверяет наличие файлов ключей (для обратной совместимости) */
int check_key_files(int verbose);
/* Генерирует пару ключей RSA и переименовывает их по хешу */
int generate_rsa_keys(int verbose);
/* Вычисляет хеш публичного ключа */
unsigned char *compute_pubkey_hash(EVP_PKEY *pubkey, size_t *hash_len, int verbose);
/* Шифрует сообщение с использованием публичного ключа */
int encrypt_message(const char *plaintext, unsigned char **encrypted, size_t *encrypted_len,
                   unsigned char **encrypted_key, size_t *encrypted_key_len,
                   unsigned char **iv, size_t *iv_len, unsigned char **tag, size_t *tag_len,
                   const char *pubkey_file, int verbose);
/* Расшифровывает сообщение с использованием указанного приватного ключа */
int decrypt_message(unsigned char *encrypted, size_t encrypted_len, unsigned char *encrypted_key,
                   size_t encrypted_key_len, unsigned char *iv, size_t iv_len,
                   unsigned char *tag, char **plaintext, const char *privkey_file, int verbose);
/* Кодирует данные в base64 */
char *base64_encode(const unsigned char *data, size_t len);
/* Декодирует данные из base64 */
unsigned char *base64_decode(const char *data, size_t *out_len);

#endif
