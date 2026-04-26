/* 
* BSD 3-Clause License
* Copyright (c) 2025, Alexander Shcheglov
* All rights reserved. 
*/

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

/* Checks for the presence of key files (for backward compatibility) */
int check_key_files(int verbose);
/* Generates an RSA key pair and renames them based on their hash */
int generate_rsa_keys(int verbose);
/* Вычисляет хеш публичного ключа */
unsigned char *compute_pubkey_hash(EVP_PKEY *pubkey, size_t *hash_len, int verbose);
/* Encrypts the message using a public key */
int encrypt_message(const char *plaintext, unsigned char **encrypted, size_t *encrypted_len,
                   unsigned char **encrypted_key, size_t *encrypted_key_len,
                   unsigned char **iv, size_t *iv_len, unsigned char **tag, size_t *tag_len,
                   const char *pubkey_file, int verbose);
/* Decrypts the message using the specified private key */
int decrypt_message(unsigned char *encrypted, size_t encrypted_len, unsigned char *encrypted_key,
                   size_t encrypted_key_len, unsigned char *iv, size_t iv_len,
                   unsigned char *tag, char **plaintext, const char *privkey_file, int verbose);
/* Encodes data in Base64 */
char *base64_encode(const unsigned char *data, size_t len);
/* Decodes data from Base64 */
unsigned char *base64_decode(const char *data, size_t *out_len);
/* This is a mathematical proof to the server that it is indeed the key owner who is requesting the message be revoked. */
int sign_message_id(uint64_t id, const char *priv_key_path, char *out_b64, size_t out_len, int verbose);
/* Calculates the hash of a raw public key buffer (PEM) */
int compute_raw_pubkey_hash(unsigned char *pub_raw, size_t pub_len, unsigned char *out_hash);
/* Verifies the message ID signature using the sent key */
int verify_id_signature(uint64_t id, unsigned char *pub_raw, size_t pub_len, const char *sig_b64);
#endif
