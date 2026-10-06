/* 
* BSD 3-Clause License
* Copyright (c) 2025, Alexander Shcheglov
* All rights reserved. 
*/

#include <openssl/bn.h>
#include "encrypt.h"
#include <openssl/sha.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/buffer.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if OPENSSL_VERSION_NUMBER < 0x10100000L
#define EVP_MD_CTX_new() ({ EVP_MD_CTX *ctx = malloc(sizeof(EVP_MD_CTX)); EVP_MD_CTX_init(ctx); ctx; })
#define EVP_MD_CTX_free(ctx) do { EVP_MD_CTX_cleanup(ctx); free(ctx); } while (0)
#endif

/* Checks for the presence of the public.pem and private.pem files (for backward compatibility) */
int check_key_files(int verbose) {
    FILE *pub_fp = fopen("public.pem", "r");
    if (!pub_fp) {
        fprintf(stderr, "Файл публичного ключа public.pem не найден\n");
        return -1;
    }
    fclose(pub_fp);

    FILE *priv_fp = fopen("private.pem", "r");
    if (!priv_fp) {
        fprintf(stderr, "Файл приватного ключа private.pem не найден\n");
        return -1;
    }
    fclose(priv_fp);

    if (verbose) printf("Файлы ключей public.pem и private.pem найдены\n");
    return 0;
}

/* Generates an RSA key pair and renames them based on their hash */
int generate_rsa_keys(int verbose) {
    EVP_PKEY *pkey = NULL;
    char *pubkey_hash_b64 = NULL;

    while (1) {
        EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
        if (!ctx || EVP_PKEY_keygen_init(ctx) <= 0) {
            fprintf(stderr, "Failed to initialize key generation: %s\n", ERR_error_string(ERR_get_error(), NULL));
            if (ctx) EVP_PKEY_CTX_free(ctx);
            return -1;
        }

        if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 2048) <= 0) {
            fprintf(stderr, "Unable to determine the RSA key size: %s\n", ERR_error_string(ERR_get_error(), NULL));
            EVP_PKEY_CTX_free(ctx);
            return -1;
        }

        if (EVP_PKEY_keygen(ctx, &pkey) <= 0) {
            fprintf(stderr, "Unable to generate an RSA key: %s\n", ERR_error_string(ERR_get_error(), NULL));
            EVP_PKEY_CTX_free(ctx);
            return -1;
        }
        EVP_PKEY_CTX_free(ctx);

        /* Calculating the hash of the public key */
        size_t hash_len;
        unsigned char *pubkey_hash = compute_pubkey_hash(pkey, &hash_len, verbose);
        if (!pubkey_hash || hash_len != PUBKEY_HASH_LEN) {
            fprintf(stderr, "Unable to calculate the hash of the public key\n");
            free(pubkey_hash);
            EVP_PKEY_free(pkey);
            return -1;
        }

        pubkey_hash_b64 = base64_encode(pubkey_hash, hash_len);
        free(pubkey_hash);
        if (!pubkey_hash_b64) {
            fprintf(stderr, "Failed to encode the public key hash\n");
            EVP_PKEY_free(pkey);
            return -1;
        }

        /*
         * Check for characters that are invalid or undesirable in file names.
         * If the hash contains '/' (path) or '+' (CLI/URL issues), regenerate it.
         */
        if (strchr(pubkey_hash_b64, '/') || strchr(pubkey_hash_b64, '+')) {
            if (verbose) {
                printf("Hash %s contains invalid characters ('/' or '+'), retrying...\n", pubkey_hash_b64);
            }
            free(pubkey_hash_b64);
            pubkey_hash_b64 = NULL;
            EVP_PKEY_free(pkey);
            pkey = NULL;
            continue;
        }
        break;
    }

    /* Saving the keys */
    char pub_file[256], priv_file[256];
    snprintf(pub_file, sizeof(pub_file), "/etc/gorgona/%s.pub", pubkey_hash_b64);
    snprintf(priv_file, sizeof(priv_file), "/etc/gorgona/%s.key", pubkey_hash_b64);

    FILE *pub_fp = fopen(pub_file, "wb");
    if (!pub_fp) {
        fprintf(stderr, "Could not open file for public key, use sudo to generate new keys: %s\n", pub_file);
        free(pubkey_hash_b64);
        EVP_PKEY_free(pkey);
        return -1;
    }
    if (PEM_write_PUBKEY(pub_fp, pkey) != 1) {
        fprintf(stderr, "Не удалось записать публичный ключ в %s\n", pub_file);
        fclose(pub_fp);
        free(pubkey_hash_b64);
        EVP_PKEY_free(pkey);
        return -1;
    }
    fclose(pub_fp);

    FILE *priv_fp = fopen(priv_file, "wb");
    if (!priv_fp) {
        fprintf(stderr, "Не удалось открыть файл для приватного ключа: %s\n", priv_file);
        free(pubkey_hash_b64);
        EVP_PKEY_free(pkey);
        return -1;
    }
    if (PEM_write_PrivateKey(priv_fp, pkey, NULL, NULL, 0, NULL, NULL) != 1) {
        fprintf(stderr, "Не удалось записать приватный ключ в %s\n", priv_file);
        fclose(priv_fp);
        free(pubkey_hash_b64);
        EVP_PKEY_free(pkey);
        return -1;
    }
    fclose(priv_fp);

    printf("Keys generated:\n%s (public)\n%s (private)\n", pub_file, priv_file);

    free(pubkey_hash_b64);
    EVP_PKEY_free(pkey);
    return 0;
}

/* Calculates the hash of the public key */
unsigned char *compute_pubkey_hash(EVP_PKEY *pubkey, size_t *hash_len, int verbose) {
    EVP_MD_CTX *md_ctx = EVP_MD_CTX_new();
    if (!md_ctx) {
        fprintf(stderr, "Не удалось создать EVP_MD_CTX\n");
        ERR_print_errors_fp(stderr);
        return NULL;
    }

    unsigned char *der = NULL;
    int der_len = i2d_PUBKEY(pubkey, &der);
    if (der_len <= 0) {
        fprintf(stderr, "Не удалось конвертировать публичный ключ в DER\n");
        ERR_print_errors_fp(stderr);
        EVP_MD_CTX_free(md_ctx);
        return NULL;
    }

    unsigned char hash[SHA256_DIGEST_LENGTH];
    if (EVP_DigestInit_ex(md_ctx, EVP_sha256(), NULL) != 1 ||
        EVP_DigestUpdate(md_ctx, der, der_len) != 1 ||
        EVP_DigestFinal_ex(md_ctx, hash, NULL) != 1) {
        fprintf(stderr, "Не удалось вычислить SHA256 хеш\n");
        ERR_print_errors_fp(stderr);
        OPENSSL_free(der);
        EVP_MD_CTX_free(md_ctx);
        return NULL;
    }

    OPENSSL_free(der);
    EVP_MD_CTX_free(md_ctx);

    unsigned char *truncated_hash = malloc(PUBKEY_HASH_LEN);
    if (!truncated_hash) {
        fprintf(stderr, "Не удалось выделить память для хеша\n");
        return NULL;
    }
    memcpy(truncated_hash, hash, PUBKEY_HASH_LEN);
    *hash_len = PUBKEY_HASH_LEN;

    if (verbose) {
        printf("Хеш публичного ключа (hex): ");
        for (size_t i = 0; i < PUBKEY_HASH_LEN; i++) printf("%02x", truncated_hash[i]);
        printf("\n");
    }

    return truncated_hash;
}

/* обёртка над bin-версией */
int encrypt_message(const char *plaintext,
                    unsigned char **encrypted, size_t *encrypted_len,
                    unsigned char **encrypted_key, size_t *encrypted_key_len,
                    unsigned char **iv, size_t *iv_len,
                    unsigned char **tag, size_t *tag_len,
                    const char *pubkey_file, int verbose)
{
    if (!plaintext) return -1;
    return encrypt_message_bin((const uint8_t *)plaintext, strlen(plaintext),
                               encrypted, encrypted_len,
                               encrypted_key, encrypted_key_len,
                               iv, iv_len, tag, tag_len,
                               pubkey_file, verbose);
}

/* обёртка над bin-версией */
int decrypt_message(unsigned char *encrypted, size_t encrypted_len,
                    unsigned char *encrypted_key, size_t encrypted_key_len,
                    unsigned char *iv, size_t iv_len,
                    unsigned char *tag,
                    char **plaintext, const char *privkey_file, int verbose)
{
    uint8_t *bin = NULL;
    size_t bin_len = 0;

    int rc = decrypt_message_bin(encrypted, encrypted_len,
                                 encrypted_key, encrypted_key_len,
                                 iv, iv_len, tag, GCM_TAG_LEN,
                                 &bin, &bin_len,
                                 privkey_file, verbose);
    if (rc != 0) {
        *plaintext = NULL;
        return rc;
    }

    /* Добавляем нуль-терминатор для текстового API */
    uint8_t *tmp = realloc(bin, bin_len + 1);
    if (!tmp) {
        free(bin);
        *plaintext = NULL;
        return -1;
    }
    tmp[bin_len] = '\0';
    *plaintext = (char *)tmp;
    return 0;
}

/* -------------------------------------------------------------------------
 * Бинарная версия encrypt (без strlen)
 * ------------------------------------------------------------------------- */
int encrypt_message_bin(const uint8_t *data, size_t data_len,
                        unsigned char **encrypted, size_t *encrypted_len,
                        unsigned char **encrypted_key, size_t *encrypted_key_len,
                        unsigned char **iv, size_t *iv_len,
                        unsigned char **tag, size_t *tag_len,
                        const char *pubkey_file, int verbose)
{
    if (!data || data_len == 0) {
        fprintf(stderr, "[encrypt_bin] invalid input (data=%p, len=%zu)\n", (void*)data, data_len);
        return -1;
    }

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        fprintf(stderr, "[encrypt_bin] EVP_CIPHER_CTX_new failed\n");
        return -1;
    }

    FILE *pub_fp = fopen(pubkey_file, "rb");
    if (!pub_fp) {
        fprintf(stderr, "[encrypt_bin] cannot open pubkey: %s\n", pubkey_file);
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    EVP_PKEY *pubkey = PEM_read_PUBKEY(pub_fp, NULL, NULL, NULL);
    fclose(pub_fp);
    if (!pubkey) {
        fprintf(stderr, "[encrypt_bin] PEM_read_PUBKEY failed\n");
        ERR_print_errors_fp(stderr);
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    /* Generate AES key */
    unsigned char aes_key[32];
    if (RAND_bytes(aes_key, sizeof(aes_key)) != 1) {
        fprintf(stderr, "[encrypt_bin] RAND_bytes(AES key) failed\n");
        EVP_PKEY_free(pubkey);
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    /* RSA-OAEP encrypt AES key */
    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new(pubkey, NULL);
    if (!pctx || EVP_PKEY_encrypt_init(pctx) <= 0 ||
        EVP_PKEY_CTX_set_rsa_padding(pctx, RSA_PKCS1_OAEP_PADDING) <= 0 ||
        EVP_PKEY_CTX_set_rsa_oaep_md(pctx, EVP_sha256()) <= 0 ||
        EVP_PKEY_CTX_set_rsa_mgf1_md(pctx, EVP_sha256()) <= 0) {
        fprintf(stderr, "[encrypt_bin] RSA-OAEP init failed\n");
        ERR_print_errors_fp(stderr);
        EVP_PKEY_CTX_free(pctx);
        EVP_PKEY_free(pubkey);
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    size_t rsa_len = 0;
    if (EVP_PKEY_encrypt(pctx, NULL, &rsa_len, aes_key, sizeof(aes_key)) <= 0) {
        fprintf(stderr, "[encrypt_bin] EVP_PKEY_encrypt (size query) failed\n");
        ERR_print_errors_fp(stderr);
        EVP_PKEY_CTX_free(pctx);
        EVP_PKEY_free(pubkey);
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    *encrypted_key = malloc(rsa_len);
    if (!*encrypted_key) {
        fprintf(stderr, "[encrypt_bin] malloc(encrypted_key) failed\n");
        EVP_PKEY_CTX_free(pctx);
        EVP_PKEY_free(pubkey);
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    *encrypted_key_len = rsa_len;
    if (EVP_PKEY_encrypt(pctx, *encrypted_key, encrypted_key_len, aes_key, sizeof(aes_key)) <= 0) {
        fprintf(stderr, "[encrypt_bin] EVP_PKEY_encrypt (AES key) failed\n");
        ERR_print_errors_fp(stderr);
        free(*encrypted_key);
        EVP_PKEY_CTX_free(pctx);
        EVP_PKEY_free(pubkey);
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    EVP_PKEY_CTX_free(pctx);
    EVP_PKEY_free(pubkey);

    /* IV */
    *iv_len = 12;
    *iv = malloc(*iv_len);
    if (!*iv || RAND_bytes(*iv, *iv_len) != 1) {
        fprintf(stderr, "[encrypt_bin] IV generation failed\n");
        free(*encrypted_key);
        free(*iv);
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    /* AES-256-GCM */
    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1 ||
        EVP_EncryptInit_ex(ctx, NULL, NULL, aes_key, *iv) != 1) {
        fprintf(stderr, "[encrypt_bin] AES-GCM init failed\n");
        ERR_print_errors_fp(stderr);
        free(*encrypted_key);
        free(*iv);
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    *encrypted = malloc(data_len + AES_BLOCK_SIZE);
    if (!*encrypted) {
        fprintf(stderr, "[encrypt_bin] malloc(encrypted) failed\n");
        free(*encrypted_key);
        free(*iv);
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    int len = 0;
    if (EVP_EncryptUpdate(ctx, *encrypted, &len, data, (int)data_len) != 1) {
        fprintf(stderr, "[encrypt_bin] EVP_EncryptUpdate failed\n");
        ERR_print_errors_fp(stderr);
        free(*encrypted);
        free(*encrypted_key);
        free(*iv);
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    *encrypted_len = (size_t)len;

    if (EVP_EncryptFinal_ex(ctx, *encrypted + len, &len) != 1) {
        fprintf(stderr, "[encrypt_bin] EVP_EncryptFinal_ex failed\n");
        ERR_print_errors_fp(stderr);
        free(*encrypted);
        free(*encrypted_key);
        free(*iv);
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    *encrypted_len += (size_t)len;

    /* Tag */
    *tag_len = GCM_TAG_LEN;
    *tag = malloc(*tag_len);
    if (!*tag || EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, (int)*tag_len, *tag) != 1) {
        fprintf(stderr, "[encrypt_bin] GCM GET_TAG failed\n");
        ERR_print_errors_fp(stderr);
        free(*encrypted);
        free(*encrypted_key);
        free(*iv);
        free(*tag);
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    EVP_CIPHER_CTX_free(ctx);
    return 0;
}

/* -------------------------------------------------------------------------
 * Бинарная версия decrypt (возвращает длину)
 * ------------------------------------------------------------------------- */
int decrypt_message_bin(unsigned char *encrypted, size_t encrypted_len,
                        unsigned char *encrypted_key, size_t encrypted_key_len,
                        unsigned char *iv, size_t iv_len,
                        unsigned char *tag, size_t tag_len,
                        uint8_t **plaintext, size_t *plaintext_len,
                        const char *privkey_file, int verbose)
{
    if (!encrypted || !encrypted_key || !iv || !tag || !plaintext || !plaintext_len) {
        fprintf(stderr, "[decrypt_bin] NULL argument\n");
        return -1;
    }

    *plaintext = NULL;
    *plaintext_len = 0;

    if (verbose) {
        fprintf(stderr, "[decrypt_bin] encrypted_len=%zu  key_len=%zu  iv_len=%zu  tag_len=%zu\n",
                encrypted_len, encrypted_key_len, iv_len, tag_len);
    }

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        fprintf(stderr, "[decrypt_bin] EVP_CIPHER_CTX_new failed\n");
        return -1;
    }

    FILE *priv_fp = fopen(privkey_file, "rb");
    if (!priv_fp) {
        fprintf(stderr, "[decrypt_bin] cannot open private key: %s\n", privkey_file);
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    EVP_PKEY *privkey = PEM_read_PrivateKey(priv_fp, NULL, NULL, NULL);
    fclose(priv_fp);
    if (!privkey) {
        fprintf(stderr, "[decrypt_bin] PEM_read_PrivateKey failed\n");
        ERR_print_errors_fp(stderr);
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    /* ===== RSA-OAEP decrypt AES key (с обязательным size-query) ===== */
    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new(privkey, NULL);
    if (!pctx || EVP_PKEY_decrypt_init(pctx) <= 0 ||
        EVP_PKEY_CTX_set_rsa_padding(pctx, RSA_PKCS1_OAEP_PADDING) <= 0 ||
        EVP_PKEY_CTX_set_rsa_oaep_md(pctx, EVP_sha256()) <= 0 ||
        EVP_PKEY_CTX_set_rsa_mgf1_md(pctx, EVP_sha256()) <= 0) {
        fprintf(stderr, "[decrypt_bin] RSA-OAEP init failed\n");
        ERR_print_errors_fp(stderr);
        EVP_PKEY_CTX_free(pctx);
        EVP_PKEY_free(privkey);
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    /* 1. Узнаём нужный размер */
    size_t aes_key_len = 0;
    if (EVP_PKEY_decrypt(pctx, NULL, &aes_key_len, encrypted_key, encrypted_key_len) <= 0) {
        fprintf(stderr, "[decrypt_bin] EVP_PKEY_decrypt (size query) failed\n");
        ERR_print_errors_fp(stderr);
        EVP_PKEY_CTX_free(pctx);
        EVP_PKEY_free(privkey);
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    unsigned char *aes_key = malloc(aes_key_len);
    if (!aes_key) {
        EVP_PKEY_CTX_free(pctx);
        EVP_PKEY_free(privkey);
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    /* 2. Расшифровываем */
    if (EVP_PKEY_decrypt(pctx, aes_key, &aes_key_len, encrypted_key, encrypted_key_len) <= 0) {
        fprintf(stderr, "[decrypt_bin] EVP_PKEY_decrypt (AES key) failed\n");
        ERR_print_errors_fp(stderr);
        free(aes_key);
        EVP_PKEY_CTX_free(pctx);
        EVP_PKEY_free(privkey);
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    if (verbose) {
        fprintf(stderr, "[decrypt_bin] AES key decrypted OK, len=%zu\n", aes_key_len);
    }

    EVP_PKEY_CTX_free(pctx);
    EVP_PKEY_free(privkey);

    /* ===== AES-256-GCM decrypt ===== */
    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1 ||
        EVP_DecryptInit_ex(ctx, NULL, NULL, aes_key, iv) != 1) {
        fprintf(stderr, "[decrypt_bin] AES-GCM init failed\n");
        ERR_print_errors_fp(stderr);
        free(aes_key);
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, (int)tag_len, tag) != 1) {
        fprintf(stderr, "[decrypt_bin] EVP_CTRL_GCM_SET_TAG failed (tag_len=%zu)\n", tag_len);
        ERR_print_errors_fp(stderr);
        free(aes_key);
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    *plaintext = malloc(encrypted_len + 16);
    if (!*plaintext) {
        free(aes_key);
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    int len = 0;
    if (EVP_DecryptUpdate(ctx, *plaintext, &len, encrypted, (int)encrypted_len) != 1) {
        fprintf(stderr, "[decrypt_bin] EVP_DecryptUpdate failed\n");
        ERR_print_errors_fp(stderr);
        free(*plaintext);
        *plaintext = NULL;
        free(aes_key);
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    int total = len;

    if (EVP_DecryptFinal_ex(ctx, *plaintext + len, &len) != 1) {
        fprintf(stderr, "[decrypt_bin] EVP_DecryptFinal_ex FAILED (GCM tag mismatch)\n");
        ERR_print_errors_fp(stderr);
        free(*plaintext);
        *plaintext = NULL;
        free(aes_key);
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    total += len;

    *plaintext_len = (size_t)total;

    if (verbose) {
        fprintf(stderr, "[decrypt_bin] SUCCESS, plaintext_len=%zu\n", *plaintext_len);
    }

    free(aes_key);
    EVP_CIPHER_CTX_free(ctx);
    return 0;
}

/* Encodes data in Base64 */
char *base64_encode(const unsigned char *data, size_t len) {
    BIO *bio, *b64;
    BUF_MEM *bufferPtr;

    b64 = BIO_new(BIO_f_base64());
    if (!b64) {
        fprintf(stderr, "Не удалось создать BIO для base64\n");
        return NULL;
    }
    bio = BIO_new(BIO_s_mem());
    if (!bio) {
        BIO_free(b64);
        fprintf(stderr, "Не удалось создать BIO памяти\n");
        return NULL;
    }
    bio = BIO_push(b64, bio);

    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);
    BIO_write(bio, data, len);
    (void)BIO_flush(bio); 

    BIO_get_mem_ptr(bio, &bufferPtr);
    char *out = malloc(bufferPtr->length + 1);
    if (!out) {
        BIO_free_all(bio);
        fprintf(stderr, "Не удалось выделить память для кодировки base64\n");
        return NULL;
    }
    memcpy(out, bufferPtr->data, bufferPtr->length);
    out[bufferPtr->length] = '\0';

    BIO_free_all(bio);
    return out;
}

/* Decodes data from Base64 */
unsigned char *base64_decode(const char *data, size_t *out_len) {
    BIO *bio, *b64;
    size_t len = strlen(data);
    if (len == 0) return NULL;
    /* 
     * Buffer allocation: Base64 is always ~33% larger than binary data, 
     * so 'len' is a safe upper bound for the decoded output. 
     */
    unsigned char *out = malloc(len);
    if (!out) {
        fprintf(stderr, "Error: Memory allocation failed for Base64 decoding\n");
        return NULL;
    }
    b64 = BIO_new(BIO_f_base64());
    if (!b64) {
        free(out);
        fprintf(stderr, "Error: Failed to create Base64 BIO\n");
        return NULL;
    }
    /* 
     * Set the flag to ignore newlines and treat the input as a single line.
     * This matches our client-side sanitization.
     */
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    bio = BIO_new_mem_buf(data, len);
    if (!bio) {
        BIO_free(b64);
        free(out);
        fprintf(stderr, "Error: Failed to create memory BIO\n");
        return NULL;
    }
    bio = BIO_push(b64, bio);
    int decoded_len = BIO_read(bio, out, len);
    if (decoded_len < 0) {
        /* This often happens if there's an illegal character or unexpected newline */
        fprintf(stderr, "Error: Base64 decoding failed (invalid format or unexpected newline)\n");
        BIO_free_all(bio);
        free(out);
        return NULL;
    }
    *out_len = (size_t)decoded_len;
    BIO_free_all(bio);
    return out;
}

/**
 * Creates a digital signature for the message ID. 
 * Used to verify revocation requests. 
 */
int sign_message_id(uint64_t id, const char *priv_key_path, char *out_b64, size_t out_len, int verbose) {
    int ret = -1;
    EVP_PKEY *privkey = NULL;
    EVP_MD_CTX *ctx = NULL;
    unsigned char *sig = NULL;
    size_t sig_len = 0;
    FILE *fp = fopen(priv_key_path, "rb");

    if (!fp) {
        if (verbose) perror("fopen private key");
        return -1;
    }

    /* Reading the private key */
    privkey = PEM_read_PrivateKey(fp, NULL, NULL, NULL);
    fclose(fp);

    if (!privkey) {
        if (verbose) fprintf(stderr, "Error: Could not read private key from %s\n", priv_key_path);
        return -1;
    }

    /* Preparing data for signing (converting uint64_t to a string for stability) */
    char id_str[32];
    int data_len = snprintf(id_str, sizeof(id_str), "%" PRIu64, id);

    /* Creating an RSA-SHA256 signature context */
    ctx = EVP_MD_CTX_new();
    if (!ctx) goto cleanup;

    if (EVP_SignInit(ctx, EVP_sha256()) <= 0) goto cleanup;
    if (EVP_SignUpdate(ctx, id_str, data_len) <= 0) goto cleanup;

    /* Set the signature size */
    sig_len = EVP_PKEY_size(privkey);
    sig = malloc(sig_len);
    if (!sig) goto cleanup;

    /* Finalizing the signature */
    if (EVP_SignFinal(ctx, sig, (unsigned int *)&sig_len, privkey) <= 0) {
        if (verbose) ERR_print_errors_fp(stderr);
        goto cleanup;
    }

    /* Encode the result in Base64 */
    char *b64_res = base64_encode(sig, sig_len);
    if (b64_res) {
        strncpy(out_b64, b64_res, out_len - 1);
        out_b64[out_len - 1] = '\0';
        free(b64_res);
        ret = 0; /* Success */
    }

cleanup:
    if (ctx) EVP_MD_CTX_free(ctx);
    if (privkey) EVP_PKEY_free(privkey);
    if (sig) free(sig);
    return ret;
}

/**
 * Utility function: calculates the hash of a PEM key buffer.
 * The server needs this to verify that the submitted public key matches the hash in the request.
 */
int compute_raw_pubkey_hash(unsigned char *pub_raw, size_t pub_len, unsigned char *out_hash) {
    BIO *bio = BIO_new_mem_buf(pub_raw, pub_len);
    EVP_PKEY *pkey = PEM_read_bio_PUBKEY(bio, NULL, NULL, NULL);
    BIO_free(bio);

    if (!pkey) return -1;

    size_t hash_len;
    unsigned char *hash = compute_pubkey_hash(pkey, &hash_len, 0);
    if (hash) {
        memcpy(out_hash, hash, PUBKEY_HASH_LEN);
        free(hash);
        EVP_PKEY_free(pkey);
        return 0;
    }

    EVP_PKEY_free(pkey);
    return -1;
}

/**
 * Server-side signature verification. 
 * Verifies that the sig_b64 signature was created for the string “id” by the owner of the pub_raw key.
 */
int verify_id_signature(uint64_t id, unsigned char *pub_raw, size_t pub_len, const char *sig_b64) {
    size_t sig_len;
    unsigned char *sig_raw = base64_decode(sig_b64, &sig_len);
    if (!sig_raw) return -1;

    BIO *bio = BIO_new_mem_buf(pub_raw, pub_len);
    EVP_PKEY *pkey = PEM_read_bio_PUBKEY(bio, NULL, NULL, NULL);
    BIO_free(bio);

    if (!pkey) {
        free(sig_raw);
        return -1;
    }

    char id_str[32];
    int data_len = snprintf(id_str, sizeof(id_str), "%" PRIu64, id);

    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    int res = -1;

    if (EVP_DigestVerifyInit(ctx, NULL, EVP_sha256(), NULL, pkey) > 0) {
        if (EVP_DigestVerifyUpdate(ctx, id_str, data_len) > 0) {
            if (EVP_DigestVerifyFinal(ctx, sig_raw, sig_len) == 1) {
                res = 0; /* Success */
            }
        }
    }

    EVP_MD_CTX_free(ctx);
    EVP_PKEY_free(pkey);
    free(sig_raw);
    return res;
}
