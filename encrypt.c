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

/* Проверяет наличие файлов public.pem и private.pem (для обратной совместимости) */
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

/* Генерирует пару RSA ключей и переименовывает их по хешу */
int generate_rsa_keys(int verbose) {
    EVP_PKEY *pkey = NULL;
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    if (!ctx) {
        fprintf(stderr, "Не удалось создать EVP_PKEY_CTX\n");
        ERR_print_errors_fp(stderr);
        return -1;
    }

    if (EVP_PKEY_keygen_init(ctx) <= 0) {
        fprintf(stderr, "Не удалось инициализировать генерацию ключей\n");
        ERR_print_errors_fp(stderr);
        EVP_PKEY_CTX_free(ctx);
        return -1;
    }

    if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 2048) <= 0) {
        fprintf(stderr, "Не удалось установить длину ключа RSA\n");
        ERR_print_errors_fp(stderr);
        EVP_PKEY_CTX_free(ctx);
        return -1;
    }

    if (EVP_PKEY_keygen(ctx, &pkey) <= 0) {
        fprintf(stderr, "Не удалось сгенерировать пару ключей RSA\n");
        ERR_print_errors_fp(stderr);
        EVP_PKEY_CTX_free(ctx);
        return -1;
    }

    /* Сохраняем приватный ключ во временный файл */
    FILE *priv_fp = fopen("private.pem", "w");
    if (!priv_fp) {
        fprintf(stderr, "Не удалось открыть private.pem для записи\n");
        EVP_PKEY_free(pkey);
        EVP_PKEY_CTX_free(ctx);
        return -1;
    }
    if (!PEM_write_PrivateKey(priv_fp, pkey, NULL, NULL, 0, NULL, NULL)) {
        fprintf(stderr, "Не удалось записать приватный ключ\n");
        ERR_print_errors_fp(stderr);
        fclose(priv_fp);
        EVP_PKEY_free(pkey);
        EVP_PKEY_CTX_free(ctx);
        return -1;
    }
    fclose(priv_fp);

    /* Сохраняем публичный ключ во временный файл */
    FILE *pub_fp = fopen("public.pem", "w");
    if (!pub_fp) {
        fprintf(stderr, "Не удалось открыть public.pem для записи\n");
        EVP_PKEY_free(pkey);
        EVP_PKEY_CTX_free(ctx);
        return -1;
    }
    if (!PEM_write_PUBKEY(pub_fp, pkey)) {
        fprintf(stderr, "Не удалось записать публичный ключ\n");
        ERR_print_errors_fp(stderr);
        fclose(pub_fp);
        EVP_PKEY_free(pkey);
        EVP_PKEY_CTX_free(ctx);
        return -1;
    }
    fclose(pub_fp);

    /* Вычисляем хеш публичного ключа для переименования файлов */
    EVP_PKEY *pubkey_temp = NULL;
    FILE *pub_fp_temp = fopen("public.pem", "rb");
    if (!pub_fp_temp) {
        fprintf(stderr, "Не удалось повторно открыть public.pem\n");
        EVP_PKEY_free(pkey);
        EVP_PKEY_CTX_free(ctx);
        return -1;
    }
    pubkey_temp = PEM_read_PUBKEY(pub_fp_temp, NULL, NULL, NULL);
    fclose(pub_fp_temp);
    if (!pubkey_temp) {
        fprintf(stderr, "Не удалось прочитать временный публичный ключ\n");
        ERR_print_errors_fp(stderr);
        EVP_PKEY_free(pkey);
        EVP_PKEY_CTX_free(ctx);
        return -1;
    }

    size_t hash_len;
    unsigned char *hash = compute_pubkey_hash(pubkey_temp, &hash_len, verbose);
    EVP_PKEY_free(pubkey_temp);
    if (!hash || hash_len != PUBKEY_HASH_LEN) {
        fprintf(stderr, "Не удалось вычислить хеш публичного ключа\n");
        EVP_PKEY_free(pkey);
        EVP_PKEY_CTX_free(ctx);
        free(hash);
        return -1;
    }

    char *hash_b64 = base64_encode(hash, hash_len);
    free(hash);
    if (!hash_b64) {
        fprintf(stderr, "Не удалось закодировать хеш в base64\n");
        EVP_PKEY_free(pkey);
        EVP_PKEY_CTX_free(ctx);
        return -1;
    }

    /* Формируем имена файлов на основе base64 хеша */
    char pub_file[256], priv_file[256];
    snprintf(pub_file, sizeof(pub_file), "%s.pub", hash_b64);
    snprintf(priv_file, sizeof(priv_file), "%s.key", hash_b64);

    /* Переименовываем файлы */
    if (rename("public.pem", pub_file) != 0) {
        perror("Не удалось переименовать public.pem");
        free(hash_b64);
        EVP_PKEY_free(pkey);
        EVP_PKEY_CTX_free(ctx);
        return -1;
    }
    if (rename("private.pem", priv_file) != 0) {
        perror("Не удалось переименовать private.pem");
        free(hash_b64);
        EVP_PKEY_free(pkey);
        EVP_PKEY_CTX_free(ctx);
        return -1;
    }

    printf("Ключи сгенерированы и сохранены как %s и %s\n", pub_file, priv_file);
    free(hash_b64);
    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(ctx);
    return 0;
}

/* Вычисляет хеш публичного ключа */
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

/* Шифрует сообщение с использованием публичного ключа */
int encrypt_message(const char *plaintext, unsigned char **encrypted, size_t *encrypted_len,
                   unsigned char **encrypted_key, size_t *encrypted_key_len,
                   unsigned char **iv, size_t *iv_len, unsigned char **tag, size_t *tag_len,
                   const char *pubkey_file, int verbose) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    EVP_PKEY_CTX *pctx = NULL;
    EVP_PKEY *pubkey = NULL;
    FILE *pub_fp = fopen(pubkey_file, "rb");
    if (!pub_fp) {
        fprintf(stderr, "Не удалось открыть файл публичного ключа: %s\n", pubkey_file);
        return -1;
    }
    pubkey = PEM_read_PUBKEY(pub_fp, NULL, NULL, NULL);
    fclose(pub_fp);
    if (!pubkey) {
        fprintf(stderr, "Не удалось прочитать публичный ключ из %s\n", pubkey_file);
        ERR_print_errors_fp(stderr);
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    /* Генерируем случайный ключ AES */
    unsigned char aes_key[32];
    if (RAND_bytes(aes_key, sizeof(aes_key)) != 1) {
        fprintf(stderr, "Не удалось сгенерировать ключ AES\n");
        ERR_print_errors_fp(stderr);
        EVP_PKEY_free(pubkey);
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    if (verbose) {
        printf("Сгенерированный ключ AES (hex): ");
        for (size_t i = 0; i < sizeof(aes_key); i++) printf("%02x", aes_key[i]);
        printf("\n");
    }

    /* Шифруем ключ AES публичным RSA ключом с OAEP padding */
    pctx = EVP_PKEY_CTX_new(pubkey, NULL);
    if (!pctx || EVP_PKEY_encrypt_init(pctx) <= 0) {
        fprintf(stderr, "Не удалось инициализировать шифрование RSA\n");
        ERR_print_errors_fp(stderr);
        EVP_PKEY_free(pubkey);
        EVP_CIPHER_CTX_free(ctx);
        EVP_PKEY_CTX_free(pctx);
        return -1;
    }
    EVP_PKEY_CTX_set_rsa_padding(pctx, RSA_PKCS1_OAEP_PADDING);

    if (EVP_PKEY_encrypt(pctx, NULL, encrypted_key_len, aes_key, sizeof(aes_key)) <= 0) {
        fprintf(stderr, "Не удалось определить длину зашифрованного ключа AES\n");
        ERR_print_errors_fp(stderr);
        EVP_PKEY_CTX_free(pctx);
        EVP_PKEY_free(pubkey);
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    *encrypted_key = malloc(*encrypted_key_len);
    if (!*encrypted_key || EVP_PKEY_encrypt(pctx, *encrypted_key, encrypted_key_len, aes_key, sizeof(aes_key)) <= 0) {
        fprintf(stderr, "Не удалось зашифровать ключ AES\n");
        ERR_print_errors_fp(stderr);
        free(*encrypted_key);
        EVP_PKEY_CTX_free(pctx);
        EVP_PKEY_free(pubkey);
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    EVP_PKEY_CTX_free(pctx);
    EVP_PKEY_free(pubkey);

    if (verbose) {
        printf("Зашифрованный ключ AES (hex): ");
        for (size_t i = 0; i < *encrypted_key_len; i++) printf("%02x", (*encrypted_key)[i]);
        printf("\n");
    }

    /* Генерируем IV */
    *iv_len = 12;
    *iv = malloc(*iv_len);
    if (!*iv || RAND_bytes(*iv, *iv_len) != 1) {
        fprintf(stderr, "Не удалось сгенерировать IV\n");
        ERR_print_errors_fp(stderr);
        free(*encrypted_key);
        free(*iv);
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    if (verbose) {
        printf("IV (hex): ");
        for (size_t i = 0; i < *iv_len; i++) printf("%02x", (*iv)[i]);
        printf("\n");
    }

    /* Инициализируем AES-256-GCM */
    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1) {
        fprintf(stderr, "Не удалось инициализировать AES-256-GCM\n");
        ERR_print_errors_fp(stderr);
        free(*encrypted_key);
        free(*iv);
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    if (EVP_EncryptInit_ex(ctx, NULL, NULL, aes_key, *iv) != 1) {
        fprintf(stderr, "Не удалось установить ключ AES и IV\n");
        ERR_print_errors_fp(stderr);
        free(*encrypted_key);
        free(*iv);
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    /* Шифруем сообщение */
    int len;
    *encrypted_len = strlen(plaintext);
    *encrypted = malloc(*encrypted_len + AES_BLOCK_SIZE);
    if (!*encrypted) {
        fprintf(stderr, "Не удалось выделить память для зашифрованного текста\n");
        ERR_print_errors_fp(stderr);
        free(*encrypted_key);
        free(*iv);
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    if (EVP_EncryptUpdate(ctx, *encrypted, &len, (unsigned char *)plaintext, *encrypted_len) != 1) {
        fprintf(stderr, "Не удалось зашифровать сообщение\n");
        ERR_print_errors_fp(stderr);
        free(*encrypted);
        free(*encrypted_key);
        free(*iv);
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    *encrypted_len = len;

    if (EVP_EncryptFinal_ex(ctx, *encrypted + len, &len) != 1) {
        fprintf(stderr, "Не удалось завершить шифрование\n");
        ERR_print_errors_fp(stderr);
        free(*encrypted);
        free(*encrypted_key);
        free(*iv);
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    *encrypted_len += len;

    /* Получаем тег GCM */
    *tag_len = GCM_TAG_LEN;
    *tag = malloc(*tag_len);
    if (!*tag || EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, *tag_len, *tag) != 1) {
        fprintf(stderr, "Не удалось получить тег GCM\n");
        ERR_print_errors_fp(stderr);
        free(*encrypted);
        free(*encrypted_key);
        free(*iv);
        free(*tag);
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    if (verbose) {
        printf("Тег GCM (hex): ");
        for (size_t i = 0; i < *tag_len; i++) printf("%02x", (*tag)[i]);
        printf("\n");
    }

    EVP_CIPHER_CTX_free(ctx);
    return 0;
}

/* Расшифровывает сообщение с использованием указанного приватного ключа */
int decrypt_message(unsigned char *encrypted, size_t encrypted_len, unsigned char *encrypted_key,
                   size_t encrypted_key_len, unsigned char *iv, size_t iv_len,
                   unsigned char *tag, char **plaintext, const char *privkey_file, int verbose) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    EVP_PKEY_CTX *pctx = NULL;
    EVP_PKEY *privkey = NULL;
    FILE *priv_fp = fopen(privkey_file, "rb");
    if (!priv_fp) {
        fprintf(stderr, "Не удалось открыть файл приватного ключа: %s\n", privkey_file);
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    privkey = PEM_read_PrivateKey(priv_fp, NULL, NULL, NULL);
    fclose(priv_fp);
    if (!privkey) {
        fprintf(stderr, "Не удалось прочитать приватный ключ из %s\n", privkey_file);
        ERR_print_errors_fp(stderr);
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    /* Расшифровываем ключ AES приватным RSA ключом */
    pctx = EVP_PKEY_CTX_new(privkey, NULL);
    if (!pctx || EVP_PKEY_decrypt_init(pctx) <= 0) {
        fprintf(stderr, "Не удалось инициализировать расшифровку RSA\n");
        ERR_print_errors_fp(stderr);
        EVP_PKEY_free(privkey);
        EVP_CIPHER_CTX_free(ctx);
        EVP_PKEY_CTX_free(pctx);
        return -1;
    }
    EVP_PKEY_CTX_set_rsa_padding(pctx, RSA_PKCS1_OAEP_PADDING);

    size_t aes_key_len;
    if (EVP_PKEY_decrypt(pctx, NULL, &aes_key_len, encrypted_key, encrypted_key_len) <= 0) {
        fprintf(stderr, "Не удалось определить длину расшифрованного ключа AES\n");
        ERR_print_errors_fp(stderr);
        EVP_PKEY_CTX_free(pctx);
        EVP_PKEY_free(privkey);
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    unsigned char *aes_key = malloc(aes_key_len);
    if (!aes_key || EVP_PKEY_decrypt(pctx, aes_key, &aes_key_len, encrypted_key, encrypted_key_len) <= 0) {
        fprintf(stderr, "Не удалось расшифровать ключ AES\n");
        ERR_print_errors_fp(stderr);
        free(aes_key);
        EVP_PKEY_CTX_free(pctx);
        EVP_PKEY_free(privkey);
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    EVP_PKEY_CTX_free(pctx);
    EVP_PKEY_free(privkey);

    if (verbose) {
        printf("Расшифрованный ключ AES (hex): ");
        for (size_t i = 0; i < aes_key_len; i++) printf("%02x", aes_key[i]);
        printf("\n");
    }

    /* Инициализируем AES-256-GCM для расшифровки */
    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1) {
        fprintf(stderr, "Не удалось инициализировать AES-256-GCM для расшифровки\n");
        ERR_print_errors_fp(stderr);
        free(aes_key);
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    if (EVP_DecryptInit_ex(ctx, NULL, NULL, aes_key, iv) != 1) {
        fprintf(stderr, "Не удалось установить ключ AES и IV для расшифровки\n");
        ERR_print_errors_fp(stderr);
        free(aes_key);
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, GCM_TAG_LEN, tag) != 1) {
        fprintf(stderr, "Не удалось установить тег GCM\n");
        ERR_print_errors_fp(stderr);
        free(aes_key);
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    /* Расшифровываем сообщение */
    int len;
    *plaintext = malloc(encrypted_len + 1);
    if (!*plaintext) {
        fprintf(stderr, "Не удалось выделить память для открытого текста\n");
        ERR_print_errors_fp(stderr);
        free(aes_key);
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    if (EVP_DecryptUpdate(ctx, (unsigned char *)*plaintext, &len, encrypted, encrypted_len) != 1) {
        fprintf(stderr, "Не удалось расшифровать сообщение\n");
        ERR_print_errors_fp(stderr);
        free(*plaintext);
        free(aes_key);
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    int plaintext_len = len;

    if (EVP_DecryptFinal_ex(ctx, (unsigned char *)*plaintext + len, &len) != 1) {
        fprintf(stderr, "Не удалось завершить расшифровку\n");
        ERR_print_errors_fp(stderr);
        free(*plaintext);
        free(aes_key);
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    plaintext_len += len;

    (*plaintext)[plaintext_len] = '\0';
    free(aes_key);
    EVP_CIPHER_CTX_free(ctx);
    return 0;
}

/* Кодирует данные в base64 */
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
    BIO_flush(bio);

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

/* Декодирует данные из base64 */
unsigned char *base64_decode(const char *data, size_t *out_len) {
    BIO *bio, *b64;
    size_t len = strlen(data);
    unsigned char *out = malloc(len);
    if (!out) {
        fprintf(stderr, "Не удалось выделить память для декодировки base64\n");
        return NULL;
    }

    b64 = BIO_new(BIO_f_base64());
    if (!b64) {
        free(out);
        fprintf(stderr, "Не удалось создать BIO для base64\n");
        return NULL;
    }
    bio = BIO_new_mem_buf(data, len);
    if (!bio) {
        BIO_free(b64);
        free(out);
        fprintf(stderr, "Не удалось создать BIO памяти\n");
        return NULL;
    }
    bio = BIO_push(b64, bio);

    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);
    *out_len = BIO_read(bio, out, len);
    if (*out_len == (size_t)-1) {
        fprintf(stderr, "Не удалось декодировать base64 данные\n");
        BIO_free_all(bio);
        free(out);
        return NULL;
    }
    BIO_free_all(bio);
    return out;
}
