/* 
* BSD 3-Clause License
* Copyright (c) 2025, Alexander Shcheglov
* All rights reserved. 
*/

#define _XOPEN_SOURCE 700
#include "encrypt.h"
#include "config.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <stdint.h>
#include <sys/time.h>
#include <signal.h> 
#include <stdbool.h>

/* Parses date and time in format "YYYY-MM-DD HH:MM:SS"
   Interprets the supplied datetime string as UTC (not localtime). */
time_t parse_datetime(const char *datetime) {
    struct tm tm = {0};
    if (strptime(datetime, "%Y-%m-%d %H:%M:%S", &tm) == NULL) {
        fprintf(stderr, "Error: Invalid time format: %s\n", datetime);
        return -1;
    }
    tm.tm_isdst = -1; /* don't try to guess DST */

#if defined(_GNU_SOURCE) || defined(__USE_MISC) || defined(_BSD_SOURCE) || defined(__APPLE__)
    /* timegm converts tm interpreted as UTC into time_t */
    return timegm(&tm);
#else
    /* Portable fallback: temporarily force TZ=UTC, call mktime, then restore */
    char *old_tz = getenv("TZ");
    char *old_tz_copy = old_tz ? strdup(old_tz) : NULL;

    setenv("TZ", "UTC", 1);
    tzset();

    time_t t = mktime(&tm);

    if (old_tz_copy) {
        setenv("TZ", old_tz_copy, 1);
        free(old_tz_copy);
    } else {
        unsetenv("TZ");
    }
    tzset();
    return t;
#endif
}


/* Reads input from stdin into a dynamically allocated buffer */
char *read_from_stdin(size_t *out_len) {
    size_t capacity = 1024; // Initial buffer size
    size_t len = 0;
    char *buffer = malloc(capacity);
    if (!buffer) {
        fprintf(stderr, "Error: Failed to allocate memory for stdin input\n");
        return NULL;
    }

    int c;
    while ((c = getchar()) != EOF) {
        if (len + 1 >= capacity) {
            capacity *= 2; // Double the buffer size
            char *new_buffer = realloc(buffer, capacity);
            if (!new_buffer) {
                fprintf(stderr, "Error: Failed to reallocate memory for stdin input\n");
                free(buffer);
                return NULL;
            }
            buffer = new_buffer;
        }
        buffer[len++] = (char)c;
    }

    buffer[len] = '\0'; // Null-terminate the string
    *out_len = len;
    return buffer;
}

/* Sends encrypted message to server */
int send_alert(int argc, char *argv[], int verbose) {
    if (argc != 5) {
        fprintf(stderr, "Usage: send <unlock_time> <expire_time> <message> <public_key_file>\n");
        return 1;
    }

    time_t unlock_at = parse_datetime(argv[1]);
    time_t expire_at = parse_datetime(argv[2]);
    if (unlock_at == -1 || expire_at == -1) {
        return 1;
    }
    
    const char *message_arg = argv[3];
    const char *pubkey_file = argv[4];
    char *message = NULL;
    size_t message_len = 0;

    /* Read message from stdin if message_arg is "-" */
    if (strcmp(message_arg, "-") == 0) {
        message = read_from_stdin(&message_len);
        if (!message) {
            return 1;
        }
    } else {
        message = strdup(message_arg);
        if (!message) {
            fprintf(stderr, "Error: Failed to allocate memory for message\n");
            return 1;
        }
        message_len = strlen(message);
    }

    /* Read recipient's public key */
    char full_pubkey_file[256];
    snprintf(full_pubkey_file, sizeof(full_pubkey_file), "/etc/gorgona/%s", pubkey_file);
    FILE *pub_fp = fopen(full_pubkey_file, "rb");
    if (!pub_fp) {
        fprintf(stderr, "Failed to open public key file: %s\n", full_pubkey_file);
        free(message);
        return 1;
    }
    EVP_PKEY *pubkey = PEM_read_PUBKEY(pub_fp, NULL, NULL, NULL);
    fclose(pub_fp);
    if (!pubkey) {
        fprintf(stderr, "Failed to read public key from %s\n", full_pubkey_file);
        ERR_print_errors_fp(stderr);
        free(message);
        return 1;
    }

    /* Compute public key hash */
    size_t hash_len;
    unsigned char *pubkey_hash = compute_pubkey_hash(pubkey, &hash_len, verbose);
    EVP_PKEY_free(pubkey);
    if (!pubkey_hash || hash_len != PUBKEY_HASH_LEN) {
        fprintf(stderr, "Failed to compute public key hash\n");
        free(pubkey_hash);
        free(message);
        return 1;
    }
    char *pubkey_hash_b64 = base64_encode(pubkey_hash, hash_len);
    if (!pubkey_hash_b64) {
        fprintf(stderr, "Failed to encode public key hash\n");
        free(pubkey_hash);
        free(message);
        return 1;
    }
    if (verbose) {
        printf("Public key hash (base64): %s\n", pubkey_hash_b64);
    }

    /* Encrypt message */
    unsigned char *encrypted = NULL, *encrypted_key = NULL, *iv = NULL, *tag = NULL;
    size_t encrypted_len, encrypted_key_len, iv_len, tag_len;
    if (encrypt_message(message, &encrypted, &encrypted_len, &encrypted_key, &encrypted_key_len, &iv, &iv_len, &tag, &tag_len, full_pubkey_file, verbose) != 0) {
        fprintf(stderr, "Failed to encrypt message\n");
        free(pubkey_hash);
        free(pubkey_hash_b64);
        free(message);
        return 1;
    }

    /* Check data sizes */
    if (tag_len != GCM_TAG_LEN || iv_len != 12) {
        fprintf(stderr, "Invalid encryption data sizes\n");
        free(pubkey_hash); free(pubkey_hash_b64); free(encrypted);
        free(encrypted_key); free(iv); free(tag); free(message);
        return 1;
    }

    /* Encode to base64 */
    char *encrypted_b64 = base64_encode(encrypted, encrypted_len);
    char *encrypted_key_b64 = base64_encode(encrypted_key, encrypted_key_len);
    char *iv_b64 = base64_encode(iv, iv_len);
    char *tag_b64 = base64_encode(tag, tag_len);
    if (!encrypted_b64 || !encrypted_key_b64 || !iv_b64 || !tag_b64) {
        fprintf(stderr, "Failed to encode encrypted data to base64\n");
        free(pubkey_hash); free(pubkey_hash_b64); free(encrypted);
        free(encrypted_key); free(iv); free(tag);
        free(encrypted_b64); free(encrypted_key_b64); free(iv_b64); free(tag_b64);
        free(message);
        return 1;
    }

    Config config;
    read_config(&config, verbose);

    /* --- РАСЧЕТ РАЗМЕРА И ПРОВЕРКА ЛИМИТА (50 МБ) --- */
    size_t needed_len = strlen("SEND|") + strlen(pubkey_hash_b64) + 64 + 
                        strlen(encrypted_b64) + strlen(encrypted_key_b64) + 
                        strlen(iv_b64) + strlen(tag_b64);

    const size_t CLIENT_MAX_LIMIT = 50 * 1024 * 1024;
    if (needed_len > CLIENT_MAX_LIMIT) {
        fprintf(stderr, "Error: Message is too large to send (%.2f MB). Client limit is 50 MB.\n", 
                (double)needed_len / (1024 * 1024));
        free(pubkey_hash); free(pubkey_hash_b64); free(encrypted); 
        free(encrypted_key); free(iv); free(tag); 
        free(encrypted_b64); free(encrypted_key_b64); free(iv_b64); free(tag_b64); 
        free(message);
        return 1;
    }

    /* Формируем финальный буфер один раз */
    char *buffer = malloc(needed_len + 1);
    if (!buffer) {
        fprintf(stderr, "Error: Failed to allocate memory for message\n");
        free(pubkey_hash); free(pubkey_hash_b64); free(encrypted); 
        free(encrypted_key); free(iv); free(tag); 
        free(encrypted_b64); free(encrypted_key_b64); free(iv_b64); free(tag_b64); 
        free(message);
        return 1;
    }

    int len = snprintf(buffer, needed_len + 1, "SEND|%s|%ld|%ld|%s|%s|%s|%s",
             pubkey_hash_b64, (long)unlock_at, (long)expire_at,
             encrypted_b64, encrypted_key_b64, iv_b64, tag_b64);

    if (verbose) {
        printf("Sending message (%d bytes)...\n", len);
    }

    /* Connect to server */
    int sock = 0;
    struct sockaddr_in serv_addr;
    if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        fprintf(stderr, "Socket creation error\n");
        free(buffer); free(pubkey_hash); free(pubkey_hash_b64); free(encrypted);
        free(encrypted_key); free(iv); free(tag);
        free(encrypted_b64); free(encrypted_key_b64); free(iv_b64); free(tag_b64);
        free(message);
        return 1;
    }

    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(config.server_port);
    if (inet_pton(AF_INET, config.server_ip, &serv_addr.sin_addr) <= 0) {
        fprintf(stderr, "Invalid address/ Address not supported\n");
        close(sock); free(buffer); free(pubkey_hash); free(pubkey_hash_b64);
        free(message);
        return 1;
    }

    if (connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
        fprintf(stderr, "Connection failed\n");
        close(sock); free(pubkey_hash); free(pubkey_hash_b64);
        free(encrypted); free(encrypted_key); free(iv); free(tag);
        free(encrypted_b64); free(encrypted_key_b64); free(iv_b64); free(tag_b64);
        free(message);
        return 1;
    }

    /* Игнорируем SIGPIPE, чтобы не вылететь при записи в сокет, который сервер закрыл на чтение */
    signal(SIGPIPE, SIG_IGN);

    // 4. Отправляем длину (4 байта)
    uint32_t msg_len_net = htonl((uint32_t)len);
    if (send(sock, &msg_len_net, sizeof(uint32_t), 0) != sizeof(uint32_t)) {
        perror("Failed to send length");
        close(sock); goto cleanup_all;
    }

    // 5. Отправляем данные ЧАНКАМИ по 64КБ
    size_t total_sent = 0;
    size_t chunk_size = 65536; 
    bool aborted = false;

    while (total_sent < (size_t)len) {
        size_t to_send = ((size_t)len - total_sent > chunk_size) ? chunk_size : ((size_t)len - total_sent);
        ssize_t sent = send(sock, buffer + total_sent, to_send, MSG_NOSIGNAL);
        
        if (sent <= 0) {
            // Если send вернул ошибку, значит сервер уже закрыл сокет (отклонил лимит)
            aborted = true;
            break;
        }
        total_sent += sent;

        // КРИТИЧЕСКИЙ МОМЕНТ: Проверяем, не прислал ли сервер ошибку ПРЯМО СЕЙЧАС (не блокируя поток)
        struct timeval tv_poll = {0, 0}; // 0 секунд, 0 микросекунд - мгновенный опрос
        fd_set rset;
        FD_ZERO(&rset);
        FD_SET(sock, &rset);
        if (select(sock + 1, &rset, NULL, NULL, &tv_poll) > 0) {
            // В сокете появились данные от сервера (вероятно, ошибка)
            aborted = true;
            break;
        }
    }
    free(buffer); buffer = NULL;

    /* 6. Читаем финальный ответ или ошибку */
    struct timeval tv; tv.tv_sec = 5; tv.tv_usec = 0;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof tv);

    uint32_t resp_len_net;
    if (read(sock, &resp_len_net, sizeof(uint32_t)) == sizeof(uint32_t)) {
        size_t resp_len = ntohl(resp_len_net);
        if (resp_len > 0 && resp_len < 2048) {
            char *resp_buffer = malloc(resp_len + 1);
            if (resp_buffer) {
                size_t tr = 0;
                while (tr < resp_len) {
                    ssize_t r = read(sock, resp_buffer + tr, resp_len - tr);
                    if (r <= 0) break;
                    tr += r;
                }
                resp_buffer[tr] = '\0';
                printf("Server response: %s\n", resp_buffer);
                free(resp_buffer);
            }
        }
    } else if (aborted) {
        fprintf(stderr, "Server rejected the data (likely size limit) and closed connection.\n");
    }

    close(sock);

cleanup_all:
    if (buffer) free(buffer);
    free(pubkey_hash); free(pubkey_hash_b64);
    free(encrypted); free(encrypted_key); free(iv); free(tag);
    free(encrypted_b64); free(encrypted_key_b64); free(iv_b64); free(tag_b64);
    free(message);
    return 0;
}
