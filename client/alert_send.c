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

/* Parses date and time in format "YYYY-MM-DD HH:MM:SS" */
time_t parse_datetime(const char *datetime) {
    struct tm tm = {0};
    if (strptime(datetime, "%Y-%m-%d %H:%M:%S", &tm) == NULL) {
        fprintf(stderr, "Error: Invalid time format: %s\n", datetime);
        return -1;
    }
    return mktime(&tm);
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
    snprintf(full_pubkey_file, sizeof(full_pubkey_file), "/etc/gargona/%s", pubkey_file);
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
        fprintf(stderr, "Invalid data sizes: tag_len=%zu (expected %d), iv_len=%zu (expected 12)\n", 
                tag_len, GCM_TAG_LEN, iv_len);
        free(pubkey_hash);
        free(pubkey_hash_b64);
        free(encrypted);
        free(encrypted_key);
        free(iv);
        free(tag);
        free(message);
        return 1;
    }

    /* Encode data to base64 */
    char *encrypted_b64 = base64_encode(encrypted, encrypted_len);
    char *encrypted_key_b64 = base64_encode(encrypted_key, encrypted_key_len);
    char *iv_b64 = base64_encode(iv, iv_len);
    char *tag_b64 = base64_encode(tag, tag_len);
    if (!encrypted_b64 || !encrypted_key_b64 || !iv_b64 || !tag_b64) {
        fprintf(stderr, "Failed to encode data to base64\n");
        free(pubkey_hash);
        free(pubkey_hash_b64);
        free(encrypted);
        free(encrypted_key);
        free(iv);
        free(tag);
        free(encrypted_b64);
        free(encrypted_key_b64);
        free(iv_b64);
        free(tag_b64);
        free(message);
        return 1;
    }

    /* Load config */
    Config config;
    read_config(&config, verbose);

    /* Create socket */
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        perror("Socket creation error");
        free(pubkey_hash);
        free(pubkey_hash_b64);
        free(encrypted);
        free(encrypted_key);
        free(iv);
        free(tag);
        free(encrypted_b64);
        free(encrypted_key_b64);
        free(iv_b64);
        free(tag_b64);
        free(message);
        return 1;
    }

    struct sockaddr_in serv_addr = { .sin_family = AF_INET, .sin_port = htons(config.server_port) };
    if (inet_pton(AF_INET, config.server_ip, &serv_addr.sin_addr) <= 0) {
        perror("Invalid address");
        close(sock);
        free(pubkey_hash);
        free(pubkey_hash_b64);
        free(encrypted);
        free(encrypted_key);
        free(iv);
        free(tag);
        free(encrypted_b64);
        free(encrypted_key_b64);
        free(iv_b64);
        free(tag_b64);
        free(message);
        return 1;
    }

    /* Connect to server */
    if (connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
        perror("Connection failed");
        close(sock);
        free(pubkey_hash);
        free(pubkey_hash_b64);
        free(encrypted);
        free(encrypted_key);
        free(iv);
        free(tag);
        free(encrypted_b64);
        free(encrypted_key_b64);
        free(iv_b64);
        free(tag_b64);
        free(message);
        return 1;
    }

    /* Form message to server */
    time_t create_at = time(NULL);
    // Calculate required buffer length
    size_t needed_len = strlen("SEND|") + strlen(pubkey_hash_b64) + 3*20 + strlen(encrypted_b64) + strlen(encrypted_key_b64) + strlen(iv_b64) + strlen(tag_b64) + 8;  // + for | and margin
    char *buffer = malloc(needed_len + 1);
    if (!buffer) {
        fprintf(stderr, "Error: Failed to allocate memory for message\n");
        close(sock);
        free(pubkey_hash);
        free(pubkey_hash_b64);
        free(encrypted);
        free(encrypted_key);
        free(iv);
        free(tag);
        free(encrypted_b64);
        free(encrypted_key_b64);
        free(iv_b64);
        free(tag_b64);
        free(message);
        return 1;
    }
    int len = snprintf(buffer, needed_len + 1, "SEND|%s|%ld|%ld|%ld|%s|%s|%s|%s",
             pubkey_hash_b64, create_at, unlock_at, expire_at,
             encrypted_b64, encrypted_key_b64, iv_b64, tag_b64);
    if (len < 0 || (size_t)len > needed_len) {
        fprintf(stderr, "Error: Failed to format message\n");
        free(buffer);
        close(sock);
        free(pubkey_hash);
        free(pubkey_hash_b64);
        free(encrypted);
        free(encrypted_key);
        free(iv);
        free(tag);
        free(encrypted_b64);
        free(encrypted_key_b64);
        free(iv_b64);
        free(tag_b64);
        free(message);
        return 1;
    }

    if (verbose) {
        printf("Sending: %s\n", buffer);
    }

    // Send length (4 bytes)
    uint32_t msg_len_net = htonl(len);
    if (send(sock, &msg_len_net, sizeof(uint32_t), 0) != sizeof(uint32_t)) {
        perror("Length send error");
        free(buffer);
        close(sock);
        free(pubkey_hash);
        free(pubkey_hash_b64);
        free(encrypted);
        free(encrypted_key);
        free(iv);
        free(tag);
        free(encrypted_b64);
        free(encrypted_key_b64);
        free(iv_b64);
        free(tag_b64);
        free(message);
        return 1;
    }

    // Send data
    if (send(sock, buffer, len, 0) != len) {
        perror("Send error");
        free(buffer);
        close(sock);
        free(pubkey_hash);
        free(pubkey_hash_b64);
        free(encrypted);
        free(encrypted_key);
        free(iv);
        free(tag);
        free(encrypted_b64);
        free(encrypted_key_b64);
        free(iv_b64);
        free(tag_b64);
        free(message);
        return 1;
    }
    free(buffer);

    /* Receive server response */
    uint32_t resp_len_net;
    int valread = read(sock, &resp_len_net, sizeof(uint32_t));
    if (valread != sizeof(uint32_t)) {
        perror("Response length read error");
        close(sock);
        free(pubkey_hash);
        free(pubkey_hash_b64);
        free(encrypted);
        free(encrypted_key);
        free(iv);
        free(tag);
        free(encrypted_b64);
        free(encrypted_key_b64);
        free(iv_b64);
        free(tag_b64);
        free(message);
        return 1;
    }
    size_t resp_len = ntohl(resp_len_net);

    char *resp_buffer = malloc(resp_len + 1);
    if (!resp_buffer) {
        fprintf(stderr, "Error: Failed to allocate memory for response\n");
        close(sock);
        free(pubkey_hash);
        free(pubkey_hash_b64);
        free(encrypted);
        free(encrypted_key);
        free(iv);
        free(tag);
        free(encrypted_b64);
        free(encrypted_key_b64);
        free(iv_b64);
        free(tag_b64);
        free(message);
        return 1;
    }

    size_t total_read = 0;
    while (total_read < resp_len) {
        valread = read(sock, resp_buffer + total_read, resp_len - total_read);
        if (valread <= 0) {
            if (valread < 0) perror("Read error");
            else fprintf(stderr, "Connection closed by server\n");
            free(resp_buffer);
            close(sock);
            free(pubkey_hash);
            free(pubkey_hash_b64);
            free(encrypted);
            free(encrypted_key);
            free(iv);
            free(tag);
            free(encrypted_b64);
            free(encrypted_key_b64);
            free(iv_b64);
            free(tag_b64);
            free(message);
            return 1;
        }
        total_read += valread;
    }
    resp_buffer[resp_len] = '\0';

    printf("Server response: %s\n", resp_buffer);

    free(resp_buffer);

    /* Free resources and close socket */
    close(sock);
    free(pubkey_hash);
    free(pubkey_hash_b64);
    free(encrypted);
    free(encrypted_key);
    free(iv);
    free(tag);
    free(encrypted_b64);
    free(encrypted_key_b64);
    free(iv_b64);
    free(tag_b64);
    free(message);
    return 0;
}
