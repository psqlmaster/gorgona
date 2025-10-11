#define _XOPEN_SOURCE 700
#include "encrypt.h"
#include "config.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <time.h>
#include <ctype.h>
#include <stdint.h>  // Добавлено для uint32_t

/* Removes trailing spaces, \n, \r from a string */
void trim_string(char *str) {
    size_t len = strlen(str);
    while (len > 0 && (str[len - 1] == ' ' || str[len - 1] == '\n' || str[len - 1] == '\r')) {
        str[len - 1] = '\0';
        len--;
    }
}

/* Converts time_t to UTC string (buffer provided externally) */
void time_to_utc_string(time_t t, char *buf, size_t bufsize) {
    struct tm *tm = gmtime(&t);
    if (!tm) {
        /* In case of gmtime error */
        snprintf(buf, bufsize, "(invalid time)");
        return;
    }
    strftime(buf, bufsize, "%Y-%m-%d %H:%M:%S", tm);
}

/* Checks for private key for pubkey_hash_b64 */
int has_private_key(const char *pubkey_hash_b64, int verbose) {
    char priv_file[256];
    snprintf(priv_file, sizeof(priv_file), "/etc/gargona/%s.key", pubkey_hash_b64);
    FILE *priv_fp = fopen(priv_file, "rb");
    if (!priv_fp) {
        if (verbose) fprintf(stderr, "Private key not found: /etc/gargona/%s\n", priv_file);
        return 0;
    }
    fclose(priv_fp);
    return 1;
}

/* Parses server response and processes message */
void parse_response(const char *response, const char *expected_pubkey_hash_b64, int verbose) {
    if (strncmp(response, "ALERT|", 6) != 0) {
        printf("Server response: %s\n", response);
        return;
    }

    char *copy = strdup(response + 6);
    if (!copy) {
        fprintf(stderr, "Failed to allocate memory for response\n");
        return;
    }

    char *pubkey_hash_b64 = strtok(copy, "|");
    if (!pubkey_hash_b64) {
        fprintf(stderr, "Error: Invalid ALERT format\n");
        free(copy);
        return;
    }

    char *create_at_str = strtok(NULL, "|");
    char *unlock_at_str = strtok(NULL, "|");
    char *expire_at_str = strtok(NULL, "|");
    char *encrypted_text = strtok(NULL, "|");
    char *encrypted_key = strtok(NULL, "|");
    char *iv = strtok(NULL, "|");
    char *tag = strtok(NULL, "|");

    if (!create_at_str || !unlock_at_str || !expire_at_str || !encrypted_text || 
        !encrypted_key || !iv || !tag) {
        fprintf(stderr, "Error: Incomplete data in ALERT\n");
        free(copy);
        return;
    }

    time_t create_at = atol(create_at_str);
    time_t unlock_at = atol(unlock_at_str);
    time_t expire_at = atol(expire_at_str);
    time_t now = time(NULL);

    /* Check filter by pubkey_hash_b64 */
    if (expected_pubkey_hash_b64 && strcmp(pubkey_hash_b64, expected_pubkey_hash_b64) != 0) {
        if (verbose) {
            printf("Skipped message for another pubkey_hash: %s\n", pubkey_hash_b64);
        }
        free(copy);
        return;
    }

    /* Check for private key early; if missing, skip silently */
    if (!has_private_key(pubkey_hash_b64, verbose)) {
        free(copy);
        return;
    }

    printf("Received message: Pubkey_Hash=%s\n", pubkey_hash_b64);
    /* Use separate buffers to avoid overwriting static buffer */
    char buf_create[32], buf_unlock[32], buf_expire[32];
    time_to_utc_string(create_at, buf_create, sizeof(buf_create));
    time_to_utc_string(unlock_at, buf_unlock, sizeof(buf_unlock));
    time_to_utc_string(expire_at, buf_expire, sizeof(buf_expire));

    printf("Metadata: Create=%s, Unlock=%s, Expire=%s\n", buf_create, buf_unlock, buf_expire);

    if (expire_at <= now) {
        printf("Message expired\n");
        free(copy);
        return;
    } else if (unlock_at > now) {
        printf("Locked message (type: text)\n");
        free(copy);
        return;
    }

    /* Decode base64 data */
    size_t encrypted_len, encrypted_key_len, iv_len, tag_len;
    unsigned char *encrypted = base64_decode(encrypted_text, &encrypted_len);
    unsigned char *encrypted_key_dec = base64_decode(encrypted_key, &encrypted_key_len);
    unsigned char *iv_dec = base64_decode(iv, &iv_len);
    unsigned char *tag_dec = base64_decode(tag, &tag_len);

    if (!encrypted || !encrypted_key_dec || !iv_dec || !tag_dec) {
        fprintf(stderr, "Error decoding base64 data\n");
        free(encrypted);
        free(encrypted_key_dec);
        free(iv_dec);
        free(tag_dec);
        free(copy);
        return;
    }

    /* Debug output */
    if (verbose) {
        printf("Before decryption: encrypted_len=%zu, encrypted_key_len=%zu, iv_len=%zu, tag_len=%zu\n",
               encrypted_len, encrypted_key_len, iv_len, tag_len);
        printf("encrypted_key (hex): ");
        for (size_t i = 0; i < encrypted_key_len; i++) printf("%02x", encrypted_key_dec[i]);
        printf("\n");
        printf("iv (hex): ");
        for (size_t i = 0; i < iv_len; i++) printf("%02x", iv_dec[i]);
        printf("\n");
        printf("tag (hex): ");
        for (size_t i = 0; i < tag_len; i++) printf("%02x", tag_dec[i]);
        printf("\n");
    }

    char priv_file[256];
    snprintf(priv_file, sizeof(priv_file), "/etc/gargona/%s.key", pubkey_hash_b64);

    char *plaintext = NULL;
    int ret = decrypt_message(encrypted, encrypted_len, encrypted_key_dec, encrypted_key_len,
                             iv_dec, iv_len, tag_dec, &plaintext, priv_file, verbose);

    free(encrypted);
    free(encrypted_key_dec);
    free(iv_dec);
    free(tag_dec);

    if (ret == 0 && plaintext) {
        printf("Decrypted message: \n%s\n\n", plaintext);
        free(plaintext);
    } else {
        fprintf(stderr, "Failed to decrypt message\n");
    }

    free(copy);
}

/* Listens for messages from server in specified mode */
int listen_alerts(int argc, char *argv[], int verbose) {
    if (argc < 2) {
        fprintf(stderr, "Usage: listen <mode> [<count>] [pubkey_hash_b64]\n");
        fprintf(stderr, "Modes: live, all, lock, single, last, new\n");
        fprintf(stderr, "For last mode: listen last [<count>] <pubkey_hash_b64> (count defaults to 1)\n");
        return 1;
    }

    char *mode = argv[1];
    int count = 1;  /* Default count for 'last' mode */
    char *pubkey_hash_b64 = NULL;

    /* Check mode */
    char *upper_mode = strdup(mode);
    for (char *p = upper_mode; *p; p++) *p = toupper((unsigned char)*p);
    int valid_mode = (strcmp(upper_mode, "LIVE") == 0 || 
                      strcmp(upper_mode, "ALL") == 0 || 
                      strcmp(upper_mode, "LOCK") == 0 || 
                      strcmp(upper_mode, "SINGLE") == 0 ||
                      strcmp(upper_mode, "LAST") == 0 ||
                      strcmp(upper_mode, "NEW") == 0);  // Добавлен режим new
    free(upper_mode);
    if (!valid_mode) {
        fprintf(stderr, "Invalid mode: %s\n", mode);
        return 1;
    }

    /* Parse arguments based on mode */
    if (strcmp(mode, "last") == 0) {
        if (argc == 3) {
            /* Format: listen last <pubkey_hash_b64> -> count=1 */
            pubkey_hash_b64 = argv[2];
        } else if (argc == 4) {
            /* Format: listen last <count> <pubkey_hash_b64> */
            char *endptr;
            count = strtol(argv[2], &endptr, 10);
            if (*endptr != '\0' || count <= 0) {
                fprintf(stderr, "Invalid count: %s (must be a positive integer)\n", argv[2]);
                return 1;
            }
            pubkey_hash_b64 = argv[3];
        } else {
            fprintf(stderr, "Usage for last mode: listen last [<count>] <pubkey_hash_b64>\n");
            return 1;
        }
    } else if (strcmp(mode, "single") == 0) {
        if (argc < 3) {
            fprintf(stderr, "Pubkey hash required for single mode\n");
            return 1;
        }
        pubkey_hash_b64 = argv[2];
    } else {
        if (argc > 2) {
            pubkey_hash_b64 = argv[2];
        }
    }

    char server_ip[256];
    int server_port;
    read_config(server_ip, &server_port);

    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        perror("Socket creation error");
        return 1;
    }

    struct sockaddr_in serv_addr = { .sin_family = AF_INET, .sin_port = htons(server_port) };
    if (inet_pton(AF_INET, server_ip, &serv_addr.sin_addr) <= 0) {
        perror("Invalid address");
        close(sock);
        return 1;
    }

    if (connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
        perror("Connection failed");
        close(sock);
        return 1;
    }

    /* Form request dynamically */
    size_t needed_len = 256;  /* Buffer size for request */
    char *buffer = malloc(needed_len);
    if (!buffer) {
        fprintf(stderr, "Error: Failed to allocate memory\n");
        close(sock);
        return 1;
    }
    int len;
    if (strcmp(mode, "single") == 0) {
        if (!pubkey_hash_b64) {
            fprintf(stderr, "Pubkey hash required for single mode\n");
            free(buffer);
            close(sock);
            return 1;
        }
        len = snprintf(buffer, needed_len, "LISTEN|%s|%s", pubkey_hash_b64, mode);
    } else if (strcmp(mode, "last") == 0) {
        if (!pubkey_hash_b64) {
            fprintf(stderr, "Pubkey hash required for last mode\n");
            free(buffer);
            close(sock);
            return 1;
        }
        len = snprintf(buffer, needed_len, "LISTEN|%s|%s|%d", pubkey_hash_b64, mode, count);
    } else {
        if (pubkey_hash_b64) {
            len = snprintf(buffer, needed_len, "SUBSCRIBE %s|%s", mode, pubkey_hash_b64);
        } else {
            len = snprintf(buffer, needed_len, "SUBSCRIBE %s", mode);
        }
    }
    if (len < 0 || (size_t)len >= needed_len) {
        fprintf(stderr, "Error: Message too long\n");
        free(buffer);
        close(sock);
        return 1;
    }

    if (verbose) {
        printf("Sending: %s\n", buffer);
    }

    /* Send length and data */
    uint32_t msg_len_net = htonl(len);
    if (send(sock, &msg_len_net, sizeof(uint32_t), 0) != sizeof(uint32_t)) {
        perror("Send error (length)");
        free(buffer);
        close(sock);
        return 1;
    }
    if (send(sock, buffer, len, 0) != len) {
        perror("Send error");
        free(buffer);
        close(sock);
        return 1;
    }
    free(buffer);

    /* Read responses in a loop */
    int messages_received = 0;
    while (1) {
        uint32_t resp_len_net;
        int valread = read(sock, &resp_len_net, sizeof(uint32_t));
        if (valread != sizeof(uint32_t)) {
            if (valread < 0) perror("Read error (length)");
            else printf("Connection closed by server\n");
            break;
        }
        size_t resp_len = ntohl(resp_len_net);

        char *resp_buffer = malloc(resp_len + 1);
        if (!resp_buffer) {
            fprintf(stderr, "Error: Failed to allocate memory for response\n");
            break;
        }

        size_t total_read = 0;
        while (total_read < resp_len) {
            valread = read(sock, resp_buffer + total_read, resp_len - total_read);
            if (valread <= 0) {
                if (valread < 0) perror("Read error");
                else fprintf(stderr, "Connection closed by server\n");
                free(resp_buffer);
                close(sock);
                return 1;
            }
            total_read += valread;
        }
        resp_buffer[resp_len] = '\0';

        if (verbose) {
            printf("Received response: %s\n", resp_buffer);
        }
        parse_response(resp_buffer, pubkey_hash_b64, verbose);

        free(resp_buffer);

        if (strcmp(mode, "last") == 0) {
            messages_received++;
            if (messages_received >= count) {
                break;
            }
        }
    }

    close(sock);
    return 0;
}
