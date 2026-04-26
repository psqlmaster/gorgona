/* 
* client/alert_send.c - Implementation of encrypted alert transmission
* BSD 3-Clause License
* Copyright (c) 2025, Alexander Shcheglov
*/

#define _XOPEN_SOURCE 700
#include "encrypt.h"
#include "config.h"
#include "admin_mesh.h"
#include "peer_manager.h"
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

extern int verbose;

/**
 * Parses date and time in format "YYYY-MM-DD HH:MM:S"
 * Interprets the supplied datetime string as UTC.
 */
time_t parse_datetime(const char *datetime) {
    struct tm tm = {0};
    if (strptime(datetime, "%Y-%m-%d %H:%M:%S", &tm) == NULL) {
        fprintf(stderr, "Error: Invalid time format: %s\n", datetime);
        return -1;
    }
    tm.tm_isdst = -1;
#if defined(_GNU_SOURCE) || defined(__USE_MISC) || defined(_BSD_SOURCE) || defined(__APPLE__)
    return timegm(&tm);
#else
    char *old_tz = getenv("TZ");
    char *old_tz_copy = old_tz ? strdup(old_tz) : NULL;
    setenv("TZ", "UTC", 1);
    tzset();
    time_t t = mktime(&tm);
    if (old_tz_copy) {
        setenv("TZ", old_tz_copy, 1);
        free(old_tz_copy);
    } else unsetenv("TZ");
    tzset();
    return t;
#endif
}

/**
 * Reads input from stdin into a dynamically allocated buffer.
 */
char *read_from_stdin(size_t *out_len) {
    size_t capacity = 1024;
    size_t len = 0;
    char *buffer = malloc(capacity);
    if (!buffer) return NULL;

    int c;
    while ((c = getchar()) != EOF) {
        if (len + 1 >= capacity) {
            capacity *= 2;
            char *new_buffer = realloc(buffer, capacity);
            if (!new_buffer) {
                free(buffer);
                return NULL;
            }
            buffer = new_buffer;
        }
        buffer[len++] = (char)c;
    }
    buffer[len] = '\0';
    *out_len = len;
    return buffer;
}

/**
 * Primary function to encrypt and transmit an alert to the Mesh.
 */
int send_alert(int argc, char *argv[], int verbose_flag) {
    char *buffer = NULL;
    if (argc != 5) {
        fprintf(stderr, "Usage: send <unlock_time> <expire_time> <message> <public_key_file>\n");
        return 1;
    }

    /* 1. Extract and Parse Arguments */
    time_t unlock_at = parse_datetime(argv[1]);
    time_t expire_at = parse_datetime(argv[2]);
    if (unlock_at == -1 || expire_at == -1) return 1;
    
    const char *message_arg = argv[3];
    const char *pubkey_file = argv[4];
    char *message = NULL;
    size_t message_len = 0;

    if (strcmp(message_arg, "-") == 0) {
        message = read_from_stdin(&message_len);
    } else {
        message = strdup(message_arg);
        if (message) message_len = strlen(message);
    }
    if (!message) return 1;

    /* 2. Cryptography: Load Public Key and Hash it */
    char full_pubkey_file[256];
    snprintf(full_pubkey_file, sizeof(full_pubkey_file), "/etc/gorgona/%s", pubkey_file);
    FILE *pub_fp = fopen(full_pubkey_file, "rb");
    if (!pub_fp) {
        fprintf(stderr, "Failed to open public key: %s\n", full_pubkey_file);
        free(message); return 1;
    }
    EVP_PKEY *pubkey = PEM_read_PUBKEY(pub_fp, NULL, NULL, NULL);
    fclose(pub_fp);
    if (!pubkey) {
        fprintf(stderr, "Failed to parse RSA key\n");
        free(message); return 1;
    }

    size_t hash_len;
    unsigned char *pubkey_hash = compute_pubkey_hash(pubkey, &hash_len, verbose_flag);
    EVP_PKEY_free(pubkey);
    char *pubkey_hash_b64 = base64_encode(pubkey_hash, hash_len);
    free(pubkey_hash);

    /* 3. Data Encryption (AES-256-GCM) */
    unsigned char *encrypted = NULL, *encrypted_key = NULL, *iv = NULL, *tag = NULL;
    size_t e_len, k_len, i_len, t_len;
    if (encrypt_message(message, &encrypted, &e_len, &encrypted_key, &k_len, &iv, &i_len, &tag, &t_len, full_pubkey_file, verbose_flag) != 0) {
        free(pubkey_hash_b64); free(message); return 1;
    }

    char *encrypted_b64 = base64_encode(encrypted, e_len);
    char *encrypted_key_b64 = base64_encode(encrypted_key, k_len);
    char *iv_b64 = base64_encode(iv, i_len);
    char *tag_b64 = base64_encode(tag, t_len);

    /* 4. Configuration and Networking initialization */
    Config config;
    read_config(&config, verbose_flag);
    bool l2_enabled = (config.sync_psk[0] != '\0');
    if (l2_enabled) {
        mesh_init(config.sync_psk);
    }

    /* Assemble Protocol Buffer and Check 50MB hard-limit */
    size_t needed_len = strlen("SEND|") + strlen(pubkey_hash_b64) + 128 + strlen(encrypted_b64) + strlen(encrypted_key_b64) + strlen(iv_b64) + strlen(tag_b64);
    const size_t CLIENT_MAX_LIMIT = 50 * 1024 * 1024;
    if (needed_len > CLIENT_MAX_LIMIT) {
        fprintf(stderr, "Error: Payload exceeds 50MB limit.\n");
        goto cleanup_all;
    }

    /* 2. Сначала выделяем память */
    buffer = malloc(needed_len + 1);
    if (!buffer) {
        fprintf(stderr, "Error: Memory allocation failed\n");
        goto cleanup_all;
    }

    /* 3. И только теперь записываем данные в уже выделенную память */
    int total_len = snprintf(buffer, needed_len + 1, "SEND|%s|%ld|%ld|%s|%s|%s|%s",
                             pubkey_hash_b64, (long)unlock_at, (long)expire_at, 
                             encrypted_b64, encrypted_key_b64, iv_b64, tag_b64);

    struct timeval tv_start, tv_conn, tv_auth, tv_send, tv_ack;
    gettimeofday(&tv_start, NULL);

    /* 5. MESH-AWARE CONNECTION */
    peer_manager_load_cache(&config);
    int sock = peer_manager_get_best_connection();
    gettimeofday(&tv_conn, NULL);

    if (sock < 0) {
        fprintf(stderr, "Mesh Error: All node candidates are unreachable.\n");
        goto cleanup_all;
    }

    char current_ip[INET_ADDRSTRLEN] = "unknown";
    struct sockaddr_in p_addr; 
    socklen_t p_l = sizeof(p_addr);
    if (getpeername(sock, (struct sockaddr *)&p_addr, &p_l) == 0) {
        inet_ntop(AF_INET, &p_addr.sin_addr, current_ip, sizeof(current_ip));
    }

    /* 6. MESH LAYER AUTHENTICATION (The L2 Handshake) */
    if (l2_enabled) {
        char auth_req[256];
        int al = snprintf(auth_req, 256, "AUTH|%s|0", config.sync_psk);
        uint32_t al_net = htonl(al);
        if (send(sock, &al_net, 4, MSG_NOSIGNAL) != 4 || send(sock, auth_req, al, MSG_NOSIGNAL) != al) {
            peer_manager_mark_bad(current_ip);
            close(sock); goto cleanup_all;
        }
        /* Drain auth response - this is a blocking RTT call */
        uint32_t a_r_l_n;
        if (read(sock, &a_r_l_n, 4) == 4) {
            size_t a_r_l = ntohl(a_r_l_n);
            if (a_r_l < 1024) { 
                char a_buf[1024]; 
                read(sock, a_buf, a_r_l); 
            }
        }
    }
    gettimeofday(&tv_auth, NULL);

    /* 7. DATA TRANSMISSION (CHUNKED) */
    if (verbose_flag) printf("Transmission: Sending %d bytes to %s\n", total_len, current_ip);
    signal(SIGPIPE, SIG_IGN);

    uint32_t msg_len_net = htonl((uint32_t)total_len);
    if (send(sock, &msg_len_net, 4, MSG_NOSIGNAL) != 4) {
        peer_manager_mark_bad(current_ip); close(sock); goto cleanup_all;
    }

    size_t total_sent = 0;
    size_t chunk_size = 65536; 
    bool aborted = false;

    while (total_sent < (size_t)total_len) {
        size_t to_send = ((size_t)total_len - total_sent > chunk_size) ? chunk_size : ((size_t)total_len - total_sent);
        ssize_t sent = send(sock, buffer + total_sent, to_send, MSG_NOSIGNAL);
        
        if (sent <= 0) { aborted = true; break; }
        total_sent += sent;
   }
    gettimeofday(&tv_send, NULL);

    /* 8. WAIT FOR SERVER ACKNOWLEDGEMENT */
    if (!aborted) {
        struct timeval tv_to = {10, 0};
        setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv_to, sizeof(tv_to));
        uint32_t resp_len_net;
        if (read(sock, &resp_len_net, 4) == 4) {
            size_t resp_len = ntohl(resp_len_net);
            if (resp_len > 0 && resp_len < 2048) {
                char *resp_buf = malloc(resp_len + 1);
                if (read(sock, resp_buf, resp_len) == (ssize_t)resp_len) {
                    resp_buf[resp_len] = '\0';
                    printf("Server Result: %s\n", resp_buf);
                }
                free(resp_buf);
            }
        }
    } else {
        peer_manager_mark_bad(current_ip);
        fprintf(stderr, "Error: Transmission failed or server dropped the connection.\n");
    }
    gettimeofday(&tv_ack, NULL);

    if (verbose_flag) {
        double diff_conn = (tv_conn.tv_sec - tv_start.tv_sec) * 1000.0 + (tv_conn.tv_usec - tv_start.tv_usec) / 1000.0;
        double diff_auth = (tv_auth.tv_sec - tv_conn.tv_sec) * 1000.0 + (tv_auth.tv_usec - tv_conn.tv_usec) / 1000.0;
        double diff_send = (tv_send.tv_sec - tv_auth.tv_sec) * 1000.0 + (tv_send.tv_usec - tv_auth.tv_usec) / 1000.0;
        double diff_ack  = (tv_ack.tv_sec - tv_send.tv_sec) * 1000.0 + (tv_ack.tv_usec - tv_send.tv_usec) / 1000.0;
        double diff_total = (tv_ack.tv_sec - tv_start.tv_sec) * 1000.0 + (tv_ack.tv_usec - tv_start.tv_usec) / 1000.0;

        printf("\n--- Performance Metrics ---\n");
        printf("TCP Connection:   %.2f ms\n", diff_conn);
        printf("L2 Mesh Auth:     %.2f ms (Wait for AUTH_SUCCESS)\n", diff_auth);
        printf("Data Send:        %.2f ms (Raw Payload)\n", diff_send);
        printf("Server ACK:       %.2f ms (Wait for Confirmation)\n", diff_ack);
        printf("Total Net Time:   %.2f ms\n", diff_total);
        printf("---------------------------\n");
    }

    close(sock); 

cleanup_all:
    if (buffer) free(buffer);
    free(pubkey_hash_b64); free(message);
    free(encrypted); free(encrypted_key); free(iv); free(tag);
    free(encrypted_b64); free(encrypted_key_b64); free(iv_b64); free(tag_b64);
    return 0;
}

/**
 * Function to recall (cancel) a previously sent alert.
 * Command format: gorgona revoke <id> <pubkey_hash_b64>
 */
int send_revocation(int argc, char *argv[], int verbose_flag) {
    if (argc != 3) {
        fprintf(stderr, "Usage: revoke <alert_id> <pubkey_hash_b64>\n");
        return 1;
    }

    uint64_t alert_id = strtoull(argv[1], NULL, 10);
    const char *pubkey_hash_b64 = argv[2];

    /* Download and encrypt the public key (the server needs it to verify the signature) */
    char pub_path[256];
    snprintf(pub_path, sizeof(pub_path), "/etc/gorgona/%s.pub", pubkey_hash_b64);
    
    FILE *f_pub = fopen(pub_path, "rb");
    if (!f_pub) {
        fprintf(stderr, "Error: Public key file not found: %s\n", pub_path);
        return 1;
    }
    fseek(f_pub, 0, SEEK_END);
    long pub_fsize = ftell(f_pub);
    fseek(f_pub, 0, SEEK_SET);
    unsigned char *pub_content = malloc(pub_fsize);
    fread(pub_content, 1, pub_fsize, f_pub);
    fclose(f_pub);

    char *pubkey_b64 = base64_encode(pub_content, pub_fsize);
    free(pub_content);

    /* Sign the ID with the private key */
    char priv_path[256];
    snprintf(priv_path, sizeof(priv_path), "/etc/gorgona/%s.key", pubkey_hash_b64);
    char sig_b64[512] = {0};
    if (sign_message_id(alert_id, priv_path, sig_b64, sizeof(sig_b64), verbose_flag) != 0) {
        fprintf(stderr, "Error: Failed to sign revocation request.\n");
        free(pubkey_b64);
        return 1;
    }

    /* Network initialization */
    Config config;
    read_config(&config, verbose_flag);
    peer_manager_load_cache(&config);
    int sock = peer_manager_get_best_connection();
    if (sock < 0) { free(pubkey_b64); return 1; }

    /* We are forming a complete team (4 fields after REVOKE|) */
    /* Format: REVOKE|ID|HASH|PUBKEY_B64|SIG_B64 */
    size_t cmd_max = strlen(pubkey_hash_b64) + strlen(pubkey_b64) + strlen(sig_b64) + 128;
    char *cmd = malloc(cmd_max);
    int cmd_len = snprintf(cmd, cmd_max, "REVOKE|%" PRIu64 "|%s|%s|%s", 
                           alert_id, pubkey_hash_b64, pubkey_b64, sig_b64);

    uint32_t net_len = htonl((uint32_t)cmd_len);
    send(sock, &net_len, 4, 0);
    send(sock, cmd, cmd_len, 0);

    /* Server response */
    uint32_t r_len_n;
    if (read(sock, &r_len_n, 4) == 4) {
        uint32_t r_len = ntohl(r_len_n);
        char *resp = malloc(r_len + 1);
        read(sock, resp, r_len);
        resp[r_len] = '\0';
        printf("Server Result: %s\n", resp);
        free(resp);
    }

    close(sock);
    free(pubkey_b64);
    free(cmd);
    return 0;
}
