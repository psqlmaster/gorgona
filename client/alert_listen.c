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
#include <stdint.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netinet/tcp.h>

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
        if (verbose) fprintf(stderr, "Private key not found: %s\n", priv_file);
        return 0;
    }
    fclose(priv_fp);
    return 1;
}

/* Parses server response and processes message */
void parse_response(const char *response, const char *expected_pubkey_hash_b64, int verbose, int execute, Config *config) {
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
        free(copy);
        free(encrypted);
        free(encrypted_key_dec);
        free(iv_dec);
        free(tag_dec);
        return;
    }
    char priv_file[256];
    snprintf(priv_file, sizeof(priv_file), "/etc/gargona/%s.key", pubkey_hash_b64);
    char *plaintext = NULL;
    int ret = decrypt_message(encrypted, encrypted_len, encrypted_key_dec, encrypted_key_len, iv_dec, iv_len, tag_dec, &plaintext, priv_file, verbose);
    free(encrypted);
    free(encrypted_key_dec);
    free(iv_dec);
    free(tag_dec);
    if (ret == 0 && plaintext) {
        if (execute) {
            char *script_to_run = NULL;
            if (config->exec_count == 0) {
                script_to_run = plaintext;
            } else {
                for (int i = 0; i < config->exec_count; i++) {
                    if (strcmp(plaintext, config->exec_commands[i].key) == 0) {
                        script_to_run = config->exec_commands[i].value;
                        break;
                    }
                }
            }
            if (script_to_run) {
                if (verbose) {
                    printf("Executing command: %s\n", script_to_run);
                }
                int ret = system(script_to_run);
                if (ret != 0) {
                    fprintf(stderr, "Command execution failed: %s\n", script_to_run);
                }
            } else if (verbose) {
                printf("No matching script found for message: %s\n", plaintext);
            }
        } else {
            printf("Decrypted message:\n%s\n", plaintext);
        }
        free(plaintext);
    }
    free(copy);
}

/* Listens for messages from server in specified mode */
int listen_alerts(int argc, char *argv[], int verbose, int execute) {
    if (argc < 2) {
        fprintf(stderr, "Usage: listen <mode> [<count>] [pubkey_hash_b64]\n");
        fprintf(stderr, "Modes: live, all, lock, single, last, new\n");
        fprintf(stderr, "For last mode: listen last [<count>] <pubkey_hash_b64> (count defaults to 1)\n");
        return 1;
    }
    
    char *mode = argv[1];
    int count = 1; // Default count
    char *pubkey_hash_b64 = NULL;
    
    /* Mode validation */
    char *upper_mode = strdup(mode);
    for (char *p = upper_mode; *p; p++) *p = toupper((unsigned char)*p);
    int valid_mode = (strcmp(upper_mode, "LIVE") == 0 ||
                      strcmp(upper_mode, "ALL") == 0 ||
                      strcmp(upper_mode, "LOCK") == 0 ||
                      strcmp(upper_mode, "SINGLE") == 0 ||
                      strcmp(upper_mode, "LAST") == 0 ||
                      strcmp(upper_mode, "NEW") == 0);
    free(upper_mode);
    if (!valid_mode) {
        fprintf(stderr, "Invalid mode: %s\n", mode);
        return 1;
    }
    
    /* Parse arguments */
    if (strcmp(mode, "last") == 0) {
        if (argc == 3) {
            pubkey_hash_b64 = argv[2];
        } else if (argc == 4) {
            char *endptr;
            count = strtol(argv[2], &endptr, 10);
            if (*endptr != '\0' || count <= 0) {
                fprintf(stderr, "Invalid count: %s\n", argv[2]);
                return 1;
            }
            pubkey_hash_b64 = argv[3];
        } else {
            fprintf(stderr, "Usage for last: listen last [<count>] <pubkey_hash_b64>\n");
            return 1;
        }
    } else if (strcmp(mode, "single") == 0) {
        if (argc != 3) {
            fprintf(stderr, "Usage for single: listen single <pubkey_hash_b64>\n");
            return 1;
        }
        pubkey_hash_b64 = argv[2];
    } else {
        if (argc == 3) {
            pubkey_hash_b64 = argv[2];
        } else if (argc != 2) {
            fprintf(stderr, "Usage for %s: listen %s [pubkey_hash_b64]\n", mode, mode);
            return 1;
        }
    }
    
    // Debug: Print parsed arguments
    if (verbose) {
        printf("Debug: Parsed mode='%s', count=%d, pubkey_hash_b64='%s'\n", mode, count, pubkey_hash_b64 ? pubkey_hash_b64 : "NULL");
    }

    Config config;
    read_config(&config, verbose);

    int reconnect_delay = 5;
    int reconnect_increment = 10;
    int max_reconnect_delay = 60;

    while (1) {
        int sock = socket(AF_INET, SOCK_STREAM, 0);
        if (sock < 0) {
            perror("Socket creation error");
            sleep(reconnect_delay);
            reconnect_delay = (reconnect_delay + reconnect_increment) < max_reconnect_delay ? 
                             (reconnect_delay + reconnect_increment) : max_reconnect_delay;
            continue;
        }

        struct sockaddr_in serv_addr = { .sin_family = AF_INET, .sin_port = htons(config.server_port) };
        if (inet_pton(AF_INET, config.server_ip, &serv_addr.sin_addr) <= 0) {
            fprintf(stderr, "Invalid address: %s\n", config.server_ip);
            close(sock);
            sleep(reconnect_delay);
            reconnect_delay = (reconnect_delay + reconnect_increment) < max_reconnect_delay ? 
                             (reconnect_delay + reconnect_increment) : max_reconnect_delay;
            continue;
        }

        if (connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
            fprintf(stderr, "Connection failed: %s\n", strerror(errno));
            close(sock);
            sleep(reconnect_delay);
            reconnect_delay = (reconnect_delay + reconnect_increment) < max_reconnect_delay ? 
                             (reconnect_delay + reconnect_increment) : max_reconnect_delay;
            continue;
        }

        // Enable TCP keepalive
        int opt = 1;
        if (setsockopt(sock, SOL_SOCKET, SO_KEEPALIVE, &opt, sizeof(opt)) < 0) {
            fprintf(stderr, "setsockopt SO_KEEPALIVE failed: %s\n", strerror(errno));
            close(sock);
            sleep(reconnect_delay);
            continue;
        }

        // Platform-specific keepalive settings
        #ifdef __linux__
            int idle = 60;  // Start probing after 60 sec of idle
            if (setsockopt(sock, IPPROTO_TCP, TCP_KEEPIDLE, &idle, sizeof(idle)) < 0) {
                fprintf(stderr, "setsockopt TCP_KEEPIDLE failed: %s\n", strerror(errno));
            }

            int interval = 10;  // Probe every 10 sec
            if (setsockopt(sock, IPPROTO_TCP, TCP_KEEPINTVL, &interval, sizeof(interval)) < 0) {
                fprintf(stderr, "setsockopt TCP_KEEPINTVL failed: %s\n", strerror(errno));
            }

            int keep_count = 3;  // Max 3 probes before closing (renamed to avoid shadowing)
            if (setsockopt(sock, IPPROTO_TCP, TCP_KEEPCNT, &keep_count, sizeof(keep_count)) < 0) {
                fprintf(stderr, "setsockopt TCP_KEEPCNT failed: %s\n", strerror(errno));
            }
        #elif defined(__APPLE__)
            int keepalive_time = 60;  // macOS uses TCP_KEEPALIVE (in seconds)
            if (setsockopt(sock, IPPROTO_TCP, TCP_KEEPALIVE, &keepalive_time, sizeof(keepalive_time)) < 0) {
                fprintf(stderr, "setsockopt TCP_KEEPALIVE failed: %s\n", strerror(errno));
            }
        #else
            if (verbose) {
                printf("Warning: Platform-specific TCP keepalive settings not implemented, using SO_KEEPALIVE only\n");
            }
        #endif

        // Reset reconnect delay on successful connection
        reconnect_delay = 5;
        
        if (verbose) {
            printf("Connected to %s:%d\n", config.server_ip, config.server_port);
        }
        
        /* Form request */
        size_t needed_len = 256;
        char *buffer = malloc(needed_len);
        if (!buffer) {
            fprintf(stderr, "Error: Failed to allocate memory\n");
            close(sock);
            sleep(reconnect_delay);
            continue;
        }
        
        int len;
        if (strcmp(mode, "single") == 0) {
            len = snprintf(buffer, needed_len, "LISTEN|%s|%s", pubkey_hash_b64, mode);
        } else if (strcmp(mode, "last") == 0) {
            len = snprintf(buffer, needed_len, "LISTEN|%s|%s|%d", pubkey_hash_b64, mode, count);
            if (verbose) {
                printf("Debug: Forming request with count=%d\n", count);
            }
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
            sleep(reconnect_delay);
            continue;
        }
        
        if (verbose) {
            printf("Sending: %s\n", buffer);
        }
        
        /* Send request */
        uint32_t msg_len_net = htonl(len);
        ssize_t send_result;
        
        send_result = send(sock, &msg_len_net, sizeof(uint32_t), MSG_NOSIGNAL);
        if (send_result != sizeof(uint32_t)) {
            fprintf(stderr, "Send error (length): %s\n", strerror(errno));
            free(buffer);
            close(sock);
            sleep(reconnect_delay);
            continue;
        }
        
        send_result = send(sock, buffer, len, MSG_NOSIGNAL);
        if (send_result != len) {
            fprintf(stderr, "Send error: %s\n", strerror(errno));
            free(buffer);
            close(sock);
            sleep(reconnect_delay);
            continue;
        }
        
        free(buffer);
        
        /* Read responses */
        int messages_received = 0;
        int connection_ok = 1;
        struct timeval start_time;
        gettimeofday(&start_time, NULL);

        // Set shorter periodic timeout for one-time modes (last, single)
        int periodic_reconnect_sec = (strcmp(mode, "last") == 0 || strcmp(mode, "single") == 0) ? 10 : 1200;

        while (connection_ok) {
            // Check time for periodic reconnection
            struct timeval current_time;
            gettimeofday(&current_time, NULL);
            long elapsed_sec = current_time.tv_sec - start_time.tv_sec;
            if (elapsed_sec > periodic_reconnect_sec) {
                if (verbose) printf("Periodic reconnect after %ld seconds\n", elapsed_sec);
                connection_ok = 0;
                break;
            }

            uint32_t resp_len_net;
            ssize_t valread;
            
            valread = recv(sock, &resp_len_net, sizeof(uint32_t), MSG_WAITALL);
            if (valread == 0) {
                if (verbose) fprintf(stderr, "Debug: Connection closed by server\n");
                connection_ok = 0;
                break;
            } else if (valread < 0) {
                if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK) {
                    continue;
                }
                fprintf(stderr, "Read error (length): %s\n", strerror(errno));
                connection_ok = 0;
                break;
            } else if (valread != sizeof(uint32_t)) {
                fprintf(stderr, "Incomplete length read: %zd/%zu\n", valread, sizeof(uint32_t));
                connection_ok = 0;
                break;
            }
            
            size_t resp_len = ntohl(resp_len_net);
            if (resp_len == 0 || resp_len > 1024 * 1024) { // Sanity check
                fprintf(stderr, "Invalid response length: %zu\n", resp_len);
                connection_ok = 0;
                break;
            }
            
            char *resp_buffer = malloc(resp_len + 1);
            if (!resp_buffer) {
                fprintf(stderr, "Error: Failed to allocate memory for response\n");
                connection_ok = 0;
                break;
            }
            
            size_t total_read = 0;
            while (total_read < resp_len && connection_ok) {
                valread = recv(sock, resp_buffer + total_read, resp_len - total_read, 0);
                if (valread == 0) {
                    if (verbose) fprintf(stderr, "Debug: Connection closed by server during data read\n");
                    connection_ok = 0;
                    break;
                } else if (valread < 0) {
                    if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK) {
                        continue;
                    }
                    fprintf(stderr, "Read error: %s\n", strerror(errno));
                    connection_ok = 0;
                    break;
                }
                total_read += valread;
            }
            
            if (!connection_ok) {
                free(resp_buffer);
                break;
            }
            
            if (total_read != resp_len) {
                fprintf(stderr, "Incomplete data read: %zu/%zu\n", total_read, resp_len);
                free(resp_buffer);
                connection_ok = 0;
                break;
            }
            
            resp_buffer[resp_len] = '\0';
            if (verbose) {
                printf("Received response: %s\n", resp_buffer);
            }
            
            // Process the response
            parse_response(resp_buffer, pubkey_hash_b64, verbose, execute, &config);
            
            // Increment messages_received only for ALERT messages and break if count reached in last mode
            if (strcmp(mode, "last") == 0 && strncmp(resp_buffer, "ALERT|", 6) == 0) {
                messages_received++;
                if (verbose) {
                    printf("Debug: Processed ALERT message %d of %d\n", messages_received, count);
                }
                if (messages_received >= count) {
                    free(resp_buffer);
                    close(sock);
                    if (verbose) {
                        printf("Debug: Reached requested count (%d), exiting\n", count);
                    }
                    return 0; // Exit after receiving the requested number of messages
                }
            }

            free(resp_buffer);
        }
        
        close(sock);
        
        // Always return for 'last' and 'single' modes to prevent reconnect
        if (strcmp(mode, "last") == 0 || strcmp(mode, "single") == 0) {
            if (verbose && messages_received == 0) {
                printf("Debug: No messages received, exiting\n");
            }
            return 0;
        }
        
        fprintf(stderr, "Connection lost, reconnecting in %d seconds...\n", reconnect_delay);
        sleep(reconnect_delay);
        reconnect_delay = (reconnect_delay + reconnect_increment) < max_reconnect_delay ? 
                         (reconnect_delay + reconnect_increment) : max_reconnect_delay;
    }
    
    return 0;
}
