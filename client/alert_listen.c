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
#include <dirent.h>
#include <inttypes.h>
#include <fcntl.h>
#include <sys/wait.h> 
#include <ctype.h> 
#define SNOWFLAKE_EPOCH 1735689600000ULL  /* 1 January 2025 в ms (из snowflake.h) */

typedef struct PendingAlert {
    char *pubkey_hash_b64;
    uint64_t id;
    time_t unlock_at;
    time_t expire_at;
    char *encrypted_text;
    char *encrypted_key;
    char *iv;
    char *tag;
    struct PendingAlert *next;
} PendingAlert;

static PendingAlert *pending_alerts = NULL;

/**
 * Escapes single quotes for shell safety.
 */
static void append_escaped(char **dst, const char *src) {
    while (*src) {
        if (*src == '\'') {
            memcpy(*dst, "'\\''", 4);
            *dst += 4;
        } else if (*src != '\n' && *src != '\r') { /* Skip newlines/CR in tokens */
            **dst = *src;
            (*dst)++;
        }
        src++;
    }
}

/**
 * Advanced sanitize and concat for complex shell commands with pipes.
 */
char* sanitize_and_concat(const char *script, const char *args) {
    if (!args || strlen(args) == 0) return strdup(script);

    /* Allocate plenty of memory (script + 5x args + margin) */
    size_t safe_len = strlen(script) + (strlen(args) * 5) + 256;
    char *result = (char *)calloc(1, safe_len);
    if (!result) return NULL;

    /* 1. Find the first shell operator (| ; > &) */
    const char *insertion_point = strpbrk(script, "|;>&");
    size_t head_len = insertion_point ? (size_t)(insertion_point - script) : strlen(script);

    char *ptr = result;

    /* 2. Copy the command head (before the pipe) */
    memcpy(ptr, script, head_len);
    ptr += head_len;

    /* Trim trailing spaces from head to avoid "cmd  'arg'" */
    while (ptr > result && isspace((unsigned char)*(ptr - 1))) {
        ptr--;
    }

    /* 3. Safely process and add arguments */
    char *args_copy = strdup(args);
    if (!args_copy) { free(result); return NULL; }

    /* Split by any whitespace: space, tab, newline, carriage return */
    char *token = strtok(args_copy, " \t\n\r");
    while (token != NULL) {
        *ptr++ = ' ';
        *ptr++ = '\'';
        append_escaped(&ptr, token);
        *ptr++ = '\'';
        token = strtok(NULL, " \t\n\r");
    }
    free(args_copy);

    /* 4. Add the rest of the command (tail) */
    if (insertion_point) {
        /* Add a space before the operator if it's not already there */
        if (ptr > result && *(ptr - 1) != ' ') {
            *ptr++ = ' ';
        }
        size_t tail_len = strlen(insertion_point);
        memcpy(ptr, insertion_point, tail_len);
        ptr += tail_len;
    }

    *ptr = '\0';
    return result;
}

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
        snprintf(buf, bufsize, "(invalid time)");
        return;
    }
    strftime(buf, bufsize, "%Y-%m-%d %H:%M:%S", tm);
}

/* Checks for private key for pubkey_hash_b64 */
int has_private_key(const char *pubkey_hash_b64, int verbose) {
    char priv_file[256];
    snprintf(priv_file, sizeof(priv_file), "/etc/gorgona/%s.key", pubkey_hash_b64);
    FILE *priv_fp = fopen(priv_file, "rb");
    if (!priv_fp) {
        if (verbose) fprintf(stderr, "Private key not found: %s\n", priv_file);
        return 0;
    }
    fclose(priv_fp);
    return 1;
}

/* Collects all private key hashes from /etc/gorgona/ */
int collect_key_hashes(char ***key_hashes, int *key_count, int verbose) {
    *key_hashes = NULL;
    *key_count = 0;
    DIR *dir = opendir("/etc/gorgona");
    if (!dir) {
        if (verbose) fprintf(stderr, "Failed to open directory /etc/gorgona: %s\n", strerror(errno));
        return 0;
    }
    struct dirent *entry;
    int capacity = 10;
    *key_hashes = malloc(capacity * sizeof(char *));
    if (!*key_hashes) {
        closedir(dir);
        return 0;
    }
    while ((entry = readdir(dir))) {
        if (strstr(entry->d_name, ".key")) {
            char *hash = strdup(entry->d_name);
            if (!hash) continue;
            hash[strlen(hash) - 4] = '\0'; // Remove .key extension
            if (*key_count >= capacity) {
                capacity *= 2;
                char **new_hashes = realloc(*key_hashes, capacity * sizeof(char *));
                if (!new_hashes) {
                    free(hash);
                    continue;
                }
                *key_hashes = new_hashes;
            }
            (*key_hashes)[*key_count] = hash;
            (*key_count)++;
        }
    }
    closedir(dir);
    return 1;
}

/* Frees key hashes array */
void free_key_hashes(char **key_hashes, int key_count) {
    for (int i = 0; i < key_count; i++) {
        free(key_hashes[i]);
    }
    free(key_hashes);
}

/* flag (-d) Executes command in background (daemon) */
void daemon_exec(const char *command, int verbose) {
    pid_t pid = fork();
    if (pid == 0) {
        setsid();
        const char *log_path = getenv("gorgona_LOG_FILE");
        int fd = -1;
        if (log_path && log_path[0]) {
            fd = open(log_path, O_WRONLY | O_CREAT | O_APPEND, 0644);
        }
        if (fd == -1) {
            fd = open("/dev/null", O_RDWR);
        }
        if (fd != -1) {
            dup2(fd, STDIN_FILENO);
            dup2(fd, STDOUT_FILENO);
            dup2(fd, STDERR_FILENO);
            if (fd > 2) close(fd);
        }
        execl("/bin/sh", "sh", "-c", command, (char *)NULL);
        _exit(127);
    } else if (pid > 0) {
        if (verbose) {
            printf("Launched background process PID=%d\n", (int)pid);
        }
    } else {
        perror("fork");
    }
}

static void execute_pending_alert(PendingAlert *pa, int verbose, Config *config) {
    size_t encrypted_len, encrypted_key_len, iv_len, tag_len;
    unsigned char *encrypted = base64_decode(pa->encrypted_text, &encrypted_len);
    unsigned char *encrypted_key_dec = base64_decode(pa->encrypted_key, &encrypted_key_len);
    unsigned char *iv_dec = base64_decode(pa->iv, &iv_len);
    unsigned char *tag_dec = base64_decode(pa->tag, &tag_len);

    if (!encrypted || !encrypted_key_dec || !iv_dec || !tag_dec) {
        fprintf(stderr, "Base64 decode failed for pending alert ID=%" PRIu64 "\n", pa->id);
        goto cleanup;
    }

    char priv_file[256];
    snprintf(priv_file, sizeof(priv_file), "/etc/gorgona/%s.key", pa->pubkey_hash_b64);
    char *plaintext = NULL;
    int ret = decrypt_message(encrypted, encrypted_len, encrypted_key_dec, encrypted_key_len,
                             iv_dec, iv_len, tag_dec, &plaintext, priv_file, verbose);
    
    if (ret != 0 || !plaintext) {
        fprintf(stderr, "Decryption failed for pending alert ID=%" PRIu64 "\n", pa->id);
        goto cleanup;
    }

    /* Start of updated execution logic */
    char *final_command = NULL;

    if (config->exec_count == 0) {
        final_command = strdup(plaintext);
    } else {
        for (int i = 0; i < config->exec_count; i++) {
            size_t key_len = strlen(config->exec_commands[i].key);
            
            /* Check if the message starts with the allowed key */
            if (strncmp(plaintext, config->exec_commands[i].key, key_len) == 0) {
                /* 
                 * Verify that it's a boundary match: either the key ends exactly 
                 * or it is followed by a space (arguments).
                 */
                if (plaintext[key_len] == '\0' || plaintext[key_len] == ' ') {
                    const char *dynamic_part = plaintext + key_len;
                    /* Skip any additional spaces between the key and arguments */
                    while (*dynamic_part == ' ') dynamic_part++;
                    /* 
                     * Combine the script path from config with the dynamic arguments.
                     * Arguments are wrapped in single quotes for security.
                     */
                    final_command = sanitize_and_concat(config->exec_commands[i].value, dynamic_part);
                    break;
                }
            }
        }
    }

    if (final_command) {
        if (verbose) {
            printf("Executing pending alert ID=%" PRIu64 ": %s\n", pa->id, final_command);
        }
        
        int exec_ret = system(final_command);
        if (exec_ret != 0 && verbose) {
            fprintf(stderr, "Pending command returned error code: %d\n", exec_ret);
        }
        
        free(final_command);
    } else if (verbose) {
        printf("No matching config key found for pending alert message: %s\n", plaintext);
    }

    free(plaintext);

cleanup:
    free(encrypted); 
    free(encrypted_key_dec); 
    free(iv_dec); 
    free(tag_dec);
}

/* Parses server response and processes message */
void parse_response(const char *response, const char *expected_pubkey_hash_b64, int verbose, int execute, Config *config, int daemon_exec_flag) {
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

    // REPLACE START: Добавляем парсинг id_str вместо create_at_str
    char *id_str = strtok(NULL, "|");
    char *unlock_at_str = strtok(NULL, "|");
    char *expire_at_str = strtok(NULL, "|");
    char *encrypted_text = strtok(NULL, "|");
    char *encrypted_key = strtok(NULL, "|");
    char *iv = strtok(NULL, "|");
    char *tag = strtok(NULL, "|");
    if (!id_str || !unlock_at_str || !expire_at_str || !encrypted_text ||
        !encrypted_key || !iv || !tag) {
        fprintf(stderr, "Error: Incomplete data in ALERT\n");
        free(copy);
        return;
    }
    // Вычисляем create_at из id
    uint64_t id = strtoull(id_str, NULL, 10);
    time_t create_at = ((id >> 12) + SNOWFLAKE_EPOCH) / 1000;
    // REPLACE END

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
    printf("ID: %" PRIu64 "\n", id);

    /* format and show both UTC and localtime to avoid confusion */
    char buf_create_utc[32], buf_unlock_utc[32], buf_expire_utc[32];
    char buf_create_local[32], buf_unlock_local[32], buf_expire_local[32];

    /* UTC */
    time_to_utc_string(create_at, buf_create_utc, sizeof(buf_create_utc));
    time_to_utc_string(unlock_at, buf_unlock_utc, sizeof(buf_unlock_utc));
    time_to_utc_string(expire_at, buf_expire_utc, sizeof(buf_expire_utc));

    /* local time for clarity */
    struct tm tm_local;
    if (localtime_r(&create_at, &tm_local))
        strftime(buf_create_local, sizeof(buf_create_local), "%Y-%m-%d %H:%M:%S", &tm_local);
    else
        snprintf(buf_create_local, sizeof(buf_create_local), "(invalid)");

    if (localtime_r(&unlock_at, &tm_local))
        strftime(buf_unlock_local, sizeof(buf_unlock_local), "%Y-%m-%d %H:%M:%S", &tm_local);
    else
        snprintf(buf_unlock_local, sizeof(buf_unlock_local), "(invalid)");

    if (localtime_r(&expire_at, &tm_local))
        strftime(buf_expire_local, sizeof(buf_expire_local), "%Y-%m-%d %H:%M:%S", &tm_local);
    else
        snprintf(buf_expire_local, sizeof(buf_expire_local), "(invalid)");
    if (verbose) {
        printf("Metadata (UTC):   Create=%s, Unlock=%s, Expire=%s\n",
               buf_create_utc, buf_unlock_utc, buf_expire_utc);
    }
    printf("Metadata (local): Create=%s, Unlock=%s, Expire=%s\n",
           buf_create_local, buf_unlock_local, buf_expire_local);

    /* Now check expiry / lock BEFORE an expensive decryption */
    if (expire_at <= now) {
        printf("Message expired\n");
        free(copy);
        return;
    }
    if (unlock_at > now) {
        printf("Locked message until %s (UTC) / %s (local)\n",
               buf_unlock_utc, buf_unlock_local);
        if (execute) {
            PendingAlert *pa = malloc(sizeof(PendingAlert));
            if (pa) {
                pa->pubkey_hash_b64 = strdup(pubkey_hash_b64);
                pa->id = id;
                pa->unlock_at = unlock_at;
                pa->expire_at = expire_at;
                pa->encrypted_text = strdup(encrypted_text);
                pa->encrypted_key = strdup(encrypted_key);
                pa->iv = strdup(iv);
                pa->tag = strdup(tag);
                pa->next = pending_alerts;
                pending_alerts = pa;
                if (verbose) {
                    printf("Queued locked message ID=%" PRIu64 " for execution at %s\n", id, buf_unlock_utc);
                }
            }
        }
        free(copy);
        return;
    }

    /* At this point the message is valid to attempt decoding / decryption.
       Perform base64 decode and RSA/AES decryption here. 
       Decode base64 data */
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
    snprintf(priv_file, sizeof(priv_file), "/etc/gorgona/%s.key", pubkey_hash_b64);
    char *plaintext = NULL;
    int ret = decrypt_message(encrypted, encrypted_len, encrypted_key_dec, encrypted_key_len,
                             iv_dec, iv_len, tag_dec, &plaintext, priv_file, verbose);
    free(encrypted);
    free(encrypted_key_dec);
    free(iv_dec);
    free(tag_dec);
    if (ret != 0 || !plaintext) {
        fprintf(stderr, "Failed to decrypt message\n");
        free(copy);
        return;
    }
    if (execute) {
        char *final_command = NULL;
        if (config->exec_count == 0) {
            /* Config [exec_commands] is empty: execute the decrypted message directly */
            final_command = strdup(plaintext);
        } else {
            /* Config has specific allowed commands: check for prefix matching */
            for (int i = 0; i < config->exec_count; i++) {
                size_t key_len = strlen(config->exec_commands[i].key);
                /* Match the start of the message with a config key */
                if (strncmp(plaintext, config->exec_commands[i].key, key_len) == 0) {
                    /* Verify boundary: exact match or followed by space */
                    if (plaintext[key_len] == '\0' || plaintext[key_len] == ' ') {
                        const char *dynamic_part = plaintext + key_len;
                        /* Move pointer to the start of arguments, skipping spaces */
                        while (*dynamic_part == ' ') dynamic_part++;
                        /* Wrap arguments in safe quotes */
                        final_command = sanitize_and_concat(config->exec_commands[i].value, dynamic_part);
                        break;
                    }
                }
            }
        }
        if (final_command) {
            if (daemon_exec_flag) {
                if (verbose) printf("Executing command in background: %s\n", final_command);
                daemon_exec(final_command, verbose);
            } else {
                if (verbose) printf("Executing command: %s\n", final_command);
                int exec_ret = system(final_command);
                if (exec_ret != 0 && verbose) {
                    fprintf(stderr, "Command returned non-zero exit code: %d\n", exec_ret);
                }
            }
            free(final_command);
        } else if (verbose) {
            printf("Security: No matching key found in [exec_commands] for message: %s\n", plaintext);
        }
    } else {
        printf("Decrypted message:\n%s\n", plaintext);
    }
    free(plaintext);
    free(copy);
}

/* Listens for messages from server in specified mode */
int listen_alerts(int argc, char *argv[], int verbose, int execute, int daemon_exec_flag) {
    if (argc < 2) {
        fprintf(stderr, "Usage: listen <mode> [<count>] [pubkey_hash_b64]\n");
        fprintf(stderr, "Modes: live, all, lock, single, last, new\n");
        fprintf(stderr, "For last mode: listen last [<count>] [pubkey_hash_b64]\n");
        return 1;
    }
    
    char *mode = argv[1];
    int count = 1;
    char *pubkey_hash_b64 = NULL;

    /* Mode validation - ИСПРАВЛЕНО: убраны пробелы в строках */
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

    /* Parse arguments - ИСПРАВЛЕНО: убраны пробелы */
    if (strcmp(mode, "last") == 0) {
        if (argc == 2) {
            // No pubkey_hash_b64
        } else if (argc == 3) {
            char *endptr;
            count = strtol(argv[2], &endptr, 10);
            if (*endptr != '\0' || count <= 0) {
                pubkey_hash_b64 = argv[2];
                count = 1;
            }
        } else if (argc == 4) {
            char *endptr;
            count = strtol(argv[2], &endptr, 10);
            if (*endptr != '\0' || count <= 0) {
                fprintf(stderr, "Invalid count: %s\n", argv[2]);
                return 1;
            }
            pubkey_hash_b64 = argv[3];
        } else {
            fprintf(stderr, "Usage for last: listen last [<count>] [pubkey_hash_b64]\n");
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

    if (verbose) {
        printf("Debug: Parsed mode='%s', count=%d, pubkey_hash_b64='%s'\n", 
               mode, count, pubkey_hash_b64 ? pubkey_hash_b64 : "NULL");
    }

    Config config;
    read_config(&config, verbose);
    
    int reconnect_delay = 5;
    int reconnect_increment = 10;
    int max_reconnect_delay = 60;
    int periodic_reconnect_sec = (strcmp(mode, "last") == 0 || strcmp(mode, "single") == 0) ? 10 : 1200;

    /* Determine whether you need to reconnect after a breakup */
    int should_reconnect = (strcmp(mode, "last") != 0 && strcmp(mode, "single") != 0);

    char **key_hashes = NULL;
    int key_count = 0;
    
    /* Infinite reconnection cycle for persistent modes */
    while (1) {
        if (strcmp(mode, "last") == 0 && !pubkey_hash_b64) {
            if (!collect_key_hashes(&key_hashes, &key_count, verbose)) {
                fprintf(stderr, "Failed to collect key hashes\n");
                return 1;
            }
            if (verbose) {
                printf("Debug: Found %d keys in /etc/gorgona\n", key_count);
            }
        } else {
            if (key_hashes) free_key_hashes(key_hashes, key_count);
            key_hashes = malloc(sizeof(char *));
            key_hashes[0] = pubkey_hash_b64 ? strdup(pubkey_hash_b64) : NULL;
            key_count = pubkey_hash_b64 ? 1 : 0;
        }

        for (int key_idx = 0; key_idx < (key_count > 0 ? key_count : 1); key_idx++) {
            char *current_pubkey_hash = (key_count > 0) ? key_hashes[key_idx] : NULL;
            if (verbose && current_pubkey_hash) {
                printf("Debug: Processing key %s\n", current_pubkey_hash);
            }

            int sock = socket(AF_INET, SOCK_STREAM, 0);
            if (sock < 0) {
                perror("Socket creation error");
                sleep(reconnect_delay);
                reconnect_delay = (reconnect_delay + reconnect_increment) < max_reconnect_delay ?
                                 (reconnect_delay + reconnect_increment) : max_reconnect_delay;
                continue;
            }
            
            /* ИСПРАВЛЕНО: убраны пробелы в структуре */
            struct sockaddr_in serv_addr = { .sin_family = AF_INET, .sin_port = htons(config.server_port) };
            if (inet_pton(AF_INET, config.server_ip, &serv_addr.sin_addr) <= 0) {
                fprintf(stderr, "Invalid address: %s\n", config.server_ip);
                close(sock);
                sleep(reconnect_delay);
                continue;
            }
            
            if (connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
                fprintf(stderr, "Connection failed: %s\n", strerror(errno));
                close(sock);
                sleep(reconnect_delay);
                continue;
            }
            
            /* TCP keepalive settings - ИСПРАВЛЕНО: убраны пробелы */
            int opt = 1;
            if (setsockopt(sock, SOL_SOCKET, SO_KEEPALIVE, &opt, sizeof(opt)) < 0) {
                fprintf(stderr, "setsockopt SO_KEEPALIVE failed: %s\n", strerror(errno));
            }
            #ifdef __linux__
                int idle = 60;
                if (setsockopt(sock, IPPROTO_TCP, TCP_KEEPIDLE, &idle, sizeof(idle)) < 0) {
                    fprintf(stderr, "setsockopt TCP_KEEPIDLE failed: %s\n", strerror(errno));
                }
                int interval = 10;
                if (setsockopt(sock, IPPROTO_TCP, TCP_KEEPINTVL, &interval, sizeof(interval)) < 0) {
                    fprintf(stderr, "setsockopt TCP_KEEPINTVL failed: %s\n", strerror(errno));
                }
                int keep_count = 3;
                if (setsockopt(sock, IPPROTO_TCP, TCP_KEEPCNT, &keep_count, sizeof(keep_count)) < 0) {
                    fprintf(stderr, "setsockopt TCP_KEEPCNT failed: %s\n", strerror(errno));
                }
            #elif defined(__APPLE__)
                int keepalive_time = 60;
                if (setsockopt(sock, IPPROTO_TCP, TCP_KEEPALIVE, &keepalive_time, sizeof(keepalive_time)) < 0) {
                    fprintf(stderr, "setsockopt TCP_KEEPALIVE failed: %s\n", strerror(errno));
                }
            #endif
            
            reconnect_delay = 5;

            if (verbose) {
                printf("Connected to %s:%d\n", config.server_ip, config.server_port);
            }

            /* Form request - ИСПРАВЛЕНО: убраны пробелы */
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
                len = snprintf(buffer, needed_len, "LISTEN|%s|%s", current_pubkey_hash, mode);
            } else if (strcmp(mode, "last") == 0) {
                if (current_pubkey_hash) {
                    len = snprintf(buffer, needed_len, "LISTEN|%s|%s|%d", current_pubkey_hash, mode, count);
                } else {
                    len = snprintf(buffer, needed_len, "LISTEN||%s|%d", mode, count);
                }
            } else {
                if (current_pubkey_hash) {
                    len = snprintf(buffer, needed_len, "SUBSCRIBE %s|%s", mode, current_pubkey_hash);
                } else {
                    len = snprintf(buffer, needed_len, "SUBSCRIBE %s", mode);
                }
            } 
            
            /* Send request */
            uint32_t msg_len_net = htonl(len);
            ssize_t send_result = send(sock, &msg_len_net, sizeof(uint32_t), MSG_NOSIGNAL);
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
            int received_any_message = 0;

            while (connection_ok) {
                /* Periodic reconnect check */
                struct timeval current_time;
                gettimeofday(&current_time, NULL);
                long elapsed_sec = current_time.tv_sec - start_time.tv_sec;
                if (elapsed_sec > periodic_reconnect_sec) {
                    if (verbose) printf("Periodic reconnect after %ld seconds\n", elapsed_sec);
                    connection_ok = 0;
                    break;
                }

                /* Find next unlock time */
                time_t now = time(NULL);
                time_t next_unlock = 0;
                PendingAlert *pa = pending_alerts;
                while (pa) {
                    if (pa->unlock_at > now && (!next_unlock || pa->unlock_at < next_unlock)) {
                        next_unlock = pa->unlock_at;
                    }
                    pa = pa->next;
                }

                /* Set timeout for select */
                struct timeval timeout, *timeout_ptr = NULL;
                if (next_unlock) {
                    long delay = next_unlock - now;
                    if (delay < 0) delay = 0;
                    timeout.tv_sec = delay;
                    timeout.tv_usec = 0;
                    timeout_ptr = &timeout;
                }

                /* Check pending alerts */
                now = time(NULL);
                PendingAlert **prev = &pending_alerts;
                while (*prev) {
                    if ((*prev)->unlock_at <= now && (*prev)->expire_at > now) {
                        PendingAlert *to_exec = *prev;
                        *prev = to_exec->next;
                        execute_pending_alert(to_exec, verbose, &config);
                        free(to_exec->pubkey_hash_b64);
                        free(to_exec->encrypted_text);
                        free(to_exec->encrypted_key);
                        free(to_exec->iv);
                        free(to_exec->tag);
                        free(to_exec);
                    } else {
                        prev = &(*prev)->next;
                    }
                }

                /* Use select to wait for data */
                fd_set readfds;
                FD_ZERO(&readfds);
                FD_SET(sock, &readfds);
                int activity = select(sock + 1, &readfds, NULL, NULL, timeout_ptr);

                if (activity < 0) {
                    if (errno == EINTR) continue;
                    fprintf(stderr, "Select error: %s\n", strerror(errno));
                    connection_ok = 0;
                    break;
                }

                if (activity == 0) {
                    continue;
                }

                /* Read response length */
                uint32_t resp_len_net;
                ssize_t valread = recv(sock, &resp_len_net, sizeof(uint32_t), MSG_WAITALL);
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
                if (resp_len == 0 || resp_len > 1024 * 1024) {
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

                parse_response(resp_buffer, current_pubkey_hash, verbose, execute, &config, daemon_exec_flag);

                if (strcmp(mode, "last") == 0 && strncmp(resp_buffer, "ALERT|", 6) == 0) {
                    messages_received++;
                    received_any_message = 1;
                    if (pubkey_hash_b64 && messages_received >= count) {
                        free(resp_buffer);
                        connection_ok = 0;
                        break;
                    }
                }

                free(resp_buffer);
            }
            
            close(sock);
 
            if (strcmp(mode, "last") == 0 && !pubkey_hash_b64 && verbose && !received_any_message) {
                printf("Debug: No messages for key %s\n", current_pubkey_hash ? current_pubkey_hash : "NULL");
            }
        }

        if (key_hashes) {
            free_key_hashes(key_hashes, key_count);
            key_hashes = NULL;
            key_count = 0;
        }

        /* For last/single mode, exit after completion */
        if (strcmp(mode, "last") == 0 || strcmp(mode, "single") == 0) {
            return 0;
        }

        /* For persistent modes (new, live, all, lock) - reconnect */
        if (should_reconnect) {
            fprintf(stderr, "Connection lost, reconnecting in %d seconds...\n", reconnect_delay);
            sleep(reconnect_delay);
            reconnect_delay = (reconnect_delay + reconnect_increment) < max_reconnect_delay ?
                             (reconnect_delay + reconnect_increment) : max_reconnect_delay;
            /* Continue the outer while(1) loop for reconnection */
        } else {
            break;
        }
    }

    return 0;
}
