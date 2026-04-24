/* 
* BSD 3-Clause License
* Copyright (c) 2025, Alexander Shcheglov
* All rights reserved. 
*/

#define _XOPEN_SOURCE 700
#include "encrypt.h"
#include "config.h"
#include "common.h"
#include "client_history.h"
#include "admin_mesh.h"
#include "peer_manager.h"
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
#include <unistd.h>
#include <time.h>
#define _POSIX_C_SOURCE 200809L
#define SNOWFLAKE_EPOCH 1735689600000ULL  /* 1 January 2025 в ms (из snowflake.h) */
#define STICKY_NODE_PATH "/dev/shm/gorgona_sticky_node"

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
        char time_str[32];
        get_utc_time_str(time_str, sizeof(time_str));
        if (verbose) fprintf(stderr, "%s Private key not found: %s\n", time_str, priv_file);
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

static void execute_pending_alert(int sock, PendingAlert *pa, int verbose, Config *config, int do_execute, int daemon_exec_flag) {
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

    if (!do_execute) {
        printf("Unlocked pending message ID=%" PRIu64 "\n", pa->id);
        printf("Decrypted message:\n%s\n", plaintext);
        free(plaintext);
        goto cleanup;
    }

    /* Start of updated execution logic */
    char *final_command = NULL;

    if (config->exec_count == 0) {
        final_command = strdup(plaintext);
    } else {
        for (int i = 0; i < config->exec_count; i++) {
            /* If the config entry requires a specific key, ensure it matches the message owner */
            if (config->exec_commands[i].required_key[0] != '\0') {
                if (pa->pubkey_hash_b64 == NULL || strcmp(config->exec_commands[i].required_key, pa->pubkey_hash_b64) != 0) {
                    continue; /* Not allowed for this key */
                }
            }
            size_t key_len = strlen(config->exec_commands[i].key);
            
            /* Check if the message starts with the allowed key */
            if (strncmp(plaintext, config->exec_commands[i].key, key_len) == 0) {
                /* 
                 * Verify that it's a boundary match: either the key ends exactly 
                 * or it is followed by a space (arguments).
                 */
                if (plaintext[key_len] == '\0' || isspace((unsigned char)plaintext[key_len])) {
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
        if (daemon_exec_flag) {
            daemon_exec(final_command, verbose);
        } else {
            int exec_ret = system(final_command);
            if (exec_ret != 0 && verbose) {
                fprintf(stderr, "Pending command returned error code: %d\n", exec_ret);
            }
        }
        free(final_command);
    } else if (verbose) {
        printf("No matching config key found for pending alert message: %s\n", plaintext);
    }

    client_history_record(pa->id);
    free(plaintext);

cleanup:
    free(encrypted); 
    free(encrypted_key_dec); 
    free(iv_dec); 
    free(tag_dec);
}

/* 
 * A helper function that does the same thing as `send_alert`, 
 * but without opening a new socket or parsing the arguments 
 */
static void internal_reply_error(int sock, const char *target_hash, const char *msg, int verbose) {
    char pub_path[256];
    snprintf(pub_path, sizeof(pub_path), "/etc/gorgona/%s.pub", target_hash);

    unsigned char *enc = NULL, *enc_key = NULL, *iv = NULL, *tag = NULL;
    size_t e_len, k_len, i_len, t_len;

    if (encrypt_message(msg, &enc, &e_len, &enc_key, &k_len, &iv, &i_len, &tag, &t_len, pub_path, verbose) != 0) {
        return;
    }

    char *e_b64 = base64_encode(enc, e_len);
    char *k_b64 = base64_encode(enc_key, k_len);
    char *i_b64 = base64_encode(iv, i_len);
    char *t_b64 = base64_encode(tag, t_len);

    time_t now = time(NULL);
    size_t needed = strlen(target_hash) + strlen(e_b64) + strlen(k_b64) + 
                    strlen(i_b64) + strlen(t_b64) + 128; 
    char *payload = malloc(needed);
    if (payload) {
        int total = snprintf(payload, needed, "SEND|%s|%ld|%ld|%s|%s|%s|%s",
                             target_hash, (long)now, (long)(now + 3600), 
                             e_b64, k_b64, i_b64, t_b64);
        
        if (total > 0) {
            uint32_t net_len = htonl((uint32_t)total);
            send(sock, &net_len, 4, MSG_NOSIGNAL);
            send(sock, payload, (size_t)total, MSG_NOSIGNAL);
        }
        free(payload);
    }

    free(enc); free(enc_key); free(iv); free(tag);
    free(e_b64); free(k_b64); free(i_b64); free(t_b64);
}

/**
 * Parses the raw server response and processes incoming alert data.
 * 
 * This function acts as the primary protocol handler for the client. It handles 
 * new alerts, manages time-locked queues, and executes commands while silently 
 * filtering out internal P2P replication traffic (REPL, SYNC, AUTH) to ensure 
 * the user interface remains clean.
 * 
 * @param response The raw null-terminated string received from the server.
 * @param expected_pubkey_hash_b64 Optional filter to ignore alerts not belonging to this hash.
 * @param verbose Enables detailed debug logging to stdout.
 * @param execute Boolean flag: if true, decrypted messages are treated as system commands.
 * @param config Pointer to the configuration containing execution ACLs and scripts.
 * @param daemon_exec_flag If true, commands are executed as background processes.
 */
void parse_response(int sock, const char *response, const char *expected_pubkey_hash_b64, 
                    int verbose, int execute, Config *config, int daemon_exec_flag) {
    /* -------------------------------------------------------------------------
     * 1. LAYER 2 DECRYPTION (New Block)
     * -------------------------------------------------------------------------
     * If the server sends an administrative mesh packet, it is wrapped in MGMT.
     * We need to decrypt it using the sync_psk from our config.
     */
    bool l2_mesh_enabled = (config->sync_psk[0] != '\0');
    if (strncmp(response, "MGMT|", 5) == 0) {
        if (l2_mesh_enabled) {
            char *frame = strdup(response + 5);
            if (!frame) return;

            char *iv_b64 = strtok(frame, "|");
            char *tag_b64 = strtok(NULL, "|");
            char *payload_b64 = strtok(NULL, "|");
            
            if (iv_b64 && tag_b64 && payload_b64) {
                size_t iv_len, tag_len, p_len;
                uint8_t *iv = base64_decode(iv_b64, &iv_len);
                uint8_t *tag = base64_decode(tag_b64, &tag_len);
                uint8_t *payload = base64_decode(payload_b64, &p_len);
                
                int decrypted_len;
                /* Decrypt the payload using the admin_mesh.c module from common/ */
                uint8_t *plain = mesh_decrypt(payload, (int)p_len, iv, tag, &decrypted_len);
                
                if (plain) {
                    if (verbose) {
                        printf("L2 Decrypted on Client: %s\n", (char*)plain);
                    }
                    
                    /* [GOSSIP HANDLER] Process incoming PEX topology */
                    if (strncmp((char*)plain, "PEX_LIST|", 9) == 0) {
                        mesh_discover_nodes((char*)plain + 9, config->server_ip);  
                    }
                    /* Optionally, answer PING here if you want servers to track client latency */
                    
                    free(plain);
                }
                if (iv) free(iv); 
                if (tag) free(tag); 
                if (payload) free(payload);
            }
            free(frame);
            return; /* Stop processing - this is a management packet, not data */
        }
         return; 
    }   

    /* -------------------------------------------------------------------------
     * 2. PROTOCOL FILTERING: P2P NOISE REDUCTION
     * -------------------------------------------------------------------------
     * Ignore internal replication and synchronization traffic. These messages 
     * are intended for server-to-server communication and should not be 
     * processed or displayed by a standard client.
     */
    if (strncmp(response, "REPL|", 5) == 0 || 
        strncmp(response, "SYNC|", 5) == 0 || 
        strncmp(response, "AUTH|", 5) == 0 ||
        strncmp(response, "MAXID_NUDGE|", 12) == 0 || 
        strcmp(response, "AUTH_SUCCESS") == 0 ||
        strcmp(response, "AUTH_FAILED") == 0) {
        return;
    }

    /* -------------------------------------------------------------------------
     * 3. STATUS & ERROR HANDLING
     * -------------------------------------------------------------------------
     * Check for plain-text status updates or error messages from the server.
     */
    if (strncmp(response, "ALERT|", 6) != 0) {
        /* Standard server feedback (e.g., "Subscription updated", "Error: ...") */
        printf("Server: %s\n", response);
        return;
    }

    /* -------------------------------------------------------------------------
     * 4. ALERT PACKET PARSING
     * -------------------------------------------------------------------------
     * Format: ALERT|pubkey_hash|id|unlock_at|expire_at|text|key|iv|tag
     */
    char *copy = strdup(response + 6);
    if (!copy) {
        fprintf(stderr, "Critical: Memory allocation failed during packet parsing\n");
        return;
    }

    char *pubkey_hash_b64 = strtok(copy, "|");
    char *id_str          = strtok(NULL, "|");
    char *unlock_at_str   = strtok(NULL, "|");
    char *expire_at_str   = strtok(NULL, "|");
    char *encrypted_text  = strtok(NULL, "|");
    char *encrypted_key   = strtok(NULL, "|");
    char *iv_str          = strtok(NULL, "|");
    char *tag_str         = strtok(NULL, "|");

    if (!tag_str) {
        fprintf(stderr, "Protocol Error: Incomplete data received in ALERT packet\n");
        free(copy);
        return;
    }

    /* -------------------------------------------------------------------------
     * 5. IDENTITY & TIMESTAMP RECONSTRUCTION
     * -------------------------------------------------------------------------
     */
    uint64_t id = strtoull(id_str, NULL, 10);

    /* [IDEMPOTENCY] Skip processing if already in history */
    if (!client_history_is_new(id)) {
        if (verbose) printf("History: Skipping duplicate Alert ID %" PRIu64 "\n", id);
        free(copy);
        return;
    }

    /* Snowflake ID Logic: 
     * Extract the timestamp (bits 63-12), add custom epoch, and convert to seconds. */
    time_t create_at = ((id >> 12) + SNOWFLAKE_EPOCH) / 1000;
    time_t unlock_at = atol(unlock_at_str);
    time_t expire_at = atol(expire_at_str);
    time_t now = time(NULL);

    /* -------------------------------------------------------------------------
     * 6. SECURITY & ACCESS CONTROL
     * -------------------------------------------------------------------------
     */

    /* Apply Pubkey Filter if specified */
    if (expected_pubkey_hash_b64 && strcmp(pubkey_hash_b64, expected_pubkey_hash_b64) != 0) {
        if (verbose) printf("Filter: Skipping alert for different recipient [%s]\n", pubkey_hash_b64);
        free(copy);
        return;
    }

    /* Check for local Private Key. Decryption is impossible without it. */
    if (!has_private_key(pubkey_hash_b64, verbose)) {
        if (verbose) printf("Security: Private key missing for hash %s. Skipping.\n", pubkey_hash_b64);
        free(copy);
        return;
    }

    /* -------------------------------------------------------------------------
     * 7. METADATA DISPLAY
     * -------------------------------------------------------------------------
     */
    printf("Received Alert: Recipient_Hash=%s\n", pubkey_hash_b64);
    printf("Alert ID: %" PRIu64 "\n", id);

    char buf_create[32], buf_unlock[32], buf_expire[32];
    struct tm tm_info;

    /* Format timestamps for human-readable local time output */
    if (localtime_r(&create_at, &tm_info)) strftime(buf_create, 32, "%Y-%m-%d %H:%M:%S", &tm_info);
    if (localtime_r(&unlock_at, &tm_info)) strftime(buf_unlock, 32, "%Y-%m-%d %H:%M:%S", &tm_info);
    if (localtime_r(&expire_at, &tm_info)) strftime(buf_expire, 32, "%Y-%m-%d %H:%M:%S", &tm_info);

    printf("Timestamps (Local): Created: %s, Unlock: %s, Expire: %s\n", 
           buf_create, buf_unlock, buf_expire);

    /* -------------------------------------------------------------------------
     * 8. LIFECYCLE MANAGEMENT (EXPIRY & TIME-LOCK)
     * -------------------------------------------------------------------------
     */

    if (expire_at <= now) {
        printf("Status: Alert has expired and is no longer valid.\n");
        free(copy);
        return;
    }

    if (unlock_at > now) {
        /* Message is still locked. Queue it for future processing. */
        printf("Status: Alert is TIME-LOCKED. Will unlock at %s\n", buf_unlock);
        
        PendingAlert *pa = malloc(sizeof(PendingAlert));
        if (pa) {
            pa->pubkey_hash_b64 = strdup(pubkey_hash_b64);
            pa->id = id;
            pa->unlock_at = unlock_at;
            pa->expire_at = expire_at;
            pa->encrypted_text = strdup(encrypted_text);
            pa->encrypted_key = strdup(encrypted_key);
            pa->iv = strdup(iv_str);
            pa->tag = strdup(tag_str);
            pa->next = pending_alerts;
            pending_alerts = pa;

            if (verbose) {
                printf("Queue: ID %" PRIu64 " added to background wait list.\n", id);
            }
        }
        free(copy);
        return;
    }

    /* -------------------------------------------------------------------------
    * 9. DECRYPTION & EXECUTION
    * -------------------------------------------------------------------------
    * If we reach here, the alert is unlocked and valid.
    */
    size_t e_len, k_len, i_len, t_len;
    unsigned char *e_raw = base64_decode(encrypted_text, &e_len);
    unsigned char *k_raw = base64_decode(encrypted_key, &k_len);
    unsigned char *i_raw = base64_decode(iv_str, &i_len);
    unsigned char *t_raw = base64_decode(tag_str, &t_len);

    if (!e_raw || !k_raw || !i_raw || !t_raw) {
        fprintf(stderr, "Error: Base64 decoding failed for alert ID %" PRIu64 "\n", id);
        goto decryption_cleanup;
    }

    char priv_path[256];
    snprintf(priv_path, sizeof(priv_path), "/etc/gorgona/%s.key", pubkey_hash_b64);
    
    char *plaintext = NULL;
    int status = decrypt_message(e_raw, e_len, k_raw, k_len, i_raw, i_len, t_raw, 
                                 &plaintext, priv_path, verbose);

    if (status == 0 && plaintext) {
        /* SUCCESS: Write to persistent history log MAPPED in memory */
        client_history_record(id);

        if (!execute) {
            printf("Decrypted Content:\n%s\n", plaintext);
        } else {
            /* Command Execution Logic */
            char *final_cmd = NULL;

            if (config->exec_count == 0) {
                /* No ACLs defined: run raw message as command (no time_limit available) */
                final_cmd = strdup(plaintext);
            } else {
                /* ACL Check: match message to allowed scripts */
                for (int j = 0; j < config->exec_count; j++) {
                    ExecCommand *ec = &config->exec_commands[j];
                    
                    /* Key restriction (if defined in config) */
                    if (ec->required_key[0] != '\0' && strcmp(ec->required_key, pubkey_hash_b64) != 0) {
                        continue;
                    }

                    size_t k_match_len = strlen(ec->key);
                    if (strncmp(plaintext, ec->key, k_match_len) == 0) {
                        /* Check for boundary match: exact string or followed by space */
                        if (plaintext[k_match_len] == '\0' || isspace((unsigned char)plaintext[k_match_len])) {
                            const char *args = plaintext + k_match_len;
                            while (isspace((unsigned char)*args)) args++;

                            /* Generate sanitized command with arguments */
                            char *raw_cmd = sanitize_and_concat(ec->value, args);
                            if (raw_cmd) {
                                /* Apply time_limit if set (> 0) using the 'timeout' utility.
                                 * This prevents the client from hanging if the script freezes. */
                                if (ec->time_limit > 0) {
                                    size_t len = strlen(raw_cmd) + 64;
                                    final_cmd = malloc(len);
                                    if (final_cmd) {
                                        snprintf(final_cmd, len, "timeout -s KILL %d %s", ec->time_limit, raw_cmd);
                                    }
                                    free(raw_cmd);
                                } else {
                                    final_cmd = raw_cmd;
                                }
                            }
                            break; /* Found a match, exit the loop */
                        }
                    }
                }
            }

            /* Execute the final command (either raw or wrapped in timeout) */
            if (final_cmd) {
                if (daemon_exec_flag) {
                    if (verbose) printf("Execution: Launching daemon: %s\n", final_cmd);
                    daemon_exec(final_cmd, verbose);
                } else {
                    if (verbose) printf("Execution: Running: %s\n", final_cmd);
                    
                    int res = system(final_cmd);
                    int exit_status = WEXITSTATUS(res);

                    /* 
                     * 124 - стандартный код timeout. 
                     * 137 - если таймаут убил процесс через KILL (128 + SIGKILL).
                     */
                    if (WIFEXITED(res) && (exit_status == 124 || exit_status == 137)) {
                        char feedback[512];
                        int limit = 0;

                        /* Ищем, какой лимит времени был задан в конфиге для этой команды */
                        for (int j = 0; j < config->exec_count; j++) {
                            if (strncmp(plaintext, config->exec_commands[j].key, strlen(config->exec_commands[j].key)) == 0) {
                                limit = config->exec_commands[j].time_limit;
                                break;
                            }
                        }

                        snprintf(feedback, sizeof(feedback), 
                                 "Error: execution timed out! Limit in config file for this command: %d seconds. Command aborted.", 
                                 limit);
                        
                        fprintf(stderr, "Alert ID %" PRIu64 ": %s\n", id, feedback);

                        /* ОТПРАВКА ЗАШИФРОВАННОГО ОТВЕТА ОБРАТНО ОТПРАВИТЕЛЮ */
                        internal_reply_error(sock, pubkey_hash_b64, feedback, verbose);
                    } 
                    else if (res != 0 && verbose) {
                        fprintf(stderr, "Execution: Process exited with code %d\n", exit_status);
                    }
                }
                free(final_cmd);
            } else if (verbose) {
                printf("Security: Content does not match any configured execution triggers.\n");
            }
        }
        free(plaintext);
    } else {
        fprintf(stderr, "Error: RSA/AES Decryption failed for alert ID %" PRIu64 "\n", id);
    }

decryption_cleanup:
    free(e_raw); free(k_raw); free(i_raw); free(t_raw);
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
    /* [INIT] Initialize configuration and global tracking systems */
    read_config(&config, verbose);

    /* Logic: Switch between Smart Mesh Mode and Legacy Mode based on PSK presence */
    bool l2_mesh_enabled = (config.sync_psk[0] != '\0');

    if (l2_mesh_enabled) {
        /* Layer 2 initialization (GCM Encryption + PEX system) */
        mesh_init(config.sync_psk);
        mesh_force_save = true; /* We want the client to persist peers.cache for future use */
        if (verbose) printf("Client: Smart Mesh Mode enabled (Layer 2 initialized).\n");
    } else {
        if (verbose) printf("Client: Legacy Mode enabled (Layer 2 disabled).\n");
    }
    
    /* Execution History (Idempotency) is initialized regardless of mode for safety */
    client_history_init(); 
    
    /* Connection management variables */
    int periodic_reconnect_sec = (strcmp(mode, "last") == 0 || strcmp(mode, "single") == 0) ? 10 : 1800;
    int should_reconnect = (strcmp(mode, "last") != 0 && strcmp(mode, "single") != 0);
    int consecutive_failures = 0;
    char **key_hashes = NULL;
    int key_count = 0;
    const int MAX_BACKOFF_CAP_MS = 60000;   /* 60 seconds */
    const int MAX_FAILURES_CAP    = 16;     /* 2^16 = 65536 ms → capped anyway */

    /* INFINITE RECONNECTION CYCLE */
    while (1) {
        /* 1. KEY COLLECTION LOGIC (Identify target recipients) */
        if (strcmp(mode, "last") == 0 && !pubkey_hash_b64) {
            if (key_hashes) free_key_hashes(key_hashes, key_count);
            if (!collect_key_hashes(&key_hashes, &key_count, verbose)) {
                fprintf(stderr, "Error: Critical failure in local key collection\n");
                return 1;
            }
        } else {
            if (key_hashes) free_key_hashes(key_hashes, key_count);
            key_hashes = NULL;
            if (pubkey_hash_b64) {
                key_hashes = malloc(sizeof(char *));
                if (!key_hashes) return 1;
                key_hashes[0] = strdup(pubkey_hash_b64);
                key_count = 1;
            } else {
                key_count = 0; // Global discovery mode
            }
        }

        bool any_key_success = false;

        /* 2. CONNECTION AND PROCESSING LOOP */
        for (int key_idx = 0; key_idx < (key_count > 0 ? key_count : 1); key_idx++) {
            char *current_pubkey_hash = (key_count > 0) ? key_hashes[key_idx] : NULL;
            int sock = -1;

            if (verbose && current_pubkey_hash) {
                printf("Debug: Starting subscription session for key %s\n", current_pubkey_hash);
            }

            /* --- 2.1 ESTABLISH MESH-AWARE CONNECTION --- */ 
            /* peer_manager_load_cache automatically detects l2_mesh_enabled 
               and adjusts the candidate list accordingly. */
            peer_manager_load_cache(&config);
            sock = peer_manager_get_best_connection();
            
            if (sock < 0) {
                /* Display error only if it's the first attempt or we are in persistent mode */
                if (should_reconnect || !any_key_success) {
                    fprintf(stderr, "Mesh Error: All node candidates unreachable.\n");
                }
                goto backoff;
            }

            /* Identify the winning node for debug and penalty logic */
            char current_ip[INET_ADDRSTRLEN] = "unknown";
            struct sockaddr_in p_addr; 
            socklen_t p_l = sizeof(p_addr);
            if (getpeername(sock, (struct sockaddr *)&p_addr, &p_l) == 0) {
                inet_ntop(AF_INET, &p_addr.sin_addr, current_ip, sizeof(current_ip));
            }

            if (verbose) {
                printf("Connection Success: Established via [%s:%d]\n", current_ip, ntohs(p_addr.sin_port));
            }

            /* --- 2.2 LAYER 2 HANDSHAKE --- */
            if (l2_mesh_enabled) {
                char auth_req[256];
                int auth_len = snprintf(auth_req, sizeof(auth_req), "AUTH|%s|0", config.sync_psk);
                uint32_t auth_len_net = htonl(auth_len);
                
                /* Perform PSK-based authentication */
                if (send(sock, &auth_len_net, sizeof(uint32_t), MSG_NOSIGNAL) != sizeof(uint32_t) ||
                    send(sock, auth_req, auth_len, MSG_NOSIGNAL) != auth_len) {
                    peer_manager_mark_bad(current_ip);
                    close(sock); 
                    continue; /* Try next available node */
                }

                /* SYNC BLOCK: Clear AUTH_SUCCESS from socket to keep alert stream clean */
                uint32_t a_resp_len_n;
                if (recv(sock, &a_resp_len_n, sizeof(uint32_t), MSG_WAITALL) == sizeof(uint32_t)) {
                    size_t a_resp_len = ntohl(a_resp_len_n);
                    if (a_resp_len < 1024) {
                        char a_buf[1024];
                        recv(sock, a_buf, a_resp_len, MSG_WAITALL);
                        a_buf[a_resp_len] = '\0';
                        if (verbose) printf("Mesh Status: %s\n", a_buf);
                    }
                }
            } else if (verbose) {
                printf("Mesh Status: Skipping L2 Handshake (Legacy Mode Active).\n");
            }

            /* --- 2.3 STANDARD COMMAND (LISTEN/SUBSCRIBE) --- */
            size_t needed_len = 512;
            char *req_buffer = malloc(needed_len);
            if (!req_buffer) { close(sock); goto backoff; }

            int req_len;
            if (strcmp(mode, "single") == 0) {
                req_len = snprintf(req_buffer, needed_len, "LISTEN|%s|%s", current_pubkey_hash, mode);
            } else if (strcmp(mode, "last") == 0) {
                req_len = snprintf(req_buffer, needed_len, "LISTEN|%s|%s|%d", 
                                   current_pubkey_hash ? current_pubkey_hash : "", mode, count);
            } else {
                /* Continuous subscriptions use standard SUBSCRIBE format */
                req_len = snprintf(req_buffer, sizeof(char) * needed_len, "SUBSCRIBE %s|%s", 
                                   mode, current_pubkey_hash ? current_pubkey_hash : "");
            }
            
            /* Ship the protocol request to the mesh provider */
            uint32_t msg_len_net = htonl(req_len);
            if (send(sock, &msg_len_net, sizeof(uint32_t), MSG_NOSIGNAL) != sizeof(uint32_t) ||
                send(sock, req_buffer, req_len, MSG_NOSIGNAL) != req_len) {
                peer_manager_mark_bad(current_ip);
                free(req_buffer); close(sock); 
                continue; 
            }
            free(req_buffer);

            /* Signal that at least one node-key session was established */
            any_key_success = true;

            /* --- 3. DATA RECEIVE LOOP --- */
            int connection_ok = 1;
            int messages_received = 0;
            int received_any_message = 0;
            struct timeval start_time; 
            gettimeofday(&start_time, NULL);

            while (connection_ok) {
                struct timeval current_time;
                gettimeofday(&current_time, NULL);
                long elapsed_sec = current_time.tv_sec - start_time.tv_sec;
                if (elapsed_sec > periodic_reconnect_sec) {
                    connection_ok = 0; break;
                }

                /* [TIMELOCK LOGIC] Check pending alerts */
                time_t now = time(NULL);
                PendingAlert **prev = &pending_alerts;
                while (*prev) {
                    if ((*prev)->unlock_at <= now && (*prev)->expire_at > now) {
                        PendingAlert *to_exec = *prev;
                        *prev = to_exec->next;
                        execute_pending_alert(sock, to_exec, verbose, &config, execute, daemon_exec_flag);
                        free(to_exec->pubkey_hash_b64); free(to_exec->encrypted_text);
                        free(to_exec->encrypted_key); free(to_exec->iv);
                        free(to_exec->tag); free(to_exec);
                    } else prev = &(*prev)->next;
                }

                fd_set readfds; FD_ZERO(&readfds); FD_SET(sock, &readfds);
                struct timeval timeout = { .tv_sec = 2, .tv_usec = 0 };

                int activity = select(sock + 1, &readfds, NULL, NULL, &timeout);
                if (activity < 0) { if (errno == EINTR) continue; connection_ok = 0; break; }
                if (activity == 0) {
                    /* Для разовых режимов выходим по таймауту тишины */
                    if (!should_reconnect) break;
                    continue;
                }

                consecutive_failures = 0; 
                uint32_t resp_len_net;
                ssize_t valread = recv(sock, &resp_len_net, 4, MSG_WAITALL);
                if (valread <= 0) {
                    if (valread == 0) {
                        /* Сервер просто закрыл сокет - для LAST/SINGLE это НОРМАЛЬНО */
                        if (strcmp(mode, "last") != 0 && strcmp(mode, "single") != 0) {
                            peer_manager_mark_bad(current_ip);
                        }
                    } else {
                        /* Это реальная ошибка сокета */
                        peer_manager_mark_bad(current_ip);
                    }
                    connection_ok = 0; 
                    break;
                }

                size_t resp_len = ntohl(resp_len_net);
                if (resp_len == 0 || resp_len > 50 * 1024 * 1024) { connection_ok = 0; break; }

                char *resp_buffer = malloc(resp_len + 1);
                if (!resp_buffer) { connection_ok = 0; break; }

                if (recv(sock, resp_buffer, resp_len, MSG_WAITALL) != (ssize_t)resp_len) {
                    free(resp_buffer); connection_ok = 0; break;
                }
                resp_buffer[resp_len] = '\0';

                parse_response(sock, resp_buffer, current_pubkey_hash, verbose, execute, &config, daemon_exec_flag); 

                if (strncmp(resp_buffer, "ALERT|", 6) == 0) {
                    received_any_message = 1;
                    any_key_success = true;
                    if (strcmp(mode, "last") == 0) {
                        messages_received++;
                        if (messages_received >= count) { free(resp_buffer); connection_ok = 0; break; }
                    }
                }
                free(resp_buffer);
                if (strcmp(mode, "single") == 0) { connection_ok = 0; break; }
            }
            
            close(sock);

            if (strcmp(mode, "last") == 0 && !pubkey_hash_b64 && verbose && !received_any_message) {
                printf("Debug: No messages for key %s\n", current_pubkey_hash ? current_pubkey_hash : "NULL");
            }

            /* Если режим не постоянный, и это был последний ключ - выходим из функции */
            if (!should_reconnect && (key_idx == (key_count > 0 ? key_count - 1 : 0))) {
                if (key_hashes) free_key_hashes(key_hashes, key_count);
                mesh_save_peers_cache();
                return 0;
            }
        }

        /* --- 4. BACKOFF & RECOVERY (только для live/new) --- */
        backoff: 
        if (key_hashes) { free_key_hashes(key_hashes, key_count); key_hashes = NULL; key_count = 0; }
        if (!should_reconnect) return 0;

        int backoff_ms = (1 << consecutive_failures) * 1000;
        if (backoff_ms > MAX_BACKOFF_CAP_MS) backoff_ms = MAX_BACKOFF_CAP_MS;

        char time_str[32]; get_utc_time_str(time_str, sizeof(time_str));
        fprintf(stderr, "%s Connection lost, reconnecting in %d ms...\n", time_str, backoff_ms);

        struct timespec ts = { .tv_sec = backoff_ms / 1000, .tv_nsec = (backoff_ms % 1000) * 1000000L };
        nanosleep(&ts, NULL); 
        if (consecutive_failures < MAX_FAILURES_CAP) consecutive_failures++;
    }

    return 0;
}
