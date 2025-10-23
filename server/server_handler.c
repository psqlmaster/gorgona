#include "gorgona_utils.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/select.h>
#include <errno.h>
#include <ctype.h>
#include <time.h>
#include <stdbool.h>
#include <fcntl.h>

extern int verbose;
extern FILE *log_file;
extern int max_clients;
extern size_t max_message_size;
extern char log_level[32];
extern int client_sockets[];
extern Subscriber subscribers[];

void enqueue_message(int sub_index, const char *msg, size_t msg_len) {
    OutBuffer *new_buf;
    uint32_t len_net = htonl(msg_len);

    /* Enqueue len_net */
    new_buf = malloc(sizeof(OutBuffer));
    if (!new_buf) return;  /* Error handling omitted for brevity */
    new_buf->data = malloc(sizeof(uint32_t));
    if (!new_buf->data) { free(new_buf); return; }
    memcpy(new_buf->data, &len_net, sizeof(uint32_t));
    new_buf->len = sizeof(uint32_t);
    new_buf->pos = 0;
    new_buf->next = NULL;

    if (subscribers[sub_index].out_tail) {
        subscribers[sub_index].out_tail->next = new_buf;
        subscribers[sub_index].out_tail = new_buf;
    } else {
        subscribers[sub_index].out_head = subscribers[sub_index].out_tail = new_buf;
    }

    /* Enqueue msg */
    new_buf = malloc(sizeof(OutBuffer));
    if (!new_buf) return;
    new_buf->data = malloc(msg_len);
    if (!new_buf->data) { free(new_buf); return; }
    memcpy(new_buf->data, msg, msg_len);
    new_buf->len = msg_len;
    new_buf->pos = 0;
    new_buf->next = NULL;

    if (subscribers[sub_index].out_tail) {
        subscribers[sub_index].out_tail->next = new_buf;
        subscribers[sub_index].out_tail = new_buf;
    } else {
        subscribers[sub_index].out_head = subscribers[sub_index].out_tail = new_buf;
    }
}

void process_out(int sub_index, int sd) {
    OutBuffer *head = subscribers[sub_index].out_head;
    while (head) {
        ssize_t sent = send(sd, head->data + head->pos, head->len - head->pos, 0);
        if (sent > 0) {
            head->pos += sent;
            if (head->pos == head->len) {
                OutBuffer *tmp = head;
                subscribers[sub_index].out_head = head->next;
                if (subscribers[sub_index].out_head == NULL) subscribers[sub_index].out_tail = NULL;
                free(tmp->data);
                free(tmp);
                head = subscribers[sub_index].out_head;
            }
        } else if (sent == 0) {
            /* Client closed */
            close(sd);
            client_sockets[sub_index] = 0;
            free_out_queue(sub_index);
            break;
        } else {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                break;  /* Wait for next select */
            } else {
                /* Error */
                if (log_file) {
                    char time_str[32];
                    get_utc_time_str(time_str, sizeof(time_str));
                    fprintf(log_file, "%s Send error for fd %d: %s\n", time_str, sd, strerror(errno));
                    fflush(log_file);
                }
                close(sd);
                client_sockets[sub_index] = 0;
                free_out_queue(sub_index);
                break;
            }
        }
    }
    /* Check if queue is empty and close is pending */
    if (subscribers[sub_index].out_head == NULL && subscribers[sub_index].close_after_send) {
        close(sd);
        client_sockets[sub_index] = 0;
        subscribers[sub_index].sock = 0;
        subscribers[sub_index].mode = 0;
        subscribers[sub_index].pubkey_hash[0] = '\0';
        free_out_queue(sub_index);  /* Already empty, but for consistency */
        if (subscribers[sub_index].in_buffer) free(subscribers[sub_index].in_buffer);
        subscribers[sub_index].in_buffer = NULL;
        subscribers[sub_index].in_pos = 0;
        subscribers[sub_index].close_after_send = false;
    }
}

int has_pending_data(int sub_index) {
    return subscribers[sub_index].out_head != NULL || subscribers[sub_index].close_after_send;
}

void free_out_queue(int sub_index) {
    OutBuffer *current = subscribers[sub_index].out_head;
    while (current) {
        OutBuffer *tmp = current;
        current = current->next;
        free(tmp->data);
        free(tmp);
    }
    subscribers[sub_index].out_head = NULL;
    subscribers[sub_index].out_tail = NULL;
}

void run_server(int server_fd) {
    int new_socket, activity, valread, sd;
    int max_sd;
    struct sockaddr_in address;
    int addrlen = sizeof(address);
    fd_set readfds;
    fd_set writefds;

    while (1) {
        FD_ZERO(&readfds);
        FD_ZERO(&writefds);
        FD_SET(server_fd, &readfds);
        max_sd = server_fd;

        for (int i = 0; i < max_clients; i++) {
            sd = client_sockets[i];
            if (sd > 0) {
                FD_SET(sd, &readfds);
                if (has_pending_data(i)) {
                    FD_SET(sd, &writefds);
                }
                if (sd > max_sd) max_sd = sd;
            }
        }

        activity = select(max_sd + 1, &readfds, &writefds, NULL, NULL);

        if ((activity < 0) && (errno != EINTR)) {
            if (log_file) {
                char time_str[32];
                get_utc_time_str(time_str, sizeof(time_str));
                fprintf(log_file, "%s Select error: %s\n", time_str, strerror(errno));
                fflush(log_file);
            }
            continue;
        }

        if (FD_ISSET(server_fd, &readfds)) {
            if ((new_socket = accept(server_fd, (struct sockaddr *)&address, (socklen_t*)&addrlen)) < 0) {
                if (log_file) {
                    char time_str[32];
                    get_utc_time_str(time_str, sizeof(time_str));
                    fprintf(log_file, "%s Accept failed: %s\n", time_str, strerror(errno));
                    fflush(log_file);
                }
                perror("accept");
                continue;
            }

            int flags = fcntl(new_socket, F_GETFL, 0);
            if (flags == -1 || fcntl(new_socket, F_SETFL, flags | O_NONBLOCK) == -1) {
                if (log_file) {
                    char time_str[32];
                    get_utc_time_str(time_str, sizeof(time_str));
                    fprintf(log_file, "%s fcntl failed for fd %d: %s\n", time_str, new_socket, strerror(errno));
                    fflush(log_file);
                }
                close(new_socket);
                continue;
            }

            int i;
            for (i = 0; i < max_clients; i++) {
                if (client_sockets[i] == 0) {
                    client_sockets[i] = new_socket;
                    subscribers[i].sock = new_socket;
                    subscribers[i].connect_time = time(NULL);
                    subscribers[i].out_head = NULL;
                    subscribers[i].out_tail = NULL;
                    subscribers[i].read_state = READ_LEN;
                    subscribers[i].expected_msg_len = 0;
                    subscribers[i].in_buffer = NULL;
                    subscribers[i].in_pos = 0;
                    subscribers[i].mode = 0;
                    subscribers[i].pubkey_hash[0] = '\0';
                    subscribers[i].close_after_send = false; 
                    if (log_file && strcmp(log_level, "info") == 0) {
                        char time_str[32];
                        get_utc_time_str(time_str, sizeof(time_str));
                        fprintf(log_file, "%s New connection, socket fd %d, ip %s, port %d\n",
                              time_str, new_socket, inet_ntoa(address.sin_addr), ntohs(address.sin_port));
                        fflush(log_file);
                        rotate_log();
                    } 
                    break;
                }
            }
            if (i == max_clients) {
                /* Поскольку new_socket non-blocking, но для error отправляем синхронно (редко, малый размер) */
                char *error_msg = "Error: Too many clients";
                uint32_t error_len_net = htonl(strlen(error_msg));
                send(new_socket, &error_len_net, sizeof(uint32_t), 0);
                send(new_socket, error_msg, strlen(error_msg), 0);
                close(new_socket);
                if (log_file) {
                    char time_str[32];
                    get_utc_time_str(time_str, sizeof(time_str));
                    fprintf(log_file, "%s Too many clients, connection refused\n", time_str);
                    fflush(log_file);
                    rotate_log();
                }
                continue;
            }
        }

        for (int i = 0; i < max_clients; i++) {
            sd = client_sockets[i];
            if (sd <= 0) continue;

            if (FD_ISSET(sd, &writefds)) {
                process_out(i, sd);
            }

            if (FD_ISSET(sd, &readfds)) {
                Subscriber *sub = &subscribers[i];
                valread = 0;

                if (sub->read_state == READ_LEN) {
                    char buf[sizeof(uint32_t) - sub->in_pos];
                    valread = read(sd, buf, sizeof(uint32_t) - sub->in_pos);
                    if (valread > 0) {
                        // Копируем в expected_msg_len (он uint32_t, но накапливаем байты)
                        memcpy(((char*)&sub->expected_msg_len) + sub->in_pos, buf, valread);
                        sub->in_pos += valread;
                        if (sub->in_pos == sizeof(uint32_t)) {
                            sub->expected_msg_len = ntohl(sub->expected_msg_len);
                            if (sub->expected_msg_len > max_message_size) {
                                char *error_msg = "Error: Message too large";
                                enqueue_message(i, error_msg, strlen(error_msg));
                                if (log_file) {
                                    char time_str[32];
                                    get_utc_time_str(time_str, sizeof(time_str));
                                    fprintf(log_file, "%s Message too large from fd %d: %u bytes > max %zu\n", time_str, sd, sub->expected_msg_len, max_message_size);
                                    fflush(log_file);
                                    rotate_log();
                                }
                                close(sd);
                                client_sockets[i] = 0;
                                sub->sock = 0;
                                sub->mode = 0;
                                sub->pubkey_hash[0] = '\0';
                                free_out_queue(i);
                                if (sub->in_buffer) free(sub->in_buffer);
                                sub->in_buffer = NULL;
                                sub->in_pos = 0;
                                continue;
                            }
                            sub->in_buffer = malloc(sub->expected_msg_len + 1);
                            if (!sub->in_buffer) {
                                char *error_msg = "Error: Memory allocation failed";
                                enqueue_message(i, error_msg, strlen(error_msg));
                                close(sd);
                                client_sockets[i] = 0;
                                sub->sock = 0;
                                sub->mode = 0;
                                sub->pubkey_hash[0] = '\0';
                                free_out_queue(i);
                                sub->in_pos = 0;
                                continue;
                            }
                            sub->in_pos = 0;
                            sub->read_state = READ_MSG;
                        }
                    }
                } else if (sub->read_state == READ_MSG) {
                    valread = read(sd, sub->in_buffer + sub->in_pos, sub->expected_msg_len - sub->in_pos);
                    if (valread > 0) {
                        sub->in_pos += valread;
                        if (sub->in_pos == sub->expected_msg_len) {
                            sub->in_buffer[sub->expected_msg_len] = '\0';
                            char *buffer = sub->in_buffer;

                            if (verbose) {
                                printf("Received: %s\n", buffer);
                                if (log_file) {
                                    char time_str[32];
                                    get_utc_time_str(time_str, sizeof(time_str));
                                    fprintf(log_file, "%s Received from fd %d: %s\n", time_str, sd, buffer);
                                    fflush(log_file);
                                }
                            }

                            if (is_http_request(buffer)) {
                                char *http_response = "HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n";
                                enqueue_message(i, http_response, strlen(http_response));
                                close(sd);
                                client_sockets[i] = 0;
                                sub->sock = 0;
                                sub->mode = 0;
                                sub->pubkey_hash[0] = '\0';
                                free_out_queue(i);
                                if (log_file) {
                                    char time_str[32];
                                    get_utc_time_str(time_str, sizeof(time_str));
                                    fprintf(log_file, "%s HTTP request detected and rejected from fd %d\n", time_str, sd);
                                    fflush(log_file);
                                    rotate_log();
                                }
                                free(buffer);
                                sub->in_buffer = NULL;
                                sub->read_state = READ_LEN;
                                sub->in_pos = 0;
                                continue;
                            }

                            if (strncmp(buffer, "SEND|", 5) == 0) {
                                char *rest = strdup(buffer + 5);
                                if (!rest) {
                                    char *error_msg = "Error: Memory allocation failed";
                                    enqueue_message(i, error_msg, strlen(error_msg));
                                    close(sd);
                                    client_sockets[i] = 0;
                                    free(buffer);
                                    sub->in_buffer = NULL;
                                    sub->read_state = READ_LEN;
                                    sub->in_pos = 0;
                                    continue;
                                }
                                char *pubkey_hash_b64 = strtok(rest, "|");
                                char *unlock_at_str = strtok(NULL, "|");
                                char *expire_at_str = strtok(NULL, "|");
                                char *base64_text = strtok(NULL, "|");
                                char *base64_encrypted_key = strtok(NULL, "|");
                                char *base64_iv = strtok(NULL, "|");
                                char *base64_tag = strtok(NULL, "|");

                                if (!pubkey_hash_b64 || !unlock_at_str || !expire_at_str || !base64_text || !base64_encrypted_key || !base64_iv || !base64_tag) {
                                    char *error_msg = "Error: Incomplete data in SEND";
                                    enqueue_message(i, error_msg, strlen(error_msg));
                                    if (log_file) {
                                        char time_str[32];
                                        get_utc_time_str(time_str, sizeof(time_str));
                                        fprintf(log_file, "%s Incomplete SEND from %d\n", time_str, sd);
                                        fflush(log_file);
                                    }
                                    free(rest);
                                    free(buffer);
                                    close(sd);
                                    client_sockets[i] = 0;
                                    sub->in_buffer = NULL;
                                    sub->read_state = READ_LEN;
                                    sub->in_pos = 0;
                                    continue;
                                }

                                trim_string(pubkey_hash_b64);
                                if (strlen(pubkey_hash_b64) == 0) {
                                    char *error_msg = "Error: Empty pubkey hash in SEND";
                                    enqueue_message(i, error_msg, strlen(error_msg));
                                    if (log_file) {
                                        char time_str[32];
                                        get_utc_time_str(time_str, sizeof(time_str));
                                        fprintf(log_file, "%s Empty pubkey hash in SEND from %d\n", time_str, sd);
                                        fflush(log_file);
                                    }
                                    free(rest);
                                    free(buffer);
                                    close(sd);
                                    client_sockets[i] = 0;
                                    sub->in_buffer = NULL;
                                    sub->read_state = READ_LEN;
                                    sub->in_pos = 0;
                                    continue;
                                }

                                size_t pubkey_hash_len;
                                unsigned char *pubkey_hash = base64_decode(pubkey_hash_b64, &pubkey_hash_len);
                                if (!pubkey_hash || pubkey_hash_len != PUBKEY_HASH_LEN) {
                                    char *error_msg = "Error: Invalid pubkey hash";
                                    enqueue_message(i, error_msg, strlen(error_msg));
                                    free(pubkey_hash);
                                    free(rest);
                                    free(buffer);
                                    close(sd);
                                    client_sockets[i] = 0;
                                    sub->in_buffer = NULL;
                                    sub->read_state = READ_LEN;
                                    sub->in_pos = 0;
                                    continue;
                                }

                                time_t unlock_at = atol(unlock_at_str);
                                time_t expire_at = atol(expire_at_str);

                                add_alert(pubkey_hash, unlock_at, expire_at, base64_text, base64_encrypted_key, base64_iv, base64_tag, sd);

                                char *success_msg = "Alert added successfully";
                                enqueue_message(i, success_msg, strlen(success_msg));
                                Recipient *rec = find_recipient(pubkey_hash);
                                if (rec) {
                                    notify_subscribers(pubkey_hash, &rec->alerts[rec->count - 1]);
                                }
                                free(pubkey_hash);
                                free(rest);
                            } else if (strncmp(buffer, "LISTEN|", 7) == 0) {
                                char *rest = strdup(buffer + 7);
                                if (!rest) {
                                    char *error_msg = "Error: Memory allocation failed";
                                    enqueue_message(i, error_msg, strlen(error_msg));
                                    close(sd);
                                    client_sockets[i] = 0;
                                    free(buffer);
                                    sub->in_buffer = NULL;
                                    sub->read_state = READ_LEN;
                                    sub->in_pos = 0;
                                    continue;
                                }
                                char *pubkey_hash_b64 = strtok(rest, "|");
                                char *mode_str = strtok(NULL, "|");
                                char *count_str = strtok(NULL, "|");
                                trim_string(pubkey_hash_b64);
                                if (strlen(pubkey_hash_b64) == 0) {
                                    char *error_msg = "Error: Empty pubkey hash in LISTEN";
                                    enqueue_message(i, error_msg, strlen(error_msg));
                                    if (log_file) {
                                        char time_str[32];
                                        get_utc_time_str(time_str, sizeof(time_str));
                                        fprintf(log_file, "%s Empty pubkey hash in LISTEN from %d\n", time_str, sd);
                                        fflush(log_file);
                                    }
                                    free(rest);
                                    free(buffer);
                                    close(sd);
                                    client_sockets[i] = 0;
                                    sub->in_buffer = NULL;
                                    sub->read_state = READ_LEN;
                                    sub->in_pos = 0;
                                    continue;
                                }
                                int sub_mode = MODE_SINGLE;
                                if (mode_str) {
                                    trim_string(mode_str);
                                    char upper_mode[16];
                                    strncpy(upper_mode, mode_str, sizeof(upper_mode) - 1);
                                    upper_mode[sizeof(upper_mode) - 1] = '\0';
                                    for (char *p = upper_mode; *p; p++) *p = toupper(*p);
                                    if (strcmp(upper_mode, "LAST") == 0) sub_mode = MODE_LAST;
                                }
                                int count = 1;
                                if (count_str) {
                                    trim_string(count_str);
                                    char *endptr;
                                    count = strtol(count_str, &endptr, 10);
                                    if (*endptr != '\0' || count <= 0) {
                                        char *error_msg = "Error: Invalid count in LISTEN last mode";
                                        enqueue_message(i, error_msg, strlen(error_msg));
                                        free(rest);
                                        free(buffer);
                                        close(sd);
                                        client_sockets[i] = 0;
                                        sub->in_buffer = NULL;
                                        sub->read_state = READ_LEN;
                                        sub->in_pos = 0;
                                        continue;
                                    }
                                }
                                sub->mode = sub_mode;
                                strncpy(sub->pubkey_hash, pubkey_hash_b64, sizeof(sub->pubkey_hash) - 1);
                                sub->pubkey_hash[sizeof(sub->pubkey_hash) - 1] = '\0';
                                send_current_alerts(i, sub_mode, pubkey_hash_b64, count);
                                char sub_msg[256];
                                if (sub_mode == MODE_SINGLE) {
                                    int sub_len = snprintf(sub_msg, sizeof(sub_msg), "Subscribed to SINGLE for %s", pubkey_hash_b64);
                                    enqueue_message(i, sub_msg, sub_len);
                                }
                                free(rest);
                            } else if (strncmp(buffer, "SUBSCRIBE ", 10) == 0) {
                                fprintf(stderr, "Processing SUBSCRIBE request: %s\n", buffer);
                                char *rest = strdup(buffer + 10);
                                if (!rest) {
                                    char *error_msg = "Error: Memory allocation failed";
                                    enqueue_message(i, error_msg, strlen(error_msg));
                                    close(sd);
                                    client_sockets[i] = 0;
                                    free(buffer);
                                    sub->in_buffer = NULL;
                                    sub->read_state = READ_LEN;
                                    sub->in_pos = 0;
                                    continue;
                                }
                                char *mode_str = strtok(rest, "|");
                                char *pubkey_hash_b64 = strtok(NULL, "|");
                                if (!mode_str) {
                                    char *error_msg = "Error: Missing mode in SUBSCRIBE";
                                    enqueue_message(i, error_msg, strlen(error_msg));
                                    if (log_file) {
                                        char time_str[32];
                                        get_utc_time_str(time_str, sizeof(time_str));
                                        fprintf(log_file, "%s Missing mode in SUBSCRIBE from %d\n", time_str, sd);
                                        fflush(log_file);
                                    }
                                    free(rest);
                                    free(buffer);
                                    close(sd);
                                    client_sockets[i] = 0;
                                    sub->in_buffer = NULL;
                                    sub->read_state = READ_LEN;
                                    sub->in_pos = 0;
                                    continue;
                                }
                                trim_string(mode_str);
                                int sub_mode = 0;
                                char upper_mode[16];
                                strncpy(upper_mode, mode_str, sizeof(upper_mode) - 1);
                                upper_mode[sizeof(upper_mode) - 1] = '\0';
                                for (char *p = upper_mode; *p; p++) *p = toupper(*p);
                                if (strcmp(upper_mode, "LIVE") == 0) sub_mode = MODE_LIVE;
                                else if (strcmp(upper_mode, "ALL") == 0) sub_mode = MODE_ALL;
                                else if (strcmp(upper_mode, "LOCK") == 0) sub_mode = MODE_LOCK;
                                else if (strcmp(upper_mode, "LAST") == 0) sub_mode = MODE_LAST;
                                else if (strcmp(upper_mode, "NEW") == 0) sub_mode = MODE_NEW;
                                else {
                                    char error_msg[256];
                                    int err_len = snprintf(error_msg, sizeof(error_msg), "Error: Unknown mode %s", mode_str);
                                    enqueue_message(i, error_msg, err_len);
                                    if (log_file) {
                                        char time_str[32];
                                        get_utc_time_str(time_str, sizeof(time_str));
                                        fprintf(log_file, "%s Unknown mode from %d: %s\n", time_str, sd, mode_str);
                                        fflush(log_file);
                                    }
                                    free(rest);
                                    free(buffer);
                                    close(sd);
                                    client_sockets[i] = 0;
                                    sub->in_buffer = NULL;
                                    sub->read_state = READ_LEN;
                                    sub->in_pos = 0;
                                    continue;
                                }
                                sub->mode = sub_mode;
                                if (pubkey_hash_b64 && strlen(pubkey_hash_b64) > 0) {
                                    trim_string(pubkey_hash_b64);
                                    strncpy(sub->pubkey_hash, pubkey_hash_b64, sizeof(sub->pubkey_hash) - 1);
                                    sub->pubkey_hash[sizeof(sub->pubkey_hash) - 1] = '\0';
                                } else {
                                    sub->pubkey_hash[0] = '\0';
                                }
                                if (sub_mode != MODE_NEW) {
                                    send_current_alerts(i, sub_mode, pubkey_hash_b64, 1);
                                }
                                char sub_msg[256];
                                int sub_len = snprintf(sub_msg, sizeof(sub_msg), "Subscribed to %s%s", mode_str, pubkey_hash_b64 ? " for the specified key" : "");
                                enqueue_message(i, sub_msg, sub_len);
                                free(rest);
                            }
                            free(buffer);
                            sub->in_buffer = NULL;
                            sub->read_state = READ_LEN;
                            sub->in_pos = 0;
                        }
                    }
                }

                if (valread == 0) {
                    /* Client closed connection cleanly */
                    if (log_file && strcmp(log_level, "info") == 0) {
                        char time_str[32];
                        get_utc_time_str(time_str, sizeof(time_str));
                        fprintf(log_file, "%s Client disconnected, fd %d\n", time_str, sd);
                        fflush(log_file);
                    }
                    close(sd);
                    client_sockets[i] = 0;
                    sub->sock = 0;
                    sub->mode = 0;
                    sub->pubkey_hash[0] = '\0';
                    free_out_queue(i);
                    if (sub->in_buffer) free(sub->in_buffer);
                    sub->in_buffer = NULL;
                    sub->in_pos = 0;
                    continue;
                } else if (valread < 0) {
                    if (errno == EAGAIN || errno == EWOULDBLOCK) {
                        continue;
                    }
                    if (log_file) {
                        char time_str[32];
                        get_utc_time_str(time_str, sizeof(time_str));
                        fprintf(log_file, "%s Read error from fd %d: %s\n", time_str, sd, strerror(errno));
                        fflush(log_file);
                    }
                    close(sd);
                    client_sockets[i] = 0;
                    sub->sock = 0;
                    sub->mode = 0;
                    sub->pubkey_hash[0] = '\0';
                    free_out_queue(i);
                    if (sub->in_buffer) free(sub->in_buffer);
                    sub->in_buffer = NULL;
                    sub->in_pos = 0;
                    continue;
                }
            }
        }
    }
}
