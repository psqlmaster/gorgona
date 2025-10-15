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

extern int verbose;
extern FILE *log_file;
extern int max_clients;
extern size_t max_message_size;
extern int client_sockets[];
extern Subscriber subscribers[];

void run_server(int server_fd) {
    int new_socket, activity, valread, sd;
    int max_sd;
    struct sockaddr_in address;
    int addrlen = sizeof(address);
    fd_set readfds;

    while (1) {
        FD_ZERO(&readfds);
        FD_SET(server_fd, &readfds);
        max_sd = server_fd;

        for (int i = 0; i < max_clients; i++) {
            sd = client_sockets[i];
            if (sd > 0) FD_SET(sd, &readfds);
            if (sd > max_sd) max_sd = sd;
        }

        activity = select(max_sd + 1, &readfds, NULL, NULL, NULL);

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

            int i;
            for (i = 0; i < max_clients; i++) {
                if (client_sockets[i] == 0) {
                    client_sockets[i] = new_socket;
                    subscribers[i].sock = new_socket;
                    subscribers[i].connect_time = time(NULL);
                    if (log_file) {
                        char time_str[32];
                        get_utc_time_str(time_str, sizeof(time_str));
                        fprintf(log_file, "%s New connection, socket fd %d, ip %s, port %d\n",
                                time_str, new_socket, inet_ntoa(address.sin_addr), ntohs(address.sin_port));
                        fflush(log_file);
                    }
                    break;
                }
            }
            if (i == max_clients) {
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
                }
                continue;
            }
        }

        for (int i = 0; i < max_clients; i++) {
            sd = client_sockets[i];
            if (FD_ISSET(sd, &readfds)) {
                uint32_t msg_len_net;
                valread = read(sd, &msg_len_net, sizeof(uint32_t));
                if (valread != sizeof(uint32_t)) {
                    if (valread == 0) {
                        if (log_file) {
                            char time_str[32];
                            get_utc_time_str(time_str, sizeof(time_str));
                            fprintf(log_file, "%s Client disconnected, fd %d\n", time_str, sd);
                            fflush(log_file);
                        }
                    } else {
                        if (log_file) {
                            char time_str[32];
                            get_utc_time_str(time_str, sizeof(time_str));
                            fprintf(log_file, "%s Read error (length) from fd %d: %s\n", time_str, sd, strerror(errno));
                            fflush(log_file);
                        }
                    }
                    close(sd);
                    client_sockets[i] = 0;
                    subscribers[i].sock = 0;
                    subscribers[i].mode = 0;
                    subscribers[i].pubkey_hash[0] = '\0';
                    continue;
                }
                size_t msg_len = ntohl(msg_len_net);
                if (msg_len > max_message_size) {
                    char *error_msg = "Error: Message too large";
                    uint32_t error_len_net = htonl(strlen(error_msg));
                    send(sd, &error_len_net, sizeof(uint32_t), 0);
                    send(sd, error_msg, strlen(error_msg), 0);
                    if (log_file) {
                        char time_str[32];
                        get_utc_time_str(time_str, sizeof(time_str));
                        fprintf(log_file, "%s Message too large from fd %d: %zu bytes > max %zu\n", time_str, sd, msg_len, max_message_size);
                        fflush(log_file);
                    }
                    close(sd);
                    client_sockets[i] = 0;
                    subscribers[i].sock = 0;
                    subscribers[i].mode = 0;
                    subscribers[i].pubkey_hash[0] = '\0';
                    continue;
                }
                char *buffer = malloc(msg_len + 1);
                if (!buffer) {
                    char *error_msg = "Error: Memory allocation failed";
                    uint32_t error_len_net = htonl(strlen(error_msg));
                    send(sd, &error_len_net, sizeof(uint32_t), 0);
                    send(sd, error_msg, strlen(error_msg), 0);
                    close(sd);
                    client_sockets[i] = 0;
                    continue;
                }
                size_t total_read = 0;
                bool read_error = false;
                while (total_read < msg_len) {
                    valread = read(sd, buffer + total_read, msg_len - total_read);
                    if (valread <= 0) {
                        if (valread < 0) {
                            if (log_file) {
                                char time_str[32];
                                get_utc_time_str(time_str, sizeof(time_str));
                                fprintf(log_file, "%s Read error from fd %d: %s\n", time_str, sd, strerror(errno));
                                fflush(log_file);
                            }
                        } else {
                            if (log_file) {
                                char time_str[32];
                                get_utc_time_str(time_str, sizeof(time_str));
                                fprintf(log_file, "%s Client disconnected during read, fd %d\n", time_str, sd);
                                fflush(log_file);
                            }
                        }
                        read_error = true;
                        free(buffer);
                        close(sd);
                        client_sockets[i] = 0;
                        subscribers[i].sock = 0;
                        subscribers[i].mode = 0;
                        subscribers[i].pubkey_hash[0] = '\0';
                        break;
                    }
                    total_read += valread;
                }
                if (read_error) {
                    continue;
                }
                buffer[msg_len] = '\0';

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
                    send(sd, http_response, strlen(http_response), 0);
                    close(sd);
                    client_sockets[i] = 0;
                    subscribers[i].sock = 0;
                    subscribers[i].mode = 0;
                    subscribers[i].pubkey_hash[0] = '\0';
                    free(buffer);
                    if (log_file) {
                        char time_str[32];
                        get_utc_time_str(time_str, sizeof(time_str));
                        fprintf(log_file, "%s HTTP request detected and rejected from fd %d\n", time_str, sd);
                        fflush(log_file);
                    }
                    continue;
                }

                if (strncmp(buffer, "SEND|", 5) == 0) {
                    char *rest = strdup(buffer + 5);
                    if (!rest) {
                        char *error_msg = "Error: Memory allocation failed";
                        uint32_t error_len_net = htonl(strlen(error_msg));
                        send(sd, &error_len_net, sizeof(uint32_t), 0);
                        send(sd, error_msg, strlen(error_msg), 0);
                        close(sd);
                        client_sockets[i] = 0;
                        free(buffer);
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
                        uint32_t error_len_net = htonl(strlen(error_msg));
                        send(sd, &error_len_net, sizeof(uint32_t), 0);
                        send(sd, error_msg, strlen(error_msg), 0);
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
                        continue;
                    }

                    trim_string(pubkey_hash_b64);
                    if (strlen(pubkey_hash_b64) == 0) {
                        char *error_msg = "Error: Empty pubkey hash in SEND";
                        uint32_t error_len_net = htonl(strlen(error_msg));
                        send(sd, &error_len_net, sizeof(uint32_t), 0);
                        send(sd, error_msg, strlen(error_msg), 0);
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
                        continue;
                    }

                    size_t pubkey_hash_len;
                    unsigned char *pubkey_hash = base64_decode(pubkey_hash_b64, &pubkey_hash_len);
                    if (!pubkey_hash || pubkey_hash_len != PUBKEY_HASH_LEN) {
                        char *error_msg = "Error: Invalid pubkey hash";
                        uint32_t error_len_net = htonl(strlen(error_msg));
                        send(sd, &error_len_net, sizeof(uint32_t), 0);
                        send(sd, error_msg, strlen(error_msg), 0);
                        free(pubkey_hash);
                        free(rest);
                        free(buffer);
                        close(sd);
                        client_sockets[i] = 0;
                        continue;
                    }

                    time_t unlock_at = atol(unlock_at_str);
                    time_t expire_at = atol(expire_at_str);

                    add_alert(pubkey_hash, unlock_at, expire_at, base64_text, base64_encrypted_key, base64_iv, base64_tag, sd);

                    char *success_msg = "Alert added successfully";
                    uint32_t success_len_net = htonl(strlen(success_msg));
                    send(sd, &success_len_net, sizeof(uint32_t), 0);
                    send(sd, success_msg, strlen(success_msg), 0);
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
                        uint32_t error_len_net = htonl(strlen(error_msg));
                        send(sd, &error_len_net, sizeof(uint32_t), 0);
                        send(sd, error_msg, strlen(error_msg), 0);
                        close(sd);
                        client_sockets[i] = 0;
                        free(buffer);
                        continue;
                    }
                    char *pubkey_hash_b64 = strtok(rest, "|");
                    char *mode_str = strtok(NULL, "|");
                    char *count_str = strtok(NULL, "|");
                    trim_string(pubkey_hash_b64);
                    if (strlen(pubkey_hash_b64) == 0) {
                        char *error_msg = "Error: Empty pubkey hash in LISTEN";
                        uint32_t error_len_net = htonl(strlen(error_msg));
                        send(sd, &error_len_net, sizeof(uint32_t), 0);
                        send(sd, error_msg, strlen(error_msg), 0);
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
                            uint32_t error_len_net = htonl(strlen(error_msg));
                            send(sd, &error_len_net, sizeof(uint32_t), 0);
                            send(sd, error_msg, strlen(error_msg), 0);
                            free(rest);
                            free(buffer);
                            close(sd);
                            client_sockets[i] = 0;
                            continue;
                        }
                    }
                    for (int j = 0; j < max_clients; j++) {
                        if (client_sockets[j] == sd) {
                            subscribers[j].mode = sub_mode;
                            strncpy(subscribers[j].pubkey_hash, pubkey_hash_b64, sizeof(subscribers[j].pubkey_hash) - 1);
                            subscribers[j].pubkey_hash[sizeof(subscribers[j].pubkey_hash) - 1] = '\0';
                            break;
                        }
                    }
                    send_current_alerts(sd, sub_mode, pubkey_hash_b64, count);
                    char sub_msg[256];
                    int sub_len = snprintf(sub_msg, sizeof(sub_msg), "Subscribed to %s for %s", (sub_mode == MODE_LAST ? "LAST" : "SINGLE"), pubkey_hash_b64);
                    uint32_t sub_len_net = htonl(sub_len);
                    send(sd, &sub_len_net, sizeof(uint32_t), 0);
                    send(sd, sub_msg, sub_len, 0);
                    free(rest);
                    if (sub_mode == MODE_LAST) {
                        close(sd);
                        client_sockets[i] = 0;
                        subscribers[i].sock = 0;
                        subscribers[i].mode = 0;
                        subscribers[i].pubkey_hash[0] = '\0';
                    }
                } else if (strncmp(buffer, "SUBSCRIBE ", 10) == 0) {
                    char *rest = strdup(buffer + 10);
                    if (!rest) {
                        char *error_msg = "Error: Memory allocation failed";
                        uint32_t error_len_net = htonl(strlen(error_msg));
                        send(sd, &error_len_net, sizeof(uint32_t), 0);
                        send(sd, error_msg, strlen(error_msg), 0);
                        close(sd);
                        client_sockets[i] = 0;
                        free(buffer);
                        continue;
                    }
                    char *mode_str = strtok(rest, "|");
                    char *pubkey_hash_b64 = strtok(NULL, "|");
                    if (!mode_str) {
                        char *error_msg = "Error: Missing mode in SUBSCRIBE";
                        uint32_t error_len_net = htonl(strlen(error_msg));
                        send(sd, &error_len_net, sizeof(uint32_t), 0);
                        send(sd, error_msg, strlen(error_msg), 0);
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
                        uint32_t err_len_net = htonl(err_len);
                        send(sd, &err_len_net, sizeof(uint32_t), 0);
                        send(sd, error_msg, err_len, 0);
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
                        continue;
                    }
                    for (int j = 0; j < max_clients; j++) {
                        if (client_sockets[j] == sd) {
                            subscribers[j].mode = sub_mode;
                            if (pubkey_hash_b64 && strlen(pubkey_hash_b64) > 0) {
                                trim_string(pubkey_hash_b64);
                                strncpy(subscribers[j].pubkey_hash, pubkey_hash_b64, sizeof(subscribers[j].pubkey_hash) - 1);
                                subscribers[j].pubkey_hash[sizeof(subscribers[j].pubkey_hash) - 1] = '\0';
                            } else {
                                subscribers[j].pubkey_hash[0] = '\0';
                            }
                            break;
                        }
                    }
                    if (sub_mode != MODE_NEW) {
                        send_current_alerts(sd, sub_mode, pubkey_hash_b64, 1);
                    }
                    char sub_msg[256];
                    int sub_len = snprintf(sub_msg, sizeof(sub_msg), "Subscribed to %s%s", mode_str, pubkey_hash_b64 ? " for the specified key" : "");
                    uint32_t sub_len_net = htonl(sub_len);
                    send(sd, &sub_len_net, sizeof(uint32_t), 0);
                    send(sd, sub_msg, sub_len, 0);
                    free(rest);
                    if (sub_mode == MODE_LAST) {
                        close(sd);
                        client_sockets[i] = 0;
                        subscribers[i].sock = 0;
                        subscribers[i].mode = 0;
                        subscribers[i].pubkey_hash[0] = '\0';
                    }
                }
                free(buffer);
            }
        }
    }
}
