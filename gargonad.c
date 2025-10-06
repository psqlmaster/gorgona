/* BSD 3-Clause License
Copyright (c) 2025, Alexander Shcheglov
All rights reserved. */

#include "gargona_utils.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/select.h>
#include <errno.h>
#include <ctype.h>
#include <signal.h>
#include <time.h>  
#include <stdint.h>
#include <getopt.h>

int verbose = 0;

/* Get current UTC time as string in format [YYYY-MM-DDThh:mm:ss UTC] */
static void get_utc_time_str(char *buffer, size_t buffer_size) {
    time_t now = time(NULL);
    struct tm *utc_time = gmtime(&now);
    strftime(buffer, buffer_size, "[%Y-%m-%d %H:%M:%S UTC]", utc_time);
}

/* Shutdown handler for graceful exit */
void shutdown_handler(int sig) {
    if (log_file) {
        char time_str[32];
        get_utc_time_str(time_str, sizeof(time_str));
        fprintf(log_file, "%s Received signal %d, shutting down\n", time_str, sig);
        fflush(log_file);
        fclose(log_file);
        log_file = NULL;
    }
    /* Free other resources if needed */
    exit(0);
}

void print_server_help(const char *program_name) {
    printf("Gargona Server\n");
    printf("Usage: %s [-h|--help] [-v|--verbose]\n", program_name);
    printf("\nDescription:\n");
    printf(" The Gargona server handles encrypted alerts, allowing clients to send and subscribe to messages.\n");
    printf(" It listens for TCP connections and processes commands: SEND, LISTEN, SUBSCRIBE.\n");
    printf("\nFlags:\n");
    printf(" -h, --help Displays this help message\n");
    printf(" -v, --verbose Enables verbose output (e.g., received messages in console)\n");
    printf("\nConfiguration:\n");
    printf(" The file ./gargonad.conf contains server settings.\n");
    printf(" Format:\n");
    printf(" [server]\n");
    printf(" port = <port> (default: 5555, example: 7777)\n");
    printf(" MAX_ALERTS = <number> (default: 1024, example: 2000)\n");
    printf(" MAX_CLIENTS = <number> (default: 100, example: 100)\n");
    printf(" max_message_size = <bytes> (default: 5242880 for 5 MB, example: 10485760 for 10 MB)\n");
    printf("\nLogging:\n");
    printf(" Logs are written to ./gargonad.log. The log rotates when it exceeds %d bytes (10 MB).\n", MAX_LOG_SIZE);
    printf("\nLimits:\n");
    printf(" - Maximum simultaneous clients: MAX_CLIENTS (default: 100 or from config).\n");
    printf(" - Maximum alerts per recipient: MAX_ALERTS (default: 1024 or from config).\n");
    printf(" - Recipient capacity expands dynamically starting from %d.\n", INITIAL_RECIPIENT_CAPACITY);
    printf("\nExample:\n");
    printf(" %s\n", program_name);
    printf(" Starts the server using settings from ./gargonad.conf or defaults.\n");
}

int main(int argc, char *argv[]) {
    int i, opt;
    static struct option long_options[] = {
        {"help", no_argument, 0, 'h'},
        {"verbose", no_argument, 0, 'v'},
        {0, 0, 0, 0}
    };
    while ((opt = getopt_long(argc, argv, "vh", long_options, NULL)) != -1) {
        switch (opt) {
            case 'v':
                verbose = 1;
                break;
            case 'h':
                print_server_help(argv[0]);
                return 0;
            case '?':
                fprintf(stderr, "Unknown option: %s. Use -h for help.\n", argv[optind-1]);
                return 1;
            default:
                fprintf(stderr, "Error processing options\n");
                return 1;
        }
    }

    int server_fd, new_socket, activity, valread, sd;
    int max_sd;
    struct sockaddr_in address;
    int addrlen = sizeof(address);
    fd_set readfds;

    /* Register signal handlers */
    signal(SIGINT, shutdown_handler);
    signal(SIGTERM, shutdown_handler);

    /* Read configuration */
    int port, max_alerts_config, max_clients_config;
    size_t max_message_size_config;
    read_config(&port, &max_alerts_config, &max_clients_config, &max_message_size_config);
    max_alerts = max_alerts_config;
    max_clients = max_clients_config;
    max_message_size = max_message_size_config;

    /* Initialize arrays */
    for (i = 0; i < max_clients; i++) {
        client_sockets[i] = 0;
        subscribers[i].sock = 0;
        subscribers[i].mode = 0;
        subscribers[i].pubkey_hash[0] = '\0';
    }

    /* Initialize logging */
    if (log_file == NULL) {
        log_file = fopen("gargonad.log", "a");
        if (!log_file) {
            perror("Failed to open gargonad.log");
            exit(EXIT_FAILURE);
        } else {
            rotate_log();
            char time_str[32];
            get_utc_time_str(time_str, sizeof(time_str));
            fprintf(log_file, "%s Server started\n", time_str);
            fflush(log_file);
        }
    }

    /* Initialize recipients */
    recipient_capacity = INITIAL_RECIPIENT_CAPACITY;
    recipients = malloc(sizeof(Recipient) * recipient_capacity);
    if (!recipients) {
        if (log_file) {
            char time_str[32];
            get_utc_time_str(time_str, sizeof(time_str));
            fprintf(log_file, "%s Failed to allocate memory for recipients\n", time_str);
            fflush(log_file);
            fclose(log_file);
            log_file = NULL;
        }
        perror("Failed to allocate memory for recipients");
        exit(EXIT_FAILURE);
    }
    recipient_count = 0;

    /* Create socket */
    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0) {
        if (log_file) {
            char time_str[32];
            get_utc_time_str(time_str, sizeof(time_str));
            fprintf(log_file, "%s Socket creation failed: %s\n", time_str, strerror(errno));
            fflush(log_file);
            fclose(log_file);
            log_file = NULL;
        }
        perror("socket failed");
        exit(EXIT_FAILURE);
    }

    /* Set socket options */
    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, (char *)&opt, sizeof(opt)) < 0) {
        if (log_file) {
            char time_str[32];
            get_utc_time_str(time_str, sizeof(time_str));
            fprintf(log_file, "%s Setsockopt failed: %s\n", time_str, strerror(errno));
            fflush(log_file);
            fclose(log_file);
            log_file = NULL;
        }
        perror("setsockopt");
        exit(EXIT_FAILURE);
    }

    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(port);

    /* Bind socket */
    if (bind(server_fd, (struct sockaddr *)&address, sizeof(address)) < 0) {
        if (log_file) {
            char time_str[32];
            get_utc_time_str(time_str, sizeof(time_str));
            fprintf(log_file, "%s Bind failed: %s\n", time_str, strerror(errno));
            fflush(log_file);
            fclose(log_file);
            log_file = NULL;
        }
        perror("bind failed");
        exit(EXIT_FAILURE);
    }

    /* Listen */
    if (listen(server_fd, 3) < 0) {
        if (log_file) {
            char time_str[32];
            get_utc_time_str(time_str, sizeof(time_str));
            fprintf(log_file, "%s Listen failed: %s\n", time_str, strerror(errno));
            fflush(log_file);
            fclose(log_file);
            log_file = NULL;
        }
        perror("listen");
        exit(EXIT_FAILURE);
    }

    printf("Server running on port %d\n", port);
    if (log_file) {
        char time_str[32];
        get_utc_time_str(time_str, sizeof(time_str));
        fprintf(log_file, "%s Server running on port %d\n", time_str, port);
        fflush(log_file);
    }

    while (1) {
        FD_ZERO(&readfds);
        FD_SET(server_fd, &readfds);
        max_sd = server_fd;

        for (i = 0; i < max_clients; i++) {
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

            for (i = 0; i < max_clients; i++) {
                if (client_sockets[i] == 0) {
                    client_sockets[i] = new_socket;
                    subscribers[i].sock = new_socket;
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
                if (log_file) {
                    char time_str[32];
                    get_utc_time_str(time_str, sizeof(time_str));
                    fprintf(log_file, "%s Max clients reached, rejecting connection\n", time_str);
                    fflush(log_file);
                }
                char *resp = "Error: Max clients reached";
                uint32_t len_net = htonl(strlen(resp));
                send(new_socket, &len_net, sizeof(uint32_t), 0);
                send(new_socket, resp, strlen(resp), 0);
                close(new_socket);
            }
        }

        for (i = 0; i < max_clients; i++) {
            sd = client_sockets[i];
            if (FD_ISSET(sd, &readfds)) {
                // Чтение длины сообщения
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
                            fprintf(log_file, "%s Read error on fd %d: %s\n", time_str, sd, strerror(errno));
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
                    if (log_file) {
                        char time_str[32];
                        get_utc_time_str(time_str, sizeof(time_str));
                        fprintf(log_file, "%s Message too large (%zu > %zu) from fd %d\n", time_str, msg_len, max_message_size, sd);
                        fflush(log_file);
                    }
                    char *error_msg = "Error: Message too large";
                    uint32_t error_len_net = htonl(strlen(error_msg));
                    send(sd, &error_len_net, sizeof(uint32_t), 0);
                    send(sd, error_msg, strlen(error_msg), 0);
                    close(sd);
                    client_sockets[i] = 0;
                    subscribers[i].sock = 0;
                    subscribers[i].mode = 0;
                    subscribers[i].pubkey_hash[0] = '\0';
                    continue;
                }

                char *buffer = malloc(msg_len + 1);
                if (!buffer) {
                    if (log_file) {
                        char time_str[32];
                        get_utc_time_str(time_str, sizeof(time_str));
                        fprintf(log_file, "%s Memory allocation failed for msg_len %zu on fd %d\n", time_str, msg_len, sd);
                        fflush(log_file);
                    }
                    char *error_msg = "Error: Server memory error";
                    uint32_t error_len_net = htonl(strlen(error_msg));
                    send(sd, &error_len_net, sizeof(uint32_t), 0);
                    send(sd, error_msg, strlen(error_msg), 0);
                    close(sd);
                    client_sockets[i] = 0;
                    continue;
                }

                size_t total_read = 0;
                while (total_read < msg_len) {
                    valread = read(sd, buffer + total_read, msg_len - total_read);
                    if (valread <= 0) {
                        if (valread < 0) {
                            if (log_file) {
                                char time_str[32];
                                get_utc_time_str(time_str, sizeof(time_str));
                                fprintf(log_file, "%s Read error during data: %s on fd %d\n", time_str, strerror(errno), sd);
                                fflush(log_file);
                            }
                        } else {
                            if (log_file) {
                                char time_str[32];
                                get_utc_time_str(time_str, sizeof(time_str));
                                fprintf(log_file, "%s Unexpected disconnect during read on fd %d\n", time_str, sd);
                                fflush(log_file);
                            }
                        }
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
                if (total_read < msg_len) continue;  // Если не дочитали, уже закрыли
                buffer[msg_len] = '\0';

                if (verbose) {
                    printf("Received: %s\n", buffer);
                }

                // Обработка команды (остальной код без изменений, но с динамической отправкой ответов)
                if (strncmp(buffer, "SEND|", 5) == 0) {
                    char *rest = strdup(buffer + 5);
                    if (!rest) {
                        char *error_msg = "Error: Memory allocation failed";
                        uint32_t error_len_net = htonl(strlen(error_msg));
                        send(sd, &error_len_net, sizeof(uint32_t), 0);
                        send(sd, error_msg, strlen(error_msg), 0);
                        free(buffer);
                        close(sd);
                        client_sockets[i] = 0;
                        continue;
                    }
                    char *pubkey_hash_b64 = strtok(rest, "|");
                    char *create_at_str = strtok(NULL, "|");
                    char *unlock_at_str = strtok(NULL, "|");
                    char *expire_at_str = strtok(NULL, "|");
                    char *encrypted_b64 = strtok(NULL, "|");
                    char *encrypted_key_b64 = strtok(NULL, "|");
                    char *iv_b64 = strtok(NULL, "|");
                    char *tag_b64 = strtok(NULL, "|");

                    if (!pubkey_hash_b64 || !create_at_str || !unlock_at_str || !expire_at_str ||
                        !encrypted_b64 || !encrypted_key_b64 || !iv_b64 || !tag_b64) {
                        char *error_msg = "Error: Incomplete SEND data";
                        uint32_t error_len_net = htonl(strlen(error_msg));
                        send(sd, &error_len_net, sizeof(uint32_t), 0);
                        send(sd, error_msg, strlen(error_msg), 0);
                        free(rest);
                        free(buffer);
                        continue;
                    }

                    trim_string(pubkey_hash_b64);
                    time_t create_at = atol(create_at_str);
                    time_t unlock_at = atol(unlock_at_str);
                    time_t expire_at = atol(expire_at_str);

                    size_t hash_len;
                    unsigned char *pubkey_hash = base64_decode(pubkey_hash_b64, &hash_len);
                    if (!pubkey_hash || hash_len != PUBKEY_HASH_LEN) {
                        char *error_msg = "Error: Invalid pubkey hash";
                        uint32_t error_len_net = htonl(strlen(error_msg));
                        send(sd, &error_len_net, sizeof(uint32_t), 0);
                        send(sd, error_msg, strlen(error_msg), 0);
                        free(pubkey_hash);
                        free(rest);
                        free(buffer);
                        continue;
                    }

                    add_alert(pubkey_hash, create_at, unlock_at, expire_at, encrypted_b64, encrypted_key_b64, iv_b64, tag_b64, sd);
                    char *success_msg = "Alert successfully added";
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
                    int sub_mode = MODE_SINGLE;  /* Default to single */
                    if (mode_str) {
                        trim_string(mode_str);
                        char upper_mode[16];
                        strncpy(upper_mode, mode_str, sizeof(upper_mode) - 1);
                        upper_mode[sizeof(upper_mode) - 1] = '\0';
                        for (char *p = upper_mode; *p; p++) *p = toupper(*p);
                        if (strcmp(upper_mode, "LAST") == 0) sub_mode = MODE_LAST;
                    }
                    for (int j = 0; j < max_clients; j++) {
                        if (client_sockets[j] == sd) {
                            subscribers[j].mode = sub_mode;
                            strncpy(subscribers[j].pubkey_hash, pubkey_hash_b64, sizeof(subscribers[j].pubkey_hash) - 1);
                            subscribers[j].pubkey_hash[sizeof(subscribers[j].pubkey_hash) - 1] = '\0';
                            break;
                        }
                    }
                    send_current_alerts(sd, sub_mode, pubkey_hash_b64);
                    char sub_msg[256];
                    int sub_len = snprintf(sub_msg, sizeof(sub_msg), "Subscribed to %s for %s", (sub_mode == MODE_LAST ? "LAST" : "SINGLE"), pubkey_hash_b64);
                    uint32_t sub_len_net = htonl(sub_len);
                    send(sd, &sub_len_net, sizeof(uint32_t), 0);
                    send(sd, sub_msg, sub_len, 0);
                    free(rest);
                    if (sub_mode == MODE_LAST) {
                        /* Close connection for last mode after sending */
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
                    else if (strcmp(upper_mode, "LAST") == 0) sub_mode = MODE_LAST;  /* New mode */
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
                    send_current_alerts(sd, sub_mode, pubkey_hash_b64);
                    char sub_msg[256];
                    int sub_len = snprintf(sub_msg, sizeof(sub_msg), "Subscribed to %s%s", mode_str, pubkey_hash_b64 ? " for the specified key" : "");
                    uint32_t sub_len_net = htonl(sub_len);
                    send(sd, &sub_len_net, sizeof(uint32_t), 0);
                    send(sd, sub_msg, sub_len, 0);
                    free(rest);
                    if (sub_mode == MODE_LAST) {
                        /* Close connection for last mode after sending */
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

    /* Free resources */
    for (int r = 0; r < recipient_count; r++) {
        for (int j = 0; j < recipients[r].count; j++) {
            free_alert(&recipients[r].alerts[j]);
        }
        free(recipients[r].alerts);  /* Free dynamic array */
    }
    free(recipients);
    if (log_file) {
        char time_str[32];
        get_utc_time_str(time_str, sizeof(time_str));
        fprintf(log_file, "%s Server shutting down\n", time_str);
        fflush(log_file);
        fclose(log_file);
    }
    close(server_fd);
    return 0;
}

