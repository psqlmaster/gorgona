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
#include <time.h>  /* Added for UTC time formatting */

/* Global flag for verbose mode */
int verbose = 0;

/* Get current UTC time as string in format [YYYY-MM-DDThh:mm:ssZ] */
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
    int i;
    for (i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            print_server_help(argv[0]);
            return 0;
        } else if (strcmp(argv[i], "-v") == 0 || strcmp(argv[i], "--verbose") == 0) {
            verbose = 1;
        } else {
            fprintf(stderr, "Unknown option: %s. Use -h for help.\n", argv[i]);
            return 1;
        }
    }

    int server_fd, new_socket, activity, valread, sd;
    int max_sd;
    struct sockaddr_in address;
    int opt = 1;
    int addrlen = sizeof(address);
    char buffer[MAX_MSG_LEN] = {0};
    fd_set readfds;

    /* Register signal handlers */
    signal(SIGINT, shutdown_handler);
    signal(SIGTERM, shutdown_handler);

    /* Read configuration */
    int port, max_alerts_config, max_clients_config;
    read_config(&port, &max_alerts_config, &max_clients_config);
    max_alerts = max_alerts_config;
    max_clients = max_clients_config;

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
            printf("select error: %s\n", strerror(errno));
            continue;
        }

        /* New connection */
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
                    subscribers[i].mode = 0;
                    subscribers[i].pubkey_hash[0] = '\0';
                    break;
                }
            }
            if (i == max_clients) {
                dprintf(new_socket, "Server full, try again later\nEND_OF_MESSAGE\n");
                close(new_socket);
                if (log_file) {
                    char time_str[32];
                    get_utc_time_str(time_str, sizeof(time_str));
                    fprintf(log_file, "%s No free slots for new connection\n", time_str);
                    fflush(log_file);
                }
            }
        }

        /* Handle client data */
        for (i = 0; i < max_clients; i++) {
            sd = client_sockets[i];
            if (FD_ISSET(sd, &readfds)) {
                valread = read(sd, buffer, MAX_MSG_LEN - 1);
                if (valread <= 0) {
                    if (valread < 0 && log_file) {
                        char time_str[32];
                        get_utc_time_str(time_str, sizeof(time_str));
                        fprintf(log_file, "%s Read error from client %d: %s\n", 
                                time_str, sd, strerror(errno));
                        fflush(log_file);
                    }
                    close(sd);
                    client_sockets[i] = 0;
                    subscribers[i].sock = 0;
                    subscribers[i].mode = 0;
                    subscribers[i].pubkey_hash[0] = '\0';
                    continue;
                }

                buffer[valread] = '\0';
                if (verbose) {  /* Print only in verbose mode */
                    printf("Received: %s\n", buffer);
                }

                if (strncmp(buffer, "SEND|", 5) != 0 &&
                    strncmp(buffer, "LISTEN|", 7) != 0 &&
                    strncmp(buffer, "SUBSCRIBE ", 10) != 0) {
                    if (is_http_request(buffer)) {
                        char http_response[] = "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
                        send(sd, http_response, sizeof(http_response) - 1, 0);
                        if (log_file) {
                            char time_str[32];
                            get_utc_time_str(time_str, sizeof(time_str));
                            fprintf(log_file, "%s Handled HTTP probe from %d: %.*s\n", 
                                    time_str, sd, valread, buffer);
                            fflush(log_file);
                        }
                    } else {
                        dprintf(sd, "Error: Unknown or malformed command\nEND_OF_MESSAGE\n");
                        if (log_file) {
                            char time_str[32];
                            get_utc_time_str(time_str, sizeof(time_str));
                            fprintf(log_file, "%s Invalid command from %d: %.*s\n", 
                                    time_str, sd, valread, buffer);
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

                if ((strncmp(buffer, "SEND|", 5) == 0 || strncmp(buffer, "LISTEN|", 7) == 0) && 
                    (valread < 8 || strchr(buffer, '|') == NULL)) {
                    dprintf(sd, "Error: Malformed SEND or LISTEN command\nEND_OF_MESSAGE\n");
                    if (log_file) {
                        char time_str[32];
                        get_utc_time_str(time_str, sizeof(time_str));
                        fprintf(log_file, "%s Malformed SEND/LISTEN from %d: %.*s\n", 
                                time_str, sd, valread, buffer);
                        fflush(log_file);
                    }
                    close(sd);
                    client_sockets[i] = 0;
                    subscribers[i].sock = 0;
                    subscribers[i].mode = 0;
                    subscribers[i].pubkey_hash[0] = '\0';
                    continue;
                }

                if (strncmp(buffer, "SEND|", 5) == 0) {
                    char *token = strtok(buffer + 5, "|");
                    if (!token) {
                        dprintf(sd, "Error: Invalid SEND format\nEND_OF_MESSAGE\n");
                        if (log_file) {
                            char time_str[32];
                            get_utc_time_str(time_str, sizeof(time_str));
                            fprintf(log_file, "%s Invalid SEND format from %d\n", time_str, sd);
                            fflush(log_file);
                        }
                        close(sd);
                        client_sockets[i] = 0;
                        continue;
                    }
                    char *pubkey_hash_b64 = token;
                    token = strtok(NULL, "|");
                    if (!token) {
                        dprintf(sd, "Error: Missing create_at\nEND_OF_MESSAGE\n");
                        if (log_file) {
                            char time_str[32];
                            get_utc_time_str(time_str, sizeof(time_str));
                            fprintf(log_file, "%s Missing create_at in SEND from %d\n", time_str, sd);
                            fflush(log_file);
                        }
                        close(sd);
                        client_sockets[i] = 0;
                        continue;
                    }
                    time_t create_at = atol(token);
                    token = strtok(NULL, "|");
                    if (!token) {
                        dprintf(sd, "Error: Missing unlock_at\nEND_OF_MESSAGE\n");
                        if (log_file) {
                            char time_str[32];
                            get_utc_time_str(time_str, sizeof(time_str));
                            fprintf(log_file, "%s Missing unlock_at in SEND from %d\n", time_str, sd);
                            fflush(log_file);
                        }
                        close(sd);
                        client_sockets[i] = 0;
                        continue;
                    }
                    time_t unlock_at = atol(token);
                    token = strtok(NULL, "|");
                    if (!token) {
                        dprintf(sd, "Error: Missing expire_at\nEND_OF_MESSAGE\n");
                        if (log_file) {
                            char time_str[32];
                            get_utc_time_str(time_str, sizeof(time_str));
                            fprintf(log_file, "%s Missing expire_at in SEND from %d\n", time_str, sd);
                            fflush(log_file);
                        }
                        close(sd);
                        client_sockets[i] = 0;
                        continue;
                    }
                    time_t expire_at = atol(token);
                    token = strtok(NULL, "|");
                    if (!token) {
                        dprintf(sd, "Error: Missing base64_text\nEND_OF_MESSAGE\n");
                        if (log_file) {
                            char time_str[32];
                            get_utc_time_str(time_str, sizeof(time_str));
                            fprintf(log_file, "%s Missing base64_text in SEND from %d\n", time_str, sd);
                            fflush(log_file);
                        }
                        close(sd);
                        client_sockets[i] = 0;
                        continue;
                    }
                    char *base64_text = token;
                    token = strtok(NULL, "|");
                    if (!token) {
                        dprintf(sd, "Error: Missing base64_encrypted_key\nEND_OF_MESSAGE\n");
                        if (log_file) {
                            char time_str[32];
                            get_utc_time_str(time_str, sizeof(time_str));
                            fprintf(log_file, "%s Missing base64_encrypted_key in SEND from %d\n", time_str, sd);
                            fflush(log_file);
                        }
                        close(sd);
                        client_sockets[i] = 0;
                        continue;
                    }
                    char *base64_encrypted_key = token;
                    token = strtok(NULL, "|");
                    if (!token) {
                        dprintf(sd, "Error: Missing base64_iv\nEND_OF_MESSAGE\n");
                        if (log_file) {
                            char time_str[32];
                            get_utc_time_str(time_str, sizeof(time_str));
                            fprintf(log_file, "%s Missing base64_iv in SEND from %d\n", time_str, sd);
                            fflush(log_file);
                        }
                        close(sd);
                        client_sockets[i] = 0;
                        continue;
                    }
                    char *base64_iv = token;
                    token = strtok(NULL, "|");
                    if (!token) {
                        dprintf(sd, "Error: Missing base64_tag\nEND_OF_MESSAGE\n");
                        if (log_file) {
                            char time_str[32];
                            get_utc_time_str(time_str, sizeof(time_str));
                            fprintf(log_file, "%s Missing base64_tag in SEND from %d\n", time_str, sd);
                            fflush(log_file);
                        }
                        close(sd);
                        client_sockets[i] = 0;
                        continue;
                    }
                    char *base64_tag = token;

                    size_t hash_len;
                    unsigned char *pubkey_hash = base64_decode(pubkey_hash_b64, &hash_len);
                    if (!pubkey_hash || hash_len != PUBKEY_HASH_LEN) {
                        dprintf(sd, "Error: Invalid public key hash\nEND_OF_MESSAGE\n");
                        if (log_file) {
                            char time_str[32];
                            get_utc_time_str(time_str, sizeof(time_str));
                            fprintf(log_file, "%s Invalid pubkey hash from %d\n", time_str, sd);
                            fflush(log_file);
                        }
                        free(pubkey_hash);
                        close(sd);
                        client_sockets[i] = 0;
                        continue;
                    }

                    add_alert(pubkey_hash, create_at, unlock_at, expire_at, base64_text, base64_encrypted_key, base64_iv, base64_tag, sd);
                    dprintf(sd, "Alert successfully added\nEND_OF_MESSAGE\n");
                    Recipient *rec = find_recipient(pubkey_hash);
                    if (rec) {
                        notify_subscribers(pubkey_hash, &rec->alerts[rec->count - 1]);
                    }
                    free(pubkey_hash);
                } else if (strncmp(buffer, "LISTEN|", 7) == 0) {
                    char *pubkey_hash_b64 = buffer + 7;
                    trim_string(pubkey_hash_b64);
                    if (strlen(pubkey_hash_b64) == 0) {
                        dprintf(sd, "Error: Empty pubkey hash in LISTEN\nEND_OF_MESSAGE\n");
                        if (log_file) {
                            char time_str[32];
                            get_utc_time_str(time_str, sizeof(time_str));
                            fprintf(log_file, "%s Empty pubkey hash in LISTEN from %d\n", time_str, sd);
                            fflush(log_file);
                        }
                        close(sd);
                        client_sockets[i] = 0;
                        continue;
                    }
                    for (int j = 0; j < max_clients; j++) {
                        if (client_sockets[j] == sd) {
                            subscribers[j].mode = 3;
                            strncpy(subscribers[j].pubkey_hash, pubkey_hash_b64, sizeof(subscribers[j].pubkey_hash) - 1);
                            subscribers[j].pubkey_hash[sizeof(subscribers[j].pubkey_hash) - 1] = '\0';
                            break;
                        }
                    }
                    send_current_alerts(sd, 3, pubkey_hash_b64);
                    dprintf(sd, "Subscribed to SINGLE for %s\nEND_OF_MESSAGE\n", pubkey_hash_b64);
                } else if (strncmp(buffer, "SUBSCRIBE ", 10) == 0) {
                    char *rest = buffer + 10;
                    char *mode_str = strtok(rest, "|");
                    char *pubkey_hash_b64 = strtok(NULL, "|");
                    if (!mode_str) {
                        dprintf(sd, "Error: Missing mode in SUBSCRIBE\nEND_OF_MESSAGE\n");
                        if (log_file) {
                            char time_str[32];
                            get_utc_time_str(time_str, sizeof(time_str));
                            fprintf(log_file, "%s Missing mode in SUBSCRIBE from %d\n", time_str, sd);
                            fflush(log_file);
                        }
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
                    if (strcmp(upper_mode, "LIVE") == 0) sub_mode = 1;
                    else if (strcmp(upper_mode, "ALL") == 0) sub_mode = 2;
                    else if (strcmp(upper_mode, "LOCK") == 0) sub_mode = 4;
                    else {
                        dprintf(sd, "Error: Unknown mode %s\nEND_OF_MESSAGE\n", mode_str);
                        if (log_file) {
                            char time_str[32];
                            get_utc_time_str(time_str, sizeof(time_str));
                            fprintf(log_file, "%s Unknown mode from %d: %s\n", time_str, sd, mode_str);
                            fflush(log_file);
                        }
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
                    dprintf(sd, "Subscribed to %s%s\nEND_OF_MESSAGE\n", mode_str, pubkey_hash_b64 ? " for the specified key" : "");
                }
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
