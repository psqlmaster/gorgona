/* BSD 3-Clause License
Copyright (c) 2025, Alexander Shcheglov
All rights reserved. */

#include "gorgona_utils.h"
#include "alert_db.h"
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
    /* Close client sockets */
    for (int i = 0; i < max_clients; i++) {
        if (client_sockets[i] > 0) close(client_sockets[i]);
    }
    /* Free other resources if needed */
    exit(0);
}

void print_server_help(const char *program_name) {
    printf("Gorgona Server (Version %s)\n", VERSION);
    printf("Usage: %s [-h|--help] [-v|--verbose] [-V|--version]\n", program_name);
    printf("\nDescription:\n");
    printf(" The gorgona server handles encrypted alerts, allowing clients to send and subscribe to messages.\n");
    printf(" It listens for TCP connections and processes commands: SEND, LISTEN, SUBSCRIBE.\n");
    printf("\nFlags:\n");
    printf(" -h, --help     Displays this help message\n");
    printf(" -v, --verbose  Enables verbose output (e.g., received messages in console)\n");
    printf(" -V, --version  Displays version information\n");
    printf("\nConfiguration:\n");
    printf(" The file /etc/gorgona/gorgonad.conf contains server settings.\n");
    printf(" Format:\n");
    printf(" [server]\n");
    printf(" port = <port> (default: 5555, example: 7777)\n");
    printf(" MAX_ALERTS = <number> (default: 1024, example: 2000)\n");
    printf(" MAX_CLIENTS = <number> (default: 100, example: 100)\n");
    printf(" max_message_size = <bytes> (default: 5242880 for 5 MB, example: 10485760 for 10 MB)\n");
    printf(" use_disk_db = <boolean> (default: false, example: true to enable disk-based storage)\n");
    printf("\nLogging:\n");
    printf(" Logs are written to ./gorgonad.log. The log rotates when it exceeds %d bytes (10 MB).\n", MAX_LOG_SIZE);
    printf("\nLimits:\n");
    printf(" - Maximum simultaneous clients: MAX_CLIENTS (default: 100 or from config).\n");
    printf(" - Maximum alerts per recipient: MAX_ALERTS (default: 1024 or from config).\n");
    printf(" - Recipient capacity expands dynamically starting from %d.\n", INITIAL_RECIPIENT_CAPACITY);
    printf("\nExample:\n");
    printf(" %s\n", program_name);
    printf(" Starts the server using settings from ./gorgonad.conf or defaults.\n");
}

int main(int argc, char *argv[]) {
    int opt;
    static struct option long_options[] = {
        {"help", no_argument, 0, 'h'},
        {"verbose", no_argument, 0, 'v'},
        {"version", no_argument, 0, 'V'},
        {0, 0, 0, 0}
    };
    while ((opt = getopt_long(argc, argv, "vhV", long_options, NULL)) != -1) {
        switch (opt) {
            case 'v':
                verbose = 1;
                break;
            case 'h':
                print_server_help(argv[0]);
                return 0;
            case 'V':
                printf("Gorgona Server Version %s\n", VERSION);
                return 0;
            case '?':
                fprintf(stderr, "Unknown option: %s. Use -h for help.\n", argv[optind-1]);
                return 1;
            default:
                fprintf(stderr, "Error processing options\n");
                return 1;
        }
    }

    /* Register signal handlers */
    signal(SIGINT, shutdown_handler);
    signal(SIGTERM, shutdown_handler);

    /* Read configuration */
    int port, max_alerts_config, max_clients_config;
    size_t max_message_size_config;
    int use_disk_db_config; // Новая переменная
    read_config(&port, &max_alerts_config, &max_clients_config, &max_message_size_config, &use_disk_db_config);
    max_alerts = max_alerts_config;
    max_clients = max_clients_config;
    max_message_size = max_message_size_config;
    use_disk_db = use_disk_db_config; // Присваиваем глобальной переменной

    /* Initialize recipients - ДОЛЖНО БЫТЬ ПЕРВЫМ! */
    recipients = NULL;
    recipient_count = 0;
    recipient_capacity = 0;

    /* Initialize arrays for clients */
    for (int i = 0; i < max_clients; i++) {
        client_sockets[i] = 0;
        subscribers[i].sock = 0;
        subscribers[i].mode = 0;
        subscribers[i].pubkey_hash[0] = '\0';
    }

    /* Initialize logging */
    if (log_file == NULL) {
        log_file = fopen("gorgonad.log", "a");
        if (!log_file) {
            perror("Failed to open gorgonad.log");
            exit(EXIT_FAILURE);
        } else {
            rotate_log();
            char time_str[32];
            get_utc_time_str(time_str, sizeof(time_str));
            fprintf(log_file, "%s Server started\n", time_str);
            fflush(log_file);
        }
    }

    if (use_disk_db && alert_db_init() != 0) { 
        fprintf(stderr, "Failed to initialize alert database\n");
        fclose(log_file);
        return 1;
    }

    if (use_disk_db && alert_db_load_recipients() != 0) {
        fprintf(stderr, "Failed to load recipients from database\n");
        fclose(log_file);
        return 1;
    }

    /* Create socket */
    int server_fd;
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
    int opt_val = 1;
    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, (char *)&opt_val, sizeof(opt_val)) < 0) {
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

    struct sockaddr_in address;
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

    /* Run the server loop */
    run_server(server_fd);

    /* Free resources (unreachable in infinite loop, but for completeness) */
    for (int r = 0; r < recipient_count; r++) {
        for (int j = 0; j < recipients[r].count; j++) {
            free_alert(&recipients[r].alerts[j]);
        }
        free(recipients[r].alerts);
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
