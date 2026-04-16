/* 
* BSD 3-Clause License
* Copyright (c) 2025, Alexander Shcheglov
* All rights reserved. 
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/select.h>
#include <errno.h>
#include <signal.h>
#include <time.h>
#include <stdint.h>
#include <getopt.h>
#include "config.h"
#include "gorgona_utils.h"
#include "alert_db.h"
#include "admin_mesh.h"

int verbose = 0;
int port;  
int sync_interval = DEFAULT_SYNC_INTERVAL; 

/* Shutdown handler for graceful exit */
void shutdown_handler(int sig) {
    log_event("INFO", -1, NULL, 0, "Received signal %d, shutting down gracefully", sig);
    mesh_save_peers_cache();
    alert_db_close_all();
    for (int i = 0; i < max_clients; i++) {
        if (client_sockets[i] > 0) close(client_sockets[i]);
    }

    if (log_file) {
        fclose(log_file);
        log_file = NULL;
    }
    exit(0);
}

void print_server_help(const char *program_name) {
    printf("Gorgona Mesh Server (Version %s)\n", VERSION);
    printf("Usage: %s [-h|--help] [-v|--verbose] [-V|--version]\n", program_name);
    
    printf("\nDescription:\n");
    printf(" The gorgona server is a decentralized P2P node for encrypted alert delivery.\n");
    printf(" It implements a Dual-Layer architecture:\n");
    printf("  - Layer 1 (Command Plane): Blind E2E encrypted data replication.\n");
    printf("  - Layer 2 (Management Plane): AES-256-GCM encrypted mesh for PEX and metrics.\n");

    printf("\nFlags:\n");
    printf(" -h, --help     Displays this help message\n");
    printf(" -v, --verbose  Enables detailed trace (L2 metrics, gossip, decryption events)\n");
    printf(" -V, --version  Displays version information\n");

    printf("\nConfiguration (/etc/gorgona/gorgonad.conf):\n");
    printf(" [server]\n");
    printf("  port = <port>           Listen port (default: 5555)\n");
    printf("  max_alerts = <number>   Storage limit per recipient key\n");
    printf("  max_clients = <number>  Total TCP connection limit (Clients + Peers)\n");
    printf("  use_disk_db = <bool>    Persistence in " ALERT_DB_DIR "\n");
    printf("  log_level = <level>     \"info\" (standard) or \"debug\" (full P2P trace)\n");
    printf("  vacuum_threshold_percent = <%%>  Trigger database compression (1-100)\n");

    printf("\n [replication]\n");
    printf("  sync_psk = <key>        Cluster-wide secret for Layer 2 encryption (AES-256-GCM)\n");
    printf("  sync_interval = <sec>   Gossip & Heartbeat frequency (default: 10s)\n");
    printf("  peer = <IP:PORT>        Seed node for initial discovery (can be multiple entries)\n");

    printf("\nMesh Resilience:\n");
    printf(" - Anti-Entropy: Continuous MaxID synchronization ensures data consistency.\n");
    printf(" - Intelligent Routing: Best peers are prioritized via 'Gorgona Score' (RTT/Throughput).\n");
    printf(" - Self-Healing: Dynamic node discovery (PEX) and boot-strapping from /var/lib/gorgona/peers.cache.\n");

    printf("\nDiagnostic Commands (via nc/telnet):\n");
    printf(" status <sync_psk>        Detailed L1/L2 metrics and cluster topology map.\n");
    printf(" info                     Brief uptime and identification.\n");
    printf(" help                     Lists available plaintext commands.\n");

    printf("\nExample:\n");
    printf(" %s --verbose\n", program_name);
}
int vacuum_threshold = DEFAULT_VACUUM_THRESHOLD;

int main(int argc, char *argv[]) {
    int opt;
    static struct option long_options[] = {
        {"help", no_argument, 0, 'h'},
        {"verbose", no_argument, 0, 'v'},
        {"version", no_argument, 0, 'V'},
        {0, 0, 0, 0}
    };

    /* Parse command line arguments */
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
                fprintf(stderr, "Unknown option. Use -h for help.\n");
                return 1;
            default:
                return 1;
        }
    }

    /* Register signal handlers for graceful shutdown */
    signal(SIGINT, shutdown_handler);
    signal(SIGTERM, shutdown_handler);
    signal(SIGPIPE, SIG_IGN); 

    /* Load configuration from file or use defaults */
    int max_alerts_config, max_clients_config, vacuum_threshold_config, sync_interval_tmp; 
    size_t max_message_size_config, max_log_size_config;
    int use_disk_db_config;

    read_config(&port, &max_alerts_config, &max_clients_config, &max_log_size_config, 
                log_level, &max_message_size_config, &use_disk_db_config, &vacuum_threshold_config, &sync_interval_tmp); 
    sync_interval = sync_interval_tmp;
    mesh_init(sync_psk);
    mesh_load_peers_cache();
    log_event("INFO", -1, NULL, 0, "Layer 2: Management Plane Initialized with PSK fingerprint");

    max_alerts = max_alerts_config;
    vacuum_threshold = vacuum_threshold_config;
    max_clients = max_clients_config;
    max_log_size = max_log_size_config;
    max_message_size = max_message_size_config;
    use_disk_db = use_disk_db_config;

    /* Initialize internal data structures */
    recipients = NULL;
    recipient_count = 0;
    recipient_capacity = 0;

    for (int i = 0; i < max_clients; i++) {
        client_sockets[i] = 0;
        subscribers[i].sock = 0;
        subscribers[i].mode = 0;
        subscribers[i].pubkey_hash[0] = '\0';
    }

    /*
     * Initialize logging system.
     * After opening the file, all subsequent logs must use log_event().
     */
    if (log_file == NULL) {
        log_file = fopen("gorgonad.log", "a");
        if (!log_file) {
            perror("Failed to open gorgonad.log");
            exit(EXIT_FAILURE);
        } else {
            /* Log rotation is handled internally by log_event() */
            log_event("INFO", -1, NULL, 0, "Gorgona Server %s is starting...", VERSION ? VERSION : "1.0");
        }
    }

    /* Initialize database if disk storage is enabled */
    if (use_disk_db) {
        if (alert_db_init() != 0) { 
            log_event("ERROR", -1, NULL, 0, "Failed to initialize alert database directory");
            return 1;
        }
        if (alert_db_load_recipients() != 0) {
            log_event("ERROR", -1, NULL, 0, "Failed to load recipient data from database");
            return 1;
        }
    }

    /* Create master TCP socket */
    int server_fd;
    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0) {
        log_event("ERROR", -1, NULL, 0, "Socket creation failed: %s", strerror(errno));
        perror("socket failed");
        exit(EXIT_FAILURE);
    }

    /* Set socket options: allow immediate reuse of the port after restart */
    int opt_val = 1;
    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, (char *)&opt_val, sizeof(opt_val)) < 0) {
        log_event("ERROR", -1, NULL, 0, "Setsockopt SO_REUSEADDR failed: %s", strerror(errno));
        perror("setsockopt");
        exit(EXIT_FAILURE);
    }

    struct sockaddr_in address;
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(port);

    /* Bind the socket to the specified port */
    if (bind(server_fd, (struct sockaddr *)&address, sizeof(address)) < 0) {
        log_event("ERROR", -1, NULL, 0, "Bind failed on port %d: %s", port, strerror(errno));
        perror("bind failed");
        exit(EXIT_FAILURE);
    }

    /* Start listening for incoming connections */
    if (listen(server_fd, 5) < 0) {
        log_event("ERROR", -1, NULL, 0, "Listen failed: %s", strerror(errno));
        perror("listen");
        exit(EXIT_FAILURE);
    }

    /* Log successful startup */
    printf("Server running on port %d\n", port);
    log_event("INFO", -1, NULL, 0, "Server is up and listening on port %d", port);

    /* Enter the main server loop (defined in server_handler.c) */
    run_server(server_fd);

    /*
     * Cleanup (this part is normally reached only via shutdown_handler).
     * Included for completeness and to assist memory leak detectors.
     */
    for (int r = 0; r < recipient_count; r++) {
        for (int j = 0; j < recipients[r].count; j++) {
            free_alert(&recipients[r].alerts[j]);
        }
        free(recipients[r].alerts);
    }
    free(recipients);

    log_event("INFO", -1, NULL, 0, "Server shutting down cleanly");
    
    if (log_file) {
        fclose(log_file);
        log_file = NULL;
    }
    close(server_fd);

    return 0;
}
