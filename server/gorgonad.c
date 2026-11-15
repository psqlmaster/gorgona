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
#include <fcntl.h>
#include "config.h"
#include "common.h"
#include "gorgona_utils.h"
#include "alert_db.h"
#include "admin_mesh.h"
#include "metrics.h"

/* Global flag for configuration reload */
volatile sig_atomic_t reload_cfg_requested = 0;

/* Global server state */
int client_sockets[MAX_CLIENTS];
Subscriber subscribers[MAX_CLIENTS];
int max_clients;
int verbose = 0;
int port;
int sync_interval = DEFAULT_SYNC_INTERVAL;
int vacuum_threshold = DEFAULT_VACUUM_THRESHOLD;
int vacuum_check_interval = DEFAULT_VACUUM_CHECK_INTERVAL;

/**
 * Shutdown handler for graceful exit.
 * Saves mesh state, closes databases and all active sockets.
 */
void shutdown_handler(int sig) {
    log_event("INFO", -1, NULL, 0, "Received signal %d, shutting down gracefully", sig);
    /* Layer 2: Save discovered peers to cache */
    mesh_save_peers_cache();
    /* Layer 1: ПРИНУДИТЕЛЬНО сохраняем актуальное состояние всех баз из RAM на диск */
    if (use_disk_db && recipients && recipient_count > 0) {
        log_event("INFO", -1, NULL, 0, "Flushing %d recipient databases to disk...", recipient_count);
        for (int r = 0; r < recipient_count; r++) {
            if (recipients[r].count > 0) {
                alert_db_sync(&recipients[r]);
            }
        }
    }
    /* Закрываем файловые дескрипторы базы данных */
    alert_db_close_all();
    /* Close all client and peer connections */
    for (int i = 0; i < max_clients; i++) {
        if (client_sockets[i] > 0) {
            close(client_sockets[i]);
        }
    }
    /* Close log file if it's not stdout */
    if (log_file && log_file != stdout && log_file != stderr) {
        fclose(log_file);
        log_file = NULL;
    }
    exit(0);
}

/**
 * SIGHUP handler for Hot Reload.
 * Just sets a flag to be processed in the main loop.
 */
void reload_handler(int sig) {
    reload_cfg_requested = 1;
}

/* ══════════════════════════════════════════════════════════════════
 *  help / ui  —  terminal-aware, styled
 * ══════════════════════════════════════════════════════════════════ */

static const char *H_RST = "";
static const char *H_BLD = "";
static const char *H_DIM = "";
static const char *H_ACC = "";
static const char *H_GRN = "";
static const char *H_YEL = "";
static const char *H_CYN = "";
static const char *H_MAG = "";
static const char *H_WHT = "";

static void help_palette(void)
{
    static int ready;
    const char *nc;
    const char *term;

    if (ready)
        return;
    ready = 1;

    /* не терминал → без цвета (пайпы, редиректы, логи) */
    if (!isatty(STDOUT_FILENO))
        return;

    nc = getenv("NO_COLOR");
    if (nc && *nc)
        return;

    term = getenv("TERM");
    if (!term || !*term || strcmp(term, "dumb") == 0)
        return;

    H_RST = "\033[0m";     /* CLR_RESET      */
    H_BLD = "\033[1m";     /* CLR_BOLD       */
    H_DIM = "\033[2m";     /* dim / subtle   */
    H_ACC = "\033[0;36m";  /* CLR_CYAN       */
    H_GRN = "\033[0;32m";  /* CLR_GREEN      */
    H_YEL = "\033[0;33m";  /* CLR_YELLOW     */
    H_CYN = "\033[0;36m";  /* CLR_CYAN       */
    H_MAG = "\033[0;35m";  /* CLR_MAGENTA    */
    H_WHT = "\033[1;37m";  /* CLR_WHITE_BOLD */
}

/* ── primitives ─────────────────────────────────────────────────── */

static int utf8_cols(const char *s)
{
    int n = 0;
    const unsigned char *p = (const unsigned char *)s;
    while (*p) {
        if ((*p & 0xC0) != 0x80)
            ++n;
        ++p;
    }
    return n;
}

static void help_title(const char *text, int width)
{
    int i;
    printf("\n  %s%s%s%s\n", H_ACC, H_BLD, text, H_RST);
    printf("  %s", H_DIM);
    for (i = 0; i < width; ++i)
        fputs("─", stdout);
    printf("%s\n", H_RST);
}

static void banner_row(const char *left, const char *right, int width,
                       const char *lc, const char *rc)
{
    int pad = width - utf8_cols(left) - utf8_cols(right);
    if (pad < 1)
        pad = 1;
    printf("  %s│%s %s%s%s%*s%s%s%s %s│%s\n",
           H_BLD, H_RST, lc, left, H_RST, pad, "", rc, right, H_RST, H_BLD, H_RST);
}

static void banner_text(const char *text, int width, const char *color)
{
    int pad = width - utf8_cols(text);
    if (pad < 0)
        pad = 0;
    printf("  %s│%s %s%s%s%*s %s│%s\n",
           H_BLD, H_RST, color, text, H_RST, pad, "", H_BLD, H_RST);
}

static void help_flag(const char *flag, const char *desc)
{
    printf("  %s%-20s%s %s\n", H_CYN, flag, H_RST, desc);
}

static void help_note(const char *text)
{
    printf("  %*s%s%s\n", 21, "", H_DIM, text);
}

static void help_bullet(const char *label, const char *desc)
{
    printf("  %s·%s %s%s:%s %s\n", H_MAG, H_RST, H_WHT, label, H_RST, desc);
}

static void help_kv(const char *key, const char *val, const char *comment)
{
    printf("      %s%-24s%s = %s%-16s%s", H_CYN, key, H_RST, H_YEL, val, H_RST);
    if (comment)
        printf("  %s%s%s", H_DIM, comment, H_RST);
    printf("\n");
}

static void help_diag(const char *cmd, const char *arg, const char *desc)
{
    printf("  %s▸%s %s%-8s%s %s%-11s%s %s\n",
           H_GRN, H_RST, H_YEL, cmd, H_RST, H_CYN, arg ? arg : "", H_RST, desc);
}

static void help_ex(const char *prog, const char *args)
{
    printf("    %s$%s %s%s%s %s\n", H_GRN, H_RST, H_WHT, prog, H_RST, args);
}

/* ── main help ──────────────────────────────────────────────────── */

void print_server_help(const char *program_name)
{
    const int W = 57;
    char ver[64];
    int i;

    help_palette();
    snprintf(ver, sizeof(ver), "v%s", VERSION);

    /* ── banner ─────────────────────────────────────────────────── */
    printf("\n  %s╭", H_BLD);
    for (i = 0; i < W + 2; ++i)
        fputs("─", stdout);
    printf("╮%s\n", H_RST);

    banner_row("GORGONA  MESH SERVER", ver, W, H_GRN, H_YEL);
    banner_text("decentralized P2P node for encrypted alert delivery", W, H_DIM);
    banner_text("L1: blind E2E replication · L2: AES-256-GCM PEX & metrics", W, H_DIM);

    printf("  %s╰", H_BLD);
    for (i = 0; i < W + 2; ++i)
        fputs("─", stdout);
    printf("╯%s\n", H_RST);

    /* ── usage ──────────────────────────────────────────────────── */
    help_title("USAGE", W);
    printf("    %s%s%s %s[-h|--help] [-v|--verbose] [-V|--version] [-c|--conf <path>]%s\n",
           H_WHT, program_name, H_RST, H_CYN, H_RST);

    /* ── flags ──────────────────────────────────────────────────── */
    help_title("FLAGS", W);
    help_flag("-h, --help",        "displays this help message");
    help_flag("-v, --verbose",     "enables detailed trace (L2 metrics, gossip, decryption events)");
    help_flag("-V, --version",     "displays version information");
    help_flag("-c, --conf <path>", "alternate config file");
    help_note("· default: /etc/gorgona/gorgonad.conf");

    /* ── architecture & resilience ──────────────────────────────── */
    help_title("DUAL-LAYER ARCHITECTURE & MESH RESILIENCE", W);
    help_bullet("Layer 1 (Command Plane)",    "blind E2E encrypted data replication");
    help_bullet("Layer 2 (Management Plane)", "AES-256-GCM encrypted mesh for PEX and metrics");
    help_bullet("Anti-Entropy",               "continuous MaxID synchronization ensures data consistency");
    help_bullet("Intelligent Routing",        "best peers prioritized via 'Gorgona Score' (RTT/Throughput)");
    help_bullet("Self-Healing",               "dynamic node discovery (PEX) & bootstrap from <data_dir>/peers.cache");

    /* ── configuration ──────────────────────────────────────────── */
    help_title("CONFIGURATION", W);
    printf("  %s/etc/gorgona/gorgonad.conf%s  %s(reloadable keys apply via SIGHUP / systemctl reload gorgonad)%s\n",
           H_CYN, H_RST, H_DIM, H_RST);

    printf("\n    %s[server]%s\n", H_MAG, H_RST);
    help_kv("port",                     "<port>",           "# listen port (default: 5555, requires restart)");
    help_kv("max_alerts",               "<number>",         "# max alerts stored per key (reloadable)");
    help_kv("max_alert_ttl",            "<sec>",            "# lifetime in sec, e.g. 7776000=90d (default: 30d, reloadable)");
    help_kv("max_clients",              "<number>",         "# concurrent TCP connections; decrease closes excess (reloadable)");
    help_kv("max_log_size",             "<MB>",             "# log rotation size in MB (reloadable)");
    help_kv("log_level",                "<level>",          "# \"info\", \"error\" or \"debug\" (reloadable)");
    help_kv("max_message_size",         "<MB>",             "# max inbound message size in MB (reloadable)");
    help_kv("use_disk_db",              "<bool>",           "# persistent storage in <data_dir>/alerts/ (requires restart)");
    help_kv("vacuum_threshold_percent", "<%>",              "# auto-cleanup threshold for deleted records, 1-100 (reloadable)");
    help_kv("vacuum_check_interval",    "<sec>",            "# DB vacuum status check interval, e.g. 300s (reloadable)");
    help_kv("data_dir",                 "/var/lib/gorgona", "# base directory for DB, cache and logs (requires restart)");
    help_kv("conf_dir",                 "/etc/gorgona",     "# config files and TLS certs directory (requires restart)");
    help_kv("log_file",                 "<path>",           "# optional log path (default: <data_dir>/gorgonad.log)");

    printf("\n    %s[replication]%s\n", H_MAG, H_RST);
    help_kv("sync_psk",      "<key>",          "# P2P cluster key for Layer 2 AES-256-GCM (reloadable)");
    help_kv("sync_interval", "<sec>",          "# mesh maintenance & gossip frequency in sec (reloadable)");
    help_kv("peer",          "<IP|FQDN:PORT>", "# seed node address, IP or DNS (repeatable, reloadable)");

    /* ── diagnostic commands ────────────────────────────────────── */
    help_title("DIAGNOSTIC COMMANDS  (via nc / telnet)", W);
    help_diag("status", "<sync_psk>", "detailed L1/L2 metrics and cluster topology map");
    help_diag("sync",   "<sync_psk>", "trigger immediate Mesh Anti-Entropy chain sync");
    help_diag("info",   NULL,         "brief uptime and identification");
    help_diag("help",   NULL,         "lists available plaintext commands");

    /* ── example ────────────────────────────────────────────────── */
    help_title("EXAMPLE", W);
    help_ex(program_name, "--verbose");
    printf("    %s$%s cmd=\"status BQQCyN8zo4La2lRSIQ2jLp5imEa0JzdXp2PKogP3\"; echo \"$cmd\" | %snc%s 64.188.70.158 7777\n", H_GRN, H_RST, H_WHT, H_RST);

    printf("\n");
}

int main(int argc, char *argv[]) {
    int opt;
    char config_path[512] = "/etc/gorgona/gorgonad.conf";
    static struct option long_options[] = {
        {"help", no_argument, 0, 'h'},
        {"verbose", no_argument, 0, 'v'},
        {"version", no_argument, 0, 'V'},
        {"conf", required_argument, 0, 'c'},
        {0, 0, 0, 0}
    };

    /* 1. Parse command line arguments */
    while ((opt = getopt_long(argc, argv, "vhVc:", long_options, NULL)) != -1) {
        switch (opt) {
            case 'c':
                if (!optarg) {
                    fprintf(stderr, "Error: -c/--conf requires a path argument\n");
                    return 1;
                }
                strncpy(config_path, optarg, sizeof(config_path) - 1);
                config_path[sizeof(config_path) - 1] = '\0';
                strncpy(config_file_path, config_path, sizeof(config_file_path) - 1);
                config_file_path[sizeof(config_file_path) - 1] = '\0';
                break;
            case 'v': verbose = 1; break;
            case 'h': print_server_help(argv[0]); return 0;
            case 'V': printf("Gorgona Server Version %s\n", VERSION); return 0;
            case '?': fprintf(stderr, "Unknown option. Use -h for help.\n"); return 1;
            default: return 1;
        }
    }

    struct sigaction sa_hup, sa_term;

    /* SIGHUP — hot reload (is NOT reset after being called) */
    sa_hup.sa_handler = reload_handler;
    sa_hup.sa_flags = SA_RESTART;       /* Do not interrupt read()/select() */
    sigemptyset(&sa_hup.sa_mask);
    sigaction(SIGHUP, &sa_hup, NULL);

    /* SIGINT / SIGTERM — graceful shutdown */
    sa_term.sa_handler = shutdown_handler;
    sa_term.sa_flags = SA_RESTART;
    sigemptyset(&sa_term.sa_mask);
    sigaction(SIGINT, &sa_term, NULL);
    sigaction(SIGTERM, &sa_term, NULL);

    signal(SIGPIPE, SIG_IGN);
    signal(SIGCHLD, SIG_IGN);



    /* Load configuration */
    int max_alerts_config, max_clients_config, vacuum_threshold_config, sync_interval_tmp, max_ttl_config, vacuum_check_interval_config;
    size_t max_message_size_config, max_log_size_config;
    int use_disk_db_config;

    read_config(config_path, &port, &max_alerts_config, &max_clients_config, &max_log_size_config,
                log_level, &max_message_size_config, &use_disk_db_config, &vacuum_threshold_config, &sync_interval_tmp, &max_ttl_config, &vacuum_check_interval_config);

    sync_interval = sync_interval_tmp;
    max_alerts = max_alerts_config;
    max_alert_ttl = max_ttl_config;
    vacuum_threshold = vacuum_threshold_config;
    vacuum_check_interval = vacuum_check_interval_config;
    max_clients = (max_clients_config > MAX_CLIENTS) ? MAX_CLIENTS : max_clients_config;
    max_log_size = max_log_size_config;
    max_message_size = max_message_size_config;
    use_disk_db = use_disk_db_config;

    if (verbose) {
        printf("DEBUG: sync_interval: %d seconds, max_clients: %d\n", sync_interval, max_clients);
    }

    /* Initialize Logging System */
    char target_log[512];
    if (gorgona_log_file[0] != '\0') {
        strncpy(target_log, gorgona_log_file, sizeof(target_log) - 1);
    } else {
        snprintf(target_log, sizeof(target_log), "%s/gorgonad.log", gorgona_data_dir);
    }

    log_file = fopen(target_log, "a");
    if (!log_file) {
        fprintf(stderr, "Warning: cannot open log file %s: %s\n", target_log, strerror(errno));
        log_file = NULL;
    } else {
        setvbuf(log_file, NULL, _IOLBF, 0);
    }

    /* Sub-systems Initialization */
    mesh_init(sync_psk);
    metrics_init_ssl();
    int cached_peers = mesh_load_peers_cache();
    if (cached_peers > 0) {
        log_event("INFO", -1, NULL, 0, "Mesh network initialized (%d peer(s) loaded from cache)", cached_peers);
    } else {
        log_event("INFO", -1, NULL, 0, "Mesh network initialized (no cached peers found)");
    }
    log_event("INFO", -1, NULL, 0, "Gorgona Server %s is starting...", VERSION);

    /* Initialize internal data structures */
    recipients = NULL;
    recipient_count = 0;
    recipient_capacity = 0;

    for (int i = 0; i < MAX_CLIENTS; i++) {
        client_sockets[i] = 0;
        subscribers[i].sock = 0;
        subscribers[i].mode = 0;
        subscribers[i].pubkey_hash[0] = '\0';
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

    /* 6. Network Setup */
    int server_fd;
    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0) {
        log_event("ERROR", -1, NULL, 0, "Socket creation failed: %s", strerror(errno));
        exit(EXIT_FAILURE);
    }

    int opt_val = 1;
    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, (char *)&opt_val, sizeof(opt_val)) < 0) {
        log_event("ERROR", -1, NULL, 0, "Setsockopt SO_REUSEADDR failed: %s", strerror(errno));
        exit(EXIT_FAILURE);
    }

    struct sockaddr_in address;
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(port);

    if (bind(server_fd, (struct sockaddr *)&address, sizeof(address)) < 0) {
        log_event("ERROR", -1, NULL, 0, "Bind failed on port %d: %s", port, strerror(errno));
        exit(EXIT_FAILURE);
    }

    if (listen(server_fd, 128) < 0) {
        log_event("ERROR", -1, NULL, 0, "Listen failed: %s", strerror(errno));
        exit(EXIT_FAILURE);
    }

    log_event("INFO", -1, NULL, 0, "Server is up and listening on port %d", port);
    printf("[SERVER] Server is up and listening on port %d\n", port);

    /* Enter the main server loop */
    run_server(server_fd);

    /* Cleanup */
    if (use_disk_db) alert_db_close_all();
    if (log_file && log_file != stdout) fclose(log_file);
    close(server_fd);
    log_event("INFO", -1, NULL, 0, "Server shutting down cleanly");
    return 0;
}
