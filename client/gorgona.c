/*
 * BSD 3-Clause License
 * Copyright (c) 2025, Alexander Shcheglov
 * All rights reserved.
 */

#include "encrypt.h"
#include "admin_mesh.h"
#include "config.h"
#include "file_sync.h"
#include <stdio.h>
#include <string.h>
#include <getopt.h>
#include <unistd.h>
#include <stdlib.h>
#include "alert_send.h"

extern int verbose;
extern int sync_interval;
extern int execute;
extern int send_revocation(int argc, char *argv[], int verbose);
extern int daemon_exec_flag;

extern int send_alert(int argc, char *argv[], int verbose);
extern int listen_alerts(int argc, char *argv[], int verbose, int execute, int daemon_exec_flag);

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

static void help_cmd(const char *syntax, const char *desc)
{
    printf("\n  %s▸%s %s%s%s\n", H_GRN, H_RST, H_CYN, syntax, H_RST);
    printf("      %s\n", desc);
}

static void help_sub(const char *text)
{
    printf("      %s%s%s\n", H_DIM, text, H_RST);
}

static void help_mode(const char *name, const char *desc)
{
    printf("        %s%-9s%s %s\n", H_YEL, name, H_RST, desc);
}

static void help_kv(const char *key, const char *val, const char *comment)
{
    printf("      %s%-13s%s = %s%s%s", H_DIM, key, H_RST, H_CYN, val, H_RST);
    if (comment)
        printf("   %s%s%s", H_DIM, comment, H_RST);
    printf("\n");
}

static void help_ex(const char *prog, const char *args)
{
    printf("    %s$%s %s%s%s %s\n", H_GRN, H_RST, H_WHT, prog, H_RST, args);
}

/* ── main help ──────────────────────────────────────────────────── */

void print_help(const char *program_name)
{
    const int W = 48;
    char ver[64];
    int i;

    help_palette();
    snprintf(ver, sizeof(ver), "v%s", VERSION);

    /* ── banner ─────────────────────────────────────────────────── */
    printf("\n  %s╭", H_BLD);
    for (i = 0; i < W + 2; ++i)
        fputs("─", stdout);
    printf("╮%s\n", H_RST);

    banner_row("GORGONA CLIENT", ver, W, H_GRN, H_YEL);
    banner_text("Decentralized P2P Cron & Remote Execution Engine", W, H_DIM);
    banner_text("End-to-End Encrypted, Time-Locked, and Resilient", W, H_DIM);

    printf("  %s╰", H_BLD);
    for (i = 0; i < W + 2; ++i)
        fputs("─", stdout);
    printf("╯%s\n", H_RST);

    /* ── usage ──────────────────────────────────────────────────── */
    help_title("USAGE", W);
    printf("    %s%s%s %s[-v] [-e] [-d] [-V] [-c <path>]%s %s<command>%s %s[arguments]%s\n",
           H_WHT, program_name, H_RST, H_CYN, H_RST, H_YEL, H_RST, H_DIM, H_RST);

    /* ── flags ──────────────────────────────────────────────────── */
    help_title("FLAGS", W);
    help_flag("-v, --verbose",     "verbose output for debugging");
    help_flag("-e, --exec",        "execute decrypted messages as commands (listen)");
    help_note("· empty [exec_commands] → run every decrypted message");
    help_note("· populated [exec_commands] → run only messages matching a key");
    help_flag("-d, --daemon-exec", "run commands detached (fork + setsid)");
    help_note("· requires -e  ·  output → $gorgona_LOG_FILE or /dev/null");
    help_flag("-c, --conf <path>", "alternate config file");
    help_note("· default: /etc/gorgona/gorgona.conf");
    help_flag("-V, --version",     "print version and exit");
    help_flag("-h, --help",        "print this help and exit");
    help_note("· flags combine freely:  -ve  -ved  -veV");

    /* ── key argument ───────────────────────────────────────────── */
    help_title("KEY ARGUMENT", W);
    help_sub("every command accepts the key in any of these forms");
    help_sub("RWTPQzuhzBw=   RWTPQzuhzBw=.pub   RWTPQzuhzBw=.key");
    help_sub("/etc/gorgona/RWTPQzuhzBw=.pub   a full path to the key file");
    help_sub("send and send-file read the public key, listen and revoke the private one");
    help_sub("an argument marked with the wrong extension resolves to the matching key");

    /* ── commands ───────────────────────────────────────────────── */
    help_title("COMMANDS", W);

    help_cmd("genkeys", "generate a fresh RSA key pair under /etc/gorgona/");

    help_cmd("send <unlock> <expire> <message> <pubkey>",
             "send an encrypted, time-locked message");
    help_sub("use '-' as <message> to read the payload from stdin");

    help_cmd("listen <mode> [<count>] [pubkey]",
             "subscribe to the message stream");
    help_mode("live",   "active messages (unlock_at ≤ now)");
    help_mode("all",    "every non-expired message, locked ones included");
    help_mode("lock",   "locked messages only (unlock_at > now)");
    help_mode("single", "active messages for one key — pubkey required");
    help_mode("last",   "the N most recent messages (N defaults to 1)");
    help_mode("new",    "messages that arrive after connecting");
    help_sub("* pubkey filters the stream; mandatory for single and last");

    help_cmd("send-file [<unlock> <expire>] <path> <pubkey>",
             "send a file (LZ4-compressed, then encrypted)");
    help_sub("times are optional — defaults to now … now + 1h");
    help_sub("--name <relative/path> overrides the name on the receiving side");

    help_cmd("revoke <alert_id> <pubkey>",
             "cancel a pending time-locked message — the dead-hand switch");

    /* ── configuration ──────────────────────────────────────────── */
    help_title("CONFIGURATION", W);
    printf("  %s/etc/gorgona/gorgona.conf%s\n", H_CYN, H_RST);

    printf("\n    %s[server]%s\n", H_MAG, H_RST);
    help_kv("ip",        "64.188.70.158",      "(example)");
    help_kv("port",      "7777",               "(example)");
    help_kv("sync_psk",  "<shared secret>",    "# optional, enables layer-2 mesh");
    help_kv("data_dir",  "/var/lib/gorgona",   NULL);
    help_kv("conf_dir",  "/etc/gorgona",       NULL);

    printf("\n    %s[exec_commands]%s   %s[exec_commands:<pubkey>]%s\n",
           H_MAG, H_RST, H_MAG, H_RST);
    help_kv("<key>", "<script_path>   time_limit = <sec>", NULL);
    help_sub("example:  app start = /usr/local/bin/app_start.sh  time_limit = 60");

    printf("\n    %s[sync]%s\n", H_MAG, H_RST);
    help_kv("max_file_size", "10485760", "# global limit, bytes (default 10 MiB)");

    printf("\n    %s[sync:<pubkey>]%s\n", H_MAG, H_RST);
    help_kv("dir",           "/etc/nginx/conf.d", "# root directory for this key");
    help_kv("direction",     "rw",                "# ro | wo | rw");
    help_kv("on_change",     "nginx -s reload",   "# run after a successful sync");
    help_kv("max_file_size", "5242880",           "# optional per-key limit");

    /* ── examples ───────────────────────────────────────────────── */
    help_title("EXAMPLES", W);

    help_ex(program_name, "listen single RWTPQzuhzBw=");
    printf("    %s$%s %s%s%s %-34s%s# Gets the last 1 message%s\n",
           H_GRN, H_RST, H_WHT, program_name, H_RST,
           "listen last RWTPQzuhzBw=", H_DIM, H_RST);
    printf("    %s$%s %s%s%s %-34s%s# Gets the last 3 messages%s\n",
           H_GRN, H_RST, H_WHT, program_name, H_RST,
           "listen last 3 RWTPQzuhzBw=", H_DIM, H_RST);
    printf("    %s$%s %s%s%s %-34s%s# Listens for new messages only%s\n",
           H_GRN, H_RST, H_WHT, program_name, H_RST,
           "listen new RWTPQzuhzBw=", H_DIM, H_RST);
    printf("    %s$%s %s%s%s %-34s%s# Listens and executes messages%s\n",
           H_GRN, H_RST, H_WHT, program_name, H_RST,
           "-e listen new RWTPQzuhzBw=", H_DIM, H_RST);
    printf("    %s$%s %s%s%s %-34s%s# Listens, executes, and shows verbose output%s\n",
           H_GRN, H_RST, H_WHT, program_name, H_RST,
           "-ve listen new RWTPQzuhzBw=", H_DIM, H_RST);

    help_ex(program_name, "send \"$(date -u '+%Y-%m-%d %H:%M:%S')\" \"$(date -u -d '+30 days' '+%Y-%m-%d %H:%M:%S')\" \"hello world\" \"RWTPQzuhzBw=.pub\"");
    help_ex(program_name, "send \"$(date -u '+%Y-%m-%d %H:%M:%S')\" \"$(date -u -d '+30 days' '+%Y-%m-%d %H:%M:%S')\" \"app start\" \"RWTPQzuhzBw=.pub\"");
    printf("    %s$%s df -h | %s%s%s send \"$(date -u '+%%Y-%%m-%%d %%H:%%M:%%S')\" \"$(date -u -d '+30 days' '+%%Y-%%m-%%d %%H:%%M:%%S')\" - \"RWTPQzuhzBw=.pub\"\n",
           H_GRN, H_RST, H_WHT, program_name, H_RST);

    help_ex(program_name, "send-file /etc/nginx/conf.d/site.conf RWTPQzuhzBw=.pub");
    help_ex(program_name, "send-file --name conf.d/new_name_site.conf /etc/nginx/conf.d/site.conf RWTPQzuhzBw=.pub");
    help_ex(program_name, "revoke 170119927746560 RWTPQzuhzBw=");

    printf("    %s$%s %s%s%s %-34s%s# Same key, other accepted forms%s\n",
           H_GRN, H_RST, H_WHT, program_name, H_RST,
           "listen last 1 RWTPQzuhzBw=.key", H_DIM, H_RST);
    help_ex(program_name, "listen new /etc/gorgona/RWTPQzuhzBw=.key");

    printf("\n");
}

int main(int argc, char *argv[]) {
    int opt;
    char config_path[512] = DEFAULT_CONFIG_FILE;

    /* Define long options for getopt_long */
    static struct option long_options[] = {
        {"help", no_argument, 0, 'h'},
        {"verbose", no_argument, 0, 'v'},
        {"exec", no_argument, 0, 'e'},
        {"version", no_argument, 0, 'V'},
        {"daemon-exec", no_argument, 0, 'd'},
        {"conf",        required_argument, 0, 'c'},
        {0, 0, 0, 0}
    };

    while ((opt = getopt_long(argc, argv, "+vheVdc:", long_options, NULL)) != -1) {
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
            case 'v':
                verbose = 1;
                break;
            case 'h':
                print_help(argv[0]);
                return 0;
            case 'e':
                execute = 1;
                break;
            case 'V':
                printf("Gorgona Client Version %s\n", VERSION);
                return 0;
            case 'd':
                daemon_exec_flag = 1;
                break;
            case '?':
                fprintf(stderr, "Unknown flag: %s\n", argv[optind - 1]);
                print_help(argv[0]);
                return 1;
            default:
                fprintf(stderr, "Error processing flags\n");
                print_help(argv[0]);
                return 1;
        }
    }

    if (daemon_exec_flag && !execute) {
        fprintf(stderr, "Error: -d (--daemon-exec) requires -e (--exec)\n");
        return 1;
    }

    if (optind >= argc) {
        fprintf(stderr, "Error: No command specified\n");
        print_help(argv[0]);
        return 1;
    }

    Config cfg;
    read_config(config_path, &cfg, verbose);

    /* Process commands */
    const char *cmd = argv[optind];

    if (strcmp(cmd, "send-file") == 0) {
        return cmd_send_file(argc - optind, argv + optind);
    } else if (strcmp(cmd, "genkeys") == 0) {
        return generate_rsa_keys(verbose);
    } else if (strcmp(cmd, "send") == 0) {
        return send_alert(argc - optind, argv + optind, verbose);
    } else if (strcmp(cmd, "listen") == 0) {
        return listen_alerts(argc - optind, argv + optind, verbose, execute, daemon_exec_flag);
    } else if (strcmp(cmd, "revoke") == 0) {
        return send_revocation(argc - optind, argv + optind, verbose);
    } else {
        fprintf(stderr, "Unknown command: %s\n", cmd);
        print_help(argv[0]);
        return 1;
    }

    mesh_force_save = true;
    return 0;
}
