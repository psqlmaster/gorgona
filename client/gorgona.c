/* 
* BSD 3-Clause License
* Copyright (c) 2025, Alexander Shcheglov
* All rights reserved. 
*/

#include "encrypt.h"
#include "admin_mesh.h"
#include <stdio.h>
#include <string.h>
#include <getopt.h>
#include "alert_send.h"

extern int verbose;
extern int sync_interval;
extern int execute;
extern int send_revocation(int argc, char *argv[], int verbose);
extern int daemon_exec_flag;

extern int send_alert(int argc, char *argv[], int verbose);
extern int listen_alerts(int argc, char *argv[], int verbose, int execute, int daemon_exec_flag);

void print_help(const char *program_name) {
    // ANSI Цвета
    #define CLR_RESET      "\033[0m"
    #define CLR_BOLD       "\033[1m"
    #define CLR_GREEN      "\033[0;32m"
    #define CLR_YELLOW     "\033[0;33m"
    #define CLR_CYAN       "\033[0;36m"
    #define CLR_MAGENTA    "\033[0;35m"
    #define CLR_WHITE_BOLD "\033[1;37m"

    printf(CLR_BOLD CLR_GREEN "Gorgona Client" CLR_RESET " (Version " CLR_YELLOW "%s" CLR_RESET ")\n", VERSION);
    printf(CLR_BOLD "Usage:" CLR_RESET "\n");
    printf("  %s " CLR_CYAN "[-v] [-e] [-d] [-V|--version] [-h|--help]" CLR_RESET " " CLR_YELLOW "<command>" CLR_RESET " [arguments]\n", program_name);

    printf("\n" CLR_BOLD "Flags:" CLR_RESET "\n");
    printf("  " CLR_CYAN "-v, --verbose" CLR_RESET "      Enables verbose output for debugging\n");
    printf("  " CLR_CYAN "-e, --exec" CLR_RESET "         For 'listen' command: execute messages as system commands (requires pubkey_hash_b64).\n");
    printf("                     If [exec_commands] in /etc/gorgona/gorgona.conf is empty, all decrypted messages are executed.\n");
    printf("                     If [exec_commands] contains entries (e.g., 'greengage start = /path/to/script.sh'), only messages\n");
    printf("                     matching a key are executed by running the corresponding script.\n");
    printf("  " CLR_CYAN "-d, --daemon-exec" CLR_RESET "  Used with -e: executes commands in background as daemons (via fork + setsid).\n");
    printf("                     Output from executed commands is written to the file specified by the environment variable\n");
    printf("                     gorgona_LOG_FILE (e.g., gorgona_LOG_FILE=/var/log/gorgona.log ./gorgona -ed listen new ...).\n");
    printf("                     If gorgona_LOG_FILE is not set, output is discarded (/dev/null).\n");
    printf(" " CLR_CYAN "-V, --version" CLR_RESET " Displays version information\n");
    printf(" " CLR_CYAN "-h, --help" CLR_RESET " Displays this help message\n");
    printf("  " CLR_MAGENTA "Note:" CLR_RESET "              Flags -v, -e, and -V can be combined (e.g., -veV) for verbose output during command execution.\n");

    printf("\n" CLR_BOLD "Commands:" CLR_RESET "\n");
    printf("  " CLR_YELLOW "genkeys" CLR_RESET "\n");
    printf("    Generates an RSA key pair in /etc/gorgona/ (Example: " CLR_WHITE_BOLD "sudo %s genkeys" CLR_RESET ")\n\n", program_name);

    printf("  " CLR_YELLOW "send" CLR_RESET " " CLR_CYAN "<unlock_time> <expire_time> <message> <public_key_file>" CLR_RESET "\n");
    printf("    Sends an encrypted message. Use " CLR_YELLOW "'-'" CLR_RESET " for " CLR_CYAN "<message>" CLR_RESET " to read from stdin.\n\n");

    printf("  " CLR_YELLOW "listen" CLR_RESET " " CLR_CYAN "<mode> [<count>] [pubkey_hash_b64]" CLR_RESET "\n");
    printf("    Listens for messages. " CLR_BOLD "Modes:" CLR_RESET "\n");
    printf("    " CLR_CYAN "live" CLR_RESET "   - only active messages (unlock_at <= now)\n");
    printf("    " CLR_CYAN "all" CLR_RESET "    - all non-expired messages, including locked\n");
    printf("    " CLR_CYAN "lock" CLR_RESET "   - only locked messages (unlock_at > now)\n");
    printf("    " CLR_CYAN "single" CLR_RESET " - only active messages for the given pubkey_hash_b64\n");
    printf("    " CLR_CYAN "last" CLR_RESET "   - the most recent [<count>] message(s), (count defaults to 1), optionally filtered by pubkey_hash_b64\n");
    printf("    " CLR_CYAN "new" CLR_RESET "    - only new messages received after connection, optionally filtered by pubkey_hash_b64\n");
    printf("    " CLR_MAGENTA "*" CLR_RESET " If pubkey_hash_b64 is provided, filters by it (mandatory for single and last modes)\n\n");

    printf("  " CLR_YELLOW "revoke" CLR_RESET " " CLR_CYAN "<alert_id> <pubkey_hash_b64>" CLR_RESET "\n");
    printf("    Cancels a previously sent time-locked message, also for the “Dead Hand” scenario.\n");

    printf("\n" CLR_BOLD "Configuration:" CLR_RESET "\n");
    printf("  The file " CLR_CYAN "/etc/gorgona/gorgona.conf" CLR_RESET " contains server settings and optional execution mappings.\n");
    printf("  " CLR_BOLD "Format:" CLR_RESET "\n");
    printf("    " CLR_MAGENTA "[server]" CLR_RESET "\n");
    printf("    ip = <IP_address>   (example: " CLR_CYAN "64.188.70.158" CLR_RESET ")\n");
    printf("    port = <port>       (example: " CLR_CYAN "7777" CLR_RESET ")\n");
    printf("    " CLR_MAGENTA "[exec_commands]" CLR_RESET "\n");
    printf("    <key> = <script_path> " CLR_YELLOW "time_limit" CLR_RESET " = <sec> (example: " CLR_CYAN "app start = /bin/lsblk.sh time_limit = 10" CLR_RESET ")\n");

    printf("\n" CLR_BOLD "Examples:" CLR_RESET "\n");
    printf("  " CLR_WHITE_BOLD "%s listen single RWTPQzuhzBw=" CLR_RESET "\n", program_name);
    printf("  " CLR_WHITE_BOLD "%s listen last RWTPQzuhzBw=" CLR_RESET "          # Gets the last 1 message\n", program_name);
    printf("  " CLR_WHITE_BOLD "%s listen last 3 RWTPQzuhzBw=" CLR_RESET "        # Gets the last 3 messages\n", program_name);
    printf("  " CLR_WHITE_BOLD "%s listen new RWTPQzuhzBw=" CLR_RESET "           # Listens for new messages only\n", program_name);
    printf("  " CLR_WHITE_BOLD "%s -e listen new RWTPQzuhzBw=" CLR_RESET "        # Listens and executes messages\n", program_name);
    printf("  " CLR_WHITE_BOLD "%s -ve listen new RWTPQzuhzBw=" CLR_RESET "       # Listens, executes, and shows verbose output\n", program_name);
    printf("  " CLR_WHITE_BOLD "%s send \"$(date -u '+%%Y-%%m-%%d %%H:%%M:%%S')\" \"$(date -u -d '+30 days' '+%%Y-%%m-%%d %%H:%%M:%%S')\" \"hello world\" \"RWTPQzuhzBw=.pub\"" CLR_RESET "\n", program_name);
    printf("  " CLR_WHITE_BOLD "%s send \"$(date -u '+%%Y-%%m-%%d %%H:%%M:%%S')\" \"$(date -u -d '+30 days' '+%%Y-%%m-%%d %%H:%%M:%%S')\" \"app start\" \"RWTPQzuhzBw=.pub\"" CLR_RESET "\n", program_name);
    printf("  " CLR_WHITE_BOLD "df -h | %s send \"$(date -u '+%%Y-%%m-%%d %%H:%%M:%%S')\" \"$(date -u -d '+30 days' '+%%Y-%%m-%%d %%H:%%M:%%S')\" - \"RWTPQzuhzBw=.pub\"" CLR_RESET "\n", program_name);
    printf("  " CLR_WHITE_BOLD "%s revoke 170119927746560 RWTPQzuhzBw=" CLR_RESET "\n", program_name);

    #undef CLR_RESET
    #undef CLR_BOLD
    #undef CLR_GREEN
    #undef CLR_YELLOW
    #undef CLR_CYAN
    #undef CLR_MAGENTA
    #undef CLR_WHITE_BOLD
}

int main(int argc, char *argv[]) {
    int opt;

    /* Define long options for getopt_long */
    static struct option long_options[] = {
        {"help", no_argument, 0, 'h'},
        {"verbose", no_argument, 0, 'v'},
        {"exec", no_argument, 0, 'e'},
        {"version", no_argument, 0, 'V'},
        {"daemon-exec", no_argument, 0, 'd'},
        {0, 0, 0, 0}
    };

    while ((opt = getopt_long(argc, argv, "vheVd", long_options, NULL)) != -1) {
      switch (opt) {
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

    /* Process commands */
    if (strcmp(argv[optind], "genkeys") == 0) {
        return generate_rsa_keys(verbose);
    } else if (strcmp(argv[optind], "send") == 0) {
        return send_alert(argc - optind, argv + optind, verbose);
    } else if (strcmp(argv[optind], "listen") == 0) {
        return listen_alerts(argc - optind, argv + optind, verbose, execute, daemon_exec_flag);
    } else if (strcmp(argv[optind], "revoke") == 0) {
        return send_revocation(argc - optind, argv + optind, verbose);  
    } else {
        fprintf(stderr, "Unknown command: %s\n", argv[optind]);
        print_help(argv[0]);
        return 1;
    }

    mesh_force_save = true; 
    return 0;
}
