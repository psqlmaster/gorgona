/* BSD 3-Clause License
 * Copyright (c) 2025, Alexander Shcheglov
 * All rights reserved.
 */

#include "encrypt.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>

extern int send_alert(int argc, char *argv[], int verbose);
extern int listen_alerts(int argc, char *argv[], int verbose, int execute);  // Updated: added execute parameter

void print_help(const char *program_name) {
    printf("Usage:\n");
    printf(" %s [-v] [-e] [-h|--help] <command> [arguments]\n", program_name);
    printf("\nFlags:\n");
    printf(" -v, --verbose  Enables verbose output for debugging\n");
    printf(" -e, --exec     For 'listen' command: execute messages as system commands (requires pubkey_hash_b64). "
           "If [exec_commands] in /etc/gorgona/gorgona.conf is empty, all decrypted messages are executed. "
           "If [exec_commands] contains entries (e.g., 'greengage start = /path/to/script.sh'), only messages "
           "matching a key are executed by running the corresponding script.\n");
    printf(" -h, --help     Displays this help message\n");
    printf(" Note: Flags -v and -e can be combined (e.g., -ve) for verbose output during command execution.\n");
    printf("\nCommands:\n");
    printf(" genkeys\n");
    printf(" Generates an RSA key pair in /etc/gorgona/ (Example: sudo %s genkeys)\n", program_name);
    printf("\n");
    printf(" send <unlock_time> <expire_time> <message> <public_key_file>\n");
    printf(" Sends an encrypted message\n");
    printf(" Use '-' for <message> to read from stdin\n");
    printf("\n");
    printf(" listen <mode> [<count>] [pubkey_hash_b64]\n");
    printf(" Listens for messages\n");
    printf(" Modes:\n");
    printf(" live   - only active messages (unlock_at <= now)\n");
    printf(" all    - all non-expired messages, including locked\n");
    printf(" lock   - only locked messages (unlock_at > now)\n");
    printf(" single - only active messages for the given pubkey_hash_b64\n");
    printf(" last   - the most recent [<count>] message(s) for the given pubkey_hash_b64 (count defaults to 1)\n");
    printf(" new    - only new messages received after connection, optionally filtered by pubkey_hash_b64\n");
    printf(" If pubkey_hash_b64 is provided, filters by it (mandatory for single and last modes)\n");
    printf("\nConfiguration:\n");
    printf(" The file /etc/gorgona/gorgona.conf contains server settings and optional execution mappings.\n");
    printf(" Format:\n");
    printf(" [server]\n");
    printf(" ip = <IP_address> (example: 64.188.70.158)\n");
    printf(" port = <port> (example: 7777)\n");
    printf(" [exec_commands]\n");
    printf(" <key> = <script_path> (example: app start = /home/su/repository/c/gorgona/test/lsblk.sh)\n");
    printf("\nExamples:\n");
    printf(" %s listen single RWTPQzuhzBw=\n", program_name);
    printf(" %s listen last RWTPQzuhzBw= # Gets the last 1 message\n", program_name);
    printf(" %s listen last 3 RWTPQzuhzBw= # Gets the last 3 messages\n", program_name);
    printf(" %s listen new RWTPQzuhzBw= # Listens for new messages only\n", program_name);
    printf(" %s -e listen new RWTPQzuhzBw= # Listens for new messages and executes them as commands\n", program_name);
    printf(" %s -ve listen new RWTPQzuhzBw= # Listens for new messages, executes them, and shows verbose output\n", program_name);
    printf(" %s send \"2025-09-30 23:55:00\" \"2025-12-30 12:00:00\" \"app start\" \"RWTPQzuhzBw=.pub\" # Executes /home/su/repository/c/gorgona/test/lsblk.sh if configured\n", program_name);
    printf(" cat message.txt | %s send \"2025-09-30 23:55:00\" \"2025-12-30 12:00:00\" - \"RWTPQzuhzBw=.pub\"\n", program_name);
}

int main(int argc, char *argv[]) {
    int verbose = 0;
    int execute = 0; 
    int opt;

    /* Define long options for getopt_long */
    static struct option long_options[] = {
        {"help", no_argument, 0, 'h'},
        {"exec", no_argument, 0, 'e'},
        {0, 0, 0, 0}
    };

    while ((opt = getopt_long(argc, argv, "vhe", long_options, NULL)) != -1) { 
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
            case '?':
                fprintf(stderr, "Unknown flag: %s\n", argv[optind-1]);
                print_help(argv[0]);
                return 1;
            default:
                fprintf(stderr, "Error processing flags\n");
                print_help(argv[0]);
                return 1;
        }
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
        return listen_alerts(argc - optind, argv + optind, verbose, execute); 
    } else {
        fprintf(stderr, "Unknown command: %s\n", argv[optind]);
        print_help(argv[0]);
        return 1;
    }

    return 0;
}
