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
extern int listen_alerts(int argc, char *argv[], int verbose);

void print_help(const char *program_name) {
    printf("Usage:\n");
    printf("  %s [-v] [-h|--help] <command> [arguments]\n", program_name);

    printf("\nFlags:\n");
    printf("  -v            Enables verbose output\n");
    printf("  -h, --help    Displays this help message\n");

    printf("\nCommands:\n");
    printf("  genkeys\n");
    printf("      Generates an RSA key pair\n");
    printf("\n");
    printf("  send <unlock_time> <expire_time> <message> <public_key_file>\n");
    printf("      Sends an encrypted message\n");
    printf("      Use '-' for <message> to read from stdin\n");
    printf("\n");
    printf("  listen <mode> [pubkey_hash_b64]\n");
    printf("      Listens for messages\n");
    printf("      Modes:\n");
    printf("        live    - only active messages (unlock_at <= now)\n");
    printf("        all     - all non-expired messages, including locked\n");
    printf("        lock    - only locked messages (unlock_at > now)\n");
    printf("        single  - only active messages for the given pubkey_hash_b64\n");
    printf("        last    - only the most recent message(s), optionally for the given pubkey_hash_b64\n");
    printf("      If pubkey_hash_b64 is provided, filters by it (mandatory for single mode)\n");

    printf("\nConfiguration:\n");
    printf("  The file ./gargona.conf contains server settings.\n");
    printf("  Format:\n");
    printf("    [server]\n");
    printf("    ip = <IP_address>   (example: 64.188.70.158)\n");
    printf("    port = <port>       (example: 7777)\n");

    printf("\nExamples:\n");
    printf("  %s listen single RWTPQzuhzBw=\n", program_name);
    printf("  %s send \"2025-09-30 23:55:00\" \"2025-12-30 12:00:00\" \"Message in the future for you my dear friend RWTPQzuhzBw=\" \"RWTPQzuhzBw=.pub\"\n", program_name);
    printf("  cat message.txt | %s send \"2025-09-30 23:55:00\" \"2025-12-30 12:00:00\" - \"RWTPQzuhzBw=.pub\"\n", program_name);
}

int main(int argc, char *argv[]) {
    int verbose = 0;
    int opt;

    /* Define long options for getopt_long */
    static struct option long_options[] = {
        {"help", no_argument, 0, 'h'},
        {0, 0, 0, 0}
    };

    while ((opt = getopt_long(argc, argv, "vh", long_options, NULL)) != -1) {
        switch (opt) {
            case 'v':
                verbose = 1;
                break;
            case 'h':
                print_help(argv[0]);
                return 0;
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
        return listen_alerts(argc - optind, argv + optind, verbose);
    } else {
        fprintf(stderr, "Unknown command: %s\n", argv[optind]);
        print_help(argv[0]);
        return 1;
    }

    return 0;
}
