/* BSD 3-Clause License
Copyright (c) 2025, Alexander Shcheglov
All rights reserved. */

#include "encrypt.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

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
}


int main(int argc, char *argv[]) {
    int verbose = 0;
    int cmd_index = 1;

    while (argc > cmd_index && argv[cmd_index][0] == '-') {
        if (strcmp(argv[cmd_index], "-v") == 0) {
            verbose = 1;
            cmd_index++;
        } else if (strcmp(argv[cmd_index], "-h") == 0 || strcmp(argv[cmd_index], "--help") == 0) {
            print_help(argv[0]);
            return 0;
        } else {
            fprintf(stderr, "Неизвестный флаг: %s\n", argv[cmd_index]);
            print_help(argv[0]);
            return 1;
        }
    }

    if (argc < cmd_index + 1) {
        fprintf(stderr, "Ошибка: Не указана команда\n");
        print_help(argv[0]);
        return 1;
    }

    if (strcmp(argv[cmd_index], "genkeys") == 0) {
        return generate_rsa_keys(verbose);
    } else if (strcmp(argv[cmd_index], "send") == 0) {
        return send_alert(argc - cmd_index, argv + cmd_index, verbose);
    } else if (strcmp(argv[cmd_index], "listen") == 0) {
        return listen_alerts(argc - cmd_index, argv + cmd_index, verbose);
    } else {
        fprintf(stderr, "Неизвестная команда: %s\n", argv[cmd_index]);
        print_help(argv[0]);
        return 1;
    }

    return 0;
}
