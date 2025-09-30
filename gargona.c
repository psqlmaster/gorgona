/* BSD 3-Clause License
Copyright (c) 2025, Alexander Shcheglov
All rights reserved. */

#include "encrypt.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Объявления функций из других модулей */
extern int send_alert(int argc, char *argv[], int verbose);
extern int listen_alerts(int argc, char *argv[], int verbose);

/* Выводит справку на русском и английском языках */
void print_help(const char *program_name) {
    printf("Использование / Usage:\n");
    printf("  %s [-v] [-h|--help] <команда> [аргументы]\n", program_name);
    printf("\nФлаги / Flags:\n");
    printf("  -v            Включает отладочный вывод / Enables verbose output\n");
    printf("  -h, --help    Показывает эту справку / Displays this help message\n");
    printf("\nКоманды / Commands:\n");
    printf("  genkeys       Генерирует пару ключей RSA / Generates an RSA key pair\n");
    printf("  send <время_разблокировки> <время_истечения> <сообщение> <файл_публичного_ключа>\n");
    printf("                Отправляет зашифрованное сообщение / Sends an encrypted message\n");
    printf("  listen <режим> [pubkey_hash_b64]\n");
    printf("                Слушает сообщения (режимы: live, all, single) / Listens for messages (modes: live, all, single)\n");
    printf("\nКонфигурация / Configuration:\n");
    printf("  Файл ./gargona.conf содержит настройки сервера.\n");
    printf("  The file ./gargona.conf contains server settings.\n");
    printf("  Формат / Format:\n");
    printf("    [server]\n");
    printf("    ip = <IP_адрес>  (например / example: 64.188.70.158)\n");
    printf("    port = <порт>    (например / example: 7777)\n");
}

/* Основная точка входа, распределяет команды */
int main(int argc, char *argv[]) {
    int verbose = 0;
    int cmd_index = 1;

    /* Проверяем наличие флагов -v, -h или --help */
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
        /* Генерируем пару ключей RSA */
        return generate_rsa_keys(verbose);
    } else if (strcmp(argv[cmd_index], "send") == 0) {
        /* Перенаправляем на функцию отправки сообщения */
        return send_alert(argc - cmd_index, argv + cmd_index, verbose);
    } else if (strcmp(argv[cmd_index], "listen") == 0) {
        /* Перенаправляем на функцию прослушивания */
        return listen_alerts(argc - cmd_index, argv + cmd_index, verbose);
    } else {
        fprintf(stderr, "Неизвестная команда: %s\n", argv[cmd_index]);
        print_help(argv[0]);
        return 1;
    }

    return 0;
}
