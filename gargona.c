#include "encrypt.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Объявления функций из других модулей */
extern int send_alert(int argc, char *argv[], int verbose);
extern int listen_alerts(int argc, char *argv[], int verbose);

/* Основная точка входа, распределяет команды */
int main(int argc, char *argv[]) {
    int verbose = 0;
    int cmd_index = 1;

    /* Проверяем наличие флага -v */
    if (argc > 1 && strcmp(argv[1], "-v") == 0) {
        verbose = 1;
        cmd_index = 2;
    }

    if (argc < cmd_index + 1) {
        fprintf(stderr, "Использование: %s [-v] <команда> [аргументы]\n", argv[0]);
        fprintf(stderr, "Флаг -v включает отладочный вывод\n");
        fprintf(stderr, "Команды:\n");
        fprintf(stderr, "  genkeys - сгенерировать пару ключей RSA\n");
        fprintf(stderr, "  send <время_разблокировки> <время_истечения> <сообщение> <файл_публичного_ключа>\n");
        fprintf(stderr, "  listen <режим> [pubkey_hash_b64] - слушать сообщения (режимы: live, all, single)\n");
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
        return 1;
    }

    return 0;
}
