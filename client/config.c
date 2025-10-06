#include "config.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

void read_config(char *server_ip, int *server_port) {
    server_ip[0] = '\0'; // Инициализируем пустой строкой
    *server_port = DEFAULT_SERVER_PORT;
    FILE *conf_fp = fopen("/etc/gargona/gargona.conf", "r");
    if (!conf_fp) {
        strcpy(server_ip, DEFAULT_SERVER_IP);
        *server_port = DEFAULT_SERVER_PORT;
        return;
    }
    char line[256];
    while (fgets(line, sizeof(line), conf_fp)) {
        // Пропускаем пустые строки, комментарии и [server]
        if (line[0] == '\n' || line[0] == '#' || strstr(line, "[server]")) continue;
        // Убираем пробелы в начале
        char *trimmed = line;
        while (*trimmed == ' ' || *trimmed == '\t') trimmed++;
        // Разделяем ключ и значение
        char *key = strtok(trimmed, " =");
        char *value = strtok(NULL, " =");
        if (key && value) {
            // Убираем \n и \r из value
            value[strcspn(value, "\n\r")] = '\0';
            // Убираем пробелы в начале и конце value
            while (*value == ' ' || *value == '\t') value++;
            char *end = value + strlen(value) - 1;
            while (end > value && (*end == ' ' || *end == '\t')) *end-- = '\0';
            if (strcmp(key, "ip") == 0) {
                strcpy(server_ip, value);
            } else if (strcmp(key, "port") == 0) {
                *server_port = atoi(value);
            }
        }
    }
    fclose(conf_fp);
    // Проверяем, что IP не пустой
    if (server_ip[0] == '\0') {
        strcpy(server_ip, DEFAULT_SERVER_IP);
    }
}
