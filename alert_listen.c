#define _XOPEN_SOURCE 700
#include "encrypt.h"
#include "config.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <time.h>

#define MAX_MSG_LEN 8192
#define MAX_ACCUM_LEN (MAX_MSG_LEN * 10)  // Для накопления данных при больших отправках

/* Удаляет пробелы, \n, \r с конца строки */
void trim_string(char *str) {
    size_t len = strlen(str);
    while (len > 0 && (str[len - 1] == ' ' || str[len - 1] == '\n' || str[len - 1] == '\r')) {
        str[len - 1] = '\0';
        len--;
    }
}

/* Проверяет наличие приватного ключа для pubkey_hash_b64 */
int has_private_key(const char *pubkey_hash_b64, int verbose) {
    char priv_file[256];
    snprintf(priv_file, sizeof(priv_file), "%s.key", pubkey_hash_b64);
    FILE *priv_fp = fopen(priv_file, "rb");
    if (!priv_fp) {
        if (verbose) fprintf(stderr, "Приватный ключ не найден: %s\n", priv_file);
        return 0;
    }
    fclose(priv_fp);
    return 1;
}

/* Разбирает ответ от сервера и расшифровывает сообщение */
void parse_response(const char *response, const char *single_pubkey_hash_b64, int verbose) {
    char *copy = strdup(response);
    if (!copy) {
        fprintf(stderr, "Не удалось выделить память для ответа\n");
        return;
    }

    char *pubkey_hash_b64 = NULL, *encrypted_text = NULL, *encrypted_key = NULL, *iv = NULL, *tag = NULL;
    char create_str[50] = "", unlock_str[50] = "", expire_str[50] = "";
    char metadata_line[256] = "";

    /* Разбираем ответ построчно */
    char *line = strtok(copy, "\n");
    while (line) {
        trim_string(line);
        if (strncmp(line, "Pubkey_Hash: ", 13) == 0) {
            pubkey_hash_b64 = line + 13;
        } else if (strncmp(line, "Encrypted Full text: ", 21) == 0) {
            encrypted_text = line + 21;
        } else if (strncmp(line, "Encrypted Key: ", 15) == 0) {
            encrypted_key = line + 15;
        } else if (strncmp(line, "IV: ", 4) == 0) {
            iv = line + 4;
        } else if (strncmp(line, "Tag: ", 5) == 0) {
            tag = line + 5;
        } else if (strncmp(line, "Metadata: ", 10) == 0) {
            strncpy(metadata_line, line + 10, sizeof(metadata_line) - 1);
            metadata_line[sizeof(metadata_line) - 1] = '\0';
        } else if (strncmp(line, "Message expired: ", 17) == 0) {
            printf("Сообщение истекло: %s\n", line + 17);
        } else if (strncmp(line, "Message not found", 17) == 0) {
            printf("Сообщение не найдено\n");
        }
        line = strtok(NULL, "\n");
    }

    if (!pubkey_hash_b64) {
        fprintf(stderr, "Ошибка: Pubkey_Hash отсутствует в ответе, есть сообщение которое можно прочитать в будущем\n");
        free(copy);
        return;
    }

    /* Проверяем режим single */
    if (single_pubkey_hash_b64 && strcmp(pubkey_hash_b64, single_pubkey_hash_b64) != 0) {
        if (verbose) {
            printf("Пропущено сообщение с Pubkey_Hash=%s (ожидаемо %s)\n", pubkey_hash_b64, single_pubkey_hash_b64);
        }
        free(copy);
        return;
    }

    /* Проверяем наличие приватного ключа */
    if (!has_private_key(pubkey_hash_b64, verbose)) {
        if (verbose) {
            printf("Пропущено сообщение с Pubkey_Hash=%s (отсутствует приватный ключ)\n", pubkey_hash_b64);
        }
        free(copy);
        return;
    }

    /* Обрабатываем строку метаданных */
    if (metadata_line[0]) {
        char *token = strtok(metadata_line, ",");
        while (token) {
            char *key = token;
            while (*key == ' ') key++;
            if (strncmp(key, "Pubkey_Hash=", 12) == 0) {
                // Пропускаем Pubkey_Hash
            } else if (strncmp(key, "Create=", 7) == 0) {
                strncpy(create_str, key + 7, sizeof(create_str) - 1);
                create_str[sizeof(create_str) - 1] = '\0';
                trim_string(create_str);
            } else if (strncmp(key, "Unlock=", 7) == 0) {
                strncpy(unlock_str, key + 7, sizeof(unlock_str) - 1);
                unlock_str[sizeof(unlock_str) - 1] = '\0';
                trim_string(unlock_str);
            } else if (strncmp(key, "Expire=", 7) == 0) {
                strncpy(expire_str, key + 7, sizeof(expire_str) - 1);
                expire_str[sizeof(expire_str) - 1] = '\0';
                trim_string(expire_str);
            }
            token = strtok(NULL, ",");
        }
    }

    printf("Получено сообщение: Pubkey_Hash=%s\n", pubkey_hash_b64);

    if (encrypted_text && encrypted_key && iv && tag) {
        size_t encrypted_len, encrypted_key_len, iv_len, tag_len;
        unsigned char *encrypted = base64_decode(encrypted_text, &encrypted_len);
        unsigned char *key = base64_decode(encrypted_key, &encrypted_key_len);
        unsigned char *iv_decoded = base64_decode(iv, &iv_len);
        unsigned char *tag_decoded = base64_decode(tag, &tag_len);

        if (!encrypted || !key || !iv_decoded || !tag_decoded) {
            fprintf(stderr, "Не удалось декодировать зашифрованные данные для Pubkey_Hash=%s\n", pubkey_hash_b64);
            free(encrypted);
            free(key);
            free(iv_decoded);
            free(tag_decoded);
            free(copy);
            return;
        }

        if (tag_len != GCM_TAG_LEN) {
            fprintf(stderr, "Неверная длина тега: %zu (ожидаемо %d) для Pubkey_Hash=%s\n", tag_len, GCM_TAG_LEN, pubkey_hash_b64);
            free(encrypted);
            free(key);
            free(iv_decoded);
            free(tag_decoded);
            free(copy);
            return;
        }

        if (iv_len != 12) {
            fprintf(stderr, "Неверная длина IV: %zu (ожидаемо 12) для Pubkey_Hash=%s\n", iv_len, pubkey_hash_b64);
            free(encrypted);
            free(key);
            free(iv_decoded);
            free(tag_decoded);
            free(copy);
            return;
        }

        if (verbose) {
            printf("Декодированные длины: encrypted=%zu, key=%zu, iv=%zu, tag=%zu\n", encrypted_len, encrypted_key_len, iv_len, tag_len);
        }

        char priv_file[256];
        snprintf(priv_file, sizeof(priv_file), "%s.key", pubkey_hash_b64);

        char *plaintext = NULL;
        if (decrypt_message(encrypted, encrypted_len, key, encrypted_key_len, iv_decoded, iv_len, tag_decoded, &plaintext, priv_file, verbose) == 0) {
            printf("Расшифрованное сообщение: %s\n", plaintext);
            printf("Метаданные: Create=%s, Unlock=%s, Expire=%s\n", create_str, unlock_str, expire_str);
            free(plaintext);
        } else {
            fprintf(stderr, "Не удалось расшифровать сообщение для Pubkey_Hash=%s (проверьте %s)\n", pubkey_hash_b64, priv_file);
        }

        free(encrypted);
        free(key);
        free(iv_decoded);
        free(tag_decoded);
    } else {
        printf("Только метаданные: Create=%s, Unlock=%s, Expire=%s\n", create_str, unlock_str, expire_str);
    }
    free(copy);
}

/* Слушает сообщения от сервера в указанном режиме */
int listen_alerts(int argc, char *argv[], int verbose) {
    if (argc < 2) {
        fprintf(stderr, "Использование: listen <режим> [pubkey_hash_b64]\n");
        fprintf(stderr, "Режимы: live, all, single\n");
        return 1;
    }

    char *mode = argv[1];
    char *pubkey_hash_b64 = (argc > 2 && strcmp(mode, "single") == 0) ? argv[2] : NULL;

    char server_ip[256];
    int server_port;
    read_config(server_ip, &server_port);

    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        perror("Ошибка создания сокета");
        return 1;
    }

    struct sockaddr_in serv_addr = { .sin_family = AF_INET, .sin_port = htons(server_port) };
    if (inet_pton(AF_INET, server_ip, &serv_addr.sin_addr) <= 0) {
        perror("Неверный адрес");
        close(sock);
        return 1;
    }

    if (connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
        perror("Не удалось подключиться");
        close(sock);
        return 1;
    }

    char buffer[MAX_MSG_LEN];
    if (strcmp(mode, "single") == 0) {
        if (!pubkey_hash_b64) {
            fprintf(stderr, "Требуется хеш публичного ключа для режима single\n");
            close(sock);
            return 1;
        }
        snprintf(buffer, MAX_MSG_LEN, "LISTEN|%s", pubkey_hash_b64);
    } else if (strcmp(mode, "live") == 0) {
        snprintf(buffer, MAX_MSG_LEN, "SUBSCRIBE LIVE");
    } else if (strcmp(mode, "all") == 0) {
        snprintf(buffer, MAX_MSG_LEN, "SUBSCRIBE ALL");
    } else {
        fprintf(stderr, "Неверный режим: %s\n", mode);
        close(sock);
        return 1;
    }

    if (verbose) {
        printf("Отправка: %s\n", buffer);
    }
    if (send(sock, buffer, strlen(buffer), 0) < 0) {
        perror("Ошибка отправки");
        close(sock);
        return 1;
    }

    char accum[MAX_ACCUM_LEN] = {0};
    int accum_len = 0;

    while (1) {
        char read_buffer[MAX_MSG_LEN];
        int valread = read(sock, read_buffer, MAX_MSG_LEN - 1);
        if (valread <= 0) {
            perror("Ошибка чтения или соединение закрыто");
            break;
        }
        read_buffer[valread] = '\0';

        if (accum_len + valread >= MAX_ACCUM_LEN) {
            fprintf(stderr, "Ошибка: Буфер накопления переполнен\n");
            break;
        }
        memcpy(accum + accum_len, read_buffer, valread);
        accum_len += valread;
        accum[accum_len] = '\0';

        char *start = accum;
        while (1) {
            char *end = strstr(start, "\nEND_OF_MESSAGE\n");
            if (end == NULL) break;

            *end = '\0';
            if (verbose) {
                printf("Получен ответ: %s\n", start);
            }
            parse_response(start, pubkey_hash_b64, verbose);

            start = end + strlen("\nEND_OF_MESSAGE\n");
        }

        // Сдвигаем оставшуюся часть
        int remain_len = accum + accum_len - start;
        memmove(accum, start, remain_len);
        accum_len = remain_len;
        accum[accum_len] = '\0';
    }

    close(sock);
    return 0;
}
