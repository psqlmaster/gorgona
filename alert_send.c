#define _XOPEN_SOURCE 700
#include "encrypt.h"
#include "config.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <arpa/inet.h>
#include <unistd.h>

#define MAX_MSG_LEN 8192  // Увеличен буфер

/* Парсит дату и время в формате "ГГГГ-ММ-ДД ЧЧ:ММ:СС" */
time_t parse_datetime(const char *datetime) {
    struct tm tm = {0};
    if (strptime(datetime, "%Y-%m-%d %H:%M:%S", &tm) == NULL) {
        fprintf(stderr, "Ошибка: Неверный формат времени: %s\n", datetime);
        return -1;
    }
    return mktime(&tm);
}

/* Отправляет зашифрованное сообщение на сервер */
int send_alert(int argc, char *argv[], int verbose) {
    if (argc != 5) {
        fprintf(stderr, "Использование: send <время_разблокировки> <время_истечения> <сообщение> <файл_публичного_ключа>\n");
        return 1;
    }

    time_t unlock_at = parse_datetime(argv[1]);
    time_t expire_at = parse_datetime(argv[2]);
    if (unlock_at == -1 || expire_at == -1) {
        return 1;
    }
    const char *message = argv[3];
    const char *pubkey_file = argv[4];

    /* Читаем публичный ключ получателя */
    FILE *pub_fp = fopen(pubkey_file, "rb");
    if (!pub_fp) {
        fprintf(stderr, "Не удалось открыть файл публичного ключа: %s\n", pubkey_file);
        return 1;
    }
    EVP_PKEY *pubkey = PEM_read_PUBKEY(pub_fp, NULL, NULL, NULL);
    fclose(pub_fp);
    if (!pubkey) {
        fprintf(stderr, "Не удалось прочитать публичный ключ из %s\n", pubkey_file);
        ERR_print_errors_fp(stderr);
        return 1;
    }

    /* Вычисляем хеш публичного ключа */
    size_t hash_len;
    unsigned char *pubkey_hash = compute_pubkey_hash(pubkey, &hash_len, verbose);
    EVP_PKEY_free(pubkey);
    if (!pubkey_hash || hash_len != PUBKEY_HASH_LEN) {
        fprintf(stderr, "Не удалось вычислить хеш публичного ключа\n");
        free(pubkey_hash);
        return 1;
    }
    char *pubkey_hash_b64 = base64_encode(pubkey_hash, hash_len);
    if (!pubkey_hash_b64) {
        fprintf(stderr, "Не удалось закодировать хеш публичного ключа\n");
        free(pubkey_hash);
        return 1;
    }
    if (verbose) {
        printf("Хеш публичного ключа (base64): %s\n", pubkey_hash_b64);
    }

    /* Шифруем сообщение */
    unsigned char *encrypted = NULL, *encrypted_key = NULL, *iv = NULL, *tag = NULL;
    size_t encrypted_len, encrypted_key_len, iv_len, tag_len;
    if (encrypt_message(message, &encrypted, &encrypted_len, &encrypted_key, &encrypted_key_len, &iv, &iv_len, &tag, &tag_len, pubkey_file, verbose) != 0) {
        fprintf(stderr, "Не удалось зашифровать сообщение\n");
        free(pubkey_hash);
        free(pubkey_hash_b64);
        return 1;
    }

    /* Проверяем корректность размеров данных */
    if (tag_len != GCM_TAG_LEN || iv_len != 12) {
        fprintf(stderr, "Неверные размеры данных: tag_len=%zu (ожидаемо %d), iv_len=%zu (ожидаемо 12)\n", 
                tag_len, GCM_TAG_LEN, iv_len);
        free(pubkey_hash);
        free(pubkey_hash_b64);
        free(encrypted);
        free(encrypted_key);
        free(iv);
        free(tag);
        return 1;
    }

    /* Кодируем данные в base64 */
    char *encrypted_b64 = base64_encode(encrypted, encrypted_len);
    char *encrypted_key_b64 = base64_encode(encrypted_key, encrypted_key_len);
    char *iv_b64 = base64_encode(iv, iv_len);
    char *tag_b64 = base64_encode(tag, tag_len);
    if (!encrypted_b64 || !encrypted_key_b64 || !iv_b64 || !tag_b64) {
        fprintf(stderr, "Не удалось закодировать данные в base64\n");
        free(pubkey_hash);
        free(pubkey_hash_b64);
        free(encrypted);
        free(encrypted_key);
        free(iv);
        free(tag);
        free(encrypted_b64);
        free(encrypted_key_b64);
        free(iv_b64);
        free(tag_b64);
        return 1;
    }

    /* Загружаем конфиг */
    char server_ip[256];
    int server_port;
    read_config(server_ip, &server_port);

    /* Создаем сокет */
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        perror("Ошибка создания сокета");
        free(pubkey_hash);
        free(pubkey_hash_b64);
        free(encrypted);
        free(encrypted_key);
        free(iv);
        free(tag);
        free(encrypted_b64);
        free(encrypted_key_b64);
        free(iv_b64);
        free(tag_b64);
        return 1;
    }

    struct sockaddr_in serv_addr = { .sin_family = AF_INET, .sin_port = htons(server_port) };
    if (inet_pton(AF_INET, server_ip, &serv_addr.sin_addr) <= 0) {
        perror("Неверный адрес");
        close(sock);
        free(pubkey_hash);
        free(pubkey_hash_b64);
        free(encrypted);
        free(encrypted_key);
        free(iv);
        free(tag);
        free(encrypted_b64);
        free(encrypted_key_b64);
        free(iv_b64);
        free(tag_b64);
        return 1;
    }

    /* Подключаемся к серверу */
    if (connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
        perror("Не удалось подключиться");
        close(sock);
        free(pubkey_hash);
        free(pubkey_hash_b64);
        free(encrypted);
        free(encrypted_key);
        free(iv);
        free(tag);
        free(encrypted_b64);
        free(encrypted_key_b64);
        free(iv_b64);
        free(tag_b64);
        return 1;
    }

    /* Формируем и отправляем сообщение серверу */
    char buffer[MAX_MSG_LEN];
    time_t create_at = time(NULL);
    int len = snprintf(buffer, MAX_MSG_LEN, "SEND|%s|%ld|%ld|%ld|%s|%s|%s|%s",
             pubkey_hash_b64, create_at, unlock_at, expire_at,
             encrypted_b64, encrypted_key_b64, iv_b64, tag_b64);
    if (len >= MAX_MSG_LEN) {
        fprintf(stderr, "Ошибка: Сообщение превышает MAX_MSG_LEN (%d)\n", MAX_MSG_LEN);
        close(sock);
        free(pubkey_hash);
        free(pubkey_hash_b64);
        free(encrypted);
        free(encrypted_key);
        free(iv);
        free(tag);
        free(encrypted_b64);
        free(encrypted_key_b64);
        free(iv_b64);
        free(tag_b64);
        return 1;
    }
    if (verbose) {
        printf("Отправка: %s\n", buffer);
    }
    if (send(sock, buffer, strlen(buffer), 0) < 0) {
        perror("Ошибка отправки");
        close(sock);
        free(pubkey_hash);
        free(pubkey_hash_b64);
        free(encrypted);
        free(encrypted_key);
        free(iv);
        free(tag);
        free(encrypted_b64);
        free(encrypted_key_b64);
        free(iv_b64);
        free(tag_b64);
        return 1;
    }

    /* Получаем ответ от сервера */
    int valread = read(sock, buffer, MAX_MSG_LEN - 1);
    if (valread <= 0) {
        perror("Ошибка чтения");
    } else {
        buffer[valread] = '\0';
        printf("Ответ сервера: %s\n", buffer);
    }

    /* Освобождаем ресурсы и закрываем сокет */
    close(sock);
    free(pubkey_hash);
    free(pubkey_hash_b64);
    free(encrypted);
    free(encrypted_key);
    free(iv);
    free(tag);
    free(encrypted_b64);
    free(encrypted_key_b64);
    free(iv_b64);
    free(tag_b64);
    return 0;
}
