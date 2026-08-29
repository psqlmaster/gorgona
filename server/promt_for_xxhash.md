**Тема:** Разработка движка синхронизации P2P-нод на базе неизменяемой цепочки хешей (Hash Chain) для системы Gorgona.

**Контекст:**
Мы разрабатываем «Gorgona» — децентрализованную P2P-систему для передачи зашифрованных оповещений (алертов).
- **Стек:** Си, хранилище на базе mmap, Snowflake ID (64-битные, упорядоченные по времени).
- **Модель данных:** Множество каналов получателей (Recipient). Каждый канал представляет собой циклический буфер.
- **Конфигурация:** Максимальное количество алертов в канале задается в конфиге сервера (`max_alerts`). При достижении лимита старые алерты удаляются (sliding window).
- **Текущая проблема:** Синхронизация по `MaxID` допускает пропуски данных. Нужно перейти на математически подтвержденную целостность.

**Задача:**
Реализовать механизм **цепочки хешей (Hash Chain)** для обеспечения 100% целостности и последовательности данных. Для хеширования необходимо использовать библиотеку **xxHash** (алгоритмы XXH3 или XXH64) как наиболее производительную.

**Технические требования:**
1. **Связывание алертов (Chaining):**
   - Каждая структура `Alert` должна включать поля `prev_hash` и `curr_hash`.
   - Формула: `curr_hash = xxHash(ID + prev_hash + хеш_полезной_нагрузки)`.
   - В метаданных канала (`Recipient`) должен храниться `last_hash` последнего алерта для добавления новых звеньев за $O(1)$.

2. **Работа с циклическим буфером:**
   - Учесть, что «генезис» цепочки постоянно смещается при удалении старых записей. Система должна уметь подтверждать целостность текущего окна (последние `N` алертов).

3. **Протокол синхронизации и восстановление пропусков:**
   - Реализовать рукопожатие (handshake), при котором ноды обмениваются парой `(last_id, last_hash)`.
   - Если хеши не совпадают, реализовать поиск **«Общего предка» (Common Ancestor)** — последней точки, где история нод была идентична (используя бинарный поиск по ID или трассировку назад).
   - Реализовать механизм «Gap Fill» (заполнение дыр) для стриминга только недостающих звеньев.

4. **Разрешение конфликтов и форков:**
   - При возникновении параллельных веток (алерты созданы на разных нодах в офлайне) использовать Snowflake ID как единственный источник истины.
   - Реализовать функцию **пересчета цепочки (re-chaining)**: если алерт вставляется в прошлое, все последующие `prev_hash` в mmap должны быть обновлены для восстановления целостности.

5. **Производительность:**
   - Максимальная интеграция **xxHash**. 
   - Логика должна быть дружелюбна к mmap (минимизация случайных записей, использование последовательного расположения данных).

Benchmarks
-------------------------

The benchmarked reference system uses an Intel i7-9700K cpu, and runs Ubuntu x64 20.04.
The [open source benchmark program] is compiled with `clang` v10.0 using `-O3` flag.

| Hash Name     | Width | Bandwidth (GB/s) | Small Data Velocity | Quality | Comment |
| ---------     | ----- | ---------------- | ----- | --- | --- |
| __XXH3__ (SSE2) |  64 | 31.5 GB/s        | 133.1 | 10
| __XXH128__ (SSE2) | 128 | 29.6 GB/s      | 118.1 | 10
| _RAM sequential read_ | N/A | 28.0 GB/s  |   N/A | N/A | _for reference_
| City64        |    64 | 22.0 GB/s        |  76.6 | 10
| T1ha2         |    64 | 22.0 GB/s        |  99.0 |  9 | Slightly worse [collisions]
| City128       |   128 | 21.7 GB/s        |  57.7 | 10
| __XXH64__     |    64 | 19.4 GB/s        |  71.0 | 10
| SpookyHash    |    64 | 19.3 GB/s        |  53.2 | 10
| Mum           |    64 | 18.0 GB/s        |  67.0 |  9 | Slightly worse [collisions]
| __XXH32__     |    32 |  9.7 GB/s        |  71.9 | 10
| City32        |    32 |  9.1 GB/s        |  66.0 | 10
| Murmur3       |    32 |  3.9 GB/s        |  56.1 | 10
| SipHash       |    64 |  3.0 GB/s        |  43.2 | 10
| FNV64         |    64 |  1.2 GB/s        |  62.7 |  5 | Poor avalanche properties
| Blake2        |   256 |  1.1 GB/s        |   5.1 | 10 | Cryptographic
| SHA1          |   160 |  0.8 GB/s        |   5.6 | 10 | Cryptographic but broken
| MD5           |   128 |  0.6 GB/s        |   7.8 | 10 | Cryptographic but broken

выбери лучший алго для хеширования который нам подойдет 
пример:
xxhash.c
/*
 * You can contact the author at:
 *   - xxHash homepage: https://www.xxhash.com
 *   - xxHash source repository: https://github.com/Cyan4973/xxHash
 * xxhash.c instantiates functions defined in xxhash.h
 */
#define XXH_STATIC_LINKING_ONLY /* access advanced declarations */
#define XXH_IMPLEMENTATION      /* access definitions */
#include "xxhash.h"

пример методов
xxhash_file_xxh3.c

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "xxhash.h"

#define BUFFER_SIZE (1024 * 1024) // 1MB буфер

void print_usage(const char* prog_name) {
    fprintf(stderr, "Usage: %s [-H3|-H128] <filename>\n", prog_name);
    fprintf(stderr, "  -H3     Calculate 64-bit XXH3 hash (default)\n");
    fprintf(stderr, "  -H128   Calculate 128-bit XXH3 hash\n");
}

int compute_hash(const char* filename, int use_128bit) {
    FILE* file = fopen(filename, "rb");
    if (!file) {
        fprintf(stderr, "Cannot open file: %s\n", filename);
        return 1;
    }

    setvbuf(file, NULL, _IOFBF, BUFFER_SIZE * 4);

    XXH3_state_t* state = XXH3_createState();
    if (!state) {
        fclose(file);
        fprintf(stderr, "Failed to create XXH3 state\n");
        return 1;
    }

    if (use_128bit) {
        XXH3_128bits_reset(state);
    } else {
        XXH3_64bits_reset(state);
    }

    unsigned char buffer[BUFFER_SIZE];
    size_t bytes_read;
    while ((bytes_read = fread(buffer, 1, BUFFER_SIZE, file)) > 0) {
        if (use_128bit) {
            XXH3_128bits_update(state, buffer, bytes_read);
        } else {
            XXH3_64bits_update(state, buffer, bytes_read);
        }
    }

    if (ferror(file)) {
        fprintf(stderr, "Error reading file: %s\n", filename);
        fclose(file);
        XXH3_freeState(state);
        return 1;
    }

    if (use_128bit) {
        XXH128_hash_t hash = XXH3_128bits_digest(state);
        printf("%016llx%016llx  %s\n", 
               (unsigned long long)hash.high64,
               (unsigned long long)hash.low64,
               filename);
    } else {
        XXH64_hash_t hash = XXH3_64bits_digest(state);
        printf("%016llx  %s\n", 
               (unsigned long long)hash,
               filename);
    }

    fclose(file);
    XXH3_freeState(state);
    return 0;
}

int main(int argc, char* argv[]) {
    int use_128bit = 0;
    const char* filename = NULL;

    // Парсинг аргументов
    if (argc == 3) {
        if (strcmp(argv[1], "-H128") == 0) {
            use_128bit = 1;
        } else if (strcmp(argv[1], "-H3") != 0) {
            print_usage(argv[0]);
            return 1;
        }
        filename = argv[2];
    } else if (argc == 2) {
        filename = argv[1];
    } else {
        print_usage(argv[0]);
        return 1;
    }

    return compute_hash(filename, use_128bit);
}


**Первое задание:**
Предложи обновленные структуры `Alert` и `Recipient`, а также алгоритм функции `add_alert_to_chain` с использованием xxHash. Опиши логику конечного автомата (state machine) для P2P-синхронизации при обнаружении расхождения хешей.


