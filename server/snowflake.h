#ifndef SNOWFLAKE_H
#define SNOWFLAKE_H

#include <stdint.h>
#include <stdatomic.h>

// Кастомная эпоха для Snowflake (1 января 2025, в ms)
#define SNOWFLAKE_EPOCH 1735689600000ULL

// Глобальные переменные
extern atomic_uint_least16_t sequence;  // Sequence number (12 бит, 0-4095)
extern uint64_t last_timestamp;         // Последний использованный timestamp (ms)

// Генерация Snowflake ID
uint64_t generate_snowflake_id(void);

#endif
