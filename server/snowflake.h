/* 
* server/snowflake.h
* BSD 3-Clause License
* Copyright (c) 2025, Alexander Shcheglov
*/

#ifndef SNOWFLAKE_H
#define SNOWFLAKE_H

#include <stdint.h>
#include <stdatomic.h>
#include <time.h>

/* Custom epoch for Snowflake (January 1, 2025, in milliseconds) */
#define SNOWFLAKE_EPOCH 1735689600000ULL

/* Global variables */
extern atomic_uint_least16_t sequence;  
extern uint64_t last_timestamp;         

/* Generating a Snowflake ID */
uint64_t generate_snowflake_id(void);

/**
 * Extracts timestamp from ID. 
 * Note: Implementation should be in snowflake.c
 */
time_t snowflake_to_timestamp(uint64_t id);

#endif
