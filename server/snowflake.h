/* 
* BSD 3-Clause License
* Copyright (c) 2025, Alexander Shcheglov
* All rights reserved. 
*/

#ifndef SNOWFLAKE_H
#define SNOWFLAKE_H

#include <stdint.h>
#include <stdatomic.h>

/* Custom epoch for Snowflake (January 1, 2025, in milliseconds) */
#define SNOWFLAKE_EPOCH 1735689600000ULL

/* Global variables */
extern atomic_uint_least16_t sequence;  /* Sequence number (12 bit, 0-4095) */
extern uint64_t last_timestamp;         /* Last timestamp used (ms) */

/* Generating a Snowflake ID */
uint64_t generate_snowflake_id(void);

#endif
