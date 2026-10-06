/* 
* BSD 3-Clause License
* Copyright (c) 2025, Alexander Shcheglov
* All rights reserved. 
*/

#ifndef ALERT_SEND_H
#define ALERT_SEND_H

#include <time.h>
#include <stddef.h>
#include <stdint.h>
int alert_send_raw(const char *target_pubkey,
                   const uint8_t *payload, size_t payload_len,
                   time_t unlock_at, time_t expire_at);
int send_alert(int argc, char *argv[], int verbose);
/* A function to recall (cancel) a previously sent alert. */
int send_revocation(int argc, char *argv[], int verbose); 
time_t parse_datetime(const char *datetime);

#endif
