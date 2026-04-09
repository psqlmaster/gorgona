/* 
* BSD 3-Clause License
* Copyright (c) 2025, Alexander Shcheglov
* All rights reserved. 
*/

#include "common.h"

void get_utc_time_str(char *buffer, size_t buffer_size) {
    time_t now = time(NULL);
    struct tm *utc_time = gmtime(&now);
    strftime(buffer, buffer_size, "[%Y-%m-%d %H:%M:%S UTC]", utc_time);
}
