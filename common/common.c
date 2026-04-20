/* 
* common/common.c 
*/
#include "common.h"
#include <stdio.h>
#include <string.h>
#include <ctype.h>

void get_utc_time_str(char *buffer, size_t buffer_size) {
    time_t now = time(NULL);
    struct tm utc_time;
    if (gmtime_r(&now, &utc_time)) {
        strftime(buffer, buffer_size, "%Y-%m-%d %H:%M:%S UTC", &utc_time);
    } else {
        snprintf(buffer, buffer_size, "0000-00-00 00:00:00 UTC");
    }
}

void trim_string(char *str) {
    if (!str || *str == '\0') return;
    
    size_t len = strlen(str);
    /* Удаляем пробелы, табы, переносы строк с конца */
    while (len > 0 && isspace((unsigned char)str[len - 1])) {
        str[len - 1] = '\0';
        len--;
    }
}
