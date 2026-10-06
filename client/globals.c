/*
BSD 3-Clause License
Copyright (c) 2025, Alexander Shcheglov
*/
#include "common.h"
#include <stdio.h>
#include <stdarg.h>
#include <stdbool.h>
#include <strings.h>
#include <unistd.h>

int verbose = 0;
int sync_interval = 30;
int execute = 0;
int daemon_exec_flag = 0;
char client_log_level[32] = "error";

static bool should_log_level(const char *level) {
    if (strcasecmp(level, "ERROR") == 0) return true;
    if (strcasecmp(level, "INFO") == 0) {
        return (strcasecmp(client_log_level, "info") == 0 ||
                strcasecmp(client_log_level, "debug") == 0);
    }
    if (strcasecmp(level, "WARN") == 0 ||
        strcasecmp(level, "DEBUG") == 0) {
        return (strcasecmp(client_log_level, "debug") == 0);
    }
    return false;
}

void log_event(const char *level, int fd, const char *ip, int port, const char *fmt, ...) {
    bool log_to_file = should_log_level(level);
    bool log_to_console = (verbose && !daemon_exec_flag);
    /* Если ни в файл, ни в консоль писать не нужно > выходим сразу */
    if (!log_to_file && !log_to_console) return;
    char time_str[32];
    get_utc_time_str(time_str, sizeof(time_str));
    char log_buf[2048];
    int pos = 0;
    pos += snprintf(log_buf + pos, sizeof(log_buf) - pos, "[%s] [CLI-PID:%d] [%s] ", time_str, getpid(), level);
    if (ip) pos += snprintf(log_buf + pos, sizeof(log_buf) - pos, "[%s:%d] ", ip, port);
    va_list args;
    va_start(args, fmt);
    pos += vsnprintf(log_buf + pos, sizeof(log_buf) - pos, fmt, args);
    va_end(args);
    if (pos >= (int)sizeof(log_buf)) pos = sizeof(log_buf) - 1;
    log_buf[pos++] = '\n';
    log_buf[pos] = '\0';
    /* Вывод на консоль (если включен verbose) */
    if (log_to_console) { 
        fputs(log_buf, stdout);
        fflush(stdout);
    }
    /* Запись в файл (строго по should_log_level) */
    if (log_to_file && gorgona_log_file[0] != '\0') {
        FILE *fp = fopen(gorgona_log_file, "a");
        if (fp) {
            fputs(log_buf, fp);
            fclose(fp);
        }
    }
}
