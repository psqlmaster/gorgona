/*
BSD 3-Clause License
Copyright (c) 2025, Alexander Shcheglov
*/
#include "common.h"
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <stdbool.h>

int verbose = 0;
int sync_interval = 30;
int execute = 0;
int daemon_exec_flag = 0;
char client_log_level[32] = "error";

static bool should_log_level(const char *level) {
    if (verbose) return true;
    if (strcmp(level, "ERROR") == 0) return true;
    if (strcmp(level, "WARN") == 0 || strcmp(level, "INFO") == 0) {
        return (strcmp(client_log_level, "info") == 0 ||
                strcmp(client_log_level, "debug") == 0);
    }
    if (strcmp(level, "DEBUG") == 0) {
        return (strcmp(client_log_level, "debug") == 0);
    }
    return false;
}

void log_event(const char *level, int fd, const char *ip, int port, const char *fmt, ...) {
    if (!should_log_level(level)) return;
    char time_str[32];
    get_utc_time_str(time_str, sizeof(time_str));
    char log_buf[2048];
    int pos = 0;
    pos += snprintf(log_buf + pos, sizeof(log_buf) - pos, "[%s] [%s] ", time_str, level);
    if (ip) pos += snprintf(log_buf + pos, sizeof(log_buf) - pos, "[%s:%d] ", ip, port);
    va_list args;
    va_start(args, fmt);
    pos += vsnprintf(log_buf + pos, sizeof(log_buf) - pos, fmt, args);
    va_end(args);
    if (pos >= (int)sizeof(log_buf)) pos = sizeof(log_buf) - 1;
    log_buf[pos++] = '\n';
    log_buf[pos] = '\0';
    if (!daemon_exec_flag) {
        fputs(log_buf, stdout);
        fflush(stdout);
    }
    if (gorgona_log_file[0] != '\0') {
        FILE *fp = fopen(gorgona_log_file, "a");
        if (fp) {
            fputs(log_buf, fp);
            fclose(fp);
        }
    }
}
