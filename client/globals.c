/* client/globals.c */
#include "common.h"
#include <stdio.h>
#include <stdarg.h>
#include <string.h>

/* Global state variables - Defined here once */
int verbose = 0;
int sync_interval = 30;
int execute = 0;
int daemon_exec_flag = 0;

/**
 * Standard client log_event implementation.
 * Accessible by both the Client and Test suite.
 */
void log_event(const char *level, int fd, const char *ip, int port, const char *fmt, ...) {
    if (verbose || strcmp(level, "ERROR") == 0 || strcmp(level, "WARN") == 0) {
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
}
