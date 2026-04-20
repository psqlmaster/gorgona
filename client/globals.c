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
        printf("[%s] [%s] ", time_str, level);
        if (ip) printf("[%s:%d] ", ip, port);

        va_list args;
        va_start(args, fmt);
        vprintf(fmt, args);
        va_end(args);
        printf("\n");
        fflush(stdout);
    }
}
