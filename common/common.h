/* 
* common/common.h 
*/
#ifndef GORGONA_COMMON_H
#define GORGONA_COMMON_H

#include <time.h>
#include <stdarg.h>

/* Shared utilities implemented in common.c */
void get_utc_time_str(char *buffer, size_t buffer_size);
void trim_string(char *str);

/**
 * Logging interface. 
 * Implementation is provided by the application (Server or Client) 
 * during the linking stage.
 */
void log_event(const char *level, int fd, const char *ip, int port, const char *fmt, ...);

#endif
