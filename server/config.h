#ifndef CONFIG_H
#define CONFIG_H
#include <stddef.h>
#define DEFAULT_MAX_ALERTS 1000
#define MAX_CLIENTS 100
#define DEFAULT_SERVER_PORT 5555
#define DEFAULT_MAX_LOG_SIZE (10 * 1024 * 1024) /* 10 MB */
#define DEFAULT_LOG_LEVEL "info" 
#define DEFAULT_MAX_MESSAGE_SIZE (5 * 1024 * 1024) /* 5 MB by default */
void read_config(int *port, int *max_alerts, int *max_clients, size_t *max_log_size, char *log_level, size_t *max_message_size, int *use_disk_db);
#endif
