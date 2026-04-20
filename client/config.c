/* 
* BSD 3-Clause License
* Copyright (c) 2025, Alexander Shcheglov
* All rights reserved. 
*/

#include "config.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <sys/select.h>
#include <sys/stat.h>
#include <errno.h>

/* Helper function to trim leading and trailing whitespace */
static char *trim_spaces(char *str) {
    if (!str) return NULL;
    while (isspace((unsigned char)*str)) str++;
    if (*str == 0) return str;
    char *end = str + strlen(str) - 1;
    while (end > str && isspace((unsigned char)*end)) end--;
    end[1] = '\0';
    return str;
}

void read_config(Config *config, int verbose) {
    /* Set default values */
    memset(config->sync_psk, 0, sizeof(config->sync_psk)); 
    strncpy(config->server_ip, DEFAULT_SERVER_IP, sizeof(config->server_ip) - 1);
    config->server_ip[sizeof(config->server_ip) - 1] = '\0';
    config->server_port = DEFAULT_SERVER_PORT;
    config->exec_count = 0;

    FILE *conf_fp = fopen("/etc/gorgona/gorgona.conf", "r");
    if (!conf_fp) {
        if (verbose) fprintf(stderr, "Warning: Failed to open config file /etc/gorgona/gorgona.conf\n");
        return;
    }

    int in_server_section = 0;
    int in_exec_section = 0;
    char current_required_key[256] = ""; /* Empty string means "allow for any valid sender" */
    char line[512];

    while (fgets(line, sizeof(line), conf_fp)) {
        char *trimmed = trim_spaces(line);
        
        /* Skip empty lines and comments */
        if (*trimmed == '\0' || *trimmed == '#') continue;

        /* Parse section headers [section] */
        if (trimmed[0] == '[') {
            char *end = strchr(trimmed, ']');
            if (end) {
                *end = '\0';
                char *sec = trim_spaces(trimmed + 1);

                /* Handle exec_commands sections. Supports both:
                   [exec_commands] -> commands available to everyone
                   [exec_commands:KEY] -> commands available only for KEY */
                if (strncmp(sec, "exec_commands", 13) == 0) {
                    in_exec_section = 1;
                    in_server_section = 0;
                    
                    char *colon = strchr(sec, ':');
                    if (colon) {
                        /* Specific key required */
                        strncpy(current_required_key, trim_spaces(colon + 1), sizeof(current_required_key) - 1);
                        current_required_key[sizeof(current_required_key) - 1] = '\0';
                    } else {
                        /* No specific key (public section) */
                        current_required_key[0] = '\0';
                    }
                    
                    if (verbose) printf("Config: Entering exec_commands section, required_key='%s'\n", 
                                       current_required_key[0] ? current_required_key : "(any)");
                } 
                else if (strcmp(sec, "server") == 0) {
                    in_server_section = 1;
                    in_exec_section = 0;
                    current_required_key[0] = '\0';
                } 
                else {
                    /* Reset flags for any other sections */
                    in_server_section = 0;
                    in_exec_section = 0;
                }
                continue;
            }
        }

        /* Parse key = value pairs */
        char *delimiter = strchr(trimmed, '=');
        if (delimiter) {
            *delimiter = '\0';
            char *key = trim_spaces(trimmed);
            char *value = trim_spaces(delimiter + 1);

            if (in_server_section) {
                if (strcmp(key, "ip") == 0) {
                    strncpy(config->server_ip, value, sizeof(config->server_ip) - 1);
                    config->server_ip[sizeof(config->server_ip) - 1] = '\0';
                } else if (strcmp(key, "port") == 0) {
                    config->server_port = atoi(value);
                } else if (strcmp(key, "sync_psk") == 0) {
                    strncpy(config->sync_psk, value, sizeof(config->sync_psk) - 1);
                    config->sync_psk[sizeof(config->sync_psk) - 1] = '\0';
                }
            } 
            else if (in_exec_section) {
                /* Handle 'key = value' */
                if (strcmp(key, "key") == 0) {
                    strncpy(current_required_key, value, sizeof(current_required_key) - 1);
                    current_required_key[sizeof(current_required_key) - 1] = '\0';
                    continue;
                }

                if (config->exec_count < MAX_EXEC_COMMANDS) {
                    ExecCommand *cmd = &config->exec_commands[config->exec_count];
                    cmd->time_limit = 0; /* By default, there is no limit */
                    /* Replace everything to the right of the #, including the # itself, with the end of the line */
                    char *comment_ptr = strchr(value, '#');
                    if (comment_ptr) {
                        *comment_ptr = '\0';
                    }
                    /* find time_limit in the remaining (empty) string */
                    char *limit_ptr = strstr(value, "time_limit =");
                    if (limit_ptr) {
                        /* Extract the number */
                        cmd->time_limit = atoi(limit_ptr + 12);
                        /* Trim the line before “time_limit =” so that only the path remains */
                        *limit_ptr = '\0';
                    }
                    char *cleaned_path = trim_spaces(value);

                    /* Копируем результат в структуру */
                    strncpy(cmd->key, key, sizeof(cmd->key) - 1);
                    cmd->key[sizeof(cmd->key) - 1] = '\0';
                    
                    strncpy(cmd->value, cleaned_path, sizeof(cmd->value) - 1);
                    cmd->value[sizeof(cmd->value) - 1] = '\0';
                    
                    strncpy(cmd->required_key, current_required_key, sizeof(cmd->required_key) - 1);
                    cmd->required_key[sizeof(cmd->required_key) - 1] = '\0';

                    if (verbose) {
                        printf("Config: Loaded exec_command[%d]: key='%s' path='%s' limit=%ds\n",
                               config->exec_count, cmd->key, cmd->value, cmd->time_limit);
                    }
                    config->exec_count++;
                }
            }
        }
    }
    fclose(conf_fp);
}

/**
 * Optimized connect with a short timeout to bypass dead nodes quickly.
 */
int connect_with_timeout(const char *ip, int port, int timeout_ms) {
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) return -1;

    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    inet_pton(AF_INET, ip, &addr.sin_addr);

    int flags = fcntl(sock, F_GETFL, 0);
    fcntl(sock, F_SETFL, flags | O_NONBLOCK);

    int res = connect(sock, (struct sockaddr *)&addr, sizeof(addr));
    if (res < 0 && errno != EINPROGRESS) { close(sock); return -1; }

    struct timeval tv = { .tv_sec = timeout_ms / 1000, .tv_usec = (timeout_ms % 1000) * 1000 };
    fd_set fdset; FD_ZERO(&fdset); FD_SET(sock, &fdset);

    res = select(sock + 1, NULL, &fdset, NULL, &tv);
    if (res > 0) {
        int so_error; socklen_t len = sizeof(so_error);
        getsockopt(sock, SOL_SOCKET, SO_ERROR, &so_error, &len);
        if (so_error == 0) {
            fcntl(sock, F_SETFL, flags);
            int nodelay = 1;
            setsockopt(sock, IPPROTO_TCP, TCP_NODELAY, (char *)&nodelay, sizeof(int));
            return sock;
        }
    }
    close(sock); return -1;
}

int try_sticky_node(int verbose) {
    int fd = open(STICKY_NODE_PATH, O_RDONLY);
    if (fd < 0) return -1;
    char buf[64]; ssize_t n = read(fd, buf, sizeof(buf)-1);
    close(fd);
    if (n <= 0) return -1;
    buf[n] = '\0';
    char *port_ptr = strchr(buf, ':');
    if (!port_ptr) return -1;
    *port_ptr = '\0';
    if (verbose) printf("Mesh: Sticky connect via [%s:%s]\n", buf, port_ptr + 1);
    return connect_with_timeout(buf, atoi(port_ptr + 1), 500);
}

void save_sticky_node(const char *ip, int port) {
    int fd = open(STICKY_NODE_PATH, O_WRONLY | O_CREAT | O_TRUNC, 0666);
    if (fd >= 0) {
        char buf[64];
        int len = snprintf(buf, sizeof(buf), "%s:%d", ip, port);
        if (len > 0) write(fd, buf, (size_t)len);
        close(fd);
        chmod(STICKY_NODE_PATH, 0666);
    }
}

void invalidate_sticky_node() {
    unlink(STICKY_NODE_PATH);
}

int perform_l2_auth(int sock, const char *psk, int verbose) {
    char auth_req[256];
    int len = snprintf(auth_req, sizeof(auth_req), "AUTH|%s|0", psk);
    uint32_t len_net = htonl((uint32_t)len);
    if (send(sock, &len_net, sizeof(uint32_t), MSG_NOSIGNAL) != sizeof(uint32_t) ||
        send(sock, auth_req, (size_t)len, MSG_NOSIGNAL) != len) return -1;

    uint32_t resp_len_net;
    if (recv(sock, &resp_len_net, sizeof(uint32_t), MSG_WAITALL) != sizeof(uint32_t)) return -1;
    size_t resp_len = ntohl(resp_len_net);
    if (resp_len > 1024) return -1;

    char buf[1024];
    if (recv(sock, buf, resp_len, MSG_WAITALL) != (ssize_t)resp_len) return -1;
    buf[resp_len] = '\0';

    if (strncmp(buf, "AUTH_SUCCESS", 12) == 0) return 0;
    if (verbose) fprintf(stderr, "Mesh: L2 Auth error: %s\n", buf);
    return -1;
}
