/* 
* BSD 3-Clause License
* Copyright (c) 2025, Alexander Shcheglov
* All rights reserved. 
*/

#include "commands.h"
#include "gorgona_utils.h"
#include "admin_mesh.h" 
#include "snowflake.h"
#include "metrics.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <sys/select.h>
#include <errno.h>
#include <time.h>
#include <stdbool.h>
#include <fcntl.h>
#include <fcntl.h>
#include <netdb.h>
#include <signal.h>

extern volatile sig_atomic_t reload_cfg_requested;
extern int verbose;
extern FILE *log_file;
extern int max_clients;
extern size_t max_message_size;
extern char log_level[32];
extern int client_sockets[];
extern Subscriber subscribers[];

time_t server_start_time = 0;

/*
 * Configures TCP Keepalive to maintain connection stability
 * and detect “dead” nodes. 
 */
static void set_tcp_keepalive(int fd) {
    int opt = 1;
    setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, &opt, sizeof(opt));
#ifdef __linux__
    int idle = 30;     /* Start the check after 30 seconds of inactivity */ 
    int interval = 5;  /* The interval between samples is 5 seconds */ 
    int keep_count = 3; /* 3 failed attempts = failure */
    setsockopt(fd, IPPROTO_TCP, TCP_KEEPIDLE, &idle, sizeof(idle));
    setsockopt(fd, IPPROTO_TCP, TCP_KEEPINTVL, &interval, sizeof(interval));
    setsockopt(fd, IPPROTO_TCP, TCP_KEEPCNT, &keep_count, sizeof(keep_count));
#endif
}

/*
 * Completely clear the client/peer state upon disconnection. 
 */
void cleanup_subscriber(int index) {
    int sd = client_sockets[index];
    if (sd <= 0) return;

    Subscriber *sub = &subscribers[index];
    /* We synchronize the port before the structure is used */
    if (sub->node_ptr && sub->node_ptr->port > 0) {
        sub->port = sub->node_ptr->port;
    }
    /* [LAYER 2 INTEGRATION] 
     * Identify the peer IP before clearing metadata.
     */
    char disconnected_ip[64];
    strncpy(disconnected_ip, subscribers[index].ip_address, sizeof(disconnected_ip) - 1);

    /* If it was an outgoing party, mark it as inactive in the global list */
    for (int p = 0; p < remote_peer_count; p++) {
        if (remote_peers[p].sd == sd) {
            remote_peers[p].active = false;
            remote_peers[p].sd = -1;
            break;
        }
    }

    /* [MESH TABLE UPDATE]
     * Find the node in the cluster table and mark it as OFFLINE.
     * This ensures the Score/Status updates immediately.
     */
    for (int n = 0; n < cluster_node_count; n++) {
        if (mesh_addr_compare(&cluster_nodes[n], disconnected_ip)) {
            cluster_nodes[n].status = PEER_STATUS_OFFLINE;
            /* Reset volatile metrics so it doesn't stay in priority routing */
            cluster_nodes[n].metrics.gorgona_score = 0.0;
            cluster_nodes[n].metrics.last_rtt = 0.0;
            break;
        }
    }

    close(sd);
    client_sockets[index] = 0;
    subscribers[index].sock = 0;
    subscribers[index].type = SUB_TYPE_CLIENT;
    subscribers[index].auth_state = AUTH_NONE;
    subscribers[index].last_repl_id = 0;
    subscribers[index].mode = 0;
    subscribers[index].pubkey_hash[0] = '\0';
    subscribers[index].close_after_send = false;
    
    free_out_queue(index);
    if (subscribers[index].in_buffer) free(subscribers[index].in_buffer);
    subscribers[index].in_buffer = NULL;
    subscribers[index].in_pos = 0;
}

/**
 * Merged Binary Enqueue (Fixes 40ms Nagle/Delayed ACK delay)
 * We pack [length:4] + [payload:N] into a single contiguous memory block.
 */
void enqueue_message(int sub_index, const char *msg, size_t msg_len) {
    if (!msg || msg_len == 0) return;

    /* Performance Logging */
    log_event("DEBUG", subscribers[sub_index].sock, subscribers[sub_index].ip_address, 
              subscribers[sub_index].port, "Enqueued combined response (%zu bytes payload)", 
              msg_len);

    /* Allocate one block for everything: 4 bytes for header + N bytes for payload */
    size_t total_payload_size = sizeof(uint32_t) + msg_len;
    
    OutBuffer *new_buf = malloc(sizeof(OutBuffer));
    if (!new_buf) return;

    new_buf->data = malloc(total_payload_size);
    if (!new_buf->data) {
        free(new_buf);
        return;
    }

    /* 1. Pack the 4-byte big-endian length header at the beginning */
    uint32_t len_net = htonl((uint32_t)msg_len);
    memcpy(new_buf->data, &len_net, sizeof(uint32_t));

    /* 2. Pack the actual message data right after the header */
    memcpy(new_buf->data + sizeof(uint32_t), msg, msg_len);

    new_buf->len = total_payload_size;
    new_buf->pos = 0;
    new_buf->next = NULL;

    /* 3. Add this SINGLE atomic packet to the outgoing queue */
    if (subscribers[sub_index].out_tail) {
        subscribers[sub_index].out_tail->next = new_buf;
        subscribers[sub_index].out_tail = new_buf;
    } else {
        subscribers[sub_index].out_head = subscribers[sub_index].out_tail = new_buf;
    }
}

/**
 * Queue plain text for sending (used for info/version commands).
 */
void enqueue_text_only(int sub_index, const char *msg, size_t msg_len) {
    OutBuffer *new_buf = malloc(sizeof(OutBuffer));
    if (!new_buf) return;
    new_buf->data = malloc(msg_len);
    if (!new_buf->data) { free(new_buf); return; }
    memcpy(new_buf->data, msg, msg_len);
    new_buf->len = msg_len;
    new_buf->pos = 0;
    new_buf->next = NULL;
    if (subscribers[sub_index].out_tail) {
        subscribers[sub_index].out_tail->next = new_buf;
        subscribers[sub_index].out_tail = new_buf;
    } else {
        subscribers[sub_index].out_head = subscribers[sub_index].out_tail = new_buf;
    }
}

/**
 * Handle outgoing data for a specific client.
 */
void process_out(int sub_index, int sd) {
    OutBuffer *head = subscribers[sub_index].out_head;
    Subscriber *sub = &subscribers[sub_index];

    while (head) {
        ssize_t sent = send(sd, head->data + head->pos, head->len - head->pos, 0);
        if (sent > 0) {
            head->pos += sent;
            if (head->pos == head->len) {
                OutBuffer *tmp = head;
                subscribers[sub_index].out_head = head->next;
                if (subscribers[sub_index].out_head == NULL) subscribers[sub_index].out_tail = NULL;
                free(tmp->data);
                free(tmp);
                head = subscribers[sub_index].out_head;
            }
        } else if (sent == 0) {
            /* Client closed connection while we were sending */
            log_event("INFO", sd, sub->ip_address, sub->port, "Connection closed by client during send");
            close(sd);
            client_sockets[sub_index] = 0;
            free_out_queue(sub_index);
            break;
        } else {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                break;  /* Socket buffer full, wait for next select */
            } else {
                log_event("ERROR", sd, sub->ip_address, sub->port, "Send error: %s", strerror(errno));
                close(sd);
                client_sockets[sub_index] = 0;
                free_out_queue(sub_index);
                break;
            }
        }
    }

    /* Handle graceful shutdown after sending requested info (like 'info' or 'version') */
    if (subscribers[sub_index].out_head == NULL && subscribers[sub_index].close_after_send) {
        if (sub->node_ptr && sub->node_ptr->port > 0) {
            sub->port = sub->node_ptr->port;
        }
        log_event("INFO", sd, sub->ip_address, sub->port, "Session finished");
        close(sd);
        client_sockets[sub_index] = 0;
        sub->sock = 0;
        sub->mode = 0;
        sub->pubkey_hash[0] = '\0';
        free_out_queue(sub_index);
        if (sub->in_buffer) free(sub->in_buffer);
        sub->in_buffer = NULL;
        sub->in_pos = 0;
        sub->close_after_send = false;
    }
}

int has_pending_data(int sub_index) {
    return subscribers[sub_index].out_head != NULL || subscribers[sub_index].close_after_send;
}

void free_out_queue(int sub_index) {
    OutBuffer *current = subscribers[sub_index].out_head;
    while (current) {
        OutBuffer *tmp = current;
        current = current->next;
        free(tmp->data);
        free(tmp);
    }
    subscribers[sub_index].out_head = NULL;
    subscribers[sub_index].out_tail = NULL;
}

void try_connect_peers() {
    static time_t last_check = 0;
    time_t now = time(NULL);
    if (now - last_check < PEER_RECONNECT_INTERVAL) return;
    last_check = now;
    for (int p = 0; p < cluster_node_count; p++) {
        MeshNode *node = &cluster_nodes[p];
        if (node->status == PEER_STATUS_BANNED || node->status == PEER_STATUS_HANDSHAKE) continue;
        if (node->port <= 0 || node->penalty_until > now) continue;
        /* --- DNS RESOLUTION & CONNECTION --- */
        struct addrinfo hints, *res, *rp;
        char port_str[12];
        snprintf(port_str, sizeof(port_str), "%d", node->port);
        memset(&hints, 0, sizeof(hints));
        hints.ai_family = AF_INET;       /* Force IPv4 for current core compatibility */
        hints.ai_socktype = SOCK_STREAM;
        /* `getaddrinfo` resolves both “gorgon-service.default.svc” and “1.2.3.4” */
        if (getaddrinfo(node->addr, port_str, &hints, &res) != 0) {
            node->metrics.fail_count++;
            continue; 
        }
        int sd = -1;
        for (rp = res; rp != NULL; rp = rp->ai_next) {
            sd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
            if (sd == -1) continue;
            set_tcp_keepalive(sd);
            fcntl(sd, F_SETFL, fcntl(sd, F_GETFL, 0) | O_NONBLOCK);
            if (connect(sd, rp->ai_addr, rp->ai_addrlen) < 0) {
                if (errno != EINPROGRESS) {
                    close(sd);
                    sd = -1;
                    continue;
                }
            }
            /* In fact, the connection was successfully established */
            char resolved_ip[64];
            getnameinfo(rp->ai_addr, rp->ai_addrlen, resolved_ip, sizeof(resolved_ip), NULL, 0, NI_NUMERICHOST);
            /* STRICT DUPLICATE CHECK по резолвленному IP */
            bool already_linked = false;
            for (int i = 0; i < max_clients; i++) {
                if (client_sockets[i] > 0 && strcmp(subscribers[i].ip_address, resolved_ip) == 0) {
                    already_linked = true;
                    
                    /* [FIX] Link logic: if we found an existing connection for this IP,
                       ensure it points to the most important node entry (SEED) */
                    if (node->is_seed && (subscribers[i].node_ptr == NULL || !subscribers[i].node_ptr->is_seed)) {
                        subscribers[i].node_ptr = node;
                    }
                    
                    /* Synchronize status */
                    if (subscribers[i].auth_state == AUTH_OK) {
                        node->status = PEER_STATUS_AUTHENTICATED;
                    }
                    break;
                }
            }
            if (already_linked) {
                close(sd);
                sd = -1;
                continue;
            }
            /* We found a slot and reserved it */
            int i;
            for (i = 0; i < max_clients; i++) {
                if (client_sockets[i] == 0) {
                    client_sockets[i] = sd;
                    Subscriber *sub = &subscribers[i];
                    sub->sock = sd;
                    /* We specifically retain the numeric IP address for logs and PEX */
                    strncpy(sub->ip_address, resolved_ip, sizeof(sub->ip_address) - 1);
                    sub->port = node->port;
                    sub->type = SUB_TYPE_PEER;
                    sub->auth_state = AUTH_SENT;
                    sub->node_ptr = node;
                    node->status = PEER_STATUS_HANDSHAKE;
                    /* PSK Handshake */
                    char auth_msg[256];
                    extern int port;
                    int auth_len = snprintf(auth_msg, sizeof(auth_msg), "AUTH|%s|%d|%d|%d", 
                                            sync_psk, max_alerts, max_alert_ttl, port);
                    enqueue_message(i, auth_msg, (size_t)auth_len);
                    break;
                }
            }
            if (i == max_clients) close(sd);
            break;
        }
        freeaddrinfo(res);
    }
}

/*
 * Main server loop using select().
 */
void run_server(int server_fd) {
    int new_socket, activity, valread, sd;
    int max_sd;
    struct sockaddr_in address;
    int addrlen = sizeof(address);
    fd_set readfds;
    fd_set writefds;

    if (server_start_time == 0) {
        server_start_time = time(NULL);
    }

    while (1) {
        /* RELOAD] */
        if (reload_cfg_requested) {
            reload_cfg_requested = 0;
            log_event("INFO", -1, NULL, 0, "SIGHUP received, reloading configuration...");
            int p_tmp, ma_tmp, mc_tmp, vt_tmp, si_tmp, ttl_tmp, db_tmp;
            size_t mls_tmp, mms_tmp;
            char lvl_tmp[32];
            read_config(&p_tmp, &ma_tmp, &mc_tmp, &mls_tmp, lvl_tmp, &mms_tmp, &db_tmp, &vt_tmp, &si_tmp, &ttl_tmp);
            max_alerts = ma_tmp;
            sync_interval = si_tmp;
            vacuum_threshold = vt_tmp;
            max_alert_ttl = ttl_tmp;
            max_log_size = mls_tmp;
            max_message_size = mms_tmp;
            strncpy(log_level, lvl_tmp, 31);
            log_level[31] = '\0';
            if (mc_tmp > max_clients) {
                if (mc_tmp > MAX_CLIENTS) mc_tmp = MAX_CLIENTS;
                max_clients = mc_tmp;
            }
            if (db_tmp != use_disk_db) {
                log_event("WARN", -1, NULL, 0, "use_disk_db change requires full restart. Ignoring.");
            }

            log_event("INFO", -1, NULL, 0, "Configuration reloaded. Sync interval: %d, Log level: %s", sync_interval, log_level);
        }

        FD_ZERO(&readfds);
        FD_ZERO(&writefds);
        FD_SET(server_fd, &readfds);
        max_sd = server_fd;
        for (int i = 0; i < max_clients; i++) {
            sd = client_sockets[i];
            if (sd > 0) {
                if (!subscribers[i].close_after_send) {
                    FD_SET(sd, &readfds);
                }
                if (has_pending_data(i)) {
                    FD_SET(sd, &writefds);
                }
                if (sd > max_sd) max_sd = sd;
            }
        }
        /* Dynamic timeout calculation */
        time_t now = time(NULL);
        static time_t last_maintenance = 0;
        /* When the program is first launched, we set the time of the last check to the current time */
        if (last_maintenance == 0) last_maintenance = now;
        /* Calculate the time remaining until the next synchronization */
        int elapsed = (int)(now - last_maintenance);
        int seconds_to_next_sync = sync_interval - elapsed;
        if (seconds_to_next_sync < 0) seconds_to_next_sync = 0;
        struct timeval timeout;
        /* Optimal interval: wait no more than 5 seconds to quickly detect 
           new connections and status changes, or less if the server is already nearby. */
        timeout.tv_sec = (seconds_to_next_sync > 5) ? 5 : seconds_to_next_sync;
        timeout.tv_usec = 0;
        /* Attempt to connect to peers (non-blocking) */
        try_connect_peers();
        /* Waiting for activity on the sockets or for a timeout */
        activity = select(max_sd + 1, &readfds, &writefds, NULL, &timeout);  
        if (activity < 0) {
            if (errno == EINTR) {
                /* A signal to reload the configuration has been received; we're going back to the beginning of the `while(1)` loop, where the `reload` block will execute. */
                continue; 
            }
            /* If this is a real socket error, log it */
            log_event("ERROR", -1, NULL, 0, "Select error: %s", strerror(errno));
            continue;
        }

        /* Checking the timeout and service */
        now = time(NULL);
        if (activity == 0 || (now - last_maintenance) >= sync_interval) {
            run_global_maintenance();
            last_maintenance = now; 
            continue;
        } 

        /* Handle new incoming connection */
        if (FD_ISSET(server_fd, &readfds)) {
            if ((new_socket = accept(server_fd, (struct sockaddr *)&address, (socklen_t*)&addrlen)) < 0) {
                log_event("ERROR", -1, NULL, 0, "Accept failed: %s", strerror(errno));
                continue;
            }

            int flags = fcntl(new_socket, F_GETFL, 0);
            if (flags == -1 || fcntl(new_socket, F_SETFL, flags | O_NONBLOCK) == -1) {
                log_event("ERROR", new_socket, inet_ntoa(address.sin_addr), ntohs(address.sin_port), "fcntl O_NONBLOCK failed");
                close(new_socket);
                continue;
            }

            int i;
            for (i = 0; i < max_clients; i++) {
                if (client_sockets[i] == 0) {
                    client_sockets[i] = new_socket;
                    subscribers[i].sock = new_socket;
                    
                    inet_ntop(AF_INET, &address.sin_addr, subscribers[i].ip_address, INET_ADDRSTRLEN); 

                    /* [NODE LINKING & PORT AUTO-CORRECTION] 
                     * We bind a pointer to the mesh node and take the logical port 
                     */
                    int display_port = ntohs(address.sin_port);
                    subscribers[i].node_ptr = NULL; 
                    
                    for (int n = 0; n < cluster_node_count; n++) {
                        if (mesh_addr_compare(&cluster_nodes[n], subscribers[i].ip_address)) { 
                            subscribers[i].node_ptr = &cluster_nodes[n]; /* Link the subscriber to the mesh node for future reference */
                            if (cluster_nodes[n].port > 0) {
                                display_port = cluster_nodes[n].port;
                            }
                            break;
                        }
                    }
                    subscribers[i].port = display_port;
                    subscribers[i].connect_time = time(NULL);
                    subscribers[i].out_head = NULL;
                    subscribers[i].out_tail = NULL;
                    subscribers[i].read_state = READ_LEN;
                    subscribers[i].expected_msg_len = 0;
                    subscribers[i].in_buffer = NULL;
                    subscribers[i].in_pos = 0;
                    subscribers[i].mode = 0;
                    subscribers[i].type = SUB_TYPE_CLIENT; 
                    subscribers[i].auth_state = AUTH_NONE;
                    subscribers[i].last_repl_id = 0;
                    subscribers[i].pubkey_hash[0] = '\0';
                    subscribers[i].close_after_send = false;

                    log_event("DEBUG", new_socket, subscribers[i].ip_address, subscribers[i].port, "New connection");
                    break;
                }
            }
            if (i == max_clients) {
                char *error_msg = "Error: Too many clients\n";
                send(new_socket, error_msg, strlen(error_msg), 0);
                log_event("WARN", new_socket, inet_ntoa(address.sin_addr), ntohs(address.sin_port), "Connection refused: MAX_CLIENTS reached");
                close(new_socket);
                continue;
            }
        }

        /* Process client activity inside the main loop */
        for (int i = 0; i < max_clients; i++) {
            sd = client_sockets[i];
            if (sd <= 0) continue;

            if (FD_ISSET(sd, &writefds)) {
                process_out(i, sd);
            }

            /* Check if the socket was closed during process_out */
            if (client_sockets[i] <= 0) continue; 

            if (FD_ISSET(sd, &readfds)) {
                Subscriber *sub = &subscribers[i];
                valread = 0;

                /* STATE: Waiting for message length or text command */
                if (sub->read_state == READ_LEN) {
                    if (!sub->in_buffer) {
                        sub->in_buffer = malloc(1024); 
                        if (!sub->in_buffer) {
                            log_event("ERROR", sd, sub->ip_address, sub->port, 
                                      "CRITICAL: Memory allocation failed for initial buffer (1KB)");
                            cleanup_subscriber(i); 
                            continue;
                        }
                        sub->in_pos = 0;
                    }

                    char peek_byte;
                    /* PEEK: look at the first byte without removing it from the socket queue */
                    valread = recv(sd, &peek_byte, 1, MSG_PEEK);
                    
                    if (valread > 0) {
                        unsigned char first_byte = (unsigned char)peek_byte;

                        /* 1. DETECTION OF HTTPS (0x16 = TLS Handshake) */
                        if (first_byte == 0x16) {
                            if (verbose) log_event("INFO", sd, sub->ip_address, sub->port, "HTTPS metrics probe detected. Forking to SSL handler.");
                            pid_t pid = fork();
                            if (pid < 0) {
                                log_event("ERROR", sd, sub->ip_address, sub->port, "Fork failed for HTTPS request");
                                cleanup_subscriber(i);
                                continue;
                            }
                            if (pid == 0) {
                                /* --- CHILD PROCESS --- */
                                /* 1. Close the listener and ALL other client sockets to prevent resource leaks */
                                if (server_fd > 0) close(server_fd); 
                                for (int j = 0; j < max_clients; j++) {
                                    if (client_sockets[j] > 0 && client_sockets[j] != sd) {
                                        close(client_sockets[j]);
                                    }
                                }
                                /* 2. FIX: Correct fcntl logic to restore blocking mode */
                                int flags = fcntl(sd, F_GETFL, 0);
                                if (flags != -1) {
                                    fcntl(sd, F_SETFL, flags & ~O_NONBLOCK);
                                }
                                /* 3. Handle the metrics request (blocking OpenSSL call) */
                                handle_https_metrics_request(sd);
                                /* 4. Exit child immediately */
                                exit(0);
                            } else {
                                /* --- PARENT PROCESS --- */
                                /* Close our reference to this socket as it's now handled by the child */
                                close(sd);
                                client_sockets[i] = 0;
                                if (sub->in_buffer) {
                                    free(sub->in_buffer);
                                    sub->in_buffer = NULL;
                                }
                                memset(sub, 0, sizeof(Subscriber));
                                /* Parent stays in select() and handles other events */
                                continue;
                            }
                        }

                        /* 2. GORGONA CORE PROTOCOLS (Binary/Text) */
                        char byte; /* Declared and initialized via read() below */
                        if (read(sd, &byte, 1) <= 0) {
                            cleanup_subscriber(i);
                            continue;
                        }

                        /* 3. DETECTION OF PLAIN HTTP (GET ) */
                        if (byte == 'G') {
                            /* If Prometheus/User comes via plain HTTP, send 403 and close */
                            const char *reject = "HTTP/1.1 403 Forbidden\r\nContent-Type: text/plain\r\n\r\nPlease use HTTPS (Port 7777).\r\n";
                            send(sd, reject, strlen(reject), 0);
                            cleanup_subscriber(i);
                            continue;
                        }

                        /* 4. PROCESS GORGONA PAYLOAD (L1 DATA) */
                        sub->in_buffer[sub->in_pos++] = byte;
                        unsigned char protocol_first_byte = (unsigned char)sub->in_buffer[0];

                        /* --- BINARY MODE DETECTION --- */
                        if (protocol_first_byte < 32 && protocol_first_byte != '\n' && protocol_first_byte != '\r' && protocol_first_byte != '\t') {
                            if (sub->in_pos == 1 && sub->auth_state == AUTH_NONE) { 
                                log_event("DEBUG", sd, sub->ip_address, sub->port, "Client identified: Gorgona Binary Protocol");
                                sub->auth_state = 99; 
                            }
                            if (sub->in_pos == 4) {
                                uint32_t temp_len;
                                memcpy(&temp_len, sub->in_buffer, 4);
                                temp_len = ntohl(temp_len);
                                
                                if (temp_len > max_message_size || temp_len == 0) {
                                    char err_size[256];
                                    int l = snprintf(err_size, sizeof(err_size), "Error: Message size (%u) exceeds limit.\n", temp_len);
                                    enqueue_message(i, err_size, l);
                                    sub->close_after_send = true; 
                                    continue; 
                                }

                                sub->expected_msg_len = temp_len;
                                char *new_binary_buf = malloc(sub->expected_msg_len + 1);
                                if (new_binary_buf) {
                                    free(sub->in_buffer);
                                    sub->in_buffer = new_binary_buf;
                                    sub->in_pos = 0;
                                    sub->read_state = READ_MSG;
                                } else {
                                    /* ДОБАВЛЯЕМ ЛОГ ОШИБКИ */
                                    log_event("ERROR", sd, sub->ip_address, sub->port, 
                                              "CRITICAL: Memory allocation failed for payload (%u bytes)", temp_len);
                                    cleanup_subscriber(i);
                                    continue;
                                }
                            }
                        } 
                        /* --- TEXT MODE DETECTION --- */
                        else if (protocol_first_byte >= 32 || protocol_first_byte == '\n' || protocol_first_byte == '\r' || protocol_first_byte == '\t') {
                            if (sub->in_pos == 1 && sub->auth_state == AUTH_NONE && byte != 'G') { 
                                log_event("INFO", sd, sub->ip_address, sub->port, "Client identified: Gorgona Text/Interactive");
                                sub->auth_state = 99;
                            }
                            if (byte == '\r') {
                                sub->in_pos--; /* Ignore carriage returns */
                                continue;
                            }
                            if (byte == '\n') {
                                sub->in_buffer[sub->in_pos] = '\0';
                                trim_string(sub->in_buffer);

                                if (strlen(sub->in_buffer) > 0) {
                                    log_event("DEBUG", sd, sub->ip_address, sub->port, "Text command received: %s", sub->in_buffer);

                                    /* Command Handlers (info, help, status...) */
                                    if (strcmp(sub->in_buffer, "help") == 0) {
                                        const char *h_msg = "--- Gorgona Node Help ---\nCommands: help, info, status <psk>\n";
                                        enqueue_text_only(i, h_msg, strlen(h_msg));
                                        sub->close_after_send = true;
                                    } 
                                    /* COMMAND: info / ? - Node identification and uptime (no version disclosure) */
                                    else if (strcmp(sub->in_buffer, "info") == 0 || strcmp(sub->in_buffer, "?") == 0) {
                                        time_t now = time(NULL);
                                        double uptime_sec = difftime(now, server_start_time);
                                        int d = (int)(uptime_sec / 86400);
                                        int h = (int)((uptime_sec / 3600) - (d * 24));
                                        int m = (int)((uptime_sec / 60) - (d * 1440) - (h * 60));

                                        char info_msg[256];
                                        int info_len = snprintf(info_msg, sizeof(info_msg),
                                            "Gorgona Node | Uptime: %dd %dh %dm\nGoodbye Sir.\n", d, h, m);
                                        enqueue_text_only(i, info_msg, info_len);
                                        sub->close_after_send = true;
                                    } 
                                    /* COMMAND: status <psk> - Authenticated diagnostic report */
                                    else if (strncmp(sub->in_buffer, "status", 6) == 0) {
                                        char *provided_psk = sub->in_buffer + 6;
                                        while (*provided_psk == ' ') provided_psk++; 

                                        if (provided_psk[0] == '\0' || strcmp(provided_psk, sync_psk) != 0) {
                                            log_event("WARN", sd, sub->ip_address, sub->port, "Unauthorized status request");
                                            enqueue_text_only(i, "Error: Unauthorized\n", 19);
                                        } else {
                                            /* 1. Предварительная очистка базы по логическому времени Pulse */
                                            run_global_maintenance();

                                            char status_msg[4096];
                                            int pos = 0; 
                                            time_t now = time(NULL);

                                            /* Получаем IP и порт сервера */
                                            struct sockaddr_in node_addr;
                                            socklen_t node_addr_len = sizeof(node_addr);
                                            char node_ip[INET_ADDRSTRLEN] = "0.0.0.0";
                                            int node_port = 0;
                                            if (getsockname(sd, (struct sockaddr *)&node_addr, &node_addr_len) == 0) {
                                                inet_ntop(AF_INET, &node_addr.sin_addr, node_ip, sizeof(node_ip));
                                                node_port = ntohs(node_addr.sin_port);
                                            }

                                            /* 2. Метрики соединений */
                                            int active_clients = 0;
                                            int authenticated_peers = 0;
                                            for (int j = 0; j < max_clients; j++) {
                                                if (client_sockets[j] > 0) {
                                                    if (subscribers[j].auth_state == AUTH_OK) {
                                                        if (subscribers[j].type == SUB_TYPE_PEER) authenticated_peers++;
                                                        else active_clients++;
                                                    }
                                                }
                                            }

                                            /* 3. Расчет метрик хранилища по живой памяти */
                                            int live_alerts = 0;
                                            int total_waste = 0;
                                            size_t total_bytes = 0;
                                            time_t oldest_ts = 0;

                                            for (int r = 0; r < recipient_count; r++) {
                                                Recipient *rec = &recipients[r];
                                                total_waste += rec->waste_count;
                                                total_bytes += rec->used_size;
                                                
                                                for (int a = 0; a < rec->count; a++) {
                                                    if (rec->alerts[a].active) {
                                                        live_alerts++;
                                                        if (oldest_ts == 0 || rec->alerts[a].create_at < oldest_ts) {
                                                            oldest_ts = rec->alerts[a].create_at;
                                                        }
                                                    }
                                                }
                                            }

                                            /* 4. Formatting of Time Stamps (Cluster Pulse Time) */
                                            uint64_t current_max_id = get_max_alert_id();
                                            char pulse_time_str[32] = "N/A";
                                            char oldest_time_str[32] = "N/A";
                                            struct tm tm_res;

                                            if (current_max_id > 0) {
                                                time_t pulse_t = snowflake_to_timestamp(current_max_id);
                                                if (gmtime_r(&pulse_t, &tm_res)) strftime(pulse_time_str, 32, "%Y-%m-%d %H:%M:%S", &tm_res);
                                            }
                                            if (oldest_ts > 0) {
                                                if (gmtime_r(&oldest_ts, &tm_res)) strftime(oldest_time_str, 32, "%Y-%m-%d %H:%M:%S", &tm_res);
                                            }

                                            double uptime_sec = difftime(now, server_start_time);
                                            int ud = (int)(uptime_sec/86400), uh = (int)(uptime_sec/3600)%24, um = (int)(uptime_sec/60)%60;

                                            /* 5. Финальная сборка в вашем оригинальном формате */
                                            pos += snprintf(status_msg + pos, sizeof(status_msg) - pos,
                                                "--- Gorgona Node [%s %d] Detailed Status ---\n" 
                                                "Version: %s\n"
                                                "Uptime: %dd %dh %dm\n"
                                                "Connections:\n"
                                                "  - Active Clients: %d / %d\n"
                                                "  - Authenticated Peers: %d / %d (connected)\n"
                                                "Storage Metrics:\n"
                                                "  - DB Storage Mode: %s\n"
                                                "  - Unique Recipients (Keys): %d\n"
                                                "  - Active Alerts (Live): %d\n"
                                                "  - Cluster Pulse (MaxID): %" PRIu64 "\n"
                                                "  - Database Size: %.2f MB\n"
                                                "  - Disk Waste (Awaiting Vacuum): %d\n"
                                                "  - Vacuum Threshold: %d%%\n"
                                                "  - History Starts From:  [%s UTC]\n"
                                                "  - Last Data Ingest:     [%s UTC]\n"
                                                "Operational Configuration:\n"
                                                "  - Max Alerts per Key: %d\n"
                                                "  - Max Alert TTL: %d seconds (%.1f days)\n"
                                                "  - Max Message Size: %zu MB\n"
                                                "  - Logging Level: %s\n",
                                                node_ip, node_port, VERSION, ud, uh, um,
                                                active_clients, max_clients,
                                                authenticated_peers, remote_peer_count,
                                                use_disk_db ? "Persistent (Disk)" : "Ephemeral (Memory)",
                                                recipient_count, live_alerts, current_max_id,
                                                (double)total_bytes / (1024 * 1024), total_waste, vacuum_threshold,
                                                oldest_time_str, pulse_time_str,
                                                max_alerts, max_alert_ttl, (double)max_alert_ttl / 86400.0,
                                                (size_t)(max_message_size / (1024 * 1024)), log_level
                                            );

                                            /* 6. Секция L2 Топологии */
                                            mesh_recalculate_scores(); 
                                            pos += snprintf(status_msg + pos, sizeof(status_msg) - pos, 
                                                            "--- L2 Cluster Topology (Known nodes: %d) ---\n", cluster_node_count);
                                            for (int n = 0; n < cluster_node_count && pos < (int)sizeof(status_msg) - 256; n++) {
                                                MeshNode *node = &cluster_nodes[n];
                                                /* Формируем строку: Имя (IP если есть) */
                                                char display_addr[1024];
                                                if (node->resolved_ip[0] != '\0' && strcmp(node->addr, node->resolved_ip) != 0) {
                                                    snprintf(display_addr, sizeof(display_addr), "%.500s (%.500s)", node->addr, node->resolved_ip); 
                                                } else {
                                                    snprintf(display_addr, sizeof(display_addr), "%.1023s", node->addr); 
                                                }

                                                pos += snprintf(status_msg + pos, sizeof(status_msg) - pos,
                                                    "  [%-40s:%-5d] Score: %.2f | RTT: %6.1f ms | Spd: %6.1f KB/s | %s [%s]\n",
                                                    display_addr, node->port, node->metrics.gorgona_score,
                                                    node->metrics.last_rtt, node->metrics.rolling_avg_speed / 1024.0,
                                                    node->is_seed ? "SEED" : (node->is_cached ? "CACHE" : "PEX "),
                                                    (node->status == PEER_STATUS_AUTHENTICATED) ? "UP" : "DEAD"); 
                                            }
                                            pos += snprintf(status_msg + pos, sizeof(status_msg) - pos, 
                                                            "-----------------------------------------------------\n");
                                            enqueue_text_only(i, status_msg, pos);
                                        }
                                        sub->close_after_send = true;
                                    }
                                    /* Handle unknown text commands */
                                    else {
                                        log_event("WARN", sd, sub->ip_address, sub->port, "Unknown text command: %s", sub->in_buffer);
                                        enqueue_text_only(i, "Error: Unknown command. Type 'help' for options.\n", 50);
                                        sub->close_after_send = true;
                                    }
                                }
                                sub->in_pos = 0;
                                continue;
                            }

                            /* Prevent text buffer overflow and DoS attempts via long strings */
                            if (sub->in_pos >= max_message_size) {
                                log_event("WARN", sd, sub->ip_address, sub->port, "Text command buffer limit exceeded");
                                enqueue_text_only(i, "Error: Command too long\n", 25);
                                sub->close_after_send = true;
                                sub->in_pos = 0;
                            }
                        }
                        /* 3. INVALID PROTOCOL (e.g., non-zero binary garbage) */
                        else {
                            log_event("WARN", sd, sub->ip_address, sub->port, "Protocol mismatch (byte 0x%02X). Closing.", first_byte);
                            close(sd);
                            client_sockets[i] = 0;
                            if (sub->in_buffer) free(sub->in_buffer);
                            sub->in_buffer = NULL;
                            sub->in_pos = 0;
                            continue;
                        }
                    } else if (valread == 0) {
                        /* Connection closed by client while idle */
                        if (sub->node_ptr && sub->node_ptr->port > 0) {
                            sub->port = sub->node_ptr->port;
                        } 
                        log_event("INFO", sd, sub->ip_address, sub->port, "Client disconnected") ;
                        cleanup_subscriber(i); 
                        if (sub->in_buffer) free(sub->in_buffer);
                        sub->in_buffer = NULL; sub->in_pos = 0;
                        continue;
                    } else {
                        if (errno != EAGAIN && errno != EWOULDBLOCK) {
                            log_event("ERROR", sd, sub->ip_address, sub->port, "Read error: %s", strerror(errno));
                            cleanup_subscriber(i); 
                        }
                    }
                } 
                /* STATE: Reading the actual binary message body */
                else if (sub->read_state == READ_MSG) {
                    valread = read(sd, sub->in_buffer + sub->in_pos, sub->expected_msg_len - sub->in_pos);
                    if (valread > 0) {
                        sub->in_pos += valread;
                        if (sub->in_pos == sub->expected_msg_len) {
                            sub->in_buffer[sub->expected_msg_len] = '\0';
                            handle_command(i, sub->in_buffer);
                            
                            /* Cleanup and return to length-waiting state */
                            free(sub->in_buffer);
                            sub->in_buffer = NULL;
                            sub->read_state = READ_LEN;
                            sub->in_pos = 0;
                        }
                    } else if (valread == 0) {
                        log_event("INFO", sd, sub->ip_address, sub->port, "Disconnected during payload transmission");
                        cleanup_subscriber(i); 
                        if (sub->in_buffer) free(sub->in_buffer);
                        sub->in_buffer = NULL; sub->in_pos = 0;
                        continue;
                    } else {
                        if (errno != EAGAIN && errno != EWOULDBLOCK) {
                            log_event("ERROR", sd, sub->ip_address, sub->port, "Payload read error: %s", strerror(errno));
                            cleanup_subscriber(i); 
                        }
                    }
                }
            }
        }
    }
}
