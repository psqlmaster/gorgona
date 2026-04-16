/* 
* BSD 3-Clause License
* Copyright (c) 2025, Alexander Shcheglov
* All rights reserved. 
*/

#include "commands.h"
#include "gorgona_utils.h"
#include "admin_mesh.h" 
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <sys/select.h>
#include <errno.h>
#include <ctype.h>
#include <time.h>
#include <stdbool.h>
#include <fcntl.h>
#include <fcntl.h>

extern int verbose;
extern FILE *log_file;
extern int max_clients;
extern size_t max_message_size;
extern char log_level[32];
extern int client_sockets[];
extern Subscriber subscribers[];

static time_t server_start_time = 0;

/*
 * Configures TCP Keepalive to maintain connection stability
 * and detect “dead” nodes. 
 */
static void set_tcp_keepalive(int fd) {
    int opt = 1;
    setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, &opt, sizeof(opt));
#ifdef __linux__
    int idle = 30;     // Начинать проверку через 30 сек простоя
    int interval = 5;  // Интервал между пробами 5 сек
    int keep_count = 3; // 3 неудачных пробы = обрыв
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

    /* [LAYER 2 INTEGRATION] 
     * Identify the peer IP before clearing metadata.
     */
    char disconnected_ip[INET_ADDRSTRLEN];
    strncpy(disconnected_ip, subscribers[index].ip_address, INET_ADDRSTRLEN - 1);

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
        if (strcmp(cluster_nodes[n].ip, disconnected_ip) == 0) {
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
 * Queue a binary message (length + payload) for sending.
 */
void enqueue_message(int sub_index, const char *msg, size_t msg_len) {
    log_event("DEBUG", subscribers[sub_index].sock, subscribers[sub_index].ip_address, 
              subscribers[sub_index].port, "Enqueued response (%zu bytes): %.*s", 
              msg_len, (int)msg_len, msg);
    OutBuffer *new_buf;
    uint32_t len_net = htonl(msg_len);

    /* 1. Enqueue 4-byte length header */
    new_buf = malloc(sizeof(OutBuffer));
    if (!new_buf) return;
    new_buf->data = malloc(sizeof(uint32_t));
    if (!new_buf->data) { free(new_buf); return; }
    memcpy(new_buf->data, &len_net, sizeof(uint32_t));
    new_buf->len = sizeof(uint32_t);
    new_buf->pos = 0;
    new_buf->next = NULL;

    if (subscribers[sub_index].out_tail) {
        subscribers[sub_index].out_tail->next = new_buf;
        subscribers[sub_index].out_tail = new_buf;
    } else {
        subscribers[sub_index].out_head = subscribers[sub_index].out_tail = new_buf;
    }

    /* 2. Enqueue actual message data */
    new_buf = malloc(sizeof(OutBuffer));
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
        log_event("INFO", sd, sub->ip_address, sub->port, "Closing connection");
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

/**
 * Dynamic Peer Connector (Progressive Layer 2 Mesh Engine)
 * 
 * This function iterates through the global cluster_nodes table,
 * identifies offline neighbors, and establishes non-blocking connections.
 */
void try_connect_peers() {
    static time_t last_check = 0;
    time_t now = time(NULL);

    /* Enforce reconnection interval to prevent CPU spikes and socket exhaustion */
    if (now - last_check < PEER_RECONNECT_INTERVAL) {
        return;
    }
    last_check = now;

    /* Loop through ALL known nodes in the Mesh Table (Seeds + PEX discovered) */
    for (int p = 0; p < cluster_node_count; p++) {
        MeshNode *node = &cluster_nodes[p];

        /* 1. Filtering: Skip banned, already connecting, or self-nodes */
        if (node->status == PEER_STATUS_BANNED || node->status == PEER_STATUS_HANDSHAKE) {
            continue;
        }

        /* 2. Port Validation: Don't connect if the listener port is unknown yet */
        if (node->port <= 0) {
            if (verbose) {
                log_event("DEBUG", -1, node->ip, 0, "Mesh: Skipping node %s - listener port not yet discovered", node->ip);
            }
            continue;
        }

        /* 3. Anti-Loopback: Avoid connecting to loopback interface */
        if (strcmp(node->ip, "127.0.0.1") == 0 || strcmp(node->ip, "localhost") == 0) {
            node->status = PEER_STATUS_BANNED; // Mark as unusable in mesh table
            continue;
        }

        /* 4. Duplicate Check: Check if we already have an active socket with this IP */
        bool already_active = false;
        for (int i = 0; i < max_clients; i++) {
            if (client_sockets[i] > 0 && strcmp(subscribers[i].ip_address, node->ip) == 0) {
                already_active = true;
                /* Sync mesh table status with actual socket state */
                if (subscribers[i].auth_state == AUTH_OK) {
                    node->status = PEER_STATUS_AUTHENTICATED;
                }
                break;
            }
        }
        if (already_active) continue;

        /* 5. Health Check: Skip unstable nodes until they are cleared by GC */
        if (node->metrics.fail_count >= PEER_MAX_FAILURES) {
            continue;
        }

        /* 6. Socket Initialization */
        int sd = socket(AF_INET, SOCK_STREAM, 0);
        if (sd < 0) continue;

        /* Setup Keepalive and Non-blocking mode */
        set_tcp_keepalive(sd);
        int flags = fcntl(sd, F_GETFL, 0);
        if (flags == -1 || fcntl(sd, F_SETFL, flags | O_NONBLOCK) == -1) {
            close(sd);
            continue;
        }

        /* Prepare network address */
        struct sockaddr_in addr;
        memset(&addr, 0, sizeof(addr));
        addr.sin_family = AF_INET;
        addr.sin_port = htons(node->port);
        
        if (inet_pton(AF_INET, node->ip, &addr.sin_addr) <= 0) {
            log_event("ERROR", -1, node->ip, node->port, "Mesh: Invalid IP format in table");
            close(sd);
            continue;
        }

        /* 7. Initiate Connection (Non-blocking) */
        if (connect(sd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
            if (errno != EINPROGRESS) {
                /* [IMMEDIATE PENALTY] 
                 * Нода отклонила соединение (Connection refused) - гасим Score сразу */
                node->metrics.fail_count++;
                node->status = PEER_STATUS_OFFLINE;
                node->metrics.gorgona_score = 0.0;
                node->metrics.last_rtt = 0.0;
                close(sd);
                continue;
            }
        }

        /* 8. Slot Allocation: Link the socket to a Subscriber slot */
        int i;
        for (i = 0; i < max_clients; i++) {
            if (client_sockets[i] == 0) {
                client_sockets[i] = sd;
                
                Subscriber *sub = &subscribers[i];
                sub->sock = sd;
                strncpy(sub->ip_address, node->ip, INET_ADDRSTRLEN - 1);
                sub->ip_address[INET_ADDRSTRLEN - 1] = '\0';
                sub->port = node->port;
                sub->type = SUB_TYPE_PEER;
                sub->connect_time = now;
                sub->auth_state = AUTH_SENT;
                sub->close_after_send = false;
                
                /* Reset protocol state machine for this slot */
                sub->read_state = READ_LEN;
                sub->expected_msg_len = 0;
                sub->in_pos = 0;
                if (sub->in_buffer) free(sub->in_buffer);
                sub->in_buffer = NULL;

                /* Mark node as pending in Mesh Table */
                node->status = PEER_STATUS_HANDSHAKE;

                /* Backward Compatibility: Sync with legacy remote_peers array if applicable */
                for (int r = 0; r < remote_peer_count; r++) {
                    if (strcmp(remote_peers[r].ip, node->ip) == 0) {
                        remote_peers[r].sd = sd;
                        remote_peers[r].active = true;
                        break;
                    }
                }

                /* 9. Send Handshake: L1 PSK Authentication */
                char auth_msg[256];
                int auth_len = snprintf(auth_msg, sizeof(auth_msg), "AUTH|%s|%d", 
                                        sync_psk, max_alerts);
                
                enqueue_message(i, auth_msg, (size_t)auth_len);

                log_event("INFO", sd, sub->ip_address, sub->port, 
                          "Mesh: Connecting to %s node (Score: %.2f)", 
                          node->is_seed ? "Seed" : "PEX", node->metrics.gorgona_score);
                break;
            }
        }

        if (i == max_clients) {
            log_event("WARN", sd, node->ip, node->port, "Mesh: Out of client slots (max_clients reached)");
            close(sd);
        }
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

        struct timeval timeout;
        timeout.tv_sec = 30;  /* Wake up every 5 seconds */
        timeout.tv_usec = 0;

        try_connect_peers();

        activity = select(max_sd + 1, &readfds, &writefds, NULL, &timeout);  

        if (activity == 0) {
            /* EVENT: Idle - The server is not busy, perfect time for background cleanup */
            run_global_maintenance();
            continue;
        }

        if ((activity < 0) && (errno != EINTR)) {
            log_event("ERROR", -1, NULL, 0, "Select error: %s", strerror(errno));
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
                    subscribers[i].port = ntohs(address.sin_port);
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

                    log_event("INFO", new_socket, subscribers[i].ip_address, subscribers[i].port, "New connection");
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
                    /* Initialize buffer if it's a new connection cycle */
                    if (!sub->in_buffer) {
                        sub->in_buffer = malloc(max_message_size + 1);
                        if (!sub->in_buffer) {
                            log_event("ERROR", sd, sub->ip_address, sub->port, "Memory allocation failed");
                            cleanup_subscriber(i); 
                            return;
                        }
                        sub->in_pos = 0;
                    }

                    char byte;
                    valread = read(sd, &byte, 1);
                    if (valread > 0) {
                        sub->in_buffer[sub->in_pos++] = byte;
                        unsigned char first_byte = (unsigned char)sub->in_buffer[0];

                        /** 
                         * PROTOCOL SNIFFER
                         * Distinguishes between Binary Length Headers and Text-based Commands.
                         */

                        /* 1. BINARY MODE DETECTION */
                        /* Since max_message_size is typically < 16MB, the first byte of 
                           a valid 4-byte big-endian length should be 0x00. 
                           This effectively rejects TLS (0x16), SSH (0x53), etc. */
                        if (first_byte < 32 && first_byte != '\n' && first_byte != '\r' && first_byte != '\t') {
                            if (sub->in_pos == 4) {
                                uint32_t temp_len;
                                memcpy(&temp_len, sub->in_buffer, 4);
                                temp_len = ntohl(temp_len);
                                log_event("DEBUG", sd, sub->ip_address, sub->port, 
                                          "Binary header detected. Expected length: %u", temp_len);
                                /* VALIDATION: Check if length is within allowed bounds */
                                if (temp_len > max_message_size || temp_len == 0) {
                                    char err_size[256];
                                    /* Creating a detailed error message */
                                    int l = snprintf(err_size, sizeof(err_size), 
                                                     "Error: Message size (%u) exceeds limit (%zu).\n", 
                                                     temp_len, max_message_size);
                                    enqueue_message(i, err_size, l);
                                    sub->close_after_send = true; 
                                    log_event("ERROR", sd, sub->ip_address, sub->port, 
                                              "Protocol Violation: Declared length %u exceeds max limit %zu. Dropping connection.", 
                                              temp_len, max_message_size);
                                    if (sub->in_buffer) free(sub->in_buffer);
                                    sub->in_buffer = NULL;
                                    sub->in_pos = 0;
                                    continue; 
                                }

                                /* Reallocate buffer to match the exact expected binary message size */
                                sub->expected_msg_len = temp_len;
                                char *new_binary_buf = malloc(sub->expected_msg_len + 1);
                                if (!new_binary_buf) {
                                    log_event("ERROR", sd, sub->ip_address, sub->port, "Allocation failed for payload");
                                    cleanup_subscriber(i);
                                    return; 
                                }

                                free(sub->in_buffer);
                                sub->in_buffer = new_binary_buf;
                                sub->in_pos = 0;
                                sub->read_state = READ_MSG;
                                continue;
                            }
                        } 
                        /* TEXT MODE DETECTION */
                        else if (first_byte >= 32 || first_byte == '\n' || first_byte == '\r' || first_byte == '\t') {
                            if (byte == '\r') {
                                sub->in_pos--; /* Ignore carriage returns */
                                continue;
                            }
                            if (byte == '\n') {
                                sub->in_buffer[sub->in_pos] = '\0';
                                trim_string(sub->in_buffer);

                                if (strlen(sub->in_buffer) > 0) {
                                    log_event("DEBUG", sd, sub->ip_address, sub->port, "Text command received: %s", sub->in_buffer);

                                    /* COMMAND: help - Anonymous command list (no version disclosure) */
                                    if (strcmp(sub->in_buffer, "help") == 0) {
                                        char h_msg[] = "--- Gorgona Node Help ---\n"
                                                       "Commands available:\n"
                                                       "  help           - Show this list\n"
                                                       "  info           - Show node uptime\n"
                                                       "  status <psk>   - Show detailed node metrics (requires authentication)\n"
                                                       "-------------------------\n";
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
                                        /* Basic authentication logic: skip "status" keyword and find the key */
                                        char *provided_psk = sub->in_buffer + 6;
                                        while (*provided_psk == ' ') provided_psk++; /* Skip whitespace */

                                        if (provided_psk[0] == '\0' || strcmp(provided_psk, sync_psk) != 0) {
                                            log_event("WARN", sd, sub->ip_address, sub->port, "Unauthorized status request (Invalid PSK)");
                                            enqueue_text_only(i, "Error: Unauthorized. Usage: status <sync_psk>\n", 45);
                                        } else {
                                            run_global_maintenance();
                                            /* Authentication successful - Gather detailed metrics */
                                            
                                            /* We increased the buffer to 4096, since the L2 table can be large */
                                            char status_msg[4096];
                                            int pos = 0; 

                                            time_t now = time(NULL);
                                            double uptime_sec = difftime(now, server_start_time);
                                            
                                            /* get ip port */
                                            struct sockaddr_in node_addr;
                                            socklen_t node_addr_len = sizeof(node_addr);
                                            char node_ip[INET_ADDRSTRLEN] = "0.0.0.0";
                                            int node_port = 0;
                                            if (getsockname(sd, (struct sockaddr *)&node_addr, &node_addr_len) == 0) {
                                                inet_ntop(AF_INET, &node_addr.sin_addr, node_ip, sizeof(node_ip));
                                                node_port = ntohs(node_addr.sin_port);
                                            }

                                            /* 1. Connection metrics */
                                            int active_clients = 0;
                                            int authenticated_peers = 0;
                                            for (int j = 0; j < max_clients; j++) {
                                                if (client_sockets[j] > 0) {
                                                    if (subscribers[j].type == SUB_TYPE_PEER && subscribers[j].auth_state == AUTH_OK) {
                                                        authenticated_peers++;
                                                    } else if (subscribers[j].type == SUB_TYPE_CLIENT) {
                                                        active_clients++;
                                                    }
                                                }
                                            }

                                            /* 2. Storage metrics calculation */
                                            int active_alerts = 0;
                                            int total_waste = 0;
                                            size_t total_bytes = 0;
                                            time_t oldest_ts = 0;

                                            for (int r = 0; r < recipient_count; r++) {
                                                clean_expired_alerts(&recipients[r]);
                                                total_waste += recipients[r].waste_count;
                                                total_bytes += recipients[r].used_size;
                                                
                                                for (int a = 0; a < recipients[r].count; a++) {
                                                    if (recipients[r].alerts[a].active) {
                                                        active_alerts++;
                                                        /* We are looking for the time of the oldest active alert */
                                                        if (oldest_ts == 0 || recipients[r].alerts[a].create_at < oldest_ts) {
                                                            oldest_ts = recipients[r].alerts[a].create_at;
                                                        }
                                                    }
                                                }
                                            }

                                            char oldest_time[32] = "N/A";
                                            if (active_alerts > 0 && oldest_ts > 0) {
                                                struct tm *tm_info = gmtime(&oldest_ts);
                                                strftime(oldest_time, sizeof(oldest_time), "%Y-%m-%d %H:%M:%S", tm_info);
                                            }

                                            /* 3. Prepare storage-specific strings */
                                            char disk_metrics[512] = "";
                                            if (use_disk_db) {
                                                snprintf(disk_metrics, sizeof(disk_metrics),
                                                         "  - Database Size: %.2f MB\n"
                                                         "  - Disk Waste (Awaiting Vacuum): %d\n"
                                                         "  - Vacuum Threshold: %d%%\n",
                                                         (double)total_bytes / (1024 * 1024), total_waste, vacuum_threshold);
                                            }

                                            int uptime_d = (int)(uptime_sec / 86400);
                                            int uptime_h = (int)((uptime_sec / 3600) - (uptime_d * 24));
                                            int uptime_m = (int)((uptime_sec / 60) - (uptime_d * 1440) - (uptime_h * 60));

                                            /* 4. Final Assemble - Part 1: L1 Stats */
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
                                                "%s" /* Это строка disk_metrics, она уже содержит \n */
                                                "  - History Starts From: %s UTC\n"
                                                "Operational Configuration:\n"
                                                "  - Max Alerts per Key: %d\n"
                                                "  - Max Message Size: %zu MB\n"
                                                "  - Logging Level: %s\n",
                                                node_ip,                                    /* %s */
                                                node_port,                                  /* %d */
                                                VERSION ? VERSION : "1.0",                  /* %s */
                                                uptime_d, uptime_h, uptime_m,               /* %d %d %d */
                                                active_clients, max_clients,                /* %d %d */
                                                authenticated_peers, remote_peer_count,     /* %d %d */
                                                use_disk_db ? "Persistent (Disk)" : "Ephemeral (Memory)", /* %s */
                                                recipient_count,                            /* %d */
                                                active_alerts,                              /* %d */
                                                disk_metrics,                               /* %s */
                                                oldest_time,                                /* %s */
                                                max_alerts,                                 /* %d */
                                                (size_t)(max_message_size / (1024 * 1024)), /* %zu */
                                                log_level                                   /* %s */
                                            );

                                            /* 5. Final Assemble - Part 2: L2 Management Mesh */
                                            mesh_recalculate_scores(); /* Update the metrics before outputting */
                                            
                                            pos += snprintf(status_msg + pos, sizeof(status_msg) - pos, 
                                                            "--- L2 Cluster Topology (Known nodes: %d) ---\n", cluster_node_count);
                                            
                                            if (cluster_node_count == 0) {
                                                pos += snprintf(status_msg + pos, sizeof(status_msg) - pos, 
                                                                "  (No mesh peers discovered or configured)\n");
                                            } else {
                                                for (int n = 0; n < cluster_node_count; n++) {
                                                    MeshNode *node = &cluster_nodes[n];
                                                    
                                                    /* Buffer overflow protection (leaving room for the ending) */
                                                    if (pos >= sizeof(status_msg) - 256) {
                                                        pos += snprintf(status_msg + pos, sizeof(status_msg) - pos, "  ... [Table Truncated]\n");
                                                        break;
                                                    }
                                                    
                                                    char *origin = "PEX ";
                                                    if (node->is_seed) origin = "SEED";
                                                    else if (node->is_cached) origin = "CACHE";
                                                    pos += snprintf(status_msg + pos, sizeof(status_msg) - pos,
                                                        "  [%-15s:%-5d] Score: %4.2f | RTT: %6.1f ms | Spd: %6.1f KB/s | %s [%s]\n",
                                                        node->ip, node->port, 
                                                        node->metrics.gorgona_score,
                                                        node->metrics.last_rtt, 
                                                        node->metrics.rolling_avg_speed / 1024.0,
                                                        origin, 
                                                        (node->status == PEER_STATUS_AUTHENTICATED) ? "UP" : "DEAD"); 
                                                }
                                            }
                                            
                                            pos += snprintf(status_msg + pos, sizeof(status_msg) - pos, 
                                                            "-----------------------------------------------------\n");

                                            /* We are sending the fully assembled message */
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
