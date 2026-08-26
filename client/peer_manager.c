/* 
* client/peer_manager.c - Autonomous Connectivity Engine Implementation
* BSD 3-Clause License
* Copyright (c) 2025, Alexander Shcheglov
*
* Autonomous Connectivity & Node Selection Logic
* ----------------------------------------------
* This module implements a prioritized, high-performance connectivity engine 
* designed for distributed mesh networks. It ensures near-instantaneous 
* reconnection by following a tiered selection strategy:
*
* 1. FAST PATH (Sticky Node):
*    The engine first attempts to connect to the last successfully used node 
*    stored in /dev/shm/gorgona_sticky_node. This bypasses discovery delays 
*    and ensures session continuity with proven endpoints.
*
* 2. DISTRIBUTED PATH (Mesh Cache / PEX):
*    If the sticky node is unavailable, the engine probes peers learned via 
*    Peer Exchange (Gossip/PEX) stored in peers.cache. This facilitates 
*    load balancing and leverages network proximity scores.
*
* 3. FALLBACK PATH (Administrative Bootstrap):
*    The static IP/Port defined in /etc/gorgona/gorgona.conf acts as the 
*    final "safety net." It is used only when dynamic caches are empty 
*    or unreachable, serving as an entry point into the network.
*
* PENALTY & RESILIENCE ENGINE:
* To prevent CLI hangs during node failures, a persistent Exponential Backoff 
* system is implemented. Failed nodes are recorded in /dev/shm/gorgona_penalties. 
* Successive failures increase the "black-box" time (30s, 60s, 120s... up to 1hr), 
* ensuring that subsequent client calls skip dead nodes instantly without 
* waiting for socket timeouts.
*/

#define _GNU_SOURCE
#include "peer_manager.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <sys/select.h>
#include <sys/stat.h> 
#include <time.h>

#define PENALTY_SHM_PATH "/dev/shm/gorgona_penalties"
#define INITIAL_PENALTY_SEC 30
#define MAX_PENALTY_SEC 3600

extern int verbose;
void trim_string(char *str); 

static PeerAddr known_peers[MAX_PEER_TARGETS];
static char penalty_ips[MAX_PEER_TARGETS][INET_ADDRSTRLEN];
static time_t penalty_until[MAX_PEER_TARGETS]; 
static int penalty_fails[MAX_PEER_TARGETS]; 
static int penalty_count = 0;
int peer_count = 0;

/**
 * Сохранение таблицы штрафов в файл (в /dev/shm)
 */
static void save_penalties() {
    FILE *fp = fopen(PENALTY_SHM_PATH, "w");
    if (!fp) return;
    for (int i = 0; i < penalty_count; i++) {
        fprintf(fp, "%s %ld %d\n", penalty_ips[i], (long)penalty_until[i], penalty_fails[i]);
    }
    fclose(fp);
    chmod(PENALTY_SHM_PATH, 0666);
}

/**
 * Загрузка таблицы штрафов из файла
 */
static void load_penalties() {
    FILE *fp = fopen(PENALTY_SHM_PATH, "r");
    if (!fp) {
        penalty_count = 0; // Если файла нет, сбрасываем счетчик в текущей памяти
        return;
    }
    
    int count = 0;
    char ip_buf[INET_ADDRSTRLEN];
    long until_val;
    int fails_val;

    while (count < MAX_PEER_TARGETS && 
           fscanf(fp, "%15s %ld %d", ip_buf, &until_val, &fails_val) == 3) {
        strncpy(penalty_ips[count], ip_buf, INET_ADDRSTRLEN - 1);
        penalty_ips[count][INET_ADDRSTRLEN - 1] = '\0';
        penalty_until[count] = (time_t)until_val;
        penalty_fails[count] = fails_val;
        count++;
    }
    penalty_count = count;
    fclose(fp);
}

static bool is_penalized(const char *ip) {
    time_t now = time(NULL);
    for (int i = 0; i < penalty_count; i++) {
        if (strcmp(penalty_ips[i], ip) == 0) {
            if (now < penalty_until[i]) return true;
            return false;
        }
    }
    return false;
}

/**
 * Helper to add unique peer addresses and prevent duplicates.
 */
static void add_peer(const char *ip, int port) {
    if (peer_count >= MAX_PEER_TARGETS || !ip || strlen(ip) < 7) return;
    
    char clean_ip[64];
    strncpy(clean_ip, ip, sizeof(clean_ip)-1);
    clean_ip[sizeof(clean_ip)-1] = '\0';
    trim_string(clean_ip);

    for (int i = 0; i < peer_count; i++) {
        if (strcmp(known_peers[i].ip, clean_ip) == 0 && known_peers[i].port == port) return;
    }

    strncpy(known_peers[peer_count].ip, clean_ip, INET_ADDRSTRLEN - 1);
    known_peers[peer_count].ip[INET_ADDRSTRLEN - 1] = '\0';
    known_peers[peer_count].port = port;
    peer_count++;
}

void peer_manager_load_cache(Config *config) {
    peer_count = 0;
    memset(known_peers, 0, sizeof(known_peers));
    /* КРИТИЧНО: Загружаем штрафы из SHM сразу при старте */
    load_penalties();
    /* Case A: Legacy mode fallback */
    if (config->sync_psk[0] == '\0') {
        if (config->server_ip[0] != '\0') {
            add_peer(config->server_ip, config->server_port);
        }
        return; 
    }
    /* Case B: Smart Mesh mode */
    /* PRIORITY 1: Distributed Intelligence (Gossip Cache) */
    FILE *fp = fopen(PEERS_CACHE_PATH, "r");
    if (fp) {
        char line[128];
        while (fgets(line, sizeof(line), fp) && peer_count < MAX_PEER_TARGETS) {
            trim_string(line);
            char *colon = strchr(line, ':');
            if (colon) {
                *colon = '\0';
                add_peer(line, atoi(colon + 1));
            }
        }
        fclose(fp);
    }
    /* PRIORITY 2: Administrative Bootstrap (Static IP из конфига) */
    if (config->server_ip[0] != '\0') {
        add_peer(config->server_ip, config->server_port);
    }
    if (verbose) {
        printf("Mesh Status: Orchestration candidates loaded (Count: %d, Head: %s)\n", 
               peer_count, peer_count > 0 ? known_peers[0].ip : "None");
    }
}

/**
 * Сброс счетчика ошибок при успешном подключении.
 */
static void reset_penalty(const char *ip) {
    bool changed = false;
    for (int i = 0; i < penalty_count; i++) {
        if (strcmp(penalty_ips[i], ip) == 0) {
            if (penalty_fails[i] > 0) {
                penalty_fails[i] = 0;
                penalty_until[i] = 0;
                changed = true;
            }
            break;
        }
    }
    if (changed) save_penalties();
}

/**
 * High-performance connection selector.
 * 
 * Logic:
 * 1. Пытается подключиться к 'Sticky' ноде (последней успешной).
 * 2. Если 'Sticky' нет или она недоступна, перебирает кандидатов из Mesh/Config.
 * 3. Пропускает ноды, находящиеся под "штрафом" (Penalty Box).
 */
int peer_manager_get_best_connection(void) {
    char sticky_ip[INET_ADDRSTRLEN] = "";
    int sticky_port = 0;
    bool has_sticky = false;

    /* 1. Читаем данные Sticky-ноды */
    int s_fd = open(STICKY_NODE_PATH, O_RDONLY);
    if (s_fd >= 0) {
        char buf[64];
        ssize_t n = read(s_fd, buf, sizeof(buf)-1);
        close(s_fd);
        if (n > 0) {
            buf[n] = '\0';
            char *colon = strchr(buf, ':');
            if (colon) {
                *colon = '\0';
                strncpy(sticky_ip, buf, INET_ADDRSTRLEN - 1);
                sticky_port = atoi(colon + 1);
                /* Если нода не в бане — пометим как рабочую */
                if (!is_penalized(sticky_ip)) {
                    has_sticky = true;
                }
            }
        }
    }

    /* 
     * FAST PATH:
     * Пробуем Sticky-ноду в первую очередь. 
     * Мы НЕ делаем Migration Check здесь, чтобы не тратить время на мертвые приоритетные ноды.
     */
    if (has_sticky) {
        if (verbose) printf("Mesh: Trying sticky node [%s:%d]\n", sticky_ip, sticky_port);
        int sd = connect_with_timeout(sticky_ip, sticky_port, PROBE_TIMEOUT_MS);
        if (sd >= 0) {
            reset_penalty(sticky_ip);
            return sd;
        }
        /* Sticky подвела — наказываем её */
        peer_manager_mark_bad(sticky_ip);
    }

    /* 
     * SLOW PATH: 
     * Перебор кандидатов (здесь и происходит Migration или Fallback)
     */
    if (peer_count == 0) return -1;

    for (int i = 0; i < peer_count; i++) {
        /* Пропускаем тех, кто в Penalty Box */
        if (is_penalized(known_peers[i].ip)) {
            continue;
        }

        /* Пропускаем ту же sticky, которую мы только что проверили и она упала */
        if (strcmp(known_peers[i].ip, sticky_ip) == 0) {
            continue;
        }

        if (verbose) {
            printf("Mesh: Probing candidate [%s:%d]... ", known_peers[i].ip, known_peers[i].port);
            fflush(stdout);
        }

        /* Используем короткий таймаут (1 сек) для перебора */
        int sd = connect_with_timeout(known_peers[i].ip, known_peers[i].port, 1000);
        
        if (sd >= 0) {
            if (verbose) printf("CONNECTED\n");
            reset_penalty(known_peers[i].ip);
            /* Сохраняем новую успешную ноду как Sticky */
            save_sticky_node(known_peers[i].ip, known_peers[i].port);
            return sd; 
        }

        if (verbose) printf("FAILED\n");
        peer_manager_mark_bad(known_peers[i].ip);
    }

    return -1;
}

/**
 * Updates the peer cache with discovered nodes from Mesh gossip.
 */
void peer_manager_update_cache(const char *payload) {
    if (!payload || strlen(payload) == 0) return;

    char *list_start = strchr(payload, '|');
    if (!list_start) return;
    list_start++; 

    FILE *fp = fopen(PEERS_CACHE_PATH, "a+");
    if (!fp) return;

    char *copy = strdup(list_start);
    char *token = strtok(copy, "|");

    while (token) {
        if (strchr(token, ':')) {
            fseek(fp, 0, SEEK_SET);
            char line[128];
            bool duplicate = false;
            while (fgets(line, sizeof(line), fp)) {
                trim_string(line);
                if (strcmp(line, token) == 0) { duplicate = true; break; }
            }

            if (!duplicate) {
                fseek(fp, 0, SEEK_END);
                fprintf(fp, "%s\n", token);
                if (verbose) printf("Mesh: Cached new peer via Gossip [%s]\n", token);
            }
        }
        token = strtok(NULL, "|");
    }

    fclose(fp);
    free(copy);
}

/**
 * Penalizes a node for protocol/auth failure to avoid retrying it.
 */
void peer_manager_mark_bad(const char *ip) {
    if (!ip) return;
    load_penalties(); /* Обновляем данные перед изменением */
    
    time_t now = time(NULL);
    int idx = -1;
    for (int i = 0; i < penalty_count; i++) {
        if (strcmp(penalty_ips[i], ip) == 0) { idx = i; break; }
    }

    if (idx == -1 && penalty_count < MAX_PEER_TARGETS) {
        idx = penalty_count++;
        strncpy(penalty_ips[idx], ip, INET_ADDRSTRLEN - 1);
        penalty_fails[idx] = 0;
    }

    if (idx != -1) {
        penalty_fails[idx]++;
        int delay = INITIAL_PENALTY_SEC * (1 << (penalty_fails[idx] - 1));
        if (delay > MAX_PENALTY_SEC) delay = MAX_PENALTY_SEC;

        penalty_until[idx] = now + delay;
        save_penalties(); /* Сразу сохраняем */
        
        if (verbose) printf("Mesh: Applied %ds penalty to %s\n", delay, ip);
    }
    invalidate_sticky_node();
}
