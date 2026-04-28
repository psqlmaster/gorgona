/* 
 * server/metrics.c - Native HTTPS Prometheus Exporter with Basic Auth
 * BSD 3-Clause License
 * Copyright (c) 2025, Alexander Shcheglov
 */

#include "common.h"
#include "admin_mesh.h"
#include "gorgona_utils.h"
#include "snowflake.h"
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

extern time_t server_start_time;
extern char sync_psk[64];

static SSL_CTX *metrics_ssl_ctx = NULL;

/**
 * Initializes the SSL context for our integrated exporter.
 */
void metrics_init_ssl() {
    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();

    const SSL_METHOD *method = TLS_server_method();
    metrics_ssl_ctx = SSL_CTX_new(method);

    if (!metrics_ssl_ctx) {
        log_event("ERROR", -1, NULL, 0, "Metrics: SSL context creation failed");
        return;
    }

    /* Standard certificate paths for Gorgona */
    if (SSL_CTX_use_certificate_file(metrics_ssl_ctx, "/etc/gorgona/server.crt", SSL_FILETYPE_PEM) <= 0 ||
        SSL_CTX_use_PrivateKey_file(metrics_ssl_ctx, "/etc/gorgona/server.key", SSL_FILETYPE_PEM) <= 0) {
        log_event("WARN", -1, NULL, 0, "Metrics: HTTPS Disabled (Certs not found in /etc/gorgona/)");
        SSL_CTX_free(metrics_ssl_ctx);
        metrics_ssl_ctx = NULL;
    }
}

/**
 * Builds a comprehensive Prometheus text response.
 * Includes Node info, Connection states, Storage metrics, and L2 Topology.
 */
static int build_prometheus_payload(char *buf, size_t max_len) {
    int pos = 0;
    uint64_t my_max_id = get_max_alert_id();
    time_t now = time(NULL);

    /* 1. NODE IDENTIFICATION & UPTIME */
    pos += snprintf(buf + pos, max_len - pos,
        "# HELP gorgona_info Version and node information\n"
        "gorgona_info{version=\"%s\"} 1\n"
        "gorgona_uptime_seconds %.0f\n", 
        VERSION ? VERSION : "3.0.1", difftime(now, server_start_time));

    /* 2. CONNECTION METRICS */
    int active_clients = 0;
    int authenticated_peers = 0;
    for (int j = 0; j < max_clients; j++) {
        if (client_sockets[j] > 0) {
            if (subscribers[j].type == SUB_TYPE_PEER && subscribers[j].auth_state == AUTH_OK) authenticated_peers++;
            else if (subscribers[j].type == SUB_TYPE_CLIENT) active_clients++;
        }
    }
    pos += snprintf(buf + pos, max_len - pos,
        "gorgona_clients_active %d\n"
        "gorgona_clients_max %d\n"
        "gorgona_peers_authenticated %d\n", 
        active_clients, max_clients, authenticated_peers);

    /* 3. STORAGE METRICS */
    int active_alerts = 0;
    int total_waste = 0;
    size_t db_bytes = 0;
    time_t oldest_ts = 0;

    for (int r = 0; r < recipient_count; r++) {
        db_bytes += recipients[r].used_size;
        total_waste += recipients[r].waste_count;
        for (int a = 0; a < recipients[r].count; a++) {
            if (recipients[r].alerts[a].active) {
                active_alerts++;
                if (oldest_ts == 0 || recipients[r].alerts[a].create_at < oldest_ts)
                    oldest_ts = recipients[r].alerts[a].create_at;
            }
        }
    }

    pos += snprintf(buf + pos, max_len - pos,
        "gorgona_storage_persistent_bool %d\n"
        "gorgona_recipients_keys_total %d\n"
        "gorgona_alerts_active_total %d\n"
        "gorgona_db_size_bytes %zu\n"
        "gorgona_db_waste_records %d\n"
        "gorgona_vacuum_threshold_percent %d\n",
        use_disk_db, recipient_count, active_alerts, db_bytes, total_waste, vacuum_threshold);

    /* 4. CLUSTER PULSE (Timestamps as Unix Epoch) */
    time_t last_ingest_ts = snowflake_to_timestamp(my_max_id);
    pos += snprintf(buf + pos, max_len - pos,
        "gorgona_max_id_pulse %" PRIu64 "\n"
        "gorgona_history_start_timestamp %ld\n"
        "gorgona_last_ingest_timestamp %ld\n", 
        my_max_id, (long)oldest_ts, (long)last_ingest_ts);

    /* 5. L2 CLUSTER TOPOLOGY (Dynamic Labels) */
    for (int i = 0; i < cluster_node_count; i++) {
        MeshNode *n = &cluster_nodes[i];
        const char *state = (n->status == PEER_STATUS_AUTHENTICATED) ? "1" : "0";
        const char *origin = n->is_seed ? "seed" : (n->is_cached ? "cache" : "pex");
        
        pos += snprintf(buf + pos, max_len - pos,
            "gorgona_peer_status{target=\"%s\",origin=\"%s\"} %s\n"
            "gorgona_peer_rtt_milliseconds{target=\"%s\"} %.2f\n"
            "gorgona_peer_score{target=\"%s\"} %.2f\n"
            "gorgona_peer_speed_bps{target=\"%s\"} %.0f\n",
            n->ip, origin, state,
            n->ip, n->metrics.last_rtt,
            n->ip, n->metrics.gorgona_score,
            n->ip, n->metrics.rolling_avg_speed);
        
        /* Response buffer overflow protection */
        if (pos > (int)max_len - 512) break;
    }
    
    return pos;
}

/**
 * Validates Prometheus Basic Auth.
 * Prometheus/curl sends: "Authorization: Basic base64(gorgona:sync_psk)"
 */
static bool validate_auth(const char *request) {
    /* We need to encode the expected string in Base64 */
    char raw_credentials[128];
    /* We'll use the fixed user “gorgona” */
    snprintf(raw_credentials, sizeof(raw_credentials), "gorgona:%s", sync_psk);
    
    char *expected_b64 = base64_encode((unsigned char*)raw_credentials, strlen(raw_credentials));
    if (!expected_b64) return false;

    /* Debugging (if -v is enabled) */
    if (verbose) {
        printf("--- Incoming HTTP Request ---\n%s\n", request);
        printf("--- Expected B64 Token: %s ---\n", expected_b64);
    }

    /* We are looking for an encrypted token in the request headers */
    bool is_valid = (strstr(request, expected_b64) != NULL);

    free(expected_b64);
    return is_valid;
}

/**
 * Handshakes and responds to a Prometheus HTTP/TLS probe.
 * Now extracts peer metadata to provide detailed logging for security audits.
 */
void handle_https_metrics_request(int client_sd) {
    if (!metrics_ssl_ctx) {
        close(client_sd);
        return;
    }

    /* Extract client metadata for logging */
    struct sockaddr_in addr;
    socklen_t addr_len = sizeof(addr);
    char client_ip[INET_ADDRSTRLEN] = "unknown";
    int client_port = 0;

    if (getpeername(client_sd, (struct sockaddr *)&addr, &addr_len) == 0) {
        inet_ntop(AF_INET, &addr.sin_addr, client_ip, sizeof(client_ip));
        client_port = ntohs(addr.sin_port);
    }

    SSL *ssl = SSL_new(metrics_ssl_ctx);
    SSL_set_fd(ssl, client_sd);

    /* Perform the SSL handshake (now in blocking mode within the child process) */
    int accept_res = SSL_accept(ssl);
    if (accept_res <= 0) {
        int err = SSL_get_error(ssl, accept_res);
        /* Log handshake failures at DEBUG level to avoid log bloating from probes */
        log_event("DEBUG", client_sd, client_ip, client_port, "Metrics: SSL Handshake failed (Error Code: %d)", err);
        if (verbose) ERR_print_errors_fp(stderr);
    } else {
        /* Reading the HTTP Request */
        char rx_buf[4096]; 
        int bytes = SSL_read(ssl, rx_buf, sizeof(rx_buf) - 1);
        
        if (bytes > 0) {
            rx_buf[bytes] = '\0';
            
            /* Verify Basic Auth against the cluster sync_psk */
            if (validate_auth(rx_buf)) {
                char body[8192];
                int body_len = build_prometheus_payload(body, sizeof(body));
                
                char header[512];
                int h_len = snprintf(header, sizeof(header),
                    "HTTP/1.1 200 OK\r\n"
                    "Content-Type: text/plain; version=0.0.4\r\n"
                    "Content-Length: %d\r\n"
                    "Connection: close\r\n\r\n", body_len);
                
                SSL_write(ssl, header, h_len);
                SSL_write(ssl, body, body_len);
            } else {
                /* Log unauthorized access attempts with the specific source IP and port */
                log_event("WARN", client_sd, client_ip, client_port, "Metrics: Unauthorized access attempt (Invalid PSK)");

                const char *denied = "HTTP/1.1 401 Unauthorized\r\n"
                                     "WWW-Authenticate: Basic realm=\"Gorgona Metrics\"\r\n"
                                     "Content-Length: 0\r\n"
                                     "Connection: close\r\n\r\n";
                SSL_write(ssl, denied, (int)strlen(denied));
            }
        }
    }

    /* Graceful SSL shutdown and resource cleanup */
    SSL_set_shutdown(ssl, SSL_SENT_SHUTDOWN | SSL_RECEIVED_SHUTDOWN);
    SSL_free(ssl);
    close(client_sd);
}
