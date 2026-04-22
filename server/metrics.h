/* server/metrics.h */
#ifndef GORGONA_METRICS_H
#define GORGONA_METRICS_H

void metrics_init_ssl(void);
void handle_https_metrics_request(int client_sd);

#endif
