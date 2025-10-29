#ifndef ALERT_LISTEN_H
#define ALERT_LISTEN_H

#include "config.h"

void trim_string(char *str);
void time_to_utc_string(time_t t, char *buf, size_t bufsize);
int has_private_key(const char *pubkey_hash_b64, int verbose);
void parse_response(const char *response, const char *expected_pubkey_hash_b64, int verbose, int execute, Config *config, int daemon_exec_flag);
int listen_alerts(int argc, char *argv[], int verbose, int execute, int daemon_exec_flag);

#endif
