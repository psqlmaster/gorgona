/* 
* BSD 3-Clause License
* Copyright (c) 2025, Alexander Shcheglov
* All rights reserved. 
*/

#ifndef ALERT_SEND_H
#define ALERT_SEND_H

#include <stddef.h>

int send_alert(int argc, char *argv[], int verbose);
/* A function to recall (cancel) a previously sent alert. */
int send_revocation(int argc, char *argv[], int verbose_flag); 

#endif
