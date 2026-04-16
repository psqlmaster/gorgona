/* 
* BSD 3-Clause License
* Copyright (c) 2025, Alexander Shcheglov
* All rights reserved. 
*/

#ifndef COMMANDS_H
#define COMMANDS_H

/**
 * Routes a fully received message to the appropriate handler (SEND, LISTEN, etc.)
 * 
 * @param sub_index Index of the client in the subscribers array
 * @param buffer The null-terminated message content
 */
void handle_command(int sub_index, char *buffer);
void send_mgmt_command(int sub_index, const char *cmd_plain);

#endif /* COMMANDS_H */
