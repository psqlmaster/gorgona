#ifndef CONFIG_H
#define CONFIG_H
#define DEFAULT_SERVER_IP "192.168.1.200"
#define DEFAULT_SERVER_PORT 7777
 
void read_config(char *server_ip, int *server_port);
int read_port_config(void);

#endif
