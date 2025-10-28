#ifndef CONFIG_H
#define CONFIG_H
#define DEFAULT_SERVER_IP "192.168.1.200"
#define DEFAULT_SERVER_PORT 7777
#define MAX_EXEC_COMMANDS 100 

typedef struct {
    char key[256];
    char value[256];
} ExecCommand;

typedef struct {
    char server_ip[256];
    int server_port;
    ExecCommand exec_commands[MAX_EXEC_COMMANDS];
    int exec_count;  // Количество записей
} Config;

void read_config(Config *config, int verbose);

#endif
