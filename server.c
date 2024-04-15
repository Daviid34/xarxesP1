#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <string.h>
#include <stdbool.h>
#include <signal.h>
#include <unistd.h>
#include <time.h>
#include <netdb.h>
#include <pthread.h>
#include <sys/select.h>
#include <ctype.h>
#include <poll.h>
#include <arpa/inet.h>

#define HASH_SIZE 20
#define MAX_CLIENTS 10
#define SIZE 1024

#define SUBS_REQ 0x00
#define SUBS_ACK 0x01
#define SUBS_REJ 0x02
#define SUBS_INFO 0x03
#define INFO_ACK 0x04
#define SUBS_NACK 0x05
#define HELLO 0x10
#define HELLO_REJ 0x11

#define SEND_DATA 0x20
#define SET_DATA 0x21
#define GET_DATA 0x22
#define DATA_ACK 0x23
#define DATA_NACK 0x24
#define DATA_REJ 0x25

#define x 3
#define v 2

int client_num = 0;
int threads_num = 0;
bool debug=false;

int copied_tcp = 0;
int copied_udp = 0;

typedef struct {
    char *name;
    char *ip;
    char *mac;
    char *rndm;
    char *state;
    char *situation;
    char *elements;
    char *tcp_port;
    int check_pack;
} Client;

typedef struct {
    char *name;
    char *mac;
    char *udp;
    char *tcp;
} Config;

typedef struct {
    char type;
    char *mac;
    char *rndm;
    char *controller;
    char *situation;
    char *info;
} Udp_packet;

typedef struct {
    char type;
    char *mac;
    char *rndm;
    char *device;
    char *value;
    char *info;
} Tcp_packet;

typedef struct {
    int udp_port;
    char *buffer;
    struct sockaddr_in cliaddr;
    int n;
} ThreadArgs;


Client clients[MAX_CLIENTS];
Config serv;

void parse_server_conf(char *config_file);
void parse_controllers(char *config_file);
void remove_spaces(char *str);
void init_server();
int init_udp_socket();
int init_tcp_socket();
void process_command(char buffer[], pthread_t thread1, pthread_t thread2);
void recieve_info(int sockfd, char* buffer, int n, struct sockaddr_in cliaddr);
Udp_packet hextoASCII_udp(char* hexArray, size_t size);
Tcp_packet hextoASCII_tcp(char* hexArray, size_t size);
void save_client_data(Udp_packet packet, char* ip);
bool check_mac(Udp_packet packet);
void send_subs_ack(int sockfd, struct sockaddr_in addr_cli, char *controller);
void send_subs_rej(int sockfd, struct sockaddr_in addr_cli, int flag);
void send_subs_nack(int sockfd, struct sockaddr_in addr_cli);
void send_info_ack(int sockfd, int sock2, struct sockaddr_in addr_cli, char *controller, int pointer);
void send_hello(int sockfd, struct sockaddr_in addr_cli, int pointer);
void send_hello_rej(int sockfd, struct sockaddr_in addr_cli, int pointer);
void *start_udp();
void* treat_udp(void* args);
void *start_tcp();
void* treat_tcp(void* args);
bool check_device(int pointer, char* device);
void parse_data(char* info, char* mac);
void send_data_ack(int socket, int pointer, char* device, char* value);
int check_credentials (int pointer, char* state, char* mac, char* rndm);
void disconnect_client(int pointer);
int check_controller(char* controller, int flag);
bool check_device_mode(char* device);
void send_set_data(int pointer, char* device, char* value);
bool check_value_len(char* value, char* device);
void send_get_data(int pointer, char* device);
void send_data_rej(int socket, int pointer, char* device, char* value, int flag);
void send_data_nack(int socket, int pointer);
void handle_sigusr1(int sig);
void handle_sigusr2(int sig);
void handle_sigint(int sig);
int pthread_kill(pthread_t thread, int sig);
void bzero(void *s, size_t n);
int snprintf(char *s, size_t n, const char *format, ...);

void handle_sigusr1(int sig) {
    close(copied_udp);
    pthread_exit(NULL);
}

void handle_sigusr2(int sig) {
    close(copied_tcp);
    pthread_exit(NULL);
}

void handle_sigint(int sig) {
    close(copied_tcp);
    close(copied_udp);
    exit(0);
}

char* strdup(const char* str) {
    size_t len = strlen(str) + 1;
    char* dup = malloc(len);
    if (dup) {
        memcpy(dup, str, len);
    }
    return dup;
}

int main(int argc, char *argv[]) {
    if (argc == 3) {
        if (strcmp(argv[1], "-c") == 0) {
            parse_server_conf(argv[2]);
            parse_controllers("controllers.dat");
        }
        else if (strcmp(argv[1], "-u") == 0) {
            parse_server_conf("server.cfg");
            parse_controllers(argv[2]);
        }
        else if (strcmp(argv[1], "-d") == 0) {
            debug = true;
            parse_server_conf("server.cfg");
            parse_controllers("controllers.dat");
        }
        else {
            parse_server_conf("server.cfg");
            parse_controllers("controllers.dat");
        }
    }

    else if (argc == 4) {
        if (strcmp(argv[1], "-c") == 0 && strcmp(argv[3], "-d") == 0) {
            parse_server_conf(argv[2]);
            parse_controllers("controllers.dat");
            debug = true;
        }
        else if (strcmp(argv[1], "-d") == 0 && strcmp(argv[2], "-c") == 0) {
            parse_server_conf(argv[3]);
            parse_controllers("controllers.dat");
            debug = true;
        }
        else if (strcmp(argv[1], "-u") == 0 && strcmp(argv[3], "-d") == 0) {
            parse_server_conf("server.cfg");
            parse_controllers(argv[2]);
            debug = true;
        }
        else if (strcmp(argv[1], "-d") == 0 && strcmp(argv[2], "-u") == 0) {
            parse_server_conf("server.cfg");
            parse_controllers(argv[3]);
            debug = true;
        }
    }

    else if (argc == 5) {
        if (strcmp(argv[1], "-c") == 0 && strcmp(argv[3], "-u") == 0) {
            parse_server_conf(argv[2]);
            parse_controllers(argv[4]);
        }
        else if (strcmp(argv[1], "-u") == 0 && strcmp(argv[3], "-c") == 0) {
            parse_server_conf(argv[4]);
            parse_controllers(argv[2]);
        }
    }

    else if (argc == 6) {
        if (strcmp(argv[1], "-c") == 0 && strcmp(argv[3], "-u") == 0 && strcmp(argv[5], "-d") == 0) {
            parse_server_conf(argv[2]);
            parse_controllers(argv[4]);
            debug = true;
        }
        else if (strcmp(argv[1], "-u") == 0 && strcmp(argv[3], "-c") == 0 && strcmp(argv[5], "-d") == 0) {
            parse_server_conf(argv[4]);
            parse_controllers(argv[2]);
            debug = true;
        }
        else if (strcmp(argv[1], "-u") == 0 && strcmp(argv[3], "-d") == 0 && strcmp(argv[4], "-c") == 0) {
            parse_server_conf(argv[5]);
            parse_controllers(argv[2]);
            debug = true;
        }
        else if (strcmp(argv[1], "-c") == 0 && strcmp(argv[3], "-d") == 0 && strcmp(argv[4], "-u") == 0) {
            parse_server_conf(argv[2]);
            parse_controllers(argv[5]);
            debug = true;
        }
        else if (strcmp(argv[1], "-d") == 0 && strcmp(argv[2], "-u") == 0 && strcmp(argv[4], "-c") == 0) {
            parse_server_conf(argv[5]);
            parse_controllers(argv[3]);
            debug = true;
        }
        else if (strcmp(argv[1], "-d") == 0 && strcmp(argv[2], "-c") == 0 && strcmp(argv[4], "-u") == 0) {
            parse_server_conf(argv[3]);
            parse_controllers(argv[5]);
            debug = true;
        }
    }

    else {
        parse_server_conf("server.cfg");
        parse_controllers("controllers.dat");
    }
    init_server();
    return 0;
}

void parse_server_conf(char *config_file) {
    FILE *file;
    char line [100];

    file = fopen(config_file, "r");
    if (file == NULL) {
        perror("Error opening file");
        exit(0);
    }
    while (fgets(line, sizeof(line), file) != NULL) {
        char *key = strtok(line, "=");
        char *value = strtok(NULL, "=");
        remove_spaces(key);
        remove_spaces(value);
        if (strcmp(key, "Name") == 0) {
            serv.name = strdup(value);
        }
        else if (strcmp(key, "MAC") == 0) {
            serv.mac = strdup(value);
        }
        else if (strcmp(key, "UDP-port") == 0) {
            serv.udp = strdup(value);
        }
        else if (strcmp(key, "TCP-port") == 0) {
            serv.tcp = strdup(value);
        }
    }
    fclose(file);
}

void parse_controllers(char *config_file) {
    FILE *file;
    char line [100];

    file = fopen(config_file, "r");
    if (file == NULL) {
        perror("Error opening file");
        exit(0);
    }
    while (fgets(line, sizeof(line), file) != NULL) {
        char *key = strtok(line, ",");
        char *value = strtok(NULL, ",");
        value[strlen(value) - 1] = 0;
        clients[client_num].name = strdup(key);
        clients[client_num].ip = "     ";
        clients[client_num].mac = strdup(value);
        clients[client_num].rndm = "";
        clients[client_num].state = "DISCONNECTED";
        clients[client_num].situation = "";
        clients[client_num].elements = "";
        clients[client_num].check_pack = 0;
        client_num++;
    }
    fclose(file);
}

void remove_spaces(char *str) {
    char *src = str;
    char *dst = str;
    while (*src) {
        if (!isspace((unsigned char)*src)) {
            *dst++ = *src;
        }
        src++;
    }
    *dst = '\0';
}

void init_server() {
    pthread_t thread_id, thread_id2;
    char buffer[1024];

    pthread_create(&thread_id, NULL, start_udp, NULL);
    pthread_create(&thread_id2, NULL, start_tcp, NULL);

    printf("YO LEO LA TERMINAL\n");
    signal(SIGINT, handle_sigint);
    while(1) {
        if (fgets(buffer, 1024, stdin) != NULL) {
            buffer[strcspn(buffer, "\n")] = '\0';
            process_command(buffer, thread_id, thread_id2);
            memset(buffer, 0, sizeof(buffer));
        }
    }
}

int init_udp_socket() {
    int sock = socket(AF_INET, SOCK_DGRAM, 0);

    struct sockaddr_in addr_server;
	memset(&addr_server,0, sizeof(struct sockaddr_in));

	addr_server.sin_family=AF_INET;
	addr_server.sin_addr.s_addr=htonl(INADDR_ANY);
	addr_server.sin_port=htons(atoi(serv.udp));

    bind(sock,(struct sockaddr *)&addr_server,sizeof(struct sockaddr_in));

    copied_udp = sock;

    return sock;
}

int init_tcp_socket() {
    int sock = socket(AF_INET, SOCK_STREAM, 0);

    struct sockaddr_in addr_server;
	memset(&addr_server,0, sizeof(struct sockaddr_in));

	addr_server.sin_family=AF_INET;
	addr_server.sin_addr.s_addr=htonl(INADDR_ANY);
	addr_server.sin_port=htons(atoi(serv.tcp));
    bind(sock,(struct sockaddr *)&addr_server,sizeof(struct sockaddr_in));

    copied_tcp = sock;

    return sock;
}

void process_command(char buffer[], pthread_t thread1, pthread_t thread2) {
    int i, j, pointer;
    char command[100];
    char controller[50];
    char device[50];
    char value[50];

    sscanf(buffer, "%s", command);

    for (i = 0; i < strlen(command); i++) {
        command[i] = tolower(command[i]);
    }

    if (strcmp(command, "list") == 0) {
        printf("--NOM--- ------IP------- -----MAC---- --RNDM-- ----ESTAT--- --SITUACIÓ-- --ELEMENTS-------------------------------------------\n");
        for (j = 0; j < client_num; j++) {
            printf("%s      %s      %s      %s     %s      %s      %s\n", clients[j].name, clients[j].ip, clients[j].mac, clients[j].rndm, 
            clients[j].state, clients[j].situation, clients[j].elements);
        }
    } else if (strcmp(command, "set") == 0) {
        sscanf(buffer, "%s %s %s %s", command, controller, device, value);
        printf("Controller: %s\nDevice: %s\nValue: %s\n", controller, device, value);
        pointer = check_controller(controller, 0);
        if (pointer >= 0 && check_device(pointer, device) && check_device_mode(device) && check_value_len(value, device)) {
            printf("ESTAMOS INNNN\n");
            send_set_data(pointer, device, value);
        }
    } else if (strcmp(command, "get") == 0) {
        sscanf(buffer, "%s %s %s %s", command, controller, device, value);
        printf("Controller: %s\nDevice: %s\n", controller, device);
        pointer = check_controller(controller, 0);
        if (pointer >= 0 && check_device(pointer, device)) {
            printf("ESTAMOS INNNN___V2\n");
            send_get_data(pointer, device);
        }
    } else if (strcmp(command, "quit") == 0) {
        printf("AAAA\n");
        pthread_kill(thread1, SIGUSR1);
        pthread_kill(thread2, SIGUSR2);
        if (pthread_join(thread1, NULL) != 0) {
            perror("Error joining thread");
            exit(EXIT_FAILURE);
        }

        if (pthread_join(thread2, NULL) != 0) {
            perror("Error joining thread");
            exit(EXIT_FAILURE);
        }
        exit(0);
    }
}

void send_get_data(int pointer, char* device) {
    int offset, tcp_socket, sock, n;
    char buffer[SIZE];
    unsigned char type = GET_DATA;
    struct sockaddr_in cliaddr;
    Tcp_packet packet;
    FILE *file;
    time_t rawtime;
    struct tm *timeinfo;
    char buffer_time[9], file_name[20], text[SIZE], buffer_date[11];

    tcp_socket = atoi(clients[pointer].tcp_port);
    sock = socket(AF_INET, SOCK_STREAM, 0);
    bzero(&cliaddr, sizeof(cliaddr));

    cliaddr.sin_family = AF_INET;
    cliaddr.sin_addr.s_addr = inet_addr("127.0.0.1");
    cliaddr.sin_port = htons(tcp_socket);

    connect(sock, (struct sockaddr *)&cliaddr, sizeof(cliaddr));

    offset = 0;
    memcpy(buffer + offset, &type, 1);
    offset += 1;
    memcpy(buffer + offset, serv.mac, 13);
    offset += 13;
    memcpy(buffer + offset, clients[pointer].rndm, 9);
    offset += 9;
    memcpy(buffer + offset, device, 8);

    write(sock, buffer, sizeof(buffer));

    n = recv(sock, buffer, sizeof(buffer), 0);
    packet = hextoASCII_tcp(buffer, n);

    if (packet.type != DATA_ACK) {
        disconnect_client(pointer);
    }

    sprintf(file_name, "%s-%s", clients[pointer].name, clients[pointer].situation);
    file = fopen(file_name, "a");
    time(&rawtime);
    timeinfo = localtime(&rawtime);
    snprintf(buffer_time, sizeof(buffer_time), "%02d:%02d:%02d", timeinfo->tm_hour, timeinfo->tm_min, timeinfo->tm_sec);
    snprintf(buffer_date, sizeof(buffer_date), "%02d-%02d-%04d", timeinfo->tm_mday, timeinfo->tm_mon + 1, timeinfo->tm_year + 1900);
    sprintf(text, "%s,%s;GET_DATA;%s;%s\n",buffer_date ,buffer_time, packet.device, packet.value);
    fprintf(file, "%s", text);
    fclose(file);
    close(sock);
}

void send_set_data(int pointer, char* device, char* value) {
    int offset, tcp_socket, sock, n;
    char buffer[SIZE];
    unsigned char type = SET_DATA;
    struct sockaddr_in cliaddr;
    Tcp_packet packet;
    FILE *file;
    time_t rawtime;
    struct tm *timeinfo;
    char buffer_time[9], file_name[20], text[SIZE], buffer_date[11];

    tcp_socket = atoi(clients[pointer].tcp_port);
    sock = socket(AF_INET, SOCK_STREAM, 0);
    bzero(&cliaddr, sizeof(cliaddr));

    cliaddr.sin_family = AF_INET;
    cliaddr.sin_addr.s_addr = inet_addr("127.0.0.1");
    cliaddr.sin_port = htons(tcp_socket);

    connect(sock, (struct sockaddr *)&cliaddr, sizeof(cliaddr));

    offset = 0;
    memcpy(buffer + offset, &type, 1);
    offset += 1;
    memcpy(buffer + offset, serv.mac, 13);
    offset += 13;
    memcpy(buffer + offset, clients[pointer].rndm, 9);
    offset += 9;
    memcpy(buffer + offset, device, 8);
    offset += 8;
    memcpy(buffer + offset, value, 7);

    write(sock, buffer, sizeof(buffer));

    n = recv(sock, buffer, sizeof(buffer), 0);
    packet = hextoASCII_tcp(buffer, n);

    if (packet.type != DATA_ACK) {
        disconnect_client(pointer);
    }

    sprintf(file_name, "%s-%s", clients[pointer].name, clients[pointer].situation);
    file = fopen(file_name, "a");
    time(&rawtime);
    timeinfo = localtime(&rawtime);
    snprintf(buffer_time, sizeof(buffer_time), "%02d:%02d:%02d", timeinfo->tm_hour, timeinfo->tm_min, timeinfo->tm_sec);
    snprintf(buffer_date, sizeof(buffer_date), "%02d-%02d-%04d", timeinfo->tm_mday, timeinfo->tm_mon + 1, timeinfo->tm_year + 1900);
    sprintf(text, "%s,%s;SET_DATA;%s;%s\n",buffer_date ,buffer_time, packet.device, packet.value);
    fprintf(file, "%s", text);
    fclose(file);
    close(sock);
}

bool check_value_len(char* value, char* device) {
    if (strlen(value) <= 6) {
        return true;
    }
    printf("El valor de %s no pot superar els 6 caracters\n", device);
    return false;
}   

bool check_device_mode(char* device) {
    int len;
    char last_char;
    len = strlen(device);
    last_char = device[len - 1];
    if (last_char == 'I') {
        return true;
    }
    printf("L'element anomenat: %s és un sensor i no permet establir el seu valor\n", device);
    return false;
}

int check_controller(char* controller, int flag) {
    int i;

    for (i = 0; i < client_num; ++i) {
        if (strcmp(clients[i].name, controller) == 0) {
            if (strcmp(clients[i].state, "SEND_HELLO") == 0) {
                return i;
            } else if (flag == 0) {
                printf("El cliente %s no esta suscrito :0\n", controller);
                return -1;
            } else if (flag == 1) {
                return i;
            }
        }
    }
    printf("El controlador %s no se encuentra en la base de datos\n", controller);
    return -1;
}

void recieve_info(int sockfd, char* buffer, int n, struct sockaddr_in cliaddr) {
    char ip[1024];
    Udp_packet packet;
    bool mac_ok, rndm_ok;
    int flag;

    sprintf(ip, "%s", inet_ntoa(cliaddr.sin_addr));
    printf("IP: %s\n", ip);

    packet = hextoASCII_udp(buffer, n);
    mac_ok = check_mac(packet);
    rndm_ok = (strcmp(packet.rndm, "00000000") == 0);
    if (packet.type == SUBS_REQ) {
        if (mac_ok && rndm_ok) {
            save_client_data(packet, ip);
            send_subs_ack(sockfd, cliaddr, packet.controller);
        } else {
            if (check_controller(packet.controller, 1) == -1) {
                flag = 0;
            } else if (!mac_ok) {
                flag = 1;
            } else if(!rndm_ok) {
                flag = 2;
            }
            send_subs_rej(sockfd, cliaddr, flag);
            /*No fa falta desconnectar doncs ja ho està en aquest estat*/
        }
    } else {
        send_subs_nack(sockfd, cliaddr);
    }
}

void send_subs_nack(int sockfd, struct sockaddr_in addr_cli) {
    char buffer[SIZE];
    unsigned char type = SUBS_NACK;
    int offset = 0;

    memcpy(buffer + offset, &type, 1);
    offset += 1;
    memcpy(buffer + offset, serv.mac, 13);
    offset += 13;
    memcpy(buffer + offset, "00000000", 9);

    sendto(sockfd, buffer, sizeof(buffer) + 1, 0, (struct sockaddr*)&addr_cli,sizeof(struct sockaddr_in));
}

void send_subs_rej(int sockfd, struct sockaddr_in addr_cli, int flag) {
    char buffer[SIZE];
    char *text;
    unsigned char type = SUBS_REJ;
    int offset = 0;

    if (flag == 0) {
        text = "Nom incorrecte :(";
    } else if (flag == 1) {
        text = "MAC incorrecta :(";
    } else if(flag == 2) {
        text = "Random number incorrecte :(";
    } else if (flag == 3) {
        text = "El camp data estava buit :(";
    }

    memcpy(buffer + offset, &type, 1);
    offset += 1;
    memcpy(buffer + offset, serv.mac, 13);
    offset += 13;
    memcpy(buffer + offset, "00000000", 9);
    offset += 9;
    memcpy(buffer + offset, text, 80);

    sendto(sockfd, buffer, sizeof(buffer) + 1, 0, (struct sockaddr*)&addr_cli,sizeof(struct sockaddr_in));
}

Udp_packet hextoASCII_udp(char* hexArray, size_t size) {
    Udp_packet packet;
    char mac[SIZE];
    char rndm[SIZE];
    char controller[SIZE];
    char situation[SIZE];
    char data[SIZE];
    size_t i;

    packet.type = hexArray[0];

    for (i = 0; i < 13; ++i) {
        sprintf(mac + i, "%c", hexArray[i + 1]);
    }
    packet.mac = strdup(mac);

    for (i = 0; i < 9; ++i) {
        sprintf(rndm + i, "%c", hexArray[i + 14]);
    }
    packet.rndm = strdup(rndm);

    if (packet.type == SUBS_REQ || packet.type == HELLO) {
        for (i = 0; i < 8; ++i) {
            sprintf(controller + i, "%c", hexArray[i + 23]);
        }

        packet.controller = strdup(controller);

        for (i = 0; i < 72; ++i) {
            sprintf(situation + i, "%c", hexArray[i + 32]);
        }
        packet.situation = strdup(situation);
    } else if (packet.type == SUBS_INFO) {
        for (i = 0; i < 80; i++) {
            sprintf(data + i, "%c", hexArray[i + 23]);
        }
        packet.info = strdup(data);
        if (!strlen(packet.info) == 0) {
            parse_data(strdup(packet.info), strdup(packet.mac));
        }
    }
    return packet;
}

void parse_data(char* info, char* mac) {
    int pointer;
    char *token;

    for (pointer = 0; pointer < client_num; pointer++) {
        if (strcmp(clients[pointer].mac, mac) == 0) {
            break;
        }
    }

    token = strtok(info, ",");
    clients[pointer].tcp_port = strdup(token);
    printf("PUERTO: %s\n", clients[pointer].tcp_port);

    token = strtok(NULL, ",");
    clients[pointer].elements = strdup(token);
    printf("Elementos: %s\n", clients[pointer].elements);
}

void save_client_data(Udp_packet packet, char* ip) {
    int i;
    for (i = 0; i < client_num; i++) {
        if (strcmp(clients[i].name, packet.controller) == 0) {
            clients[i].ip = ip;
            clients[i].situation = packet.situation;
        }
    }
}

bool check_mac(Udp_packet packet) {
    int i;
    for (i = 0; i < client_num; i++) {
        if (strcmp(clients[i].name, packet.controller) == 0) {
            if (strcmp(clients[i].mac, packet.mac) == 0) {
                return true;
            }
        }
    }
    return false;
}

void send_subs_ack(int sockfd, struct sockaddr_in addr_cli, char* controller_name) {
    char buffer[SIZE];
    unsigned char type = SUBS_ACK;
    char rndm[SIZE];
    char port[SIZE];
    char controller[SIZE];
    int offset = 0, n, random_number, random_port, i, sock, flag;
    Udp_packet packet;
    struct sockaddr_in addr_server;
    socklen_t len;
    bool mac_ok, rndm_ok;

    strcpy(controller, controller_name);
    srand(time(NULL));
    random_number = rand() % 90000000 + 10000000;
    sprintf(rndm, "%d", random_number);

    random_port = (rand() % (65535 - 1024 + 1)) + 1024;
    sprintf(port, "%d", random_port);


    memcpy(buffer + offset, &type, 1);
    offset += 1;
    memcpy(buffer + offset, serv.mac, 13);
    offset += 13;
    memcpy(buffer + offset, rndm, 9);
    offset += 9;
    memcpy(buffer + offset, port, 80);
    offset += 80;
    
    sendto(sockfd, buffer, sizeof(buffer) + 1, 0, (struct sockaddr*)&addr_cli,sizeof(struct sockaddr_in));
    
    sock = socket(AF_INET, SOCK_DGRAM, 0);
    len = sizeof(addr_cli);
	memset(&addr_server,0, sizeof(struct sockaddr_in));
	
    addr_server.sin_family=AF_INET;
	addr_server.sin_addr.s_addr=htonl(INADDR_ANY);
	addr_server.sin_port=htons(random_port);
    
    bind(sock,(struct sockaddr *)&addr_server,sizeof(struct sockaddr_in));

    n = recvfrom(sock, (char *)buffer, 1024,  
                0, ( struct sockaddr *) &addr_cli, 
                &len); 
    /*Save random number + change state*/
    packet = hextoASCII_udp(buffer, sizeof(buffer));
    rndm_ok = (strcmp(packet.rndm, rndm) == 0);

    if (n > 0 && rndm_ok) {
        for (i = 0; i < client_num; i++) {
            if (strcmp(clients[i].name, controller) == 0) {
                clients[i].rndm = strdup(rndm);
                clients[i].state = "WAIT_INFO";
                break;
            }
        }
    } 
    mac_ok = (strcmp(clients[i].mac, packet.mac) == 0);

    printf("AAAAAAA: %s vs %s  %d\n",clients[i].mac, packet.mac, rndm_ok);
    printf("LO DEMAS: || %s ||%s ||%s ||%s ||%s ||%d\n",packet.controller,packet.info, packet.mac, packet.rndm, packet.situation, packet.type);
    if (strlen(packet.info) != 0 && rndm_ok && mac_ok) {
        send_info_ack(sock, sockfd, addr_cli, controller, i);
    } else {
        if (packet.controller != NULL && check_controller(packet.controller, 1) == -1) {
            flag = 0;
        } else if (!rndm_ok) {
            flag = 2;
        } else if(!mac_ok) {
            flag = 1;
        } else if (strlen(packet.info) == 0) {
            flag = 3;
        }
        send_subs_rej(sockfd, addr_cli, flag);
    }
}

void send_info_ack(int sockfd, int sock2, struct sockaddr_in addr_cli, char *controller, int pointer) {
    char buffer[1024];
    int offset = 0, prev_check;
    unsigned char type = INFO_ACK;
    memcpy(buffer + offset, &type, 1);
    offset += 1;
    memcpy(buffer + offset, serv.mac, 13);

    offset += 13;
    memcpy(buffer + offset, clients[pointer].rndm, 9);
    offset += 9;
    memcpy(buffer + offset, serv.tcp, 80);
    offset += 80;

    sendto(sockfd, buffer, sizeof(buffer) + 1, 0, (struct sockaddr*)&addr_cli,sizeof(struct sockaddr_in));

    clients[pointer].state = "SUBSCRIBED";
    /*per veure si el primer hello es enviat*/
    prev_check = clients[pointer].check_pack;
    sleep(v * 2);
    if (prev_check == clients[pointer].check_pack) {
        disconnect_client(pointer);
    }
}

void send_hello(int sockfd, struct sockaddr_in addr_cli, int pointer) {
    char buffer[1024];
    char data[1024];
    int offset = 0;
    unsigned char type = HELLO;

    memcpy(buffer + offset, &type, 1);
    offset += 1;
    memcpy(buffer + offset, serv.mac, 13);
    offset += 13;
    memcpy(buffer + offset, clients[pointer].rndm, 9);
    offset += 9;

    sprintf(data, "%s,%s", clients[pointer].name, clients[pointer].situation);
    memcpy(buffer + offset, data, 80);
    offset += 80;

    sendto(sockfd, buffer, sizeof(buffer) + 1, 0, (struct sockaddr*)&addr_cli,sizeof(struct sockaddr_in));
}

void *start_udp() {
    pthread_t thread_id;
    int udp_sock, n;
    char buffer[1024];
    struct sockaddr_in cliaddr;
    socklen_t len;
    ThreadArgs *args = malloc(sizeof *args);

    udp_sock = init_udp_socket();
    args->udp_port = udp_sock;

    memset(&cliaddr, 0, sizeof(cliaddr)); 
    len = sizeof(cliaddr);
    signal(SIGUSR1, handle_sigusr1);
    while (1) {
        n = recvfrom(udp_sock, (char *)buffer, 1024,  
                0, ( struct sockaddr *) &cliaddr, 
                &len);
        args->cliaddr = cliaddr;
        args->n = n;
        args->buffer = buffer;
        hextoASCII_udp(buffer, n);
        pthread_create(&thread_id, NULL, treat_udp, (void*)args);
    }
}

void* treat_udp(void* args) {
    int pointer, prev_check;
    Udp_packet packet;
    ThreadArgs *threadArgs = args;

    char* buffer = threadArgs->buffer;
    int udp_sock = threadArgs->udp_port;
    struct sockaddr_in cliaddr = threadArgs->cliaddr;
    int n = threadArgs->n;
    bool data_sent_ok;

    if (buffer[0] == HELLO) {
        packet = hextoASCII_udp(buffer, sizeof(buffer));
        for (pointer = 0; pointer < client_num; pointer++) {
            if (strcmp(clients[pointer].name, packet.controller) == 0) {
                if (strcmp(clients[pointer].state, "SUBSCRIBED") == 0) {
                    clients[pointer].state = "SEND_HELLO";
                }
                break;
            }
        }
        data_sent_ok = strlen(packet.situation) > 0 && strlen(packet.controller) > 0;
        if (check_credentials(pointer,"SEND_HELLO", packet.mac, packet.rndm) == 0 && data_sent_ok) {
            send_hello(udp_sock, cliaddr, pointer);
            clients[pointer].check_pack++;
            prev_check = clients[pointer].check_pack;
            sleep(v * x);
            if (clients[pointer].check_pack == prev_check) {
                printf("COUNTER CHECKER ---> Client: %s: %d VS %d\n",clients[pointer].name ,prev_check, clients[pointer].check_pack);
                disconnect_client(pointer);
            }
        } else {
            send_hello_rej(udp_sock, cliaddr, pointer);
        }
    } else {
        printf("Tratamiento nuevo cliente pipipipi \n");
        recieve_info(udp_sock,buffer, n, cliaddr);
    }
    return NULL;
}

void send_hello_rej(int sockfd, struct sockaddr_in addr_cli, int pointer) {
    char buffer[1024];
    char data[1024];
    int offset = 0;
    unsigned char type = HELLO_REJ;

    memcpy(buffer + offset, &type, 1);
    offset += 1;
    memcpy(buffer + offset, serv.mac, 13);
    offset += 13;
    memcpy(buffer + offset, clients[pointer].rndm, 9);

    sprintf(data, "%s,%s", clients[pointer].name, clients[pointer].situation);
    memcpy(buffer + offset, data, 80);
    offset += 80;

    sendto(sockfd, buffer, sizeof(buffer) + 1, 0, (struct sockaddr*)&addr_cli,sizeof(struct sockaddr_in));
}

void disconnect_client(int pointer) {
    clients[pointer].state = "DISCONNECTED";
    clients[pointer].check_pack = 0;
    clients[pointer].elements = "";
    clients[pointer].ip = "";
    clients[pointer].rndm = "";
    clients[pointer].situation = "";
}

void *start_tcp() {
    pthread_t thread_id;
    int tcp_sock, n, newsock;
    char buffer[SIZE];
    struct sockaddr_in cliaddr;
    socklen_t len;
    ThreadArgs *args = malloc(sizeof *args);

    tcp_sock = init_tcp_socket();
    args->udp_port = tcp_sock;

    memset(&cliaddr, 0, sizeof(cliaddr)); 
    len = sizeof(cliaddr);

    listen(tcp_sock, 5);

    printf("EN ELLO JEFE \n");
    signal(SIGUSR2, handle_sigusr2);
    while(1) {
        newsock = accept(tcp_sock,(struct sockaddr*)&cliaddr,&len);
        if (newsock > 0) {
            n = read(newsock,buffer,SIZE);
            printf("Leido: %d\n", n);
            if (n > 0) {
                args->buffer = buffer;
                args->udp_port = newsock;
                args->n = n;
                hextoASCII_udp(buffer, n);
                pthread_create(&thread_id, NULL, treat_tcp, (void*)args);
            }
        }
    }
}

void* treat_tcp(void* args) {
    Tcp_packet packet;
    int pointer, flag;
    FILE *file;
    time_t rawtime;
    struct tm *timeinfo;
    char buffer_time[9], file_name[20], text[SIZE], buffer_date[11];
    ThreadArgs *threadArgs = args;
    int socket = threadArgs->udp_port;
    int n = threadArgs->n;
    char* buffer = threadArgs->buffer;


    packet = hextoASCII_tcp(buffer, n);

    if (packet.type == SEND_DATA) {
        for (pointer = 0; pointer < client_num; pointer++) {
            if (strcmp(clients[pointer].mac, packet.mac) == 0) {
                break;
            }
        }
        flag = check_credentials(pointer,"SEND_HELLO", packet.mac, packet.rndm);
        if (pointer < client_num && flag == 0 && check_device(pointer, packet.device)) {
            sprintf(file_name, "%s-%s", clients[pointer].name, clients[pointer].situation);
            file = fopen(file_name, "a");

            if (file == NULL) {
                send_data_nack(socket, pointer);
            }
            time(&rawtime);
            timeinfo = localtime(&rawtime);
            snprintf(buffer_time, sizeof(buffer_time), "%02d:%02d:%02d", timeinfo->tm_hour, timeinfo->tm_min, timeinfo->tm_sec);
            snprintf(buffer_date, sizeof(buffer_date), "%02d-%02d-%04d", timeinfo->tm_mday, timeinfo->tm_mon + 1, timeinfo->tm_year + 1900);

            sprintf(text, "%s,%s;SEND_DATA;%s;%s\n",buffer_date ,buffer_time, packet.device, packet.value);

            fprintf(file, "%s", text);
            fclose(file);

            send_data_ack(socket, pointer, packet.device, packet.value);
            close(socket);
        } else {
            if (pointer < client_num) {
                flag = 4;
            }
            send_data_rej(socket, pointer ,packet.device, packet.value, flag);
        }
    }
    return NULL;
}

void send_data_rej(int socket, int pointer, char* device, char* value, int flag) {
    char buffer[SIZE];
    char *text;
    int offset = 0;
    unsigned char type = DATA_REJ;

    if (flag == 1) {
        text = "MAC incorrecta :(";
    } else if(flag == 2) {
        text = "Random number incorrecte :(";
    } else if (flag == 3) {
        text = "El client està en un estat incorrecte :(";
    } else {
        text = "Nom de l'element incorrecte :(";
    }

    memcpy(buffer + offset, &type, 1);
    offset += 1;
    memcpy(buffer + offset, serv.mac, 13);
    offset += 13;
    memcpy(buffer + offset, clients[pointer].rndm, 9);
    offset += 9;
    memcpy(buffer + offset, device, 8);
    offset += 8;
    memcpy(buffer + offset, value, 7);
    offset += 7;
    memcpy(buffer + offset, text, 80);

    write(socket, buffer, sizeof(buffer));
}

void send_data_nack(int socket, int pointer) {
    char buffer[SIZE];
    int offset = 0;
    unsigned char type = DATA_NACK;

    memcpy(buffer + offset, &type, 1);
    offset += 1;
    memcpy(buffer + offset, serv.mac, 13);
    offset += 13;
    memcpy(buffer + offset, clients[pointer].rndm, 9);

    write(socket, buffer, sizeof(buffer));
}

Tcp_packet hextoASCII_tcp(char* hexArray, size_t size) {
    Tcp_packet packet;
    char mac[SIZE];
    char rndm[SIZE];
    char device[SIZE];
    char value[SIZE];
    char info[SIZE];
    size_t i;

    packet.type = hexArray[0];

    for (i = 0; i < 13; ++i) {
        sprintf(mac + i, "%c", hexArray[i + 1]);
    }

    packet.mac = strdup(mac);
    printf("Mac: %s\n", packet.mac);

    for (i = 0; i < 9; ++i) {
        sprintf(rndm + i, "%c", hexArray[i + 14]);
    }

    packet.rndm = rndm;
    printf("Rndm: %s\n", packet.rndm);

    for (i = 0; i < 8; ++i) {
        sprintf(device + i, "%c", hexArray[i + 23]);
    }

    packet.device = device;
    printf("Device: %s\n", packet.device);

    for (i = 0; i < 7; ++i) {
        sprintf(value + i, "%c", hexArray[i + 31]);
    }

    packet.value = value;
    printf("Value: %s\n", packet.value);

    for (i = 0; i < size; ++i) {
        sprintf(info + i, "%c", hexArray[i + 38]);
    }

    packet.info = info;
    printf("Info: %s\n", packet.info);

    return packet;
}

bool check_device(int pointer, char* device) {
    const char delimiters[] = ";";
    char *token;
    char* ctrl_elements;

    ctrl_elements = strdup(clients[pointer].elements);
    token = strtok(ctrl_elements, delimiters);

    while (token != NULL) {
        if (strcmp(token, device) == 0) {
            return true;
        }
        token = strtok(NULL, delimiters);
    }
    return false;
}

void send_data_ack(int socket, int pointer, char* device, char* value) {
    char buffer[SIZE];
    int offset = 0;
    unsigned char type = DATA_ACK;

    memcpy(buffer + offset, &type, 1);
    offset += 1;
    memcpy(buffer + offset, serv.mac, 13);
    offset += 13;
    memcpy(buffer + offset, clients[pointer].rndm, 9);
    offset += 9;
    memcpy(buffer + offset, device, 8);
    offset += 8;
    memcpy(buffer + offset, value, 7);

    write(socket, buffer, sizeof(buffer));
}

int check_credentials (int pointer, char* state, char* mac, char* rndm) {
    bool state_ok, rndm_ok, mac_ok;
    state_ok = (strcmp(clients[pointer].state, state) == 0);
    rndm_ok = (strcmp(clients[pointer].rndm, rndm) == 0);
    mac_ok = (strcmp(clients[pointer].mac, mac) == 0);
    if (state_ok && rndm_ok && mac_ok) {
                return 0;
    }

    if (!mac_ok) {
        return 1;
    } else if (!rndm_ok) {
        return 2;
    } else {
        return 3;
    }
}