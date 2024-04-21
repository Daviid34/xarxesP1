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
#include <arpa/inet.h>
#include <errno.h>

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
#define w 3
#define t 1
#define s 2

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
    int sub_try_count;
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
void send_subs_rej(int sockfd, struct sockaddr_in addr_cli, int flag, Udp_packet packet, int pointer);
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
void send_data_nack(int socket, int pointer, char* device, char* value, int flag);
void handle_sigusr1(int sig);
void handle_sigusr2(int sig);
void handle_sigint(int sig);
int pthread_kill(pthread_t thread, int sig);
void bzero(void *s_, size_t n);
int snprintf(char *s_, size_t n, const char *format, ...);
char* get_datetime();
void print_info();
const char* parse_type();

/*-------------------------
Els 3 handle's serveixen per tancar de forma ordenada els fils i el pare
-------------------------*/
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
    printf("\033[1m");
    printf("%s: MSG. => Finalització per ^C\n", get_datetime());
    printf("\033[0m");
    if (debug) {
        printf("%s: DEBUG => Petició de finalització\n", get_datetime());
    }
    printf("Terminado\n");
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

char* get_datetime() {
    time_t current_time;
    struct tm *timeinfo;
    char datetime_buffer[100];

    time(&current_time);
    timeinfo = localtime(&current_time);

    sprintf(datetime_buffer, "%02d:%02d:%02d",
            timeinfo->tm_hour, timeinfo->tm_min, timeinfo->tm_sec);

    return strdup(datetime_buffer);
}

const char* parse_type(int type) {
    switch (type) {
        case SUBS_REQ: return "SUBS_REQ";
        case SUBS_ACK: return "SUBS_ACK";
        case SUBS_REJ: return "SUBS_REJ";
        case SUBS_INFO: return "SUBS_INFO";
        case INFO_ACK: return "INFO_ACK";
        case SUBS_NACK: return "SUBS_NACK";
        case HELLO: return "HELLO";
        case HELLO_REJ: return "HELLO_REJ";
        case SEND_DATA: return "SEND_DATA";
        case SET_DATA: return "SET_DATA";
        case GET_DATA: return "GET_DATA";
        case DATA_ACK: return "DATA_ACK";
        case DATA_NACK: return "DATA_NACK";
        case DATA_REJ: return "DATA_REJ";
        default: return "Unknown";
    }
}

/*
Utilitzat per interpretar els paràmetres de la línia de comandes i inicialitzar el servidor
*/
int main(int argc, char *argv[]) {
    if (argc == 2) {
        if (strcmp(argv[1], "-d") == 0) {
            debug = true;
            printf("%s: DEBUG => Llegits paràmetres linea de comandes\n", get_datetime());
            parse_server_conf("server.cfg");
            parse_controllers("controllers.dat");
        } else {
            parse_server_conf("server.cfg");
            parse_controllers("controllers.dat");
        }
    } else if (argc == 3) {
        if (strcmp(argv[1], "-c") == 0) {
            parse_server_conf(argv[2]);
            parse_controllers("controllers.dat");
        }
        else if (strcmp(argv[1], "-u") == 0) {
            parse_server_conf("server.cfg");
            parse_controllers(argv[2]);
        }
        else {
            parse_server_conf("server.cfg");
            parse_controllers("controllers.dat");
        }
    }

    else if (argc == 4) {
        if (strcmp(argv[1], "-c") == 0 && strcmp(argv[3], "-d") == 0) {
            debug = true;
            printf("%s: DEBUG => Llegits paràmetres linea de comandes\n", get_datetime());
            parse_server_conf(argv[2]);
            parse_controllers("controllers.dat");
        }
        else if (strcmp(argv[1], "-d") == 0 && strcmp(argv[2], "-c") == 0) {
            debug = true;
            printf("%s: DEBUG => Llegits paràmetres linea de comandes\n", get_datetime());
            parse_server_conf(argv[3]);
            parse_controllers("controllers.dat");
        }
        else if (strcmp(argv[1], "-u") == 0 && strcmp(argv[3], "-d") == 0) {
            debug = true;
            printf("%s: DEBUG => Llegits paràmetres linea de comandes\n", get_datetime());
            parse_server_conf("server.cfg");
            parse_controllers(argv[2]);
        }
        else if (strcmp(argv[1], "-d") == 0 && strcmp(argv[2], "-u") == 0) {
            debug = true;
            printf("%s: DEBUG => Llegits paràmetres linea de comandes\n", get_datetime());
            parse_server_conf("server.cfg");
            parse_controllers(argv[3]);
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
            debug = true;
            printf("%s: DEBUG => Llegits paràmetres linea de comandes\n", get_datetime());
            parse_server_conf(argv[2]);
            parse_controllers(argv[4]);
        }
        else if (strcmp(argv[1], "-u") == 0 && strcmp(argv[3], "-c") == 0 && strcmp(argv[5], "-d") == 0) {
            debug = true;
            printf("%s: DEBUG => Llegits paràmetres linea de comandes\n", get_datetime());
            parse_server_conf(argv[4]);
            parse_controllers(argv[2]);
        }
        else if (strcmp(argv[1], "-u") == 0 && strcmp(argv[3], "-d") == 0 && strcmp(argv[4], "-c") == 0) {
            debug = true;
            printf("%s: DEBUG => Llegits paràmetres linea de comandes\n", get_datetime());
            parse_server_conf(argv[5]);
            parse_controllers(argv[2]);
        }
        else if (strcmp(argv[1], "-c") == 0 && strcmp(argv[3], "-d") == 0 && strcmp(argv[4], "-u") == 0) {
            debug = true;
            printf("%s: DEBUG => Llegits paràmetres linea de comandes\n", get_datetime());
            parse_server_conf(argv[2]);
            parse_controllers(argv[5]);
        }
        else if (strcmp(argv[1], "-d") == 0 && strcmp(argv[2], "-u") == 0 && strcmp(argv[4], "-c") == 0) {
            debug = true;
            printf("%s: DEBUG => Llegits paràmetres linea de comandes\n", get_datetime());
            parse_server_conf(argv[5]);
            parse_controllers(argv[3]);
        }
        else if (strcmp(argv[1], "-d") == 0 && strcmp(argv[2], "-c") == 0 && strcmp(argv[4], "-u") == 0) {
            printf("%s: DEBUG => Llegits paràmetres linea de comandes\n", get_datetime());
            debug = true;
            parse_server_conf(argv[3]);
            parse_controllers(argv[5]);
        }
    }

    else {
        parse_server_conf("server.cfg");
        parse_controllers("controllers.dat");
    }
    init_server();
    return 0;
}

/*
Interpreta l'arxiu de dades de configuració del programari
*/
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
        if (strcmp(key, "Name") == 0) {
            remove_spaces(value);
            serv.name = strdup(value);
        }
        else if (strcmp(key, "MAC") == 0) {
            remove_spaces(value);
            serv.mac = strdup(value);
        }
        else if (strcmp(key, "UDP-port") == 0) {
            remove_spaces(value);
            serv.udp = strdup(value);
        }
        else if (strcmp(key, "TCP-port") == 0) {
            remove_spaces(value);
            serv.tcp = strdup(value);
        } else {
            printf("%s: Error al llegir les dades del fitxer\n", get_datetime());
            exit(0);
        }
    }
    fclose(file);
    if (debug) {
        printf("%s: DEBUG => Llegit paràmetres arxiu de configuració\n", get_datetime());
    }
}

/*
Interpreta l'arxiu de controladors autoritzats
*/
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
        if (value == NULL) {
            printf("%s: Error al llegir les dades del fitxer\n", get_datetime());
            exit(0);
        }
        value[strlen(value) - 1] = 0;
        clients[client_num].name = strdup(key);
        clients[client_num].ip = "     ";
        clients[client_num].mac = strdup(value);
        clients[client_num].rndm = "";
        clients[client_num].state = "DISCONNECTED";
        clients[client_num].situation = "";
        clients[client_num].elements = "";
        clients[client_num].check_pack = 0;
        clients[client_num].sub_try_count = 0;
        client_num++;
    }
    fclose(file);
    if (debug) {
        printf("%s: DEBUG => Llegits %d equips autoritzats en el sistema\n", get_datetime(), client_num);
        print_info();
    }
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

/*
Inicialitza el servidor, creant dos fils, un per tractar les connexions TCP (Transmission Control Protocol)
i l'altre per les connexions UDP (User Datagram Protocol).
El programa principal es quedarà a l'espera de comandes per la terminal.
*/
void init_server() {
    pthread_t thread_id, thread_id2;
    char buffer[1024];
    pthread_create(&thread_id, NULL, start_udp, NULL);
    pthread_create(&thread_id2, NULL, start_tcp, NULL);
    if (debug) {
        printf("%s: DEBUG => Procés establert per gestionar la BBDD dels controladors\n", get_datetime());
    }
    signal(SIGINT, handle_sigint);
    while(1) {
        if (fgets(buffer, 1024, stdin) != NULL) {
            buffer[strcspn(buffer, "\n")] = '\0';
            process_command(buffer, thread_id, thread_id2);
            memset(buffer, 0, sizeof(buffer));
        }
    }
}

/*
Crea el socket per on es rebran les connexions UDP.
*/
int init_udp_socket() {
    int sock = socket(AF_INET, SOCK_DGRAM, 0);

    struct sockaddr_in addr_server;
	memset(&addr_server,0, sizeof(struct sockaddr_in));

	addr_server.sin_family=AF_INET;
	addr_server.sin_addr.s_addr=htonl(INADDR_ANY);
	addr_server.sin_port=htons(atoi(serv.udp));

    bind(sock,(struct sockaddr *)&addr_server,sizeof(struct sockaddr_in));

    copied_udp = sock;

    if (debug) {
        printf("%s: DEBUG => Socket UDP actiu\n", get_datetime());
    }

    return sock;
}

/*
Crea el socket per on es rebran les connexions TCP.
*/
int init_tcp_socket() {
    int sock = socket(AF_INET, SOCK_STREAM, 0);

    struct sockaddr_in addr_server;
	memset(&addr_server,0, sizeof(struct sockaddr_in));

	addr_server.sin_family=AF_INET;
	addr_server.sin_addr.s_addr=htonl(INADDR_ANY);
	addr_server.sin_port=htons(atoi(serv.tcp));
    bind(sock,(struct sockaddr *)&addr_server,sizeof(struct sockaddr_in));

    copied_tcp = sock;

    if (debug) {
        printf("%s: DEBUG => Socket UDP actiu\n", get_datetime());
    }

    return sock;
}

/*
Interpreta la comanda rebuda per la terminal i actua en conseqüència
*/
void process_command(char buffer[], pthread_t thread1, pthread_t thread2) {
    int i, pointer;
    char command[100];
    char controller[50];
    char device[50];
    char value[50];

    sscanf(buffer, "%s", command);

    for (i = 0; i < strlen(command); i++) {
        command[i] = tolower(command[i]);
    }

    if (strcmp(command, "list") == 0) {
        print_info();
    } else if (strcmp(command, "set") == 0) {
        sscanf(buffer, "%s %s %s %s", command, controller, device, value);
        pointer = check_controller(controller, 0);
        if (pointer >= 0 && check_device(pointer, device) && check_device_mode(device) && check_value_len(value, device)) {
            send_set_data(pointer, device, value);
        }
    } else if (strcmp(command, "get") == 0) {
        sscanf(buffer, "%s %s %s %s", command, controller, device, value);
        pointer = check_controller(controller, 0);
        if (pointer >= 0 && check_device(pointer, device)) {
            send_get_data(pointer, device);
        } else {
            printf("Error en la comanda\n");
        }
    } else if (strcmp(command, "quit") == 0) {
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
        printf("%s: Terminado\n", get_datetime());
        exit(0);
    }
}

/*
Mostra per pantalla la informació de tots els controladors autoritzats.
*/
void print_info () {
    int j;
    printf("--NOM--- ------IP------- -----MAC---- --RNDM-- ----ESTAT--- --SITUACIÓ-- --ELEMENTS-------------------------------------------\n");
        for (j = 0; j < client_num; j++) {
            printf("%-10s %-13s %-13s %-8s %-12s %-12s %s\n", clients[j].name, clients[j].ip, clients[j].mac, clients[j].rndm, 
            clients[j].state, clients[j].situation, clients[j].elements);
        }
}

/*
Envia el paquet del tipus GET_DATA.
També rep i tracta la resposta d'aquest actuant en conseqüència.
*/
void send_get_data(int pointer, char* device) {
    int offset, tcp_socket, sock, n, flag;
    char buffer[SIZE];
    unsigned char type = GET_DATA;
    struct sockaddr_in cliaddr;
    Tcp_packet packet;
    FILE *file;
    time_t rawtime;
    struct tm *timeinfo;
    char buffer_time[9], file_name[20], text[SIZE], buffer_date[11];
    bool device_ok;
    struct timeval timeout;
    timeout.tv_sec = w;
    timeout.tv_usec = 0;

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
    if (debug) {
        printf("%s: DEBUG => Enviat: bytes=%ld, comanda=%s, mac=%s, rndm=%s, element: %s, valor: %s, info=%s\n", 
                    get_datetime(), sizeof(buffer), parse_type(packet.type), packet.mac, packet.rndm, packet.device, packet.value, packet.info);
    }
    /*
    Tractament de la resposta al paquet GET_DATA
    */
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (char *)&timeout, sizeof(timeout));
    n = recv(sock, buffer, sizeof(buffer), 0);
    if (n == -1) {
        pthread_exit(NULL);
    } else {        
        packet = hextoASCII_tcp(buffer, n);
        if (debug) {
            printf("%s: DEBUG => Rebut: bytes=%d, comanda=%s, mac=%s, rndm=%s, element: %s, valor: %s, info=%s\n", 
                    get_datetime(), n, parse_type(packet.type), packet.mac, packet.rndm, packet.device, packet.value, packet.info);
        }
        if (packet.type != DATA_ACK) {
            disconnect_client(pointer);
            clients[pointer].sub_try_count++;
        }
        flag = check_credentials(pointer, "SEND_HELLO", packet.mac, packet.rndm);
        device_ok = check_device(pointer, packet.device);
        if (flag == 0 && device_ok) {
            sprintf(file_name, "%s-%s", clients[pointer].name, clients[pointer].situation);
            file = fopen(file_name, "a");
            time(&rawtime);
            timeinfo = localtime(&rawtime);
            snprintf(buffer_time, sizeof(buffer_time), "%02d:%02d:%02d", timeinfo->tm_hour, timeinfo->tm_min, timeinfo->tm_sec);
            snprintf(buffer_date, sizeof(buffer_date), "%02d-%02d-%04d", timeinfo->tm_mday, timeinfo->tm_mon + 1, timeinfo->tm_year + 1900);
            sprintf(text, "%s,%s;GET_DATA;%s;%s\n",buffer_date ,buffer_time, packet.device, packet.value);
            fprintf(file, "%s", text);
            if (debug) {
                printf("%s: DEBUG => Dades del controlador: %s [%s], element: %s emmagatzemades correctament\n",
                        get_datetime(), clients[pointer].name, clients[pointer].mac, device);
            }
            fclose(file);
        } else {
            if (!device_ok) {
                send_data_nack(sock, pointer,packet.device, packet.value, 1);
            } else {
                send_data_rej(sock, pointer, packet.device, packet.value, flag);
                disconnect_client(pointer);
                clients[pointer].sub_try_count++;
            }
        }
    }
    close(sock);
}

/*
Envia el paquet del tipus SET_DATA.
També rep i tracta la resposta d'aquest actuant en conseqüència.
*/
void send_set_data(int pointer, char* device, char* value) {
    int offset, tcp_socket, sock, n, flag;
    char buffer[SIZE];
    unsigned char type = SET_DATA;
    struct sockaddr_in cliaddr;
    Tcp_packet packet;
    FILE *file;
    time_t rawtime;
    struct tm *timeinfo;
    char buffer_time[9], file_name[20], text[SIZE], buffer_date[11];
    bool device_ok;
    struct timeval timeout;
    timeout.tv_sec = w;
    timeout.tv_usec = 0;

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
    offset += 7;

    write(sock, buffer, sizeof(buffer));
    if (debug) {
        printf("%s: DEBUG => Enviat: bytes=%ld, comanda=%s, mac=%s, rndm=%s, element: %s, valor: %s, info=\n",
                get_datetime(), sizeof(buffer), parse_type(type), serv.mac, clients[pointer].rndm, device, value);
    }
    /*
    Tractament de la resposta a SET_DATA
    */
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (char *)&timeout, sizeof(timeout));
    n = recv(sock, buffer, sizeof(buffer), 0);
    if (n == -1) {
        pthread_exit(NULL);
    } else {        
        packet = hextoASCII_tcp(buffer, n);
        if (debug) {
            printf("%s: DEBUG => Rebut: bytes=%d, comanda=%s, mac=%s, rndm=%s, element: %s, valor: %s, info=%s\n", 
                    get_datetime(), n, parse_type(packet.type), packet.mac, packet.rndm, packet.device, packet.value, packet.info);
        }
        if (packet.type != DATA_ACK) {
            disconnect_client(pointer);
            clients[pointer].sub_try_count++;
        }

        flag = check_credentials(pointer, "SEND_HELLO", packet.mac, packet.rndm);
        device_ok = check_device(pointer, packet.device);
        if (flag == 0 && device_ok) {
            sprintf(file_name, "%s-%s", clients[pointer].name, clients[pointer].situation);
            file = fopen(file_name, "a");
            time(&rawtime);
            timeinfo = localtime(&rawtime);
            snprintf(buffer_time, sizeof(buffer_time), "%02d:%02d:%02d", timeinfo->tm_hour, timeinfo->tm_min, timeinfo->tm_sec);
            snprintf(buffer_date, sizeof(buffer_date), "%02d-%02d-%04d", timeinfo->tm_mday, timeinfo->tm_mon + 1, timeinfo->tm_year + 1900);
            sprintf(text, "%s,%s;SET_DATA;%s;%s\n",buffer_date ,buffer_time, packet.device, packet.value);
            fprintf(file, "%s", text);
            if (debug) {
                printf("%s: DEBUG => Dades del controlador: %s [%s], element: %s emmagatzemades correctament\n",
                        get_datetime(), clients[pointer].name, clients[pointer].mac, device);
            }
            fclose(file);
        } else {
            if (!device_ok) {
                send_data_nack(sock, pointer,packet.device, packet.value, 1);
            } else {
                send_data_rej(sock, pointer, packet.device, packet.value, flag);
                disconnect_client(pointer);
                clients[pointer].sub_try_count++;
            }
        }
    }
    close(sock);
}

/*
Comprova que en la comanda set, l'apartat valor no superi 6 caràcters
*/
bool check_value_len(char* value, char* device) {
    if (strlen(value) <= 6) {
        return true;
    }
    printf("%s: MSG. => El valor de %s no pot superar els 6 caràcters\n", get_datetime(),device);
    return false;
}   

/*
Comprova que la comanda set es faci sobre un dispositiu d'entrada
*/
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
 
 /*
 Retorna un punter a l'array de controladors (clients) en el cas que estigui
 en l'estat SEND_HELLO, si no es troba o no està subscrit es retornarà -1.
 */
int check_controller(char* controller, int flag) {
    int i;
    for (i = 0; i < client_num; ++i) {
        if (strcmp(clients[i].name, controller) == 0) {
            if (strcmp(clients[i].state, "SEND_HELLO") == 0) {
                return i;
            } else if (flag == 0) {
                printf("El client %s no està subscrit \n", controller);
                return -1;
            } else if (flag == 1) {
                return i;
            }
        }
    }
    printf("%s: ALERT => El controlador %s no es troba en la bano es troba en la se de dades\n",get_datetime(), controller);
    return -1;
}

/*
Tracta els paquets SUBS_REQ que arriben pel port UDP
i actua en conseqüència.
*/
void recieve_info(int sockfd, char* buffer, int n, struct sockaddr_in cliaddr) {
    char ip[1024];
    Udp_packet packet;
    bool mac_ok, rndm_ok;
    int flag, i;

    sprintf(ip, "%s", inet_ntoa(cliaddr.sin_addr));

    packet = hextoASCII_udp(buffer, n);
    if (debug) {
        printf("%s: DEBUG => Rebut: bytes=%d, comanda=%s, mac=%s, rndm=%s, dades=%s,%s\n", 
                    get_datetime(), n, parse_type(packet.type), packet.mac, packet.rndm, packet.controller, packet.situation);
    }
    for (i = 0; i < client_num; i++) {
        if (strcmp(packet.mac, clients[i].mac) == 0) {
            if (strcmp(clients[i].state, "DISCONNECTED") != 0) {
                if (debug) {
                    printf("%s: DEBUG => Rebut paquet: %s en estat %s. Controlador [%s] passa a estat DISCONNECTED\n",
                        get_datetime(), parse_type(packet.type), clients[i].state,  clients[i].mac);
                }
                send_subs_rej(sockfd, cliaddr, 4, packet, i);
                disconnect_client(i);
                clients[i].sub_try_count++;
                pthread_exit(NULL);
            }
        }
    }
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
            send_subs_rej(sockfd, cliaddr, flag, packet, 4);
            /*No fa falta desconnectar doncs ja ho està en aquest estat*/
        }
    } else {
        send_subs_nack(sockfd, cliaddr);
    }
}

/*
Envia el paquet SUBS_NACK al port udp especificat (sockfd)
*/
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

/*
Envia el paquet SUBS_REJ al port udp especificat (sockfd)
*/
void send_subs_rej(int sockfd, struct sockaddr_in addr_cli, int flag, Udp_packet packet, int pointer) {
    char buffer[SIZE];
    char *text;
    unsigned char type = SUBS_REJ;
    int offset = 0;

    if (flag == 0) {
        printf("%s: INFO  => Rebutjat paquet %s. Controlador: %s [%s] (error identificació)\n", get_datetime(), parse_type(packet.type), clients[pointer].name, clients[pointer].mac);
        text = "Error identificació";
    } else if (flag == 1) {
        printf("%s: INFO => Petició de subscripció errònia. Controlador: mac=%s no autoritzat\n", get_datetime(), packet.mac);
        text = "MAC incorrecta";
    } else if(flag == 2) {
        printf("%s: INFO => Petició de subscripció errònia. Controlador: mac=%s rndm=%s (rndm incorrecte)\n", get_datetime(), packet.mac, packet.rndm);
        text = "Random number incorrecte";
    } else if (flag == 3) {
        printf("%s: INFO  => Rebutjat paquet %s. Controlador: %s [%s] (error identificació)\n", get_datetime(), parse_type(packet.type), clients[pointer].name, clients[pointer].mac);
        text = "El camp data estava buit";
    } else {
        text = "";
    }

    memcpy(buffer + offset, &type, 1);
    offset += 1;
    memcpy(buffer + offset, serv.mac, 13);
    offset += 13;
    memcpy(buffer + offset, "00000000", 9);
    offset += 9;
    memcpy(buffer + offset, text, 80);

    sendto(sockfd, buffer, sizeof(buffer) + 1, 0, (struct sockaddr*)&addr_cli,sizeof(struct sockaddr_in));
    if (debug) {
        printf("%s: DEBUG => Enviat: bytes=%ld, tipus=%s, mac=%s, rndm=00000000, dades=%s\n",
            get_datetime(), sizeof(buffer), parse_type(type), serv.mac, text);
    }
}   

/*
Descodifica els buffers utilitzats alhora de rebre informació per un socket UDP
i guarda les dades del paquet en una estructura del tipus Udp_packet.
*/
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

/*
Tracta el camp 'dades' dels paquets SUBS_INFO, separant el port TCP 
de la llista de dispositius.
*/
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
    token = strtok(NULL, ",");
    clients[pointer].elements = strdup(token);
}

/*
Guarda la IP i la situació del controlador rebudes en el paquet SUBS_REQ.
*/
void save_client_data(Udp_packet packet, char* ip) {
    int i;
    for (i = 0; i < client_num; i++) {
        if (strcmp(clients[i].name, packet.controller) == 0) {
            clients[i].ip = ip;
            clients[i].situation = packet.situation;
        }
    }
}

/*
Comprova si la mac pertany a un controlador autoritzat.
*/
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

/*
Envia el paquet SUBS_ACK i tracta la resposta per part del controlador a aquest.
*/
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
    struct timeval timeout;
    timeout.tv_sec = s * t;
    timeout.tv_usec = 0;

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
    if (debug) {
        printf("%s: DEBUG => Enviat: bytes=%ld, comanda=%s, mac=%s, rndm=%s, dades=%s\n",
                get_datetime(), sizeof(buffer), parse_type(type), serv.mac, rndm, port);

    }
    strcpy(controller, controller_name);
    for (i = 0; i < client_num; i++) {
        if (strcmp(clients[i].name, controller) == 0) {
            clients[i].state = "WAIT_INFO";
            printf("\033[1m");
            printf("%s: MSG. => Controlador: %s, passa a l'estat: %s\n"
                        , get_datetime(), clients[i].name, clients[i].state);
            printf("\033[0m");
            break;
        }
    }
    /*
    Obertura del nou port UDP per continuar el procés de subscripció
    i tractament de la resposta a SUBS_ACK.
    */
    sock = socket(AF_INET, SOCK_DGRAM, 0);
    len = sizeof(addr_cli);
	memset(&addr_server,0, sizeof(struct sockaddr_in));
	
    addr_server.sin_family=AF_INET;
	addr_server.sin_addr.s_addr=htonl(INADDR_ANY);
	addr_server.sin_port=htons(random_port);
    
    bind(sock,(struct sockaddr *)&addr_server,sizeof(struct sockaddr_in));
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (char *)&timeout, sizeof(timeout));
    n = recvfrom(sock, (char *)buffer, 1024,  
                0, ( struct sockaddr *) &addr_cli, 
                &len); 
    if (n == -1) {
        printf("%s: WARN. => Finalització del procés de subscripció en no rebre el paquet SUBS_INFO\n", get_datetime());
        disconnect_client(i);
        clients[i].sub_try_count++;
        if (debug) {
            printf("%s: DEBUG => Finalitzat procés que atenia el paquet UDP\n", get_datetime());
        }
    } else {
        packet = hextoASCII_udp(buffer, sizeof(buffer));
        if (debug) {
            printf("%s: DEBUG => Rebut: bytes=%d, comanda=%s, mac=%s, rndm=%s, dades=%s\n",
                    get_datetime(), n, parse_type(packet.type), packet.mac, packet.rndm, packet.info);
        }
        rndm_ok = (strcmp(packet.rndm, rndm) == 0);
        mac_ok = (strcmp(clients[i].mac, packet.mac) == 0);

        if (strlen(packet.info) != 0 && rndm_ok && mac_ok) {
            clients[i].rndm = strdup(rndm);
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
            send_subs_rej(sockfd, addr_cli, flag, packet, i);
            disconnect_client(i);
            clients[i].sub_try_count++;
            if (debug) {
                printf("%s: DEBUG => Finalitzat procés que atenia el paquet UDP\n",get_datetime());
            }
            pthread_exit(NULL);
        }
    }
}

/*
Envia el paquet INFO_ACK, acabant amb el procés de subscripció,
i alhora serveix de Time Out per comprovar si el primer HELLO
per part del controlador arriba.
*/
void send_info_ack(int sockfd, int sock2, struct sockaddr_in addr_cli, char *controller, int pointer) {
    char buffer[1024];
    int offset = 0, prev_check, prev_sub_count;
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
    if (debug) {
        printf("%s: DEBUG => Enviat: bytes=%ld, comanda=%s, mac=%s, rndm=%s, dades=%s\n",
                get_datetime(), sizeof(buffer), parse_type(type), serv.mac, clients[pointer].rndm, serv.tcp);
    }

    clients[pointer].state = "SUBSCRIBED";
    close(sockfd);
    printf("\033[1m");
    printf("%s: MSG. => Controlador: %s, passa a l'estat: %s\n"
                        , get_datetime(), clients[pointer].name, clients[pointer].state);
    printf("\033[0m");
    if (debug) {
        printf("%s: DEBUG => Finalitzat procés que atenia el paquet UDP\n",get_datetime());
        printf("%s: DEBUG => Establert timeout pel primer paquet HELLO\n", get_datetime());
    }
    /*Tractament per veure si el primer hello es enviat*/
    prev_check = clients[pointer].check_pack;
    /*Per veure si al no arribar el primer HELLO s'ha començat un nou procés de subscripció, doncs llavors no cal desconectar*/
    prev_sub_count = clients[pointer].sub_try_count;
    sleep(v * x);
    if (prev_check == clients[pointer].check_pack && clients[pointer].sub_try_count == prev_sub_count) {
        printf("%s: MSG. => Controlador: %s [%s] no ha rebut %d HELLO's consecutius\n",
            get_datetime(), clients[pointer].name, clients[pointer].mac, x);
        disconnect_client(pointer);
        clients[pointer].sub_try_count++;
    }
}

/*
Envia el paquet HELLO per mantenir la comunicació amb el controlador
*/
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
    if (debug) {
        printf("%s: DEBUG => Enviat: bytes=%ld, comanda=%s, mac=%s, rndm=%s, dades=%s\n",
                get_datetime(), sizeof(buffer), parse_type(type), serv.mac, clients[pointer].rndm, data);
    }
}

/*
Funció que escolta constantment pel port UDP a l'espera de paquets.
En rebre un crea un fil per tractar-lo.
*/
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
        if (debug) {
            printf("%s: DEBUG => Rebut paquet UDP, creat procés per atendre'l\n", get_datetime());
        }
        pthread_create(&thread_id, NULL, treat_udp, (void*)args);
    }
}

/*
Tracta el paquet UDP rebut, comprovant si es tracta d'un HELLO o d'una nova connexió.
*/
void* treat_udp(void* args) {
    int pointer, prev_check;
    Udp_packet packet;
    ThreadArgs *threadArgs = args;

    char* buffer = threadArgs->buffer;
    int udp_sock = threadArgs->udp_port;
    struct sockaddr_in cliaddr = threadArgs->cliaddr;
    int n = threadArgs->n;
    bool data_sent_ok;

    if (buffer[0] == HELLO_REJ) {
        pthread_exit(NULL);
    }

    if (buffer[0] == HELLO) {
        packet = hextoASCII_udp(buffer, sizeof(buffer));
        if (debug) {
            printf("%s: DEBUG => Rebut: bytes=%d, comanda=%s, mac=%s, rndm=%s, dades=%s,%s\n", 
                    get_datetime(), n, parse_type(packet.type), packet.mac, packet.rndm, packet.controller, packet.situation);
            printf("%s: DEBUG => Rebut paquet HELLO del controlador: %s [%s]\n", 
                    get_datetime(), packet.controller, packet.mac);
        }
        for (pointer = 0; pointer < client_num; pointer++) {
            if (strcmp(clients[pointer].name, packet.controller) == 0) {
                if (strcmp(clients[pointer].state, "SUBSCRIBED") == 0) {
                    clients[pointer].state = "SEND_HELLO";
                    printf("\033[1m");
                    printf("%s: MSG. => Controlador: %s, passa a l'estat: %s\n"
                        , get_datetime(), clients[pointer].name, clients[pointer].state);
                    printf("\033[0m");
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
            if (clients[pointer].check_pack == prev_check && strcmp(clients[pointer].state, "DISCONNECT") != 0) {
                printf("%s: MSG. => Controlador %s [%s] no ha rebut 3 HELLO consecutius\n",
                    get_datetime(), clients[pointer].name, clients[pointer].mac);
                disconnect_client(pointer);
                clients[pointer].sub_try_count++;
            }
        } else {
            if (debug) {
                printf("%s: DEBUG => Rebut paquet: HELLO del controlador [%s] amb dades d'identificació incorrectes\n",
                    get_datetime(), clients[pointer].mac);
            }
            send_hello_rej(udp_sock, cliaddr, pointer);
            if (strcmp(clients[pointer].state, "DISCONNECTED") != 0) {
                disconnect_client(pointer);
                clients[pointer].sub_try_count++;
            }
        }
    } else {
        recieve_info(udp_sock,buffer, n, cliaddr);
    }
    return NULL;
}

/*
Envia el paquet HELLO_REJ pel port UDP especificat (sockfd)
*/
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
    if (debug) {
        printf("%s: DEBUG => Enviat: bytes=%ld, comanda=%s, mac=%s, rndm=%s, dades=%s\n",
                get_datetime(), sizeof(buffer), parse_type(type), serv.mac, clients[pointer].rndm, data);
    }
}

/*
Desconnecta el controlador associat al punter.
*/
void disconnect_client(int pointer) {
    printf("\033[1m");
    printf("%s: MSG.  => Controlador: %s, passa a l'estat: DISCONNECTED\n",get_datetime() ,clients[pointer].name);
    printf("\033[0m");
    clients[pointer].state = "DISCONNECTED";
    clients[pointer].check_pack = 0;
    clients[pointer].elements = "";
    clients[pointer].ip = "";
    clients[pointer].rndm = "";
    clients[pointer].situation = "";
}

/*
Funció que escolta constantment pel port TCP a l'espera de paquets.
En rebre un crea un fil per tractar-lo.
*/
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

    signal(SIGUSR2, handle_sigusr2);
    while(1) {
        newsock = accept(tcp_sock,(struct sockaddr*)&cliaddr,&len);
        if (newsock > 0) {
            n = read(newsock,buffer,SIZE);
            if (n > 0) {
                args->buffer = buffer;
                args->udp_port = newsock;
                args->n = n;
                hextoASCII_udp(buffer, n);
                if (debug) {
                    printf("%s: DEBUG => Rebuda connexió TCP, creat procés per atendre'l\n", get_datetime());
                }
                pthread_create(&thread_id, NULL, treat_tcp, (void*)args);
            }
        }
    }
}

/*
Tracta el paquet rebut pel port TCP comprovant si és correcte i es tracta
d'un paquet del tipus SEND_DATA.
*/
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
    bool device_ok;

    packet = hextoASCII_tcp(buffer, n);
    if (debug) {
        printf("%s: DEBUG => Rebut: bytes=%d, comanda=%s, mac=%s, rndm=%s, element: %s, valor: %s, info=%s\n", 
                get_datetime(), n, parse_type(packet.type), packet.mac, packet.rndm, packet.device, packet.value, packet.info);
    }

    if (packet.type == SEND_DATA) {
        for (pointer = 0; pointer < client_num; pointer++) {
            if (strcmp(clients[pointer].mac, packet.mac) == 0) {
                break;
            }
        }
        flag = check_credentials(pointer,"SEND_HELLO", packet.mac, packet.rndm);
        device_ok = check_device(pointer, packet.device);
        if (pointer < client_num && flag == 0 && device_ok) {
            sprintf(file_name, "%s-%s", clients[pointer].name, clients[pointer].situation);
            file = fopen(file_name, "a");

            if (file == NULL) {
                send_data_nack(socket, pointer, packet.device, packet.value, 0);
            }
            time(&rawtime);
            timeinfo = localtime(&rawtime);
            snprintf(buffer_time, sizeof(buffer_time), "%02d:%02d:%02d", timeinfo->tm_hour, timeinfo->tm_min, timeinfo->tm_sec);
            snprintf(buffer_date, sizeof(buffer_date), "%02d-%02d-%04d", timeinfo->tm_mday, timeinfo->tm_mon + 1, timeinfo->tm_year + 1900);

            sprintf(text, "%s,%s;SEND_DATA;%s;%s\n",buffer_date ,buffer_time, packet.device, packet.value);
            fprintf(file, "%s", text);
            if (debug) {
                printf("%s: DEBUG => Dades del controlador: %s [%s], element: %s emmagatzemades correctament\n",
                        get_datetime(), clients[pointer].name, clients[pointer].mac, packet.device);
            }
            fclose(file);

            send_data_ack(socket, pointer, packet.device, packet.value);
            close(socket);
        } else {
            if (pointer < client_num) {
                flag = 4;
            }
            if (!device_ok) {
                send_data_nack(socket, pointer, packet.device, packet.value, 1);
            } else {
                send_data_rej(socket, pointer ,packet.device, packet.value, flag);
            }
        }
    }
    if (debug) {
        printf("%s: DEBUG => Finalitzat el procés que atenia a un client TCP\n", get_datetime());
    }
    return NULL;
}

/*
Envia el paquet del tipus DATA_REJ especificant el motiu del rebuig.
*/
void send_data_rej(int socket, int pointer, char* device, char* value, int flag) {
    char buffer[SIZE];
    char *text;
    int offset = 0;
    unsigned char type = DATA_REJ;

    if (flag == 1) {
        if (debug) {
            printf("%s: DEBUG  => Error en les dades d'identificació. Controlador: %s [%s] (error mac)\n", 
                get_datetime(), clients[pointer].name, clients[pointer].mac);
        }
        text = "MAC incorrecta";
    } else if(flag == 2) {
        if (debug) {
            printf("%s: DEBUG  => Rebutjat paquet SEND_DATA. Controlador: %s [%s] (error random number)\n", 
                get_datetime(), clients[pointer].name, clients[pointer].mac);
        }
        text = "Random number incorrecte";
    } else if (flag == 3) {
        if (debug) {
            printf("%s: DEBUG  => Rebutjat paquet SEND_DATA. Controlador: %s [%s] (error controler state)\n", 
                get_datetime(), clients[pointer].name, clients[pointer].mac);
        }
        text = "El client està en un estat incorrecte";
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
    if (debug) {
        printf("%s: DEBUG => Enviat: bytes=%ld, comanda=%s, mac=%s, rndm=%s, element: %s, valor: %s, info=%s\n", 
                get_datetime(), sizeof(buffer), parse_type(type), serv.mac, clients[pointer].rndm, device, value, text);
    }
}

/*
Envia el paquet del tipus DATA_NACK
*/
void send_data_nack(int socket, int pointer, char* device, char* value, int flag) {
    char buffer[SIZE];
    int offset = 0;
    unsigned char type = DATA_NACK;
    char* info = "No s'ha pogut guardar les dades";

    if (flag == 1) {
        info = "Element no pertany al controlador";
        if (debug) {
            printf("%s: DEBUG  => Rebut paquet incorrecte. Controlador: %s [%s] (element incorrecte)\n", 
                get_datetime(), clients[pointer].name, clients[pointer].mac);
        }
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
    memcpy(buffer + offset, info, 80);

    write(socket, buffer, sizeof(buffer));

    if (debug) {
        printf("%s: DEBUG => Enviat: bytes=%ld, comanda=%s, mac=%s, rndm=%s, element: %s, valor: %s, info=%s\n", 
                get_datetime(), sizeof(buffer), parse_type(type), serv.mac, clients[pointer].rndm, device, value, info);
    }
}

/*
Descodifica els buffers utilitzats alhora de rebre informació per un socket TCP
i guarda les dades del paquet en una estructura del tipus Tcp_packet.
*/
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

    for (i = 0; i < 9; ++i) {
        sprintf(rndm + i, "%c", hexArray[i + 14]);
    }
    packet.rndm = strdup(rndm);

    for (i = 0; i < 8; ++i) {
        sprintf(device + i, "%c", hexArray[i + 23]);
    }
    packet.device = strdup(device);

    for (i = 0; i < 7; ++i) {
        sprintf(value + i, "%c", hexArray[i + 31]);
    }
    packet.value = strdup(value);

    for (i = 0; i < size; ++i) {
        sprintf(info + i, "%c", hexArray[i + 38]);
    }
    packet.info = strdup(info);
    return packet;
}

/*
Comprova que el dispositiu estigui a la llista de dispositius
del controlador associat al punter.
*/
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

/*
Envia el paquet del tipus DATA_ACK
*/
void send_data_ack(int socket, int pointer, char* device, char* value) {
    char buffer[SIZE];
    char* info = "Dades emmagatzemades";
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
    offset += 7;
    memcpy(buffer + offset, info, 80);
    offset += 80;

    write(socket, buffer, sizeof(buffer));
    if (debug) {
        printf("%s: DEBUG => Enviat: bytes=%ld, comanda=%s, mac=%s, rndm=%s, element: %s, valor: %s, info=%s\n", 
                get_datetime(), sizeof(buffer), parse_type(type), serv.mac, clients[pointer].rndm, device, value, info);
    }
}

/*
Comprova que l'estat, el número aleatori i la mac del controlador associat siguin
iguals a les passades per paràmetres.
*/
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