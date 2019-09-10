
#ifndef __MAIN_H__
#define __MAIN_H__

// socks version
#define VERSION 0x05

// request command
#define CONNECT 0x01
#define BIND    0x02
#define UDP     0x03

// address type
#define IPV4    0x01
#define DOMAIN  0x03
#define IPV6    0x04

// methods
#define NO_AUTHENTICATION_REQUIRED 0x00
#define GSSAPI                     0x01
#define USERNAME_PASSWORD          0x02
#define NO_ACCEPTABLE_METHODS      0xff

// reply
#define SUCCEEDED                         0x00
#define GENERAL_SOCKS_SERVER_FAILURE      0x01
#define CONNECTION_NOT_ALLOWED_BY_RULESET 0x02
#define NETWORK_UNREACHABLE               0x03
#define HOST_UNREACHABLE                  0x04
#define CONNECTION_REFUSED                0x05
#define TTL_EXPIRED                       0x06
#define COMMAND_NOT_SUPPORTED             0x07
#define ADDRESS_TYPE_NOT_SUPPORTED        0x08

// size
#define BUFF_SIZE 1024
#define SERVER_HELLO_SIZE 2
#define RESULTS_SIZE 2
#define REPLY_SIZE 10

// default server addr and port
#define DEFAULT_SERVER_ADDR INADDR_ANY
#define DEFAULT_SERVER_PORT 1080

#define UNAME_MAX_LEN 10
#define PASSWD_MAX_LEN 10

// max user count
#define MAX_USER_COUNT 100

struct client_hello {
    uint8_t ver;
    uint8_t nmethods;
    uint8_t methods[255];
};

struct server_hello {
    uint8_t ver;
    uint8_t method;
};

struct credentials {
    uint8_t ver;
    uint8_t ulen;
    char uname;
};

struct results {
    uint8_t ver;
    uint8_t status;
};

struct request {
    uint8_t ver;
    uint8_t cmd;
    uint8_t rsv;  // reserved
    uint8_t atyp; // address type
    uint8_t addr;
};

struct reply {
    uint8_t ver;
    uint8_t rep;
    uint8_t rsv;
    uint8_t atyp;
    uint8_t addr;
};

char * inet_ntoaddr(void * addr);
void forward(int fd1, int fd2);
in_addr_t resolve_domain(char * domain);
in_addr_t get_dst_addr(struct request * request);
in_port_t get_dst_port(struct request * request);
void get_sock_addr(int sockfd, void * addr, void * port);
void fill_bnd_addr(int remote_sockfd, struct reply * reply);
int connect_to_remote(struct request * request, struct reply * reply);
void serve(int client_sockfd);
int attempt(struct credentials * credentials);
int method_exists(struct client_hello * client_hello, uint8_t method);
int auth(int client_sockfd);
void handler(int client_sockfd);
int create_server(in_addr_t addr, in_port_t port);
int load_users(const char * f);
void usage(char * name);

#endif
