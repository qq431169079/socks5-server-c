
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h> // getopt()
#include <netdb.h> // gethostbyname()
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "main.h"
#include "logger.h"

in_addr_t server_addr;
in_port_t server_port;

uint8_t method = NO_AUTHENTICATION_REQUIRED;
char * unames[MAX_USER_COUNT];
char * passwds[MAX_USER_COUNT];
int user_count = 0;

char * inet_ntoaddr(void * addr)
{
    return inet_ntoa(*(struct in_addr *)addr);
}

void forward(int fd1, int fd2)
{
    int n;
    uint8_t buff[BUFF_SIZE];

    fd_set readfds;
    struct timeval timeout;

    int maxfd;
    maxfd = fd1 > fd2 ? fd1 : fd2;

    while (1) {
        FD_ZERO(&readfds);
        FD_SET(fd1, &readfds);
        FD_SET(fd2, &readfds);

        timeout.tv_sec = 1;
        timeout.tv_usec = 0;

        n = select(maxfd + 1, &readfds, 0, 0, &timeout);
        if (n > 0) {
            memset(buff, 0, BUFF_SIZE);
            if (FD_ISSET(fd1, &readfds)) {
                n = recv(fd1, buff, BUFF_SIZE, 0);
                if (n > 0) {
                    send(fd2, buff, n, 0);
                } else if (n == 0) {
                    LOG_INFO("Connection closed by fd1 foreign host.");
                    return;
                } else if (n == -1) {
                    LOG_ERROR("recv error");
                    return;
                }
            } else if (FD_ISSET(fd2, &readfds)) {
                n = recv(fd2, buff, BUFF_SIZE, 0);
                if (n > 0) {
                    send(fd1, buff, n, 0);
                } else if (n == 0) {
                    LOG_INFO("Connection closed by fd2 foreign host.");
                    return;
                } else if (n == -1) {
                    LOG_ERROR("recv error");
                    return;
                }
            }
        } else if (n == 0) {
            continue;
        } else if (n == -1) {
            LOG_ERROR("select error");
            return;
        }
    }
}

in_addr_t resolve_domain(char * domain)
{
    struct hostent * host;
    host = gethostbyname(domain);
    if (host == NULL) {
        LOG_ERROR("Couldn't resolve host name");
        return 0;
    } else {
        return *(in_addr_t *)host->h_addr_list[0];
    }
}

in_addr_t get_dst_addr(struct request * request)
{
    if (request->atyp == IPV4) {
        return *(in_addr_t *)(&request->atyp + 1);
    } else if (request->atyp == DOMAIN) {
        size_t domain_len;
        char domain[256] = {0};

        domain_len = (size_t)*(uint8_t *)(&request->atyp + 1);
        strncpy(domain, (char *)&request->atyp + 2, domain_len);
        LOG("dst.domain: %s", domain);

        return resolve_domain(domain);
    }
}

in_port_t get_dst_port(struct request * request)
{
    if (request->atyp == IPV4) {
        return *(in_port_t *)(&request->atyp + 5);
    } else if (request->atyp == DOMAIN) {
        size_t domain_len;

        domain_len = (size_t)*(uint8_t *)(&request->atyp + 1);
        return *(in_port_t *)(&request->atyp + 2 + domain_len);
    }
}

void get_sock_addr(int sockfd, void * addr, void * port)
{
    struct sockaddr_in bind_addr;
    memset(&bind_addr, 0, sizeof(bind_addr));

    socklen_t bind_addr_len = sizeof(bind_addr);
    getsockname(sockfd, (struct sockaddr *)&bind_addr, &bind_addr_len);

    if (addr != 0) *(in_addr_t *)addr = bind_addr.sin_addr.s_addr;
    if (port != 0) *(in_port_t *)port = bind_addr.sin_port;
}

void fill_bnd_addr(int remote_sockfd, struct reply * reply)
{
    get_sock_addr(remote_sockfd, &reply->atyp + 1, &reply->atyp + 5);
}

int connect_to_remote(struct request * request, struct reply * reply)
{
    int remote_sockfd;
    remote_sockfd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (remote_sockfd == -1) {
        LOG_ERROR("Create remote socket error");
        reply->rep = GENERAL_SOCKS_SERVER_FAILURE;
        return 0;
    }

    struct sockaddr_in remote_addr;
    memset(&remote_addr, 0, sizeof(remote_addr));
    remote_addr.sin_family      = AF_INET;
    remote_addr.sin_addr.s_addr = get_dst_addr(request);
    remote_addr.sin_port        = get_dst_port(request);

    if (remote_addr.sin_addr.s_addr == 0) {
        reply->rep = NETWORK_UNREACHABLE;
        return 0;
    }

    LOG("dst.addr: %s", inet_ntoa(remote_addr.sin_addr));
    LOG("dst.port: %d", (int)ntohs(remote_addr.sin_port));

    if (connect(remote_sockfd, (struct sockaddr *)&remote_addr, sizeof(remote_addr)) == -1) {
        LOG_ERROR("Connect to remote error");
        reply->rep = NETWORK_UNREACHABLE;
        return 0;
    }

    return remote_sockfd;
}

void serve(int client_sockfd)
{
    uint8_t recv_buff[BUFF_SIZE] = {0};
    uint8_t send_buff[BUFF_SIZE] = {0};

    struct request * request;
    struct reply * reply;

    request = (struct request *)recv_buff;
    reply = (struct reply *)send_buff;
    reply->ver = VERSION;

    if (recv(client_sockfd, recv_buff, BUFF_SIZE, 0) <= 0) {
        LOG_ERROR("Receive request error");
        return;
    }

    LOG_INFO("request: ");
    LOG("cmd: %d", (int)request->cmd);
    LOG("atyp: %d", (int)request->atyp);

    if (request->cmd != CONNECT) {
        LOG_WARNIG("Command not supported.");
        reply->rep = COMMAND_NOT_SUPPORTED;
    }

    if (request->atyp == IPV6) {
        LOG_WARNIG("Address type not supported.");
        reply->rep = ADDRESS_TYPE_NOT_SUPPORTED;
    }

    if (reply->rep != 0) {
        send(client_sockfd, send_buff, REPLY_SIZE, 0);
        return;
    }

    int remote_sockfd;
    remote_sockfd = connect_to_remote(request, reply);
    if (remote_sockfd == 0) {
        send(client_sockfd, send_buff, REPLY_SIZE, 0);
        return;
    }
    LOG_INFO("Connected.");

    reply->rep = SUCCEEDED;
    reply->atyp = IPV4;
    fill_bnd_addr(remote_sockfd, reply);

    LOG_INFO("reply: ");
    LOG("bind.addr: %s", inet_ntoaddr(&reply->atyp + 1));
    LOG("bind.port: %d", (int)ntohs(*(in_port_t *)(&reply->atyp + 5)));

    send(client_sockfd, send_buff, REPLY_SIZE, 0);
    LOG_INFO("Forward...");
    forward(client_sockfd, remote_sockfd);
    close(remote_sockfd);
    LOG_INFO("Closed remote socket.");
}

int attempt(struct credentials * credentials)
{
    unsigned int ulen, plen;
    char * uname;
    char * passwd;
    char * plen_ptr;

    uname = &credentials->uname;
    ulen = credentials->ulen;
    plen_ptr = uname + ulen;
    plen = *plen_ptr;
    passwd = plen_ptr + 1;

    LOG_INFO("credentials: ");
    LOG("ulen: %d", ulen);
    LOG("plen: %d", plen);

    int i;
    for (i = 0; i < user_count; i++) {
        if (
            (strlen(unames[i]) == ulen) &&
            (strncmp(unames[i], uname, ulen) == 0) &&
            (strlen(passwds[i]) == plen) &&
            (strncmp(passwds[i], passwd, plen) == 0)
        ) {
            return 1;
        }
    }

    return 0;
}

int method_exists(struct client_hello * client_hello, uint8_t method)
{
    int i;
    for (i = 0; i < client_hello->nmethods; i++) {
        LOG("method[%d]: %d", i, (int)client_hello->methods[i]);
        if (client_hello->methods[i] == method) return 1;
    }

    return 0;
}

int auth(int client_sockfd)
{
    uint8_t recv_buff[BUFF_SIZE] = {0};
    uint8_t send_buff[BUFF_SIZE] = {0};

    struct client_hello * client_hello;
    struct server_hello * server_hello;

    client_hello = (struct client_hello *)recv_buff;
    server_hello = (struct server_hello *)send_buff;
    server_hello->ver = VERSION;

    if (recv(client_sockfd, recv_buff, BUFF_SIZE, 0) <= 0) {
        LOG_ERROR("Receive client hello error");
        return 0;
    }

    LOG_INFO("client hello: ");
    LOG("ver: %d", (int)client_hello->ver);
    if ((int)client_hello->ver != VERSION) {
        server_hello->method = NO_ACCEPTABLE_METHODS;
        send(client_sockfd, send_buff, SERVER_HELLO_SIZE, 0);
        LOG_WARNIG("Support Socks5 only.");
        return 0;
    }

    LOG("nmethods: %d", (int)client_hello->nmethods);
    if (!method_exists(client_hello, method)) {
        server_hello->method = NO_ACCEPTABLE_METHODS;
        send(client_sockfd, send_buff, SERVER_HELLO_SIZE, 0);
        LOG_WARNIG("No acceptable methods.");
        return 0;
    }
    LOG_INFO("Method %d found.", method);

    server_hello->method = method;
    send(client_sockfd, send_buff, SERVER_HELLO_SIZE, 0);

    if (method == USERNAME_PASSWORD) {
        memset(recv_buff, 0, BUFF_SIZE);
        memset(send_buff, 0, BUFF_SIZE);

        if (recv(client_sockfd, recv_buff, BUFF_SIZE, 0) > 0) {
            struct credentials * credentials;
            struct results * results;

            credentials = (struct credentials *)recv_buff;
            results = (struct results *)send_buff;
            results->ver = 0x01;

            if (attempt(credentials)) {
                results->status = 0x00;
                LOG_INFO("Authorization successful.");
            } else {
                results->status = 0x01;
                LOG_WARNIG("Incorrect username or password.");
            }

            send(client_sockfd, send_buff, RESULTS_SIZE, 0);
            return !results->status;
        } else {
            LOG_ERROR("Receive credentials error");
            return 0;
        }
    }

    return 1;
}

void handler(int client_sockfd)
{
    LOG("----------------------------------------");
    LOG_TIME();

    if (auth(client_sockfd)) {
        serve(client_sockfd);
    }

    close(client_sockfd);
    LOG_INFO("Closed client socket.");
    LOG_DUMP();
}

void loop(int server_sockfd)
{
    int client_sockfd;
    pid_t pid;

    while (1) {
        client_sockfd = accept(server_sockfd, NULL, NULL);

        pid = fork();
        if (pid == -1) {
            LOG_ERROR("Create process error");
            close(client_sockfd);
        } else {
            if (pid == 0) {
                close(server_sockfd);
                handler(client_sockfd);
                exit(0);
            } else {
                close(client_sockfd);
            }
        }
    }
}

int create_server(in_addr_t addr, in_port_t port)
{
    int server_sockfd;

    server_sockfd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (server_sockfd == -1) {
        perror("Create socket error");
        return 0;
    }

    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family      = AF_INET;
    server_addr.sin_port        = port;
    server_addr.sin_addr.s_addr = addr;

    if (bind(server_sockfd, (struct sockaddr *)&server_addr, sizeof(server_addr)) == -1) {
        perror("Socket bind error");
        return 0;
    }

    if (listen(server_sockfd, 5) == -1) {
        perror("Socket listen error");
        return 0;
    }

    return server_sockfd;
}

int load_users(const char * f)
{
    FILE * fp;
    fp = fopen(f, "r");
    if (fp == 0) {
        perror("fopen error");
        return 0;
    }

    int row_max_len = UNAME_MAX_LEN + PASSWD_MAX_LEN + 3; // +3 because ',' and '\n\0'
    char row[row_max_len]; 
    char * p;

    int i = 0;
    int ulen;

    LOG_INFO("Load user: ");
    do {
        memset(row, 0, sizeof(row));
        if (fgets(row, row_max_len, fp) != NULL) {

            p = strchr(row, ',');
            if (p == NULL) continue;
            if (p[1] == '\0' || p[1] == '\n') continue;

            unames[i] = (char *)malloc(UNAME_MAX_LEN);
            passwds[i] = (char *)malloc(PASSWD_MAX_LEN);

            memset(unames[i], 0, UNAME_MAX_LEN);
            memset(passwds[i], 0, PASSWD_MAX_LEN);

            ulen = p - row;
            strncpy(unames[i], row, ulen);
            strncpy(passwds[i], p + 1, strlen(row) - 2 - ulen); // -2 because ',' and '\n'

            LOG("%d: %s, %s.", i, unames[i], passwds[i]);
            i++;
        } else {
            break;
        }
    } while (feof(fp) == 0);
    LOG_DUMP();
    LOG_CLR();

    user_count = i;
    fclose(fp);
    return 1;
}

void usage(char * name)
{
    printf(
        "usage: %s [-a addr] [-p port] [-u path/to/passwd]\n"
        "options: \n"
        "  -a <ip address>      Bind to this address (default: 0.0.0.0)\n"
        "  -p <port number>     Bind to this port (default: 1080)\n"
        "  -u <path/to/passwd>  Each row of passwd describes a user.\n"
        "                       e.g. admin,secret\n"
        "  -d                   Run as a daemon.\n"
        "  -h                   Show this help message.\n",
        name
    );
}

int main(int argc, char * argv[])
{
    int is_daemon = 0;

    server_addr = htonl(DEFAULT_SERVER_ADDR);
    server_port = htons(DEFAULT_SERVER_PORT);

    int opt;
    opterr = 0;

    while (1) {
        opt = getopt(argc, argv, ":a:p:u:dh");
        if (opt == -1) break;

        switch (opt) {
            case 'a':
                server_addr = inet_addr(optarg);
                break;
            case 'p':
                server_port = htons(atoi(optarg));
                break;
            case 'u':
                method = USERNAME_PASSWORD;
                if (load_users(optarg) == 0) {
                    return -1;
                }
                break;
            case 'd':
                is_daemon = 1;
                break;
            case 'h':
                usage(argv[0]);
                return 0;
            case ':':
                printf("Missing argument after: -%c\n", optopt);
                usage(argv[0]);
                return -1;
            case '?':
                printf("Invalid argument: %c\n", optopt);
                usage(argv[0]);
                return -1;
        }
    }

    int server_sockfd;

    server_sockfd = create_server(server_addr, server_port);
    if (server_sockfd == 0) return -1;

    printf("Listen to port %d on %s\n",
        (int)ntohs(server_port),
        inet_ntoaddr(&server_addr)
    );

    if (method == USERNAME_PASSWORD) {
        printf("Using username/password authentication.\n");
    } else {
        printf("No authentication.\n");
    }

    signal(SIGCHLD, SIG_IGN);

    if (is_daemon) {
        pid_t pid = fork();

        if (pid == -1) {
            perror("Create process error");
            close(server_sockfd);
        } else {
            if (pid == 0) {
                loop(server_sockfd);
            } else {
                printf("Server pid is: [%d]\n", pid);
                close(server_sockfd);
            }
        }
    } else {
        loop(server_sockfd);
    }
}
