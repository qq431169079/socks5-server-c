
#include <stdio.h>
#include <string.h>
#include <sys/select.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>
#include <netdb.h> // gethostbyname()
#include <arpa/inet.h>

#include "util.h"
#include "logger.h"

char * inet_ntoaddr(void * addr)
{
    return inet_ntoa(*(struct in_addr *)addr);
}

void tcp_forward(int fd1, int fd2)
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

        timeout.tv_sec = 10;
        timeout.tv_usec = 0;

        n = select(maxfd + 1, &readfds, NULL, NULL, &timeout);
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
