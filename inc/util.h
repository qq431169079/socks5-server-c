
#ifndef __UTIL_H__
#define __UTIL_H__

#ifndef BUFF_SIZE
#define BUFF_SIZE 1024
#endif

char * inet_ntoaddr(void * addr);
void tcp_forward(int fd1, int fd2);
in_addr_t resolve_domain(char * domain);

#endif
