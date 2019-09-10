
#ifndef __LOGGER_H__
#define __LOGGER_H__

#include <stdio.h>
#include <string.h> // memset()
#include <errno.h> // errno

extern char log_buff[2048];
extern char * log_ptr;

#ifdef DEBUG
#define LOG(format, ...)        record(format "\n", ##__VA_ARGS__)
#define LOG_INFO(format, ...)   record("[info] " format "\n", ##__VA_ARGS__)
#define LOG_WARNIG(format, ...) record("[warning] " format "\n", ##__VA_ARGS__)
#define LOG_ERROR(format, ...)  record("[error] " format ": %s\n", ##__VA_ARGS__, strerror(errno))
#define LOG_TIME()              log_time()
#define LOG_DUMP()              printf("%s", log_buff)
#define LOG_CLR()               memset(log_buff, 0, sizeof(log_buff)); log_ptr = log_buff;
#else
#define LOG(format, ...)
#define LOG_INFO(format, ...)
#define LOG_WARNIG(format, ...)
#define LOG_ERROR(format, ...)
#define LOG_TIME()
#define LOG_DUMP()
#define LOG_CLR()
#endif

void record(const char * format, ...);
void log_time();

#endif
