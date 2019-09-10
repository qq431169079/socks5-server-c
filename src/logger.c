
#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include <time.h>

#include "logger.h"

char log_buff[2048];
char * log_ptr = log_buff;

void record(const char * format, ...)
{
    char s[1024];

    va_list ap;
    va_start(ap, format);

    vsprintf(s, format, ap);
    va_end(ap);

    int n = strlen(s);
    strncpy(log_ptr, s, n);
    log_ptr += n;
}

void log_time()
{
    time_t seconds = time(NULL);
    struct tm * t = localtime(&seconds);

    // 2019/09/09 03:59
    log_ptr += strftime(log_ptr, 25, "[time] %Y/%m/%d %H:%M\n", t);
}
