#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <errno.h>
#include <unistd.h>
#include <stdarg.h>
#include <regex.h>

#define SHELL_BUFF_LEN 1024
#define FALSE -1

int LOCK_FILE;

//关键变量的结构体
struct NetInfo
{
    char FAP_MAC[20];
    char RE_MAC[20];
    char SSID[128];
    char KEY[128];
    int Network_num;
};
