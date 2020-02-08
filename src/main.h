#ifndef _MAIN_H
#define _MAIN_H

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
#include <ctype.h>
#include <assert.h>

#define SHELL_BUFF_LEN 1024
#define FALSE -1
#define conf_path "./autoconn.conf"
#define productname "Deco"

int LOCK_FILE;

//关键变量的结构体
struct NetInfo
{
    char GatewayIP[20];
    
    char FAP_2G4_MAC[20];
    char FAP_5G_MAC[20];
    char RE_2G4_MAC[20];
    char RE_5G_MAC[20];

    char FAP_Guest_2G4_MAC[20];
    char FAP_Guest_5G_MAC[20];
    char RE_Guest_2G4_MAC[20];
    char RE_Guest_5G_MAC[20];

    char MAIN_2G_SSID[128];
    char MAIN_5G_SSID[128];
    char Guest_2G_SSID[128];
    char Guest_5G_SSID[128];

    char MAIN_KEY[128];
    char Guest_KEY[128];
    int Network_num;
};

#endif