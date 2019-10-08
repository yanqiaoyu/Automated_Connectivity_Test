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
