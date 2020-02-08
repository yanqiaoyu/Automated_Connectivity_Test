#ifndef _GETCONF_H
#define _GETCONF_H

#include "main.h"

#define KEYVALLEN 100

int GetProfileString(char *profile, char *AppName, char *KeyName, char *KeyVal);

#endif