#pragma once

#include <windows.h>

char* get_mac(int ip[]);
long long ping(HANDLE handle, int ip[]);
char* get_local_mac();