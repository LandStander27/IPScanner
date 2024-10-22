#pragma once

#include <sys/socket.h>

void get_source(char* buffer);
void clear_arp_cache();
char* get_mac(int ip[]);
long long ping(int ip[]);