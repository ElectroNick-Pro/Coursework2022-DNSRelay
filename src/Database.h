#ifndef __DATABASE_H
#define __DATABASE_H

#include <stdlib.h>

char** get_ip(char* s, u_int16_t* retSize);
void add_tuple(char* ip, char* domain);
void remove_tuple(char* ip, char* domain);

#endif // __DATABASE_H