#include <stdlib.h>
#include <string.h>
#include <stdio.h>

int main() {
    u_int8_t ret[4] = {192,168,0,1};
    u_int8_t ret2[20];
    sprintf(ret2, "%d.%d.%d.%d", ret, ret[1], ret+2, ret+3);
    return 0;
}