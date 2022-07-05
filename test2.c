#include <stdlib.h>
#include <string.h>
#include <stdio.h>

int main() {
    u_int8_t ret[4];
    sscanf("192.168.0.1", "%c.%c.%c.%c", ret, ret+1, ret+2, ret+3);
    return 0;
}