#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <time.h>

int main(int argc, char* argv[]) {
    printf("%s\n", argv[0]);
    printf("%ld\n", time(NULL));
    u_int32_t a = 32;
    printf("%u\n", a);
    printf("%d", 2 & 15);
    return 0;
}