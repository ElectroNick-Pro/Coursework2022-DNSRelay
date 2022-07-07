#include <stdlib.h>
#include <pthread.h>

void* sys_call(void* arg) {
    system((char*)arg);
    return NULL;
}

int main() {
    pthread_t tid = 0;
    pthread_create(&tid, NULL, sys_call, "nslookup qmplus.qmul.ac.uk 127.0.0.1 > nslookup1.txt");
    pthread_create(&tid, NULL, sys_call, "nslookup prts.wiki 127.0.0.1 > nslookup2.txt");
    pthread_create(&tid, NULL, sys_call, "nslookup example.blocked1.com 127.0.0.1 > nslookup3.txt");
    pthread_join(tid, NULL);
    return 0;
}