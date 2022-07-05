#include "Database.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

char** get_ipv4(char* s, u_int16_t* retSize) {
    char** ret = malloc(0);
    u_int16_t sz = 0;
    FILE* fp = fopen("map.txt","r");
    char s1[50];
    char s2[100];
    int r;
    do {
        r = fscanf(fp, "%s", s1);
        r = fscanf(fp, "%s", s2);
        char* it = s1;
        if(*it == 0) {
            continue;
        }
        if(strcmp(s2, s) == 0) {
            ret = realloc(ret, sizeof(char*) * (++sz));
            ret[sz - 1] = malloc(strlen(s1) + 1);
            memset(ret[sz - 1], 0, strlen(s1) + 1);
            strcpy(ret[sz - 1], s1);
        }
    } while(r != -1);
    fclose(fp);
    *retSize = sz;
    return ret;
}

void add_tuple(char* ip, char* domain) {
    FILE* fp = fopen("map.txt", "a");
    fprintf(fp,"%s %s\n", ip, domain);
    fclose(fp);
}

void remove_tuple(char* ip, char* domain) {
    char** ret = malloc(0);
    int sz = 0;
    FILE* fp = fopen("map.txt","r");
    char s1[50];
    char s2[100];
    int r;
    do {
        r = fscanf(fp, "%s", s1);
        r = fscanf(fp, "%s", s2);
        if(!strcmp(s1, ip) && !strcmp(s2, domain)) {
            continue;
        }
        ret = realloc(ret, sizeof(char*) * (++sz));
        ret[sz - 1] = malloc(strlen(s1) + strlen(s2) + 3);
        memset(ret[sz - 1], 0, strlen(s1) + strlen(s2) + 3);
        strcat(ret[sz - 1], s1);
        strcat(ret[sz - 1], " ");
        strcat(ret[sz - 1], s2);
        strcat(ret[sz - 1], "\n");
    } while(r != -1);
    fclose(fp);
    fp = fopen("map.txt", "r");
    for(int i = 0; i < sz; i++) {
        fprintf(fp, "%s", ret[i]);
    }
}