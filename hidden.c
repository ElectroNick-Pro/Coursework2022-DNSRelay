// Allocated return
u_int8_t* __toDnsAddr(u_int8_t* s) {
    int n = strlen(s);
    u_int8_t* ret = malloc(n + 2);
    int last = 0;
    for(int i = 0; i < n; i++) {
        if(s[i] == '.') {
            ret[last] = i - last;
            last = i;
        } else {
            ret[i + 1] = s[i];
        }
    }
    ret[n] = 0;
    return ret;
}

void __free_toDnsAddr(u_int8_t* ret) {
    free(ret);
}