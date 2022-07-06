#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <error.h>
#include "dnsrelay.h"

#define IP4_DB "../map.txt"
#define IP6_DB "../map6.txt"

int debug_level = 1;

// Allocated return
u_int8_t* __toReadableAddr(u_int8_t* s) {
    int n = strlen(s);
    u_int8_t* ret = malloc(n);
    for(int i = 0; i < n; i++) {
        ret[i] = s[i + 1];
        if(ret[i] < 32) {
            ret[i] = '.';
        }
    }
    ret[n - 1] = 0;
    return ret;
}

void __free_toReadableAddr(u_int8_t* ret) {
    free(ret);
}

// Allocated return
u_int8_t* __toDnsIPv4(char* ip) {
    u_int8_t* ret = malloc(4);
    sscanf(ip, "%hhu.%hhu.%hhu.%hhu", ret, ret+1, ret+2, ret+3);
    return ret;
}

void __free_toDnsIPv4(u_int8_t* ret) {
    free(ret);
}

// Allocated return
u_int8_t* __toDnsIPv6(char* ip) {
    u_int8_t* ret = malloc(16);
    sscanf(ip, "%hx:%hx:%hx:%hx:%hx:%hx:%hx:%hx",
        (u_int16_t*)ret, (u_int16_t*)(ret+2), (u_int16_t*)(ret+4), (u_int16_t*)(ret+6),
        (u_int16_t*)(ret+8), (u_int16_t*)(ret+10), (u_int16_t*)(ret+12), (u_int16_t*)(ret+14)
    );
    u_int8_t tmp;
    for(int i = 0; i < 8; i++) {
        tmp = ret[i << 1];
        ret[i << 1] = ret[(i << 1) + 1];
        ret[(i << 1) + 1] = tmp;
    }
    return ret;
}

void __free_toDnsIPv6(u_int8_t* ret) {
    free(ret);
}

// Allocated return
char* __toReadableIPv4(u_int8_t* addr) {
    char* ret = malloc(20);
    memset(ret, 0, 20);
    sprintf(ret, "%hhu.%hhu.%hhu.%hhu", addr[0], addr[1], addr[2], addr[3]);
    return ret;
}

void __free_toReadableIPv4(char* ret) {
    free(ret);
}

// Allocate return
char* __toReadableIPv6(u_int8_t* addr) {
    char* ret = malloc(40);
    memset(ret, 0, 40);
    u_int16_t tmp[8];
    for(int i = 0; i < 8; i++) {
        tmp[i] = (addr[i << 1] << 8) + addr[(i << 1) + 1];
    }
    sprintf(ret, "%hx:%hx:%hx:%hx:%hx:%hx:%hx:%hx", tmp[0], tmp[1], tmp[2], tmp[3], tmp[4], tmp[5], tmp[6], tmp[7]);
    return ret;
}

void __free_toReadableIPv6(char* ret) {
    free(ret);
}

u_int8_t* headerFromBuffer(u_int8_t* buf, DnsHeader* obj) {
    memset(obj, 0, sizeof(DnsHeader));
    memcpy(&obj->id, buf, sizeof(u_int16_t));
    obj->id = htons(obj->id);
    buf += sizeof(u_int16_t);
    memcpy(&obj->flag, buf, sizeof(u_int16_t));
    obj->flag = htons(obj->flag);
    buf += sizeof(u_int16_t);
    memcpy(&obj->question_cnt, buf, sizeof(u_int16_t));
    obj->question_cnt = htons(obj->question_cnt);
    buf += sizeof(u_int16_t);
    memcpy(&obj->answer_cnt, buf, sizeof(u_int16_t));
    obj->answer_cnt = htons(obj->answer_cnt);
    buf += sizeof(u_int16_t);
    memcpy(&obj->authority_cnt, buf, sizeof(u_int16_t));
    obj->authority_cnt = htons(obj->authority_cnt);
    buf += sizeof(u_int16_t);
    memcpy(&obj->additional_cnt, buf, sizeof(u_int16_t));
    obj->additional_cnt = htons(obj->additional_cnt);
    buf += sizeof(u_int16_t);
    return buf;
}

u_int8_t* headerToBuffer(u_int8_t* buf, DnsHeader* obj) {
    u_int16_t tmp;
    tmp = ntohs(obj->id);
    memcpy(buf, &tmp, sizeof(u_int16_t));
    buf += sizeof(u_int16_t);
    tmp = ntohs(obj->flag);
    memcpy(buf, &tmp, sizeof(u_int16_t));
    buf += sizeof(u_int16_t);
    tmp = ntohs(obj->question_cnt);
    memcpy(buf, &tmp, sizeof(u_int16_t));
    buf += sizeof(u_int16_t);
    tmp = ntohs(obj->answer_cnt);
    memcpy(buf, &tmp, sizeof(u_int16_t));
    buf += sizeof(u_int16_t);
    tmp = ntohs(obj->authority_cnt);
    memcpy(buf, &tmp, sizeof(u_int16_t));
    buf += sizeof(u_int16_t);
    tmp = ntohs(obj->additional_cnt);
    memcpy(buf, &tmp, sizeof(u_int16_t));
    buf += sizeof(u_int16_t);
    return buf;
}

void free_header(DnsHeader* obj) {
    
}

u_int8_t* queryFromBuffer(u_int8_t* buf, DnsQuery* obj) {
    memset(obj, 0, sizeof(DnsQuery));
    obj->name = malloc(sizeof(u_int8_t) * 100);
    memset(obj->name, 0, sizeof(u_int8_t) * 100);
    strcpy(obj->name, buf);
    buf += (strlen(buf) + 1);
    memcpy(&obj->type, buf, sizeof(u_int16_t));
    obj->type = htons(obj->type);
    buf += sizeof(u_int16_t);
    memcpy(&obj->klass, buf, sizeof(u_int16_t));
    obj->klass = htons(obj->klass);
    buf += sizeof(u_int16_t);
    return buf;
}

u_int8_t* queryToBuffer(u_int8_t* buf, DnsQuery* obj) {
    strcpy(buf, obj->name);
    buf += (strlen(obj->name) + 1);
    u_int16_t tmp;
    tmp = ntohs(obj->type);
    memcpy(buf, &tmp, sizeof(u_int16_t));
    buf += sizeof(u_int16_t);
    tmp = ntohs(obj->klass);
    memcpy(buf, &tmp, sizeof(u_int16_t));
    buf += sizeof(u_int16_t);
    return buf;
}

void free_query(DnsQuery* obj) {
    free(obj->name);
}

u_int8_t* resourceFromBuffer(u_int8_t* buf, DnsResource* obj) {
    memset(obj, 0, sizeof(DnsResource));
    obj->name = malloc(sizeof(u_int8_t) * 100);
    memset(obj->name, 0, sizeof(u_int8_t) * 100);
    if(*buf & 0xc0) {
        memcpy(obj->name, buf, 2);
        buf += 2;
    } else {
        strcpy(obj->name, buf);
        buf += (strlen(buf) + 1);
    }
    memcpy(&obj->type, buf, sizeof(u_int16_t));
    obj->type = htons(obj->type);
    buf += sizeof(u_int16_t);
    memcpy(&obj->klass, buf, sizeof(u_int16_t));
    obj->klass = htons(obj->klass);
    buf += sizeof(u_int16_t);
    memcpy(&obj->TTL, buf, sizeof(u_int32_t));
    obj->TTL = htonl(obj->TTL);
    buf += sizeof(u_int32_t);
    memcpy(&obj->length, buf, sizeof(u_int16_t));
    obj->length = htons(obj->length);
    buf += sizeof(u_int16_t);
    obj->data = malloc(obj->length);
    memset(obj->data, 0, obj->length);
    memcpy(obj->data, buf, obj->length);
    buf += obj->length;
    return buf;
}

u_int8_t* resourceToBuffer(u_int8_t* buf, DnsResource* obj) {
    strcpy(buf, obj->name);
    buf += (strlen(obj->name) + 1);
    u_int16_t tmp;
    tmp = ntohs(obj->type);
    memcpy(buf, &tmp, sizeof(u_int16_t));
    buf += sizeof(u_int16_t);
    tmp = ntohs(obj->klass);
    memcpy(buf, &tmp, sizeof(u_int16_t));
    buf += sizeof(u_int16_t);
    u_int32_t tmp2;
    tmp2 = ntohl(obj->TTL);
    memcpy(buf, &tmp2, sizeof(u_int32_t));
    buf += sizeof(u_int32_t);
    tmp = ntohs(obj->length);
    memcpy(buf, &tmp, sizeof(u_int16_t));
    buf += sizeof(u_int16_t);
    memcpy(buf, obj->data, obj->length);
    buf += obj->length;
    return buf;
}

void free_resource(DnsResource* obj) {
    free(obj->name);
    free(obj->data);
}

void dataframeFromBuffer(u_int8_t* buf, DnsDataframe* obj) {
    memset(obj, 0, sizeof(DnsDataframe));
    buf = headerFromBuffer(buf, &obj->header);
    obj->queries = malloc(sizeof(DnsQuery) * obj->header.question_cnt);
    for(int i = 0; i < obj->header.question_cnt; i++) {
        buf = queryFromBuffer(buf, obj->queries + i);
    }
    obj->answers = malloc(sizeof(DnsResource) * obj->header.answer_cnt);
    for(int i = 0; i < obj->header.answer_cnt; i++) {
        buf = resourceFromBuffer(buf, obj->answers + i);
    }
    obj->authorities = malloc(sizeof(DnsResource) * obj->header.authority_cnt);
    for(int i = 0; i < obj->header.authority_cnt; i++) {
        buf = resourceFromBuffer(buf, obj->authorities + i);
    }
    obj->additionals = malloc(sizeof(DnsResource) * obj->header.additional_cnt);
    for(int i = 0; i < obj->header.additional_cnt; i++) {
        buf = resourceFromBuffer(buf, obj->additionals + i);
    }
}

size_t dataframeToBuffer(u_int8_t* buf, DnsDataframe* obj) {
    u_int8_t* beg = buf;
    buf = headerToBuffer(buf, &obj->header);
    for(int i = 0; i < obj->header.question_cnt; i++) {
        buf = queryToBuffer(buf, obj->queries + i);
    }
    for(int i = 0; i < obj->header.answer_cnt; i++) {
        buf = resourceToBuffer(buf, obj->answers + i);
    }
    for(int i = 0; i < obj->header.authority_cnt; i++) {
        buf = resourceToBuffer(buf, obj->authorities + i);
    }
    for(int i = 0; i < obj->header.additional_cnt; i++) {
        buf = resourceToBuffer(buf, obj->additionals + i);
    }
    return buf - beg;
}

void free_dataframe(DnsDataframe* obj) {
    for(int i = 0; i < obj->header.question_cnt; i++) {
        free_query(obj->queries + i);
    }
    free(obj->queries);
    for(int i = 0; i < obj->header.answer_cnt; i++) {
        free_resource(obj->answers + i);
    }
    free(obj->answers);
    for(int i = 0; i < obj->header.authority_cnt; i++) {
        free_resource(obj->authorities + i);
    }
    free(obj->authorities);
    for(int i = 0; i < obj->header.additional_cnt; i++) {
        free_resource(obj->additionals + i);
    }
    free(obj->additionals);
}

// Allocated return
char** get_ip(char* s, u_int16_t* retSize, char* file) {
    char** ret = malloc(0);
    u_int16_t sz = 0;
    FILE* fp = fopen(file,"r");
    char s1[50];
    char s2[100];
    int r;
    while(1) {
        r = fscanf(fp, "%s", s1);
        r = fscanf(fp, "%s", s2);
        if(r == -1) {
            break;
        }
        if(strcmp(s2, s) == 0) {
            ret = realloc(ret, sizeof(char*) * (++sz));
            ret[sz - 1] = malloc(strlen(s1) + 1);
            memset(ret[sz - 1], 0, strlen(s1) + 1);
            strcpy(ret[sz - 1], s1);
        }
    }
    fclose(fp);
    *retSize = sz;
    return ret;
}

void __free_get_ip(char** ret, u_int16_t* retSize) {
    for(int i = 0; i < *retSize; i++) {
        free(ret[i]);
    }
    free(ret);
}

void add_tuple(char* ip, char* domain, char* file) {
    FILE* fp = fopen(file, "a");
    fprintf(fp,"%s %s\n", ip, domain);
    fclose(fp);
}

void print_bin(u_int8_t* arr, int len) {
    fprintf(stdout, "Data in hex:");
    for(int i = 0; i < len; i++) {
        if(!(i & 0b1111)) {
            fprintf(stdout, "\n");
        }
        fprintf(stdout, "%02hx ", arr[i]);
    }
    fprintf(stdout, "\n");
}

void print_header(DnsHeader* obj) {
    fprintf(stdout, "Transaction-ID:%hu Flags:0x%04hx Questions:%hu Answer-RRs:%hu Authority-RRs:%hu Additional-RRs: %hu\n",
        obj->id, obj->flag, obj->question_cnt, obj->answer_cnt, obj->authority_cnt, obj->additional_cnt
    );
    char attrs[8][30];
    int i = 0;
    memset(attrs[i++], 0, 30);
    if(obj->flag & QR_RESPONSE_BIT) {
        strcpy(attrs[i - 1], "Response");
    } else {
        strcpy(attrs[i - 1], "Query");
    }
    memset(attrs[i++], 0, 30);
    if(obj->flag & OP_REV_BIT) {
        strcpy(attrs[i - 1], "Reverse query");
    } else if(obj->flag & OP_SERVER_STAT_BIT) {
        strcpy(attrs[i - 1], "Server status query");
    } else {
        strcpy(attrs[i - 1], "Standard query");
    }
    memset(attrs[i++], 0, 30);
    if(obj->flag & AUTHORITATIVE_BIT) {
        strcpy(attrs[i - 1], "Authority for domain");
    } else {
        strcpy(attrs[i - 1], "Not authority for domain");
    }
    memset(attrs[i++], 0, 30);
    if(obj->flag & TC_BIT) {
        strcpy(attrs[i - 1], "Truncated");
    } else {
        strcpy(attrs[i - 1], "Not truncated");
    }
    memset(attrs[i++], 0, 30);
    if(obj->flag & RD_BIT) {
        strcpy(attrs[i - 1], "Recursion desired");
    } else {
        strcpy(attrs[i - 1], "Recursion not desired");
    }
    memset(attrs[i++], 0, 30);
    if(obj->flag & RA_BIT) {
        strcpy(attrs[i - 1], "Recursion available");
    } else {
        strcpy(attrs[i - 1], "Recursion not available");
    }
    memset(attrs[i++], 0, 30);
    if(obj->flag & AUTHENTICATED_BIT) {
        strcpy(attrs[i - 1], "Authenticated by server");
    } else {
        strcpy(attrs[i - 1], "Recursion not available");
    }
    memset(attrs[i++], 0, 30);
    if(obj->flag & REPLY_FORMAT_ERR) {
        strcpy(attrs[i - 1], "Format error");
    } else if (obj->flag & REPLY_SERVER_FAILURE) {
        strcpy(attrs[i - 1], "Server failure");
    } else if (obj->flag & REPLY_NAME_ERR) {
        strcpy(attrs[i - 1], "Name error");
    } else if (obj->flag & REPLY_NOT_IMPLEMENTED) {
        strcpy(attrs[i - 1], "Not implemented");
    } else if (obj->flag & REPLY_REFUSE) {
        strcpy(attrs[i - 1], "Refused");
    } else {
        strcpy(attrs[i - 1], "No error");
    }
    fprintf(stdout, "Flag attributes: ");
    for(int j = 0; j < 8; j++) {
        fprintf(stdout, "%s", attrs[j]);
        if(j < 7) {
            fprintf(stdout, ", ");
        }
    }
    fprintf(stdout, "\n");
}

void print_query(DnsQuery* obj) {
    char* dnsDomain = __toReadableAddr(obj->name);
    fprintf(stdout, "Query name: %s, type: %hu, class: %hu\n", dnsDomain, obj->type, obj->klass);
    __free_toReadableAddr(dnsDomain);
}

void print_resource(DnsResource* obj, char* type) {
    if(obj->type == TYPE_A || obj->type == TYPE_AAAA) {
        char* dnsDomain = __toReadableAddr(obj->name);
        fprintf(stdout, "%s name: %s, type: %hu, class: %hu, TTL: %u\n", 
            type, dnsDomain, obj->type, obj->klass, obj->TTL
        );
        __free_toReadableAddr(dnsDomain);
    } else {
        fprintf(stdout, "%s name: %s, type: %hu, class: %hu, TTL: %u\n", 
            type, "[N/A]", obj->type, obj->klass, obj->TTL
        );
    }
    fprintf(stdout, "%s data-", type);
    print_bin(obj->data, obj->length);
}

void print_dataframe(DnsDataframe* obj) {
    fprintf(stdout, "DNS dataframe:\n");
    print_header(&obj->header);
    print_query(&obj->queries[0]);
    fprintf(stdout, "Answer count: %hu\n", obj->header.answer_cnt);
    for(int i = 0; i < obj->header.answer_cnt; i++) {
        print_resource(&obj->answers[i], "Answer");
    }
    fprintf(stdout, "Authority count: %hu\n", obj->header.authority_cnt);
    for(int i = 0; i < obj->header.authority_cnt; i++) {
        print_resource(&obj->authorities[i], "Authority");
    }
    fprintf(stdout, "Additional count: %hu\n", obj->header.additional_cnt);
    for(int i = 0; i < obj->header.additional_cnt; i++) {
        print_resource(&obj->additionals[i], "Additional");
    }
}

void remove_tuple(char* ip, char* domain, char* file) {
    char** ret = malloc(0);
    int sz = 0;
    FILE* fp = fopen(file,"r");
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
    fp = fopen(file, "r");
    for(int i = 0; i < sz; i++) {
        fprintf(fp, "%s", ret[i]);
    }
    for(int i = 0; i < sz; i++) {
        free(ret[i]);
    }
    free(ret);
}

int main(int argc, char* argv[]) {
    if(argc > 1 && strcmp(argv[1], "-dd") == 0) {
        debug_level = 2;
    }
    // Init listening address
    struct sockaddr_in rcv_addr;
    memset(&rcv_addr, 0, sizeof(struct sockaddr_in));
    rcv_addr.sin_family = AF_INET;
    rcv_addr.sin_port = htons(53);
    inet_aton("127.0.0.1",&rcv_addr.sin_addr);
    // Start socket
    int server_fd = socket(AF_INET, SOCK_DGRAM, 0);
    if(bind(server_fd, (struct sockaddr*)&rcv_addr, sizeof(struct sockaddr)) < 0) {
        perror("");
    }

    u_int32_t le = sizeof(struct sockaddr);

    while(1) {
        // Waiting for package
        struct sockaddr_in send_addr;
        u_int8_t buf[1024];
        int recv_len = recvfrom(server_fd, buf, 1024, 0, (struct sockaddr*)&send_addr, &le);

        fprintf(stdout, "[timestamp:%ld]===Receive from %s:%hu===\n", time(NULL), inet_ntoa(send_addr.sin_addr), ntohs(send_addr.sin_port));

        // Organize the data buffer
        DnsDataframe df;
        dataframeFromBuffer(buf, &df);
        if(debug_level > 1) {
            fprintf(stdout, "Received buffer-");
            print_bin(buf, recv_len);
            print_dataframe(&df);
        }
        // get query info
        DnsQuery* query = &df.queries[0];
        u_int8_t* dnsDomain = __toReadableAddr(query->name);
        // get cached ip list
        char** ips;
        if(query->type == TYPE_A) {
            ips = get_ip(dnsDomain, &df.header.answer_cnt, IP4_DB);
        } else if(query->type == TYPE_AAAA) {
            ips = get_ip(dnsDomain, &df.header.answer_cnt, IP6_DB);
        }
        fprintf(stdout, "[timestamp:%ld]%hu records found for %s:\n", time(NULL), df.header.answer_cnt, dnsDomain);
        __free_toReadableAddr(dnsDomain);
        
        if(df.header.answer_cnt && (!strcmp(ips[0], "0.0.0.0") || !strcmp(ips[0], "0:0:0:0:0:0:0:0"))) {
            fprintf(stdout, "0 (Refused)\n");
            __free_get_ip(ips, &df.header.answer_cnt);
            df.header.answer_cnt = 0;
            df.header.flag |= (QR_RESPONSE_BIT | REPLY_NAME_ERR);
            memset(buf, 0, 1024);
            size_t len = dataframeToBuffer(buf, &df);
            if(debug_level > 1) {
                fprintf(stdout, "Sending buffer-");
                print_bin(buf, len);
                print_dataframe(&df);
            }
            free_dataframe(&df);
            sendto(server_fd, buf, len, 0, (struct sockaddr*)&send_addr, le);
            fprintf(stdout, "[timestamp:%ld]Data sent to client\n", time(NULL));
            continue;
        }

        if(df.header.answer_cnt) {
            df.header.flag |= (QR_RESPONSE_BIT | RA_BIT);
            df.answers = malloc(sizeof(DnsResource) * df.header.answer_cnt);
            if(query->type == TYPE_A) {
                for(int i = 0; i < df.header.answer_cnt; i++) {
                    fprintf(stdout, "%s\n", ips[i]);
                    DnsResource* answer = df.answers + i;
                    answer->name = malloc(100);
                    strcpy(answer->name, query->name);
                    answer->type = query->type;
                    answer->klass = query->klass;
                    answer->TTL = 10;
                    answer->length = 4;
                    answer->data = malloc(answer->length);
                    u_int8_t* data = __toDnsIPv4(ips[i]);
                    memcpy(answer->data, data, answer->length);
                    __free_toDnsIPv4(data);
                }
            } else if(query->type == TYPE_AAAA) {
                for(int i = 0; i < df.header.answer_cnt; i++) {
                    fprintf(stdout, "%s\n", ips[i]);
                    DnsResource* answer = df.answers + i;
                    answer->name = malloc(100);
                    strcpy(answer->name, query->name);
                    answer->type = query->type;
                    answer->klass = query->klass;
                    answer->TTL = 10;
                    answer->length = 16;
                    answer->data = malloc(answer->length);
                    u_int8_t* data = __toDnsIPv6(ips[i]);
                    memcpy(answer->data, data, answer->length);
                    __free_toDnsIPv6(data);
                }
            }
            __free_get_ip(ips, &df.header.answer_cnt);
            memset(buf, 0, 1024);
            size_t len = dataframeToBuffer(buf, &df);
            if(debug_level > 1) {
                fprintf(stdout, "Sending buffer-");
                print_bin(buf, len);
                print_dataframe(&df);
            }
            free_dataframe(&df);
            sendto(server_fd, buf, len, 0, (struct sockaddr*)&send_addr, le);
            fprintf(stdout, "[timestamp:%ld]Data sent to client\n", time(NULL));
        } else {
            free_dataframe(&df);
            // Init socket for the forward DNS server
            struct sockaddr_in dns_addr;
            dns_addr.sin_family = AF_INET;
            dns_addr.sin_port = htons(53);
            inet_aton("10.3.9.44", &dns_addr.sin_addr);
            int dns_soc = socket(AF_INET, SOCK_DGRAM, 0);
            // Forward the entire data buffer and wait for reply
            fprintf(stdout, "[timestamp:%ld]Requesting for the forward DNS server.\n", time(NULL));
            sendto(dns_soc, buf, recv_len, 0, (struct sockaddr*)&dns_addr, le);
            u_int8_t dns_buf[1024];
            memset(dns_buf, 0, 1024);
            size_t len = recvfrom(dns_soc, dns_buf, 1024, 0, (struct sockaddr*)&dns_addr, &le);
            if(debug_level > 1) {
                fprintf(stdout, "Buffer from DNS server-");
                print_bin(dns_buf, len);
            }
            // Send back the reply to the request port
            sendto(server_fd, dns_buf, len, 0, (struct sockaddr*)&send_addr, le);
            fprintf(stdout, "[timestamp:%ld]Data sent to client\n", time(NULL));
            // Cache the IP-domain in the backward data
            fprintf(stdout, "Parsing data\n");
            DnsDataframe df2;
            dataframeFromBuffer(dns_buf, &df2);
            for(int i = 0; i < df2.header.answer_cnt; i++) {
                if(df2.answers[i].type == TYPE_A) {
                    char* ip = __toReadableIPv4(df2.answers[i].data);
                    char* domain = __toReadableAddr(df2.answers[i].name);
                    add_tuple(ip, domain, IP4_DB);
                    __free_toReadableIPv4(ip);
                    __free_toReadableAddr(domain);
                } else if(df2.answers[i].type == TYPE_AAAA) {
                    char* ip = __toReadableIPv6(df2.answers[i].data);
                    char* domain = __toReadableAddr(df2.answers[i].name);
                    add_tuple(ip, domain, IP6_DB);
                    __free_toReadableIPv6(ip);
                    __free_toReadableAddr(domain);
                }
            }
            if(debug_level > 1) {
                print_dataframe(&df2);
            }
            free_dataframe(&df2);
        }
        fprintf(stdout, "\n");
    }
    return 0;
}