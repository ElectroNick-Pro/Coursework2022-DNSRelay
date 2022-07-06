#ifndef __DNSRELAY_H
#define __DNSRELAY_H

#include <stdlib.h>

typedef struct DnsHeader {
    u_int16_t id;
    u_int16_t flag;
    u_int16_t question_cnt;
    u_int16_t answer_cnt;
    u_int16_t authority_cnt;
    u_int16_t additional_cnt;
} DnsHeader;

enum FLAG_BIT{
    QR_RESPONSE_BIT         =0b1000000000000000,
    OP_REV_BIT              =0b0000100000000000,
    OP_SERVER_STAT_BIT      =0b0001000000000000,
    AUTHORITATIVE_BIT       =0b0000010000000000,
    TC_BIT                  =0b0000001000000000,
    RD_BIT                  =0b0000000100000000,
    RA_BIT                  =0b0000000010000000,
    AUTHENTICATED_BIT       =0b0000000000100000,
    REPLY_NOERR             =0b0000000000000000,
    REPLY_FORMAT_ERR        =0b0000000000000001,
    REPLY_SERVER_FAILURE    =0b0000000000000010,
    REPLY_NAME_ERR          =0b0000000000000011,
    REPLY_NOT_IMPLEMENTED   =0b0000000000000100,
    REPLY_REFUSE            =0b0000000000000101,
};

u_int8_t* headerFromBuffer(u_int8_t* buf, DnsHeader* obj);
u_int8_t* headerToBuffer(u_int8_t* buf, DnsHeader* obj);
void free_header(DnsHeader* obj);
void print_header(DnsHeader* obj);

typedef struct DnsQuery {
    u_int8_t* name;
    u_int16_t type;
    u_int16_t klass;
} DnsQuery;

u_int8_t* queryFromBuffer(u_int8_t* buf, DnsQuery* obj);
u_int8_t* queryToBuffer(u_int8_t* buf, DnsQuery* obj);
void free_query(DnsQuery* obj);
void print_query(DnsQuery* obj);

typedef struct DnsResource {
    u_int8_t* name;
    u_int16_t type;
    u_int16_t klass;
    u_int32_t TTL;
    u_int16_t length;
    u_int8_t* data;
} DnsResource;

u_int8_t* resourceFromBuffer(u_int8_t* buf, DnsResource* obj, u_int8_t* begBuf);
u_int8_t* resourceToBuffer(u_int8_t* buf, DnsResource* obj);
void free_resource(DnsResource* obj);
void print_resource(DnsResource* obj, char* type);

enum TYPE_BIT {
    TYPE_A           =1U,
    TYPE_AAAA        =28U,
};

enum CLASS_BIT {
    IN = 1U,
};

typedef struct DnsDataframe {
    DnsHeader header;
    DnsQuery* queries;
    DnsResource* answers;
    DnsResource* authorities;
    DnsResource* additionals;
} DnsDataframe;

void dataframeFromBuffer(u_int8_t* buf, DnsDataframe* obj);
size_t dataframeToBuffer(u_int8_t* buf, DnsDataframe* obj);
void free_dataframe(DnsDataframe* obj);


char** get_ip(char* s, u_int16_t* retSize, char* file);
void add_tuple(char* ip, char* domain, char* file);
void remove_tuple(char* ip, char* domain, char* file);

void print_bin(u_int8_t* arr, int len);

#endif // __DNSRELAY_H