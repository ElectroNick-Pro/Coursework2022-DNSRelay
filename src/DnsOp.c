#include <stdlib.h>
#include <string.h>
#include "DnsOp.h"
#include "DnsDataframe.h"

void DnsWriteV4(unsigned char* s, DnsDataframe* df) {
    df->header.flag |= (QR_RESPONSE_BIT | RA_BIT);
    df->header.answer_cnt++;
    df->answers = realloc(df->answers, sizeof(DnsResource) * df->header.answer_cnt);
    DnsResource* answer = &df->answers[df->header.answer_cnt - 1];
    DnsQuery* query = &df->queries[0];
    answer->name = malloc(100);
    strcpy(answer->name, query->name);
    answer->type = query->type;
    answer->klass = query->klass;
    answer->TTL = 10;
    answer->length = 4;
    answer->data = malloc(4);
    memcpy(answer->data, s, 4);
    char buf[1024];
    memset(buf, 0, 1024);
    size_t len = dataframeToBuffer(buf, &df);
}