#ifndef _DNS_HPP_
#define _DNS_HPP_

#include <stdint.h>

#define DNS_SERVER_IP                   "127.0.0.53"
#define DNS_PORT                        53

#define DNS_FLAG_RESPONSE               0x1000
#define DNS_FLAG_RECURSIVE              0x0100
#define DNS_FLAG_RECODE                 0x000f

#define DNS_RECODE_NO_ERROR             0
//RFC 1035
typedef enum DNS_class{
    CLASS_IN=1,
    CLASS_CS,
    CLASS_CH,
    CLASS_HS
} DNS_class_t;

typedef enum DNS_type{
    TYPE_A      =   1,//rfc 1035
    TYPE_NS     =   2,//rfc 1035
    TYPE_CNAME  =   5,//rfc 1035
    TYPE_PTR    =   12,//rfc 1035
    TYPE_TXT    =   16,//rfc 1035
    TYPE_AAAA   =   28,//rfc 3596
    TYPE_SRV    =   33
} DNS_type_t;

typedef struct DNS_rrData {
    uint32_t ttl;
    uint16_t rrLen;
    uint8_t *rrRawData;
    union {
        char ipv4Addr[16];
    }rrData;
} DNS_rrData_t;

typedef struct DNS_msgHeader {
    /*                                                   
     *  RFC 1035 : 4.1.1. Header section format          
     *  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
     *  |                      ID                       |
     *  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
     *  |QR|   Opcode  |AA|TC|RD|RA|   Z    |   RCODE   |
     *  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
     *  |                    QDCOUNT                    |
     *  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
     *  |                    ANCOUNT                    |
     *  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
     *  |                    NSCOUNT                    |
     *  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
     *  |                    ARCOUNT                    |
     *  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
     */                                                  
    uint16_t id;
    uint16_t flags;
    uint16_t qdcount;//question
    uint16_t ancount;//anwser RR
    uint16_t nscount;//authorities RR
    uint16_t arcount;//additional RR
} DNS_msgHeader_t;

typedef struct DNS_query {
    uint8_t qname[255];
    uint16_t qname_len;
    uint16_t qtype;
    uint16_t qclass;
} DNS_query_t;


uint16_t DNS_generateQuery(uint8_t **output, uint16_t buf_size, const char *domain, DNS_type_t qtype);
int DNS_parseResourceRecord(uint8_t *msg, uint16_t msgLen, DNS_type_t rrType, DNS_rrData_t **output);
#endif
