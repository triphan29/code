#include <stdint.h>
#include <dns.h>
#include <string.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <stdio.h>
#include "dns.h"


static uint16_t create_query_name(uint8_t *buf, size_t buf_size, const char *domain) {
    uint8_t size = 0;
    char name[255] = {0};
    uint8_t *ptr = buf;

    if (domain == NULL || buf == NULL) {
        return 0;
    }
    strncpy(name, domain, sizeof(name));
    char *pch = strtok(name, ".");
    while(pch) {
        *ptr++ = (uint8_t)strlen(pch);
        if (--buf_size == 0) {
            return 0;
        }
        for (uint8_t i = 0; i < strlen(pch); i++) {
            *ptr++ = (uint8_t)pch[i];
            if (--buf_size == 0) {
                return 0;
            }
        }
        size += strlen(pch) + 1;
        pch = strtok(NULL, ".");
    }
    *ptr = (uint8_t)0;
    size += 1;

    return size;
}

static uint8_t *skip_domainName(uint8_t *msg) {
    if (msg == NULL) {
        return NULL;
    }
    if ((msg[0] & 0xc0) == 0xc0) {
        //RFC 1035: Section 4.1.4
        //This is a pointer to another name location
        return &msg[2];
    } else {
        //This is entire of name
        volatile int i = 0;
        //Move to the end of domain name which is zero
        while(msg[i] != 0) {
            i++;
        }
        //Point to qtype
        return (uint8_t *)&msg[i + 1];
    }
}

static uint8_t *skip_question(uint8_t *msg) {
    if (msg == NULL) {
        return NULL;
    }
    //Skip 4 bytes are qtype and qclass
    return skip_domainName(msg) + 4;
}

static uint8_t *parse_ResourceRecord(uint8_t *msg, DNS_type_t rrType, DNS_rrData_t *output, uint8_t *outCount) {
    struct in_addr ipv4Addr;

    if (msg == NULL || output == NULL || outCount == NULL) {
        return NULL;
    }
    uint8_t *ptr = skip_domainName(msg);
    //Check type of RR
    if  (ntohs(*(uint16_t *)ptr) != rrType) {
        //Skip type and class, move to RDLENGTH
        ptr += 2 + 2 + 4;
        //Get RDATA length
        uint16_t rrLen = ntohs(*(uint16_t *)ptr);
        return ptr + 2 + rrLen;
    }
    //RR type is interested RR, prepare storage
    DNS_rrData_t *temp = output + *outCount;
    //Point to TTL
    ptr += 4;
    temp->ttl = ntohl(*(uint32_t *)ptr);
    //Point to RDLENGTH
    ptr += 4;
    temp->rrLen = ntohs(*(uint16_t *)ptr);
    //Point to RDATA
    ptr += 2;
    temp->rrRawData = calloc(temp->rrLen, sizeof(uint8_t));
    if (temp->rrRawData == NULL) {
        //Failed to allocation for RDATA, return
        return ptr + temp->rrLen; 
    }
    memcpy(temp->rrRawData, ptr, temp->rrLen);
    switch(rrType) {
        case(TYPE_A):
            ipv4Addr.s_addr = *(uint32_t *)(temp->rrRawData);
            strncpy(temp->rrData.ipv4Addr, inet_ntoa(ipv4Addr), sizeof(temp->rrData.ipv4Addr));
            break;
        default:
            break;
    }
    *outCount += 1;
    return ptr + temp->rrLen;
}

/*Call API when creating query session in DNS message*/
uint16_t DNS_generateQuery(uint8_t **output, uint16_t buf_size, const char *domain, DNS_type_t qtype) {
    static uint16_t id = 0;
    DNS_query_t query = {0};

    if (domain == NULL) {
        return 0;
    }
    //Create query section
    if ((query.qname_len = create_query_name(query.qname, sizeof(query.qname), domain)) == 0) {
        return 0;
    }
    query.qtype = htons(qtype);
    query.qclass = htons(CLASS_IN);

    //Allocate for full query msg
    if (buf_size == 0) {
        buf_size = sizeof(DNS_msgHeader_t) + query.qname_len + sizeof(query.qtype) + sizeof(query.qclass);
        *output = calloc(1, buf_size);
        if (*output == NULL) {
            return 0;
        }
    } else {
        buf_size += query.qname_len + sizeof(query.qtype) + sizeof(query.qclass);
        uint8_t *temp_output = realloc(*output, buf_size);
        if (temp_output == NULL) {
            return 0;
        }
        *output = temp_output;
    }

    //Create msg header
    DNS_msgHeader_t *header = (DNS_msgHeader_t *)*output;
    if (ntohs(header->id) == 0) {
        header->id = htons(++id);
    }
    //set flags to zero for query
    header->flags = htons(DNS_FLAG_RECURSIVE);
    header->qdcount = htons(ntohs(header->qdcount) + 1);

    uint8_t *ptr = *output + sizeof(DNS_msgHeader_t);
    memcpy(ptr, (uint8_t *)query.qname, query.qname_len);
    ptr += query.qname_len;
    memcpy(ptr, (uint8_t *)&query.qtype, sizeof(query.qtype));
    ptr += sizeof(query.qtype);
    memcpy(ptr, (uint8_t *)&query.qtype, sizeof(query.qtype));

    return buf_size;
}

int DNS_parseResourceRecord(uint8_t *msg, uint16_t msgLen, DNS_type_t rrType, DNS_rrData_t **output) {

    if ((msg == NULL) || (msgLen <= sizeof(DNS_msgHeader_t))) {
        return -1;
    }
    //parse msg header
    DNS_msgHeader_t *header = (DNS_msgHeader_t *)msg;
    //Check if the msg is response
    if (ntohs(header->flags) & (DNS_FLAG_RESPONSE != DNS_FLAG_RESPONSE)) {
        return -1;
    }
    //Check if the msg reply error
    if (ntohs(header->flags) & (DNS_FLAG_RECODE != DNS_RECODE_NO_ERROR)) {
        return -1;
    }
    //Get number of question and RR
    uint8_t numQuery = ntohs(header->qdcount);
    uint8_t numAnwser = ntohs(header->ancount);
    uint8_t numAuthor = ntohs(header->nscount);
    uint8_t numAddit = ntohs(header->arcount);
    //Check if no RR field in the msg
    if ((numQuery == 0) || ((numAnwser == 0) && (numAuthor == 0) && (numAddit == 0))) {
        return -1;
    }
    //Point to question section
    uint8_t *ptr = (uint8_t *)(header + 1);
    uint8_t i;
    for(i = 0; i < numQuery; i++) {
        ptr = skip_question(ptr);
    }
    //Parse RR data
    uint8_t outCount = 0;
    *output = calloc(numAnwser + numAuthor + numAddit, sizeof(DNS_rrData_t));
    if (*output == NULL) {
        return -1;
    }
    for(i = 0; i < numAnwser + numAuthor + numAddit; i++) {
        ptr = parse_ResourceRecord(ptr, rrType, *output, &outCount);
    }

    return (int)outCount;
}
