#ifndef _DNS_BLACKLIST_HPP_
#define _DNS_BLACKLIST_HPP_

#define CONF_PATH "./blacklist"



struct ipv4_info {
    char addr[16];
    int ttl;
    struct ipv4_info *next;
};

struct block_item {
    char domain[125];
    int blocked;
    int scheduled;
    struct ipv4_info *ipList;
    struct block_item *next;
};

struct time_mng {
    char time[2];
    int start;
    struct block_item *item;
    struct time_mng *next;
};


#endif
