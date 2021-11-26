#include <unistd.h>
#include <stdio.h>
#include <jansson.h>
#include <string.h>
#include <stdint.h>
#include <signal.h>
#include <pthread.h>
#include "config.h"
#include "connection.h"
#include "dns.h"
#include "firewall.h"
#include "time_mng.h"
/*
 * 1. Parse file -> done
 * 2. DNS query -> done
 * 3. write ip list to firewall -> done
 * 4. clean ip rules -> done
 * 4. re-query after ttl
 * 5. update rules 
 * 6. reload file
 */

struct block_item *blackList = NULL;
struct time_mng *timeList = NULL;
int running;

static void add_time_list_mng(struct time_mng *item, struct time_mng **list) {
    if (item == NULL) {
        return;
    }
    if (*list == NULL) {
        item->next = *list;
        *list = item;
    } else {
        struct time_mng *temp = *list;
        struct time_mng *pre_temp = NULL;
        while(temp != NULL) {
            //New inserted time smaller or equal with temp, put new one first
            //Compare hour
            if (item->time[0] < temp->time[0]) {
                if (pre_temp == NULL) {
                    *list = item;
                    item->next = temp;
                } else {
                    pre_temp->next = item;
                    item->next = temp;
                }
                return;
            } else if (item->time[0] == temp->time[0]) {
                //Compare minute
                if (item->time[1] <= temp->time[1]) {
                    if (pre_temp == NULL) {
                        *list = item;
                        item->next = temp;
                    } else {
                        pre_temp->next = item;
                        item->next = temp;
                    }
                    return;
                } else {
                    pre_temp = temp;
                    temp = temp->next;
                }
            } else {
                pre_temp = temp;
                temp = temp->next;
            }
        }
        pre_temp->next = item;
        item->next = NULL;
    }
}

static int get_time_value(char *buf, const char *time) {
    //Correct format is XY:ZK
    if (time == NULL || buf == NULL) {
        return -1;
    }
    if (strlen(time) > 5) {
        return -1;
    }
    char str_time[6] = {0};
    strncpy(str_time, time, sizeof(str_time));
    //Get hour
    char *pch = strtok(str_time, ":");
    if (strlen(pch) > 2) {
        return -1;
    }
    buf[0] = atoi(pch);
    //Get minute
    pch = strtok(NULL, ":");
    if (pch == NULL) {
        buf[1] = 0;
        return 0;
    }
    if (strlen(pch) > 2) {
        return -1;
    }
    buf[1] = atoi(pch);
    
    return 0;
}

static int parse_blacklist_file() {
    json_t *obj = json_load_file(CONF_PATH, 0, NULL);
    if (obj == NULL) {
        return -1;
    }
    json_t *arr = json_object_get(obj, "list");
    if (arr == NULL || json_is_array(arr) == 0) {
        json_decref(obj);
        return -1;
    }
    uint16_t index;
    json_t *value;
    //Get each item of list
    json_array_foreach(arr, index, value) {
        struct block_item *temp = (struct block_item *)calloc(1, sizeof(struct block_item));
        if (temp == NULL) {
            continue;
        }
        json_t *data = json_object_get(value, "domain");
        if (data == NULL) {
            //If no domain, it is wrong config
            free(temp);
            continue;
        }
        strncpy(temp->domain, json_string_value(data), sizeof(temp->domain));
        temp->blocked = 0;
        temp->scheduled = 0;
        data = json_object_get(value, "start");
        if (data != NULL) {
            struct time_mng *time_temp = calloc(1, sizeof(struct time_mng));
            if (time_temp != NULL) {
                if (get_time_value(time_temp->time, json_string_value(data)) == 0) {
                    time_temp->start = 1;
                    time_temp->item = temp;
                    add_time_list_mng(time_temp, &timeList);
                    temp->scheduled = 1;
                } else {
                    free(time_temp);
                }
            }
        }
        data = json_object_get(value, "end");
        if (data != NULL) {
            struct time_mng *time_temp = calloc(1, sizeof(struct time_mng));
            if (time_temp != NULL) {
                if (get_time_value(time_temp->time, json_string_value(data)) == 0) {
                    time_temp->start = 0;
                    time_temp->item = temp;
                    add_time_list_mng(time_temp, &timeList);
                    temp->scheduled = 1;
                } else {
                    free(time_temp);
                }
            }
        }
        temp->next = blackList;
        blackList = temp;
    }
    return 0;
}

static int is_ip_exist(struct ipv4_info *ipList, const char *ip) {
    int exist = 0;
    struct ipv4_info *temp = ipList;

    if (ipList == NULL || ip == NULL) {
        return exist;
    }
    while(temp != NULL) {
        if (strcmp(temp->addr, ip) == 0) {
            exist = 1;
            break;
        }
        temp = temp->next;
    }
    return exist;
}

static void store_ip_to_black_list(struct block_item *info, DNS_rrData_t *rr, int rrLen) {
    int i;
    if (info == NULL) {
        return;
    }
    for(i = 0; i < rrLen; i++) {
        if (!is_ip_exist(info->ipList, rr[i].rrData.ipv4Addr)) {
            struct ipv4_info *temp = calloc(1, sizeof(struct ipv4_info));
            if (temp == NULL) {
                continue;
            }
            strncpy(temp->addr, rr[i].rrData.ipv4Addr, sizeof(temp->addr));
            temp->ttl = rr[i].ttl;
            temp->next = info->ipList;
            info->ipList = temp;
        }
    }

}
static void resolve_ip_from_domain(struct block_item *info) {
    uint8_t *msg = NULL;
    char domainQuery[255] = {0};
    uint16_t msgLen = 0;

    if (info == NULL) {
        return;
    }
    strcpy(domainQuery, info->domain);
_processQuery:
    msgLen = DNS_generateQuery(&msg, 0, domainQuery, TYPE_A);

    if (msgLen > 0) {
        send_msg(DNS_SERVER_IP, DNS_PORT, msg, msgLen);
        uint8_t msg[513] = {0};
        uint8_t recLen = receive_msg(msg, sizeof(msg));
        DNS_rrData_t *output = NULL;
        int ret = DNS_parseResourceRecord(msg, recLen, TYPE_A, &output);
        if (ret > 0) {
            store_ip_to_black_list(info, output, ret);
        }
        if (output != NULL) {
            free(output);
        }
    }
    //Do extra query with domain contain prefix "www"
    if (strstr(domainQuery, "www") != domainQuery) {
        memset(domainQuery, 0, sizeof(domainQuery));
        strcpy(domainQuery, "www.");
        strcat(domainQuery, info->domain);
        goto _processQuery;
    }
}
static int update_ip_for_blacklist() {

    //Create socket connection to Resolver
    if (conn_create() == -1) {
        return -1;
    }
    struct block_item *temp = blackList;
    while(temp) {
        //Resolve domain name via DNS query
        resolve_ip_from_domain(temp);
        temp = temp->next;
    }
    conn_close();
    return 0;
}

static void signal_handler(int signo) {
    printf("Receive signal: %d\n", signo);
    struct block_item *temp = blackList;
    while(temp != NULL) {
        if (temp->blocked == 1) {
            firewall_removeBlockIP(temp->domain);
        }
        temp = temp->next;
    }
    running = 0;
}

static void *thread_time_calculate() {
    struct time_mng *item;
    item = timeList;
    while(item != NULL) {
        item = item->next;
    }
    schedule_start(timeList);
    return NULL;
}

int main() {

    signal(SIGTERM, signal_handler);
    signal(SIGHUP, signal_handler);
    signal(SIGINT, signal_handler);
    signal(SIGKILL, signal_handler);

    running = 1;
    if (parse_blacklist_file() == -1) {
        return -1;
    }
    if (update_ip_for_blacklist() == -1) {
        return -1;
    }
    struct block_item *temp = blackList;
    while(temp != NULL) {
        printf("RESULT: DOMAIN = %s\n", temp->domain);
        struct ipv4_info *temp_ip = temp->ipList;
        while (temp_ip != NULL) {
            printf("RESULT: IP: %s\n", temp_ip->addr);
            temp_ip = temp_ip->next;
        }
        //Block immediately which domains have no time
        if (temp->scheduled == 0) {
            if (firewall_addBlockIp(temp->domain, temp->ipList) == 0) {
                temp->blocked = 1;
            }
        }
        temp = temp->next;
    }
    pthread_t thread;
    if (pthread_create(&thread, NULL, thread_time_calculate, NULL) == 0) {
        pthread_detach(thread);
    }
    while(running) {
        sleep(1);
    }
    return 1;
}
