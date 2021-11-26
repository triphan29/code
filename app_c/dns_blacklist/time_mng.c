#include <stdio.h>
#include <time.h>
#include <unistd.h>
#include "time_mng.h"
#include "firewall.h"

int schedule_start(struct time_mng *timeList) {
    time_t rawtime;
    struct tm *timeInfo;
    struct time_mng *item = timeList;

    if (item == NULL) {
        return -1;
    }
    rawtime = time(NULL);
    timeInfo = localtime(&rawtime);
    /*Move to item will come first with current time*/
    while(item != NULL) {
        if (item->time[0] >= timeInfo->tm_hour) {
            if (item->time[0] == timeInfo->tm_hour) {
                if (item->time[1] >= timeInfo->tm_min) {
                    break;
                } else {
                    /*Continue to loop*/
                }
            } else {
                break;
            }
        }
        item = item->next;
    }

    if (item == NULL) {
        item = timeList;
    }

    while (1) {
_reCheckNewItem:
        if ((item->time[0] == timeInfo->tm_hour) && (item->time[1] == timeInfo->tm_min)) {
            if (item->start == 1) {
                printf("Process blocking domain %s\n", item->item->domain);
                if (item->item->blocked != 1) {
                    /*block domain*/
                    if (firewall_addBlockIp(item->item->domain, item->item->ipList) == 0) {
                        item->item->blocked = 1;
                    }
                    /*Move to next item*/
                    item = item->next;
                    if (item == NULL) {
                        item = timeList;
                    }
                    goto _reCheckNewItem;
                }
            } else {
                printf("Process unblocking domain %s\n", item->item->domain);
                if (item->item->blocked == 1) {
                    /*unblock domain*/
                    firewall_removeBlockIP(item->item->domain);
                    item->item->blocked = 0;
                }
                /*Move to next item*/
                item = item->next;
                if (item == NULL) {
                    item = timeList;
                }
                goto _reCheckNewItem;
            }
        }
        sleep(10);
        rawtime = time(NULL);
        timeInfo = localtime(&rawtime);
    }
}
