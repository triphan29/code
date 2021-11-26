#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "config.h"
#include "firewall.h"

void firewall_removeBlockIP(const char *name) {
    char cmd[255] = {0};

    if (name == NULL) {
        return;
    }
    snprintf(cmd, sizeof(cmd), "sudo iptables -D OUTPUT -j block_%s", name);
    if (system(cmd) == 0) {
        snprintf(cmd, sizeof(cmd), "sudo iptables -F block_%s", name);
        if (system(cmd) == 0) {
            snprintf(cmd, sizeof(cmd), "sudo iptables -X block_%s", name);
            if (system(cmd) == 0) {
                printf("Remove blocking domain %s sucessfully\n", name);
            } else {
                printf("Failed to delete chain of domain %s\n", name);
            }
        } else {
            printf("Failed to flush chain of domain %s\n", name);
        }
    } else {
        printf("Failed to delete rules of domain %s\n", name);
    }
}

int firewall_addBlockIp(const char *name, struct ipv4_info *ipList) {
    int ret = -1;
    char chainName[255] = {0};

    if (name == NULL || ipList == NULL) {
        return ret;
    }
    strcpy(chainName, "block_");
    strcat(chainName, name);

    FILE *fd = fopen(FILE_RULE, "w");
    if  (fd == NULL) {
        return ret;
    }
    fprintf(fd, "*filter\n");
    fprintf(fd, ":%s - [0:0]\n", chainName);
    fprintf(fd, "-I OUTPUT -j %s\n", chainName);

    struct ipv4_info *temp = ipList;
    while(temp != NULL) {
        fprintf(fd, "-I %s -d %s -j DROP\n", chainName, temp->addr);
        if (ret != 0) {
            ret = 0;
        }
        temp = temp->next;
    }
    fprintf(fd, "COMMIT\n");
    fclose(fd);
    //Remove old rules of chain first
    if (ret == 0) {
        firewall_removeBlockIP(name);
        char cmd[255] = {0};
        snprintf(cmd, sizeof(cmd), "sudo iptables-restore -n < %s", FILE_RULE);
        if (system(cmd) != 0) {
            printf("Failed to add blocking domain %s\n", name);
        }
    }
    unlink(FILE_RULE);
    return ret;
}
