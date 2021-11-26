#ifndef _FIREWALL_H_
#define _FIREWALL_H_

#define FILE_RULE               "./.ipt"

void firewall_removeBlockIP(const char *name);
int firewall_addBlockIp(const char *name, struct ipv4_info *ip_list);
#endif
