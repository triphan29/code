#ifndef _CONNECTION_H_
#define _CONNECTION_H_

#include <stdint.h>

int conn_create();
void conn_close();
int send_msg(const char *addr, uint16_t port, uint8_t *msg, uint16_t msgLen);
int receive_msg(uint8_t *buf, uint16_t bufSize);
#endif
