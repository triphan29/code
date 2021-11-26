#include <stdio.h>
#include <stdint.h>
#include <unistd.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <sys/socket.h>
#include <arpa/inet.h>

static int sockfd = -1;

int conn_create() {
    int ret = -1;

    if (sockfd != -1) {
        return 0;
    }

    do {
        sockfd = socket(AF_INET, SOCK_DGRAM, 0);
        if (sockfd == -1) {
            break;
        }
        struct sockaddr_in srcAddr = {
            .sin_family = AF_INET,
            .sin_port = htons(0),
            .sin_addr.s_addr = INADDR_ANY
        };
        if (bind(sockfd, (struct sockaddr *)&srcAddr, sizeof(srcAddr)) == -1) {
            break;
        }
        ret = 0;
    } while(0);

    if ((ret == -1) && (sockfd != -1)) {
        close(sockfd);
        sockfd = -1;
    }
    return ret;
}
void conn_close() {
    if (sockfd != -1) {
        close(sockfd);
        sockfd = -1;
    }
}

int send_msg(const char *addr, uint16_t port, uint8_t *msg, uint16_t msgLen) {

    if ((sockfd == -1) || (addr == NULL) || (port == 0) || (msg == NULL) || (msgLen == 0)) {
        return -1;
    }
    struct sockaddr_in destAddr = {
        .sin_family = AF_INET,
        .sin_port = htons(port),
        .sin_addr.s_addr = inet_addr(addr)
    };
    return sendto(sockfd, (const void *)msg, msgLen, 0, (const struct sockaddr *) &destAddr, sizeof(destAddr));
}

int receive_msg(uint8_t *buf, uint16_t bufSize) {
    return recv(sockfd, (void *)buf, bufSize, 0);
}
