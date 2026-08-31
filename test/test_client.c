#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <errno.h>

#define AF_CUSTOM          45
#define SOCK_CUSTOM_DGRAM  2

struct sockaddr_custom {
    unsigned short sc_family;
    uint16_t       sc_port;
    uint32_t       sc_addr;
};

int main(void) {
    int fd;
    struct sockaddr_custom src, dst;
    const char *msg = "Hello from AF_CUSTOM socket!";
    ssize_t sent;

    fd = socket(AF_CUSTOM, SOCK_CUSTOM_DGRAM, 0);
    if (fd < 0) {
        perror("socket(AF_CUSTOM)");
        return 1;
    }
    printf("[+] Successfully opened AF_CUSTOM socket (fd=%d)\n", fd);

    memset(&src, 0, sizeof(src));
    src.sc_family = AF_CUSTOM;
    src.sc_port   = htons(8888);
    inet_pton(AF_INET, "10.0.0.1", &src.sc_addr);

    if (bind(fd, (struct sockaddr *)&src, sizeof(src)) < 0) {
        perror("bind");
    } else {
        printf("[+] Bound socket to 10.0.0.1:8888\n");
    }

    memset(&dst, 0, sizeof(dst));
    dst.sc_family = AF_CUSTOM;
    dst.sc_port   = htons(9000);
    inet_pton(AF_INET, "10.0.0.2", &dst.sc_addr);

    sent = sendto(fd, msg, strlen(msg), 0,
                  (struct sockaddr *)&dst, sizeof(dst));

    if (sent < 0) {
        perror("sendto");
    } else {
        printf("[+] Sent %zd bytes to 10.0.0.2:9000\n", sent);
    }

    close(fd);
    printf("[+] Closed socket\n");
    return 0;
}