#include <stdio.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <stdbool.h>
#include "util.h"

int main() {
    unsigned char *sptr = NULL, *token = NULL, *bufferptr = NULL;
    unsigned char buffer[0x1000];

    FILE *mfd = fopen("/proc/mounts", "r");
    if (mfd == NULL) {
        fatal("failed opening /proc/mounts");
    }

    unsigned char *tokens[6];
    // fgets terminates on EOF or newline
    while (fgets(buffer, sizeof(buffer), mfd)) {
        bufferptr = buffer;
        // char *strtok_r(char *str, const char *delim, char **saveptr);
        for (int i=0; i<6; i++, bufferptr = NULL) {
            tokens[i] = strtok_r(bufferptr, " ", &sptr);
            info("token: %s", tokens[i]);
        }

        if (strcmp("/system", tokens[1]) == 0) {
            info("/system mount is %s", tokens[0]);
        }
    }
}