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

int main(int argc, char **argv, char **env) {
    /* ask for root */
    info("asking for root...");
    int result = setresuid(0, 0, 0);

    if (result) {
        printf("[!] set user root failed: %s\n", strerror(errno));
        exit(1);
    }

    /* execute a root shell */
    info("getting root shell...");
    /* for root shell */
    char *cmd[2];
    cmd[0] = "/system/bin/sh";
    cmd[1] = NULL;
    execve (cmd[0], cmd, env);

    return 0;
}