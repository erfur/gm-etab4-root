#define WIDTH 16

void hexdump(const void* data, unsigned long size) {
	char ascii[WIDTH+1];
	unsigned long i, j;
	ascii[WIDTH] = '\0';

    printf("0x%08lx ", data);
	for (i = 0; i < size; ++i) {

		printf("%02X ", ((unsigned char*)data)[i]);

		if (((unsigned char*)data)[i] >= ' ' && ((unsigned char*)data)[i] <= '~') {
			ascii[i % WIDTH] = ((unsigned char*)data)[i];
		} else {
			ascii[i % WIDTH] = '.';
		}

		if ((i+1) % 8 == 0 || i+1 == size) {
			printf(" ", 0);

			if ((i+1) % WIDTH == 0) {
				printf("|  %s \n", ascii);
        printf("0x%08lx ", data+i+1);
			} else if (i+1 == size) {
				ascii[(i+1) % WIDTH] = '\0';

				if ((i+1) % WIDTH <= 8) {
					printf(" ", 0);
				}

				for (j = (i+1) % WIDTH; j < WIDTH; ++j) {
					printf("   ", 0);
				}

				printf("|  %s \n", ascii);
			}
		}
	}
    printf("\n");
}
