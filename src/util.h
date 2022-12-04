#define fatal(msg, ...)                                     \
    do {                                                    \
        fprintf(stderr, "[-] " msg "\n", ##__VA_ARGS__);    \
        exit(-1);                                           \
    } while(0)

#define info(msg, ...)                                      \
    do {                                                    \
        fprintf(stderr, "[*] " msg "\n", ##__VA_ARGS__);    \
    } while(0)

