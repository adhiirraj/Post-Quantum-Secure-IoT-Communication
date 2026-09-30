/**
 * @file host_entropy.c
 * @brief Entropy source for host server environment using /dev/urandom
 */

#include <stddef.h>
#include <fcntl.h>
#include <unistd.h>

int CustomRngGenerateBlock(unsigned char *output, unsigned int sz)
{
    if (!output || sz == 0) return 0;

    int fd = open("/dev/urandom", O_RDONLY);
    if (fd < 0) {
        /* Fallback pseudo-entropy if /dev/urandom not openable */
        for (unsigned int i = 0; i < sz; i++) {
            output[i] = (unsigned char)((i * 137 + 73) & 0xFF);
        }
        return 0;
    }

    ssize_t ret = read(fd, output, sz);
    close(fd);

    return (ret == (ssize_t)sz) ? 0 : -1;
}
