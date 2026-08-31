#ifndef TUN_H
#define TUN_H

#include <stddef.h>

#define DEFAULT_TUN_DEV "tun0"
#define MTU_SIZE        1500

/**
 * Allocates and configures a Linux TUN device.
 * 
 * @param dev Pointer to a buffer containing the requested device name 
 *            (e.g., "tun0"), or an empty string for dynamic naming. 
 *            The assigned name is copied back into this buffer.
 * @return File descriptor for the opened TUN device, or -1 on failure.
 */
int tun_alloc(char *dev);

/**
 * Closes the TUN device file descriptor.
 * 
 * @param fd The open TUN file descriptor.
 * @return 0 on success, -1 on error.
 */
int tun_close(int fd);

#endif