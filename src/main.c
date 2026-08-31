#include <linux/module.h>
#include <linux/init.h>
#include "custom_sock.h"

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Custom Network Stack with AF_CUSTOM Socket Family");
MODULE_AUTHOR("netstack");

static int __init netstack_init(void) {
    return custom_sock_init();
}

static void __exit netstack_exit(void) {
    custom_sock_exit();
}

module_init(netstack_init);
module_exit(netstack_exit);