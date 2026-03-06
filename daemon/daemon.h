// mymodule_ioctl.h
#ifndef MYMODULE_IOCTL_H
#define MYMODULE_IOCTL_H

#ifdef __KERNEL__
/* Kernel types */
#include <linux/types.h>
#define UINT32_T __u32
#define UINT16_T __u16
#define UINT8_T __u8
#else
/* Userspace types */
#include <stdint.h>
#define UINT32_T uint32_t
#define UINT16_T uint16_t
#define UINT8_T uint8_t
#endif

#define MYMODULE_MAGIC 'M'

#define LISTENING 0
#define MONITORING 1
#define REACTIVE 2
#define DISABLED 3

#define MAX_ALLOWED_DEFINITION_FILE 64
#define MAX_PACKET_BATCH 100


struct allowed_entry_ioctl {
    UINT32_T ip;
    UINT16_T ports[MAX_ALLOWED_DEFINITION_FILE];
    UINT32_T port_count;
};

struct server_info_ioctl {
    UINT32_T server_ip;
    UINT16_T server_port;
};

struct packet_data {
    UINT32_T saddr;

    UINT32_T daddr;

    UINT16_T sport;
    UINT16_T dport;

    UINT16_T total_len;
    UINT8_T protocol;
    UINT8_T ttl;

    UINT8_T tcp_flags;
    UINT8_T src_mac[6];

    char indev[16];
    UINT8_T dst_mac[6];
};

#define IOCTL_SET_STATE _IOW(MYMODULE_MAGIC, 1, UINT8_T)
#define IOCTL_SET_SERVER_INFO _IOW(MYMODULE_MAGIC, 2, struct server_info_ioctl)
#define IOCTL_ADD_WHITELIST _IOW(MYMODULE_MAGIC, 3, struct allowed_entry_ioctl)
#define IOCTL_CLEAR_WHITELIST _IO(MYMODULE_MAGIC, 4)
#define IOCTL_GET_PACKETS _IOR(MYMODULE_MAGIC, 6, struct packet_batch)


struct packet_batch {
    int count;
    struct packet_data packets[MAX_PACKET_BATCH];
};
#endif
