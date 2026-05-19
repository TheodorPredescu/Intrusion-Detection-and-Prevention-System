#include <linux/compiler.h>
#include <linux/debugfs.h>
#include <linux/etherdevice.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/if_ether.h>
#include <linux/inet.h>
#include <linux/ip.h>
#include <linux/jiffies.h>
#include <linux/kernel.h>
#include <linux/list.h>
#include <linux/module.h>
#include <linux/namei.h>
#include <linux/netdevice.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/rhashtable.h>
#include <linux/seq_file.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/stddef.h>
#include <linux/tcp.h>
#include <linux/time64.h>
#include <linux/timer.h>
#include <linux/types.h>
#include <linux/udp.h>

#include <asm/uaccess.h>
#include <linux/atomic.h>
#include <linux/in.h>
#include <linux/net.h>
#include <linux/socket.h>
#include <net/sock.h>

#include "../daemon/daemon.h"
#include <linux/miscdevice.h>

#define CONFIG_FILE_PATH "/etc/mymodule.conf"
#define CONFIG_BUF_SIZE 256
#define CONFIG_POLL_INTERVAL_MS 5000
#define MAX_ALLOWED_DEFINITION_FILE 64 // Maximum number of allowed IP addresses

// States available.
#define LISTENING 0
#define MONITORING 1
#define REACTIVE 2
#define DISABLED 3

static u8 state = DISABLED;

struct packet_info {
    __be32 saddr, daddr;
    __be16 sport, dport;
    u8 protocol;
    u8 ttl;
    u16 total_len;
    u8 tcp_flags;
    char indev[IFNAMSIZ];
    u8 src_mac[ETH_ALEN];
    u8 dst_mac[ETH_ALEN];
    struct list_head list;
};

struct logged_packet_key {
    __be32 saddr;
    __be32 daddr;
    __be16 dport;
};

struct logged_packet {
    struct rhash_head node; // rhashtable node
    struct logged_packet_key key;
};

static LIST_HEAD(packet_list);
static DEFINE_SPINLOCK(packet_list_lock);

static struct nf_hook_ops netfilter_ops;

/**
 * Allowed table: key = IP (__be32), value = array of allowed ports for that IP.
 */
struct allowed_entry {
    struct rhash_head node;
    __be32 ip; /* stored in network byte order */
    u16 ports[MAX_ALLOWED_DEFINITION_FILE];
    int port_count;
};

static struct rhashtable *__rcu allowed_table_ptr;
static struct rhashtable_params allowed_params = {
    .nelem_hint = 65,
    .key_len = sizeof(__be32),
    .key_offset = offsetof(struct allowed_entry, ip),
    .head_offset = offsetof(struct allowed_entry, node),
    .hashfn = jhash,
};

/** the ipv4 address of the server. */
static __be32 server_ip = 0;
/** the port of the server. */
static u16 server_port = 0;

/** Used to block the reading of server_ip and server_port. */
static DEFINE_MUTEX(client_server_info_mutex);

/** Used for distruct and construct */

/** Used for lookups */
static DEFINE_MUTEX(allowed_mutex);
// ============================================================

static struct timespec64 last_mtime_model_file;

static void allowed_free_fn(void *head, void *arg) {
    kfree(container_of(head, struct allowed_entry, node));
}

static void reset_in_memory_allowed_var(void) {
    /* Free existing entries and re-init the table */

    struct rhashtable *old_table;
    struct rhashtable *new_table;

    new_table = kzalloc(sizeof(*new_table), GFP_KERNEL);
    if (!new_table) {
        pr_err("OOM allocating new allowed_table\n");
        return;
    }

    if (rhashtable_init(new_table, &allowed_params)) {
        pr_err("Failed to init new allowed_table\n");
        kfree(new_table);
        return;
    }

    mutex_lock(&allowed_mutex);

    // Atomically swap the pointer — readers using rcu_read_lock will
    // finish with the old table before we free it.
    old_table = rcu_dereference_protected(allowed_table_ptr, lockdep_is_held(&allowed_mutex));
    rcu_assign_pointer(allowed_table_ptr, new_table);

    mutex_unlock(&allowed_mutex);

    // Wait for all in-progress rcu_read_lock readers to finish
    // with old_table before we destroy it. This is the key step.
    synchronize_rcu();

    rhashtable_free_and_destroy(old_table, allowed_free_fn, NULL);
    kfree(old_table);
}

static bool allowed_connection(__be32 ip, u16 port_host) {
    struct rhashtable *tbl;
    struct allowed_entry *ent;
    bool ok = false;

    rcu_read_lock();
    tbl = rcu_dereference(allowed_table_ptr);
    if (!tbl) {
        goto end;
    }

    ent = rhashtable_lookup_fast(tbl, &ip, allowed_params);

    ok = ent ? true : false;
    if (port_host == 0 || ok == false) {
        goto end;
    }

    if (ent->port_count == 0) {
        ok = true;
    } else {
        int i;
        for (i = 0; i < ent->port_count; i++) {
            if (ent->ports[i] == port_host) {
                ok = true;
                break;
            }
        }
    }

end:

    rcu_read_unlock();
    return ok;
}

/**
 *  Cleanup packet list.
 */
static void free_packet_list(void) {
    struct packet_info *info, *tmp;

    spin_lock_bh(&packet_list_lock);
    list_for_each_entry_safe(info, tmp, &packet_list, list) {
        list_del(&info->list);
        kfree(info);
    }
    spin_unlock_bh(&packet_list_lock);
}

/**
 * Decide if this packet should be logged (same rules as dbg_show).
 * Returns true if it should be added to packet_list / sent to server.
 */
static bool should_log_packet(const struct packet_info *info) {
    bool in_allowed_list = allowed_connection(info->saddr, ntohs(info->dport));

    const u8 local_state = READ_ONCE(state);

    // Same as dbg_show
    if (in_allowed_list && (local_state == MONITORING || local_state == REACTIVE || local_state == LISTENING)) {
        return false;
    }

    if (local_state == DISABLED) {
        return false;
    }

    return true;
}

static bool is_router_noise(struct iphdr *ip, struct sk_buff *skb) {

    if (ipv4_is_loopback(ip->saddr)) {
        return true;
    }

    return false;
}

static bool add_log_if_necessary(struct packet_info *info) {

    if (!should_log_packet(info)) {
        return false;
    }

    spin_lock_bh(&packet_list_lock);
    list_add_tail(&info->list, &packet_list);
    spin_unlock_bh(&packet_list_lock);

    return true;
}

/**
 * Packet logging hook.
 */
static unsigned int packet_hook(void *priv, struct sk_buff *skb, const struct nf_hook_state *hook_state) {
    const u8 local_state = READ_ONCE(state);
    struct ethhdr *eth;
    struct iphdr *ip;
    struct tcphdr *tcp;
    struct udphdr *udp;
    struct packet_info *info;

    if (!skb) {
        return NF_ACCEPT;
    }

    eth = eth_hdr(skb);
    ip = ip_hdr(skb);
    if (!ip || skb->len < sizeof(struct iphdr)) {
        return NF_ACCEPT;
    }

    const __be32 copy_server_ip = READ_ONCE(server_ip);
    const u16 copy_server_port = READ_ONCE(server_port);

    // Skip if packet matches server IP and destination port.
    if (copy_server_ip != 0 && copy_server_port != 0 && ip->saddr == copy_server_ip) {
        if (ip->protocol == IPPROTO_TCP && skb_transport_header_was_set(skb)) {
            tcp = tcp_hdr(skb);
            if (ntohs(tcp->source) == copy_server_port) {
                return NF_ACCEPT;
            }
        } else if (ip->protocol == IPPROTO_UDP) {
            udp = udp_hdr(skb);
            if (ntohs(udp->source) == copy_server_port) {
                return NF_ACCEPT;
            }
        }
    }

    // Accept if its in disable mode.
    if (local_state == DISABLED) {
        return NF_ACCEPT;
    }

    // In your hook
    if (is_router_noise(ip, skb)) {
        return NF_ACCEPT; // skip logging
    }

    info = kmalloc(sizeof(*info), GFP_ATOMIC);
    if (!info) {
        return NF_ACCEPT;
    }

    memset(info, 0, sizeof(*info));

    info->saddr = ip->saddr;
    info->daddr = ip->daddr;
    info->protocol = ip->protocol;
    info->ttl = ip->ttl;
    info->total_len = ntohs(ip->tot_len);

    if (eth) {
        memcpy(info->src_mac, eth->h_source, ETH_ALEN);
        memcpy(info->dst_mac, eth->h_dest, ETH_ALEN);
    }

    if (hook_state->in) {
        strncpy(info->indev, hook_state->in->name, IFNAMSIZ - 1);
    }

    if (ip->protocol == IPPROTO_TCP && skb_transport_header_was_set(skb)) {
        tcp = tcp_hdr(skb);
        info->sport = tcp->source;
        info->dport = tcp->dest;
        info->tcp_flags =
            (tcp->fin << 0) | (tcp->syn << 1) | (tcp->rst << 2) | (tcp->psh << 3) | (tcp->ack << 4) | (tcp->urg << 5);
    } else if (ip->protocol == IPPROTO_UDP) {
        udp = udp_hdr(skb);
        info->sport = udp->source;
        info->dport = udp->dest;
    }

    const bool added = add_log_if_necessary(info);

    // TODO: The logic here is just bad. I need to make a decision and just stick with it - I combine monitoring and
    // listening and in some case I do nothing where I sould.

    /* In REACTIVE mode, only allow packets with daddr in allowed_ips and from the list of allowed ports.
     In the packet list will be packets that are also packets that are
     not blocked; it will be a filtering before printing it.*/
    if (local_state == REACTIVE || local_state == LISTENING || local_state == MONITORING) {
        bool should_drop = true;

        /* If the IP is known, check whether the destination port is allowed
         * (use host-order port for comparison). If the entry has port_count==0,
         * it means any port is allowed for that IP.
         */
        bool allowed_ip = false;
        if (ip->protocol == IPPROTO_TCP || ip->protocol == IPPROTO_UDP) {
            u16 dport_host = ntohs(info->dport);
            allowed_ip = allowed_connection(ip->saddr, dport_host);
        }

        if (allowed_ip) {
            should_drop = false;
        }

        if (local_state == REACTIVE) {
            if (!added) {
                kfree(info);
            }
            return should_drop ? NF_DROP : NF_ACCEPT;
        }
    }

    if (!added) {
        kfree(info);
    }
    return NF_ACCEPT;
}

static long mymodule_ioctl(struct file *file, unsigned int cmd, unsigned long arg) {
    switch (cmd) {
        case IOCTL_SET_STATE: {
            u8 new_state;
            // Copia data din userspace în kernel
            if (copy_from_user(&new_state, (void __user *)arg, sizeof(__u8))) {
                return -EFAULT;
            }

            // Actualizează variabila kernel
            pr_info("[IOCTL] State: %u → %u\n", READ_ONCE(state), new_state);
            WRITE_ONCE(state, new_state);
            pr_info("[IOCTL] ✓ State changed\n");
            return 0;
        }

        case IOCTL_SET_SERVER_INFO: {
            struct server_info_ioctl info;
            if (copy_from_user(&info, (void __user *)arg, sizeof(info))) {
                return -EFAULT;
            }

            mutex_lock(&client_server_info_mutex);
            server_ip = info.server_ip;
            server_port = info.server_port;
            mutex_unlock(&client_server_info_mutex);

            return 0;
        }

        case IOCTL_ADD_WHITELIST: {
            pr_info("[OK] DAEMON requests a new pc to be added in the ruling.\n");
            struct allowed_entry_ioctl entry;
            struct allowed_entry *ent;
            struct rhashtable *tbl;

            if (copy_from_user(&entry, (void __user *)arg, sizeof(entry))) {
                return -EFAULT;
            }

            ent = kzalloc(sizeof(*ent), GFP_KERNEL);
            if (!ent) {
                return -ENOMEM;
            }

            ent->ip = entry.ip;
            ent->port_count = entry.port_count;
            for (int i = 0; i < entry.port_count; i++) {
                ent->ports[i] = entry.ports[i];
            }

            mutex_lock(&allowed_mutex);
            tbl = rcu_dereference_protected(allowed_table_ptr, lockdep_is_held(&allowed_mutex));
            rhashtable_insert_fast(tbl, &ent->node, allowed_params);
            mutex_unlock(&allowed_mutex);

            return 0;
        }

        case IOCTL_CLEAR_WHITELIST: {
            reset_in_memory_allowed_var();
            return 0;
        }

        case IOCTL_GET_PACKETS: {
            struct packet_batch *batch_kernel;
            struct packet_info *info, *tmp;
            int count = 0;

            batch_kernel = kmalloc(sizeof(struct packet_batch), GFP_KERNEL);
            if (!batch_kernel) {
                return -ENOMEM;
            }

            memset(batch_kernel, 0, sizeof(struct packet_batch));

            spin_lock_bh(&packet_list_lock);
            list_for_each_entry_safe(info, tmp, &packet_list, list) {
                if (count >= MAX_PACKET_BATCH) {
                    break;
                }

                batch_kernel->packets[count].saddr = info->saddr;
                batch_kernel->packets[count].daddr = info->daddr;
                batch_kernel->packets[count].sport = info->sport;
                batch_kernel->packets[count].dport = info->dport;
                batch_kernel->packets[count].protocol = info->protocol;
                batch_kernel->packets[count].ttl = info->ttl;
                batch_kernel->packets[count].total_len = info->total_len;
                batch_kernel->packets[count].tcp_flags = info->tcp_flags;
                strncpy(batch_kernel->packets[count].indev, info->indev, 16);
                batch_kernel->packets[count].indev[15] = '\0';

                memcpy(batch_kernel->packets[count].dst_mac, info->dst_mac, 6);
                memcpy(batch_kernel->packets[count].src_mac, info->src_mac, 6);

                list_del(&info->list);
                kfree(info);
                count++;
            }
            spin_unlock_bh(&packet_list_lock);

            batch_kernel->count = count;

            if (copy_to_user((void __user *)arg, batch_kernel, sizeof(struct packet_batch))) {
                return -EFAULT;
            }

            kfree(batch_kernel);

            return 0;
        }

        default:
            return -ENOTTY;
    }
}

// Structura file operations
static const struct file_operations mymodule_fops = {
    .owner = THIS_MODULE,
    .unlocked_ioctl = mymodule_ioctl,
};

// Device registration
static struct miscdevice mymodule_device = {
    .minor = MISC_DYNAMIC_MINOR,
    .name = "mymodule",
    .fops = &mymodule_fops,
};

/**
 * Module init/exit.
 */
static int __init mynetfilter_init(void) {
    struct rhashtable *tbl;
    int hret;

    tbl = kzalloc(sizeof(*tbl), GFP_KERNEL);

    if (!tbl) {
        return -ENOMEM;
    }

    hret = rhashtable_init(tbl, &allowed_params);
    if (hret) {
        kfree(tbl);
        return hret;
    }

    RCU_INIT_POINTER(allowed_table_ptr, tbl);

    // Initialise timer var for detection model bin file.
    last_mtime_model_file.tv_sec = 0;
    last_mtime_model_file.tv_nsec = 0;

    netfilter_ops.hook = packet_hook;
    netfilter_ops.pf = PF_INET;
    netfilter_ops.hooknum = NF_INET_LOCAL_IN;
    netfilter_ops.priority = NF_IP_PRI_FIRST;

    nf_register_net_hook(&init_net, &netfilter_ops);

    const int ret = misc_register(&mymodule_device);
    if (ret) {
        pr_err("[ERROR] Failed to register device: %d\n", ret);
        nf_unregister_net_hook(&init_net, &netfilter_ops);
        return ret;
    }
    pr_info("[OK] /dev/mymodule registered\n");
    pr_info("Netfilter module loaded with on-demand config reload and periodic "
            "modification detection\n");
    return 0;
}

static void __exit mynetfilter_exit(void) {
    struct rhashtable *tbl;

    misc_deregister(&mymodule_device);
    nf_unregister_net_hook(&init_net, &netfilter_ops);

    free_packet_list();
    mutex_lock(&allowed_mutex);
    tbl = rcu_dereference_protected(allowed_table_ptr, lockdep_is_held(&allowed_mutex));
    rcu_assign_pointer(allowed_table_ptr, NULL);
    mutex_unlock(&allowed_mutex);

    synchronize_rcu(); // wait for all readers to finish

    rhashtable_free_and_destroy(tbl, allowed_free_fn, NULL);
    kfree(tbl);

    pr_info("Netfilter module unloaded\n");
}

module_init(mynetfilter_init);
module_exit(mynetfilter_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("PREDESCU THEODOR");
MODULE_DESCRIPTION("Netfilter Module with Config Reload from Disk and Modification Detection");
