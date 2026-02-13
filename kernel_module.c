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

#define CONFIG_FILE_PATH "/etc/mymodule.conf"
#define CONFIG_BUF_SIZE 256
#define CONFIG_POLL_INTERVAL_MS 5000
#define MAX_ALLOWED_DEFINITION_FILE 64 // Maximum number of allowed IP addresses

// States available.
#define LISTENING 0
#define MONITORING 1
#define REACTIVE 2
#define DISABLED 3

static u8 state;

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

    // Exclude the source (client) port.
    // __be16 sport;
};

struct logged_packet {
    struct rhash_head node; // rhashtable node
    struct logged_packet_key key;
};

// For table access lookup.
static DEFINE_SPINLOCK(logged_lock); // Protect hash table access
static struct rhashtable logged_table;
static struct rhashtable_params logged_params = {
    .nelem_hint = 64, // Initial hint for number of elements
    .key_len = sizeof(struct logged_packet_key),
    .key_offset = offsetof(struct logged_packet, key),
    .head_offset =
        offsetof(struct logged_packet, node), // Required for rhashtable
    .hashfn = jhash, // Use jhash as the default hash function
};

static LIST_HEAD(packet_list);
static spinlock_t list_lock;

static struct dentry *dbg_file;
static struct nf_hook_ops netfilter_ops;

static char config_buf[CONFIG_BUF_SIZE];

/** Path to allowed list file. */
static char allowed_file_path[CONFIG_BUF_SIZE];

/**
 * Allowed table: key = IP (__be32), value = array of allowed ports for that IP.
 */
struct allowed_entry {
    struct rhash_head node;
    __be32 ip; /* stored in network byte order */
    u16 ports[MAX_ALLOWED_DEFINITION_FILE];
    int port_count;
};

static struct rhashtable allowed_table;
static struct rhashtable_params allowed_params = {
    .nelem_hint = 65,
    .key_len = sizeof(__be32),
    .key_offset = offsetof(struct allowed_entry, ip),
    .head_offset = offsetof(struct allowed_entry, node),
    .hashfn = jhash,
};

// For comparing the "last time modified" of the CONFIG_FILE_PATH and
// allowed_file_path
static struct timer_list config_timer;
static struct timespec64 last_mtime_config_file;
static struct timespec64 last_mtime_allowed_file;

/** the ipv4 address of the server. */
static __be32 server_ip = 0;
/** the port of the server. */
static u16 server_port = 0;

static __be32 prev_server_ip = 0;
static u16 prev_server_port = 0;
/** Used to block the reading of server_ip and server_port. */
static DEFINE_MUTEX(client_server_info_mutex);

/**
 * To clear the table for logged information.
 */
static void rht_free_fn(void *head, void *arg) {
    kfree(container_of(head, struct logged_packet, node));
}

static DEFINE_SPINLOCK(allowed_lock);

static void allowed_free_fn(void *head, void *arg) {
    kfree(container_of(head, struct allowed_entry, node));
}

static void reset_in_memory_allowed_var(void) {
    /* Free existing entries and re-init the table */
    spin_lock(&allowed_lock);
    rhashtable_free_and_destroy(&allowed_table, allowed_free_fn, NULL);
    /* Re-initialize; ignore error here (caller will log if needed) */
    rhashtable_init(&allowed_table, &allowed_params);
    spin_unlock(&allowed_lock);
}

/* Count of entries in allowed_table (useful for reporting) */
static int allowed_entry_count = 0;

static bool ip_is_in_allowed_table(__be32 ip) {
    struct allowed_entry *ent;
    bool found = false;
    spin_lock(&allowed_lock);
    ent = rhashtable_lookup_fast(&allowed_table, &ip, allowed_params);
    if (ent)
        found = true;
    spin_unlock(&allowed_lock);
    return found;
}

static bool ip_allows_port(__be32 ip, u16 port_host) {
    struct allowed_entry *ent;
    bool ok = false;
    spin_lock(&allowed_lock);
    ent = rhashtable_lookup_fast(&allowed_table, &ip, allowed_params);
    if (ent) {
        if (ent->port_count == 0)
            ok = true; /* port wildcard */
        else {
            int i;
            for (i = 0; i < ent->port_count; i++) {
                if (ent->ports[i] == port_host) {
                    ok = true;
                    break;
                }
            }
        }
    }
    spin_unlock(&allowed_lock);
    return ok;
}

/**
 *  Cleanup packet list.
 */
static void free_packet_list(void) {
    struct packet_info *info, *tmp;

    spin_lock(&list_lock);
    list_for_each_entry_safe(info, tmp, &packet_list, list) {
        list_del(&info->list);
        kfree(info);
    }
    spin_unlock(&list_lock);
}

/**
 * Read a file and parse IP addresses
 * Returns: 0 on success, negative error on failure
 */
static int load_allowed_file(void) {
    struct file *filp;
    loff_t pos = 0;
    ssize_t bytes;
    char buf[CONFIG_BUF_SIZE];
    char *line, *end;
    __be32 ip;
    unsigned int a, b, c, d;

    /* On each new read, reset it to not have overwrite problems and old
     data still present. */
    reset_in_memory_allowed_var();

    if (allowed_file_path[0] == '\0') {
        pr_info("No allowed file path specified\n");
        return 0;
    }

    filp = filp_open(allowed_file_path, O_RDWR | O_CREAT, 0666);
    if (IS_ERR(filp)) {
        pr_err("Failed to open allowed file: %s (%ld)\n", allowed_file_path,
               PTR_ERR(filp));
        return PTR_ERR(filp);
    }

    /* Force mode to 0666 regardless of umask */
    inode_lock(file_inode(filp));
    file_inode(filp)->i_mode = S_IFREG | 0666;
    mark_inode_dirty(file_inode(filp));
    inode_unlock(file_inode(filp));

    bytes = kernel_read(filp, buf, CONFIG_BUF_SIZE - 1, &pos);
    if (bytes < 0) {
        pr_err("Failed to read allowed file: %zd\n", bytes);
        filp_close(filp, NULL);
        return bytes;
    }

    buf[bytes] = '\0';
    pr_info("Allowed file loaded (%zd bytes):\n%s", bytes, buf);

    /* We'll support two formats:
     * 1) Per-IP lines: 1.2.3.4:80,443
     * If sectioned format is used, the PORTS list will be applied to each IP.
     */

    /* Temporary storage for bare IPs and global ports */
    __be32 tmp_ips[MAX_ALLOWED_DEFINITION_FILE];
    int tmp_ip_count = 0;
    u16 tmp_ports[MAX_ALLOWED_DEFINITION_FILE];
    int tmp_port_count = 0;

    line = buf;
    while ((end = strstr(line, "\n")) != NULL) {
        *end = '\0';

        char *colon = strchr(line, ':');
        if (colon) {
            /* per-IP with ports */
            *colon = '\0';
            if (sscanf(line, "%u.%u.%u.%u", &a, &b, &c, &d) == 4) {
                ip = htonl((a << 24) | (b << 16) | (c << 8) | d);

                struct allowed_entry *ent = kzalloc(sizeof(*ent), GFP_KERNEL);
                if (!ent) {
                    pr_err("oom allocating allowed_entry\n");
                    line = end + 1;
                    continue;
                }
                ent->ip = ip;
                ent->port_count = 0;

                char *ports_str = colon + 1;
                /* Read the port as a string. */
                char *tok;
                while ((tok = strsep(&ports_str, ",")) != NULL &&
                       ent->port_count < MAX_ALLOWED_DEFINITION_FILE) {
                    u16 p = 0;
                    /* Try to transform it to a u16. On success, add the port.*/
                    if (sscanf(tok, "%hu", &p) == 1) {
                        ent->ports[ent->port_count++] = p;
                    }
                }

                spin_lock(&allowed_lock);
                if (rhashtable_insert_fast(&allowed_table, &ent->node,
                                           allowed_params) == 0)
                    allowed_entry_count++;
                spin_unlock(&allowed_lock);
                pr_info("added ip %pI4 with %d ports", &ip, ent->port_count);
            }
        } else {
            if (tmp_ip_count < MAX_ALLOWED_DEFINITION_FILE &&
                sscanf(line, "%u.%u.%u.%u", &a, &b, &c, &d) == 4) {
                ip = htonl((a << 24) | (b << 16) | (c << 8) | d);
                tmp_ips[tmp_ip_count++] = ip;
                pr_info("queued ip %pI4", &ip);
            }
        }
        line = end + 1;
    }

    /* If there are queued bare IPs, create entries with port_count==0 (allow
     * any port).
     */
    for (int i = 0; i < tmp_ip_count; i++) {
        struct allowed_entry *ent = kzalloc(sizeof(*ent), GFP_KERNEL);
        if (!ent) {
            pr_err("oom allocating allowed_entry for queued ip\n");
            continue;
        }
        ent->ip = tmp_ips[i];
        if (tmp_port_count > 0) {
            ent->port_count = tmp_port_count;
            for (int j = 0; j < tmp_port_count; j++)
                ent->ports[j] = tmp_ports[j];
        } else {
            ent->port_count = 0; /* means any port allowed for this IP */
        }
        spin_lock(&allowed_lock);
        if (rhashtable_insert_fast(&allowed_table, &ent->node,
                                   allowed_params) == 0)
            allowed_entry_count++;
        spin_unlock(&allowed_lock);
        pr_info("added queued ip %pI4 with %d ports", &ent->ip,
                ent->port_count);
    }

    /* print entries in allowed_table for inspection */
    struct rhashtable_iter iter;
    struct allowed_entry *ent;

    pr_info("________________INSPECT_________________\nInformation added in "
            "memory:");
    rhashtable_walk_enter(&allowed_table, &iter);
    while ((ent = rhashtable_walk_next(&iter)) != NULL) {
        int j;
        pr_info("IP: %pI4 ports:", &ent->ip);
        if (ent->port_count == 0) {
            pr_info("  any");
        } else {
            for (j = 0; j < ent->port_count; j++)
                pr_info("  %u", ent->ports[j]);
        }
    }
    rhashtable_walk_exit(&iter);

    filp_close(filp, NULL);
    pr_info("Loaded allowed table entries\n");
    return 0;
}

/**
 * Read config file from disk
 * @return: number of bytes read on success (>=0), negative error on failure
 */
static ssize_t load_config_from_file(void) {
    struct file *filp;
    loff_t pos = 0;
    ssize_t bytes;
    char *line, *end;
    unsigned int a, b, c, d;
    u16 parsed_port;

    /* Open the file; If the file is not present, create it.  */
    // filp = filp_open(CONFIG_FILE_PATH, O_RDWR | O_CREAT, 0666);
    filp = filp_open(CONFIG_FILE_PATH, O_RDONLY, 0);

    if (IS_ERR(filp)) {
        pr_err("Failed to open or create config file: -%s- (%ld)\n",
               CONFIG_FILE_PATH, PTR_ERR(filp));
        return PTR_ERR(filp);
    }

    /* Read up to CONFIG_BUF_SIZE-1 so we can NUL-terminate */
    bytes = kernel_read(filp, config_buf, CONFIG_BUF_SIZE - 1, &pos);
    if (bytes < 0) {
        pr_err("Failed to read config file: %zd\n", bytes);
        filp_close(filp, NULL);
        return bytes;
    }

    config_buf[bytes] = '\0';
    pr_info("Config loaded -%s-(%zd bytes):\n%s", CONFIG_FILE_PATH, bytes,
            config_buf);

    // Reset allowed_file_path.
    strcpy(allowed_file_path, "\0");

    // Clear already saved information.
    free_packet_list();

    // Parse config lines
    line = config_buf;
    while ((end = strstr(line, "\n")) != NULL) {
        *end = '\0';
        if (sscanf(line, "server IP %u.%u.%u.%u", &a, &b, &c, &d) == 4) {

            mutex_lock(&client_server_info_mutex);
            server_ip = htonl((a << 24) | (b << 16) | (c << 8) | d);
            pr_info("Parsed server IP: %pI4\n", &server_ip);
            mutex_unlock(&client_server_info_mutex);
        } else if (sscanf(line, "server port %hu", &parsed_port) == 1) {
            mutex_lock(&client_server_info_mutex);
            server_port = parsed_port;
            mutex_unlock(&client_server_info_mutex);
        } else if (strcmp(line, "Listening") == 0) {
            state = LISTENING;
        } else if (strcmp(line, "Monitoring") == 0) {
            state = MONITORING;
        } else if (strcmp(line, "Reactive") == 0) {
            state = REACTIVE;
        } else if (strcmp(line, "Disabled") == 0) {
            state = DISABLED;
        } else if (sscanf(line, "allowed_file %255s", allowed_file_path) == 1) {
            // Ensure null termination
            allowed_file_path[CONFIG_BUF_SIZE - 1] = '\0';
        }
        line = end + 1;
    }

    /* Update last_mtime_config_file on successful read */
    // last_mtime_config_file = inode_get_mtime(filp->f_inode);
    last_mtime_config_file = filp->f_inode->i_mtime;

    filp_close(filp, NULL);
    return bytes;
}

/** Workque for safer repetitive reading from a file. */
static void config_work_func(struct work_struct *work);
static DECLARE_WORK(config_work, config_work_func);

static void config_timer_callback(struct timer_list *unused) {
    schedule_work(&config_work); // defer to process context
    mod_timer(&config_timer,
              jiffies + msecs_to_jiffies(CONFIG_POLL_INTERVAL_MS));
}

static void restart_client_thread_if_needed(void);

static void config_work_func(struct work_struct *work) {
    struct file *filp;
    struct timespec64 current_mtime_config_file;
    struct timespec64 current_mtime_allowed_file;
    ssize_t ret;

    bool update_allowed_file = false;

    // ____________________________________________
    // Check config file last modification.
    filp = filp_open(CONFIG_FILE_PATH, O_RDONLY, 0);
    if (IS_ERR(filp)) {
        pr_err("Failed to open config file: %s (%ld)\n", CONFIG_FILE_PATH,
               PTR_ERR(filp));
        return;
    }

    // Kernel version diff.
    // current_mtime_config_file = inode_get_mtime(file_inode(filp));
    current_mtime_config_file = file_inode(filp)->i_mtime;
    filp_close(filp, NULL);

    if (timespec64_compare(&current_mtime_config_file,
                           &last_mtime_config_file) != 0) {
        pr_info("Config file modification detected, reloading...\n");
        ret = load_config_from_file();
        pr_info("Config file modification response: %ld\n", ret);
        if (ret >= 0) {
            last_mtime_config_file = current_mtime_config_file;

            restart_client_thread_if_needed();

            update_allowed_file = true;
        }
    }

    if (allowed_file_path[0] == '\0') {
        return;
    }
    filp = filp_open(allowed_file_path, O_RDWR | O_CREAT, 0644);
    if (IS_ERR(filp)) {
        pr_err("Failed to open allowed file: %256s (%ld)\n", allowed_file_path,
               PTR_ERR(filp));
        return;
    }

    // Kernel version diff.
    // current_mtime_allowed_file = inode_get_mtime(file_inode(filp));
    current_mtime_allowed_file = file_inode(filp)->i_mtime;
    filp_close(filp, NULL);

    if (timespec64_compare(&current_mtime_allowed_file,
                           &last_mtime_allowed_file) != 0) {
        pr_info("Config allowed modification detected, reloading...\n");
        update_allowed_file = true;
    }

    if (update_allowed_file) {
        ret = load_allowed_file();
        if (ret >= 0) {
            last_mtime_allowed_file = current_mtime_allowed_file;
        }
    }
}

static bool is_router_noise(struct iphdr *ip, struct sk_buff *skb) {

    if (ipv4_is_loopback(ip->saddr)) {
        return true;
    }

    return false;
}

/**
 * Packet logging hook.
 */
static unsigned int packet_hook(void *priv, struct sk_buff *skb,
                                const struct nf_hook_state *hook_state) {
    struct ethhdr *eth;
    struct iphdr *ip;
    struct tcphdr *tcp;
    struct udphdr *udp;
    struct packet_info *info;

    bool allowed_ip = false;
    bool allowed_port = false;

    if (!skb)
        return NF_ACCEPT;

    eth = eth_hdr(skb);
    ip = ip_hdr(skb);
    if (!ip || skb->len < sizeof(struct iphdr))
        return NF_ACCEPT;

    mutex_lock(&client_server_info_mutex);
    const __be32 copy_server_ip = server_ip;
    const u16 copy_server_port = server_port;
    mutex_unlock(&client_server_info_mutex);
    // Skip if packet matches server IP and destination port.
    if (copy_server_ip != 0 && copy_server_port != 0 &&
        ip->saddr == copy_server_ip) {
        if (ip->protocol == IPPROTO_TCP && skb_transport_header_was_set(skb)) {
            tcp = tcp_hdr(skb);
            if (ntohs(tcp->dest) == copy_server_port) {
                return NF_ACCEPT;
            }
        } else if (ip->protocol == IPPROTO_UDP) {
            udp = udp_hdr(skb);
            if (ntohs(udp->dest) == copy_server_port) {
                return NF_ACCEPT;
            }
        }
    }

    // Accept if its in disable mode.
    if (state == DISABLED)
        return NF_ACCEPT;

    // In your hook
    if (is_router_noise(ip, skb))
        return NF_ACCEPT; // skip logging

    info = kmalloc(sizeof(*info), GFP_ATOMIC);
    if (!info)
        return NF_ACCEPT;

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

    if (hook_state->in)
        strncpy(info->indev, hook_state->in->name, IFNAMSIZ - 1);

    if (ip->protocol == IPPROTO_TCP && skb_transport_header_was_set(skb)) {
        tcp = tcp_hdr(skb);
        info->sport = tcp->source;
        info->dport = tcp->dest;
        info->tcp_flags = (tcp->fin << 0) | (tcp->syn << 1) | (tcp->rst << 2) |
                          (tcp->psh << 3) | (tcp->ack << 4) | (tcp->urg << 5);
    } else if (ip->protocol == IPPROTO_UDP) {
        udp = udp_hdr(skb);
        info->sport = udp->source;
        info->dport = udp->dest;
    }

    spin_lock(&list_lock);
    list_add_tail(&info->list, &packet_list);
    spin_unlock(&list_lock);

    /* In REACTIVE mode, only allow packets with daddr in allowed_ips
     and from the list of allowed ports.
     In the packet list will be packets that are also packets that are
     not blocked; it will be a filtering before printing it.*/
    if (state == REACTIVE) {
        /* Check if source IP is known in allowed table */
        allowed_ip = ip_is_in_allowed_table(ip->saddr);

        /* If the IP is known, check whether the destination port is allowed
         * (use host-order port for comparison). If the entry has port_count==0,
         * it means any port is allowed for that IP.
         */
        if (ip->protocol == IPPROTO_TCP || ip->protocol == IPPROTO_UDP) {
            u16 dport_host = ntohs(info->dport);
            allowed_port = ip_allows_port(ip->saddr, dport_host);
        }

        if (!allowed_ip || !allowed_port) {
            return NF_DROP;
        }
    }

    return NF_ACCEPT;
}

/* Debugfs packet log read */
static int dbg_show(struct seq_file *m, void *v) {
    struct packet_info *info;
    struct logged_packet *lp;
    bool in_allowed_ip_list = false;
    bool in_allowed_port_list = false;
    struct logged_packet_key key = {0};
    struct logged_packet *existing;

    // Initialize logged_table at the start of dbg_show.
    if (rhashtable_init(&logged_table, &logged_params)) {
        pr_err("Failed to initialize logged_table in dbg_show\n");
        return -ENOMEM; // Return error to indicate failure
    }

    spin_lock(&list_lock);
    list_for_each_entry(info, &packet_list, list) {

        /* Check allowed map for IP and port */
        in_allowed_ip_list = ip_is_in_allowed_table(info->saddr);
        in_allowed_port_list = ip_allows_port(info->saddr, ntohs(info->dport));

        /* In monitoring and reactive mode, react only if the packet
        is not in the allowed list and in the list of allowed ports. */
        if (in_allowed_ip_list && in_allowed_port_list &&
            (state == MONITORING || state == REACTIVE))
            continue;

        /* In listening, if it is not found in the list of allowed ip addr
         and in the list of allowed ports to use, is ignored in the report. */
        if ((!in_allowed_ip_list || !in_allowed_port_list) &&
            state == LISTENING)
            continue;

        key.saddr = info->saddr;
        key.daddr = info->daddr;
        // key.sport = info->sport;
        key.dport = info->dport;

        spin_lock(&logged_lock);
        existing = rhashtable_lookup_fast(&logged_table, &key, logged_params);
        spin_unlock(&logged_lock);

        mutex_lock(&client_server_info_mutex);
        const __be32 copy_server_ip = server_ip;
        const u16 copy_server_port = server_port;
        mutex_unlock(&client_server_info_mutex);
        if (!existing && !(copy_server_ip == 0 && copy_server_port == 0 &&
                           info->daddr == copy_server_ip)) {
            seq_printf(m,
                       "PROTO=%u TTL=%u LEN=%u IFACE=%s\n"
                       "SRC=%pI4 SPORT=%u DST=%pI4 DPORT=%u\n"
                       "SRC_MAC=%pM DST_MAC=%pM TCP_FLAGS=%02x\n\n",
                       info->protocol, info->ttl, info->total_len, info->indev,
                       &info->saddr, ntohs(info->sport), &info->daddr,
                       ntohs(info->dport), info->src_mac, info->dst_mac,
                       info->tcp_flags);

            lp = kmalloc(sizeof(*lp), GFP_ATOMIC);
            if (lp) {
                lp->key = key;
                spin_lock(&logged_lock);
                rhashtable_insert_fast(&logged_table, &lp->node, logged_params);
                spin_unlock(&logged_lock);
            } else {
                pr_warn("Failed to allocate memory for logged packet\n");
            }
        }
    }
    spin_unlock(&list_lock);

    /* Destroy logged_table at the end of dbg_show. */
    spin_lock(&logged_lock);
    rhashtable_free_and_destroy(&logged_table, rht_free_fn, NULL);
    spin_unlock(&logged_lock);

    return 0;
}

static int dbg_open(struct inode *inode, struct file *file) {
    return single_open(file, dbg_show, NULL);
}

static const struct file_operations dbg_fops = {
    .owner = THIS_MODULE,
    .open = dbg_open,
    .read = seq_read,
    .llseek = seq_lseek,
    .release = single_release,
};

/**
 *  Config file read (trigger reload from disk).
 */
static ssize_t cfg_read(struct file *file, char __user *buf, size_t count,
                        loff_t *ppos) {
    ssize_t ret;

    /* reload into global config_buf */
    ret = load_config_from_file();
    if (ret < 0)
        return ret;

    /* present the buffer to userspace via seq-like simple helper */
    return simple_read_from_buffer(buf, count, ppos, config_buf,
                                   strlen(config_buf));
}

static const struct file_operations cfg_fops = {
    .owner = THIS_MODULE,
    .read = cfg_read,
};

// ====================================================================================

struct socket *conn_socket = NULL;
static struct task_struct *client_thread;
static atomic_t client_running = ATOMIC_INIT(0);
static DEFINE_MUTEX(client_thread_mutex);
// simple flag (atomic_t better in production)

static int tcp_client_send(struct socket *sock, const char *buf, size_t len,
                           unsigned long flags) {
    struct msghdr msg = {.msg_name = NULL,
                         .msg_namelen = 0,
                         .msg_control = NULL,
                         .msg_controllen = 0,
                         .msg_flags = flags};
    struct kvec vec;
    int written = 0;
    int left = len;
    int ret;

    while (left > 0) {
        vec.iov_base = (void *)(buf + written);
        vec.iov_len = left;

        ret = kernel_sendmsg(sock, &msg, &vec, 1, left);
        if (ret < 0) {
            if (ret == -ERESTARTSYS || (flags & MSG_DONTWAIT && ret == -EAGAIN))
                continue; // retry on signal or would-block
            pr_err("send failed: %d\n", ret);
            return ret;
        }

        written += ret;
        left -= ret;
    }

    return written;
}

static int tcp_client_receive(struct socket *sock, char *buf, size_t max_len,
                              unsigned long flags) {
    struct msghdr msg = {.msg_name = NULL,
                         .msg_namelen = 0,
                         .msg_control = NULL,
                         .msg_controllen = 0,
                         .msg_flags = flags};
    struct kvec vec;
    int ret;

    vec.iov_base = buf;
    vec.iov_len = max_len;

    ret = kernel_recvmsg(sock, &msg, &vec, 1, max_len, flags);
    if (ret < 0) {
        if (ret == -EAGAIN || ret == -ERESTARTSYS)
            return -EAGAIN; // caller can retry
        pr_err("recv failed: %d\n", ret);
        return ret;
    }

    if (ret < max_len)
        buf[ret] = '\0'; // null-terminate if string

    return ret;
}

static int tcp_client_thread(void *arg) {
    mutex_lock(&client_server_info_mutex);
    const __be32 copy_server_ip = server_ip;
    const u16 copy_server_port = server_port;
    mutex_unlock(&client_server_info_mutex);

    if (copy_server_ip == 0 || copy_server_port == 0) {
        atomic_set(&client_running, 0);
        return -1;
    }
    struct sockaddr_in saddr;
    char send_buf[] = "HOLA\n";
    char recv_buf[64];
    int ret;

    allow_signal(SIGTERM); // optional: allow kthread_stop to interrupt us

    pr_info("client thread started\n");

    ret = sock_create(PF_INET, SOCK_STREAM, IPPROTO_TCP, &conn_socket);
    if (ret < 0) {
        pr_err("sock_create failed: %d\n", ret);
        goto out;
    }

    memset(&saddr, 0, sizeof(saddr));
    saddr.sin_family = AF_INET;
    saddr.sin_port = htons(copy_server_port);
    saddr.sin_addr.s_addr = copy_server_ip;

    conn_socket->sk->sk_rcvtimeo = msecs_to_jiffies(6000);
    conn_socket->sk->sk_sndtimeo = msecs_to_jiffies(6000);

    ret = conn_socket->ops->connect(conn_socket, (struct sockaddr *)&saddr,
                                    sizeof(saddr), 0);

    if (ret && ret != -EINPROGRESS) {
        pr_err("connect failed immediately: %d\n", ret);
        goto out_sock;
    }

    if (ret == -EINPROGRESS) {
        long timeout;

        timeout = wait_event_interruptible_timeout(
            conn_socket->sk->sk_wq->wait,
            conn_socket->sk->sk_state != TCP_SYN_SENT || kthread_should_stop(),
            msecs_to_jiffies(6000));

        if (kthread_should_stop()) {
            pr_info("connect aborted due to thread stop\n");
            goto out_sock;
        }
        if (timeout <= 0) {
            pr_err("connect timeout\n");
            goto out_sock;
        }

        if (conn_socket->sk->sk_state != TCP_ESTABLISHED) {
            pr_err("connect failed, state=%d\n", conn_socket->sk->sk_state);
            goto out_sock;
        }
    }

    pr_info("connected to server\n");

    // Main loop – example: send once, receive once, then idle/sleep
    while (!kthread_should_stop()) {
        ret = tcp_client_send(conn_socket, send_buf, strlen(send_buf),
                              MSG_DONTWAIT);
        if (ret < 0) {
            if (ret != -EAGAIN)
                break;
        } else {
            pr_info("sent '%s'\n", send_buf);
        }

        memset(recv_buf, 0, sizeof(recv_buf));
        ret = tcp_client_receive(conn_socket, recv_buf, sizeof(recv_buf) - 1,
                                 MSG_DONTWAIT);
        if (ret > 0) {
            pr_info("received '%s' (%d bytes)\n", recv_buf, ret);
        } else if (ret < 0 && ret != -EAGAIN) {
            pr_err("receive error: %d\n", ret);
            break;
        }

        // poll every 2s – replace with wait_event* for efficiency
        msleep_interruptible(2000);
    }

out_sock:
    if (conn_socket)
        sock_release(conn_socket);
    conn_socket = NULL;

out:
    atomic_set(&client_running, 0);
    pr_info("client thread exiting\n");
    return 0;
}

static void restart_client_thread_if_needed(void) {
    mutex_lock(&client_server_info_mutex);
    const __be32 copy_server_ip = server_ip;
    const u16 copy_server_port = server_port;

    if (copy_server_ip == prev_server_ip &&
        copy_server_port == prev_server_port) {
        mutex_unlock(&client_server_info_mutex);
        return;
    }

    pr_info("Server config changed → restarting client thread\n");

    prev_server_ip = copy_server_ip;
    prev_server_port = copy_server_port;

    mutex_unlock(&client_server_info_mutex);
    /* Stop old thread */
    mutex_lock(&client_thread_mutex);
    if (atomic_read(&client_running)) {
        kthread_stop(client_thread);
        atomic_set(&client_running, 0);
    }

    /* Start new thread ONLY if config is valid */
    if (copy_server_ip != 0 && copy_server_port != 0) {
        client_thread = kthread_run(tcp_client_thread, NULL, "tcp-client");
        if (IS_ERR(client_thread)) {
            pr_err("Failed to restart client thread: %ld\n",
                   PTR_ERR(client_thread));
            atomic_set(&client_running, 0);
        } else {
            atomic_set(&client_running, 1);
            pr_info("Client thread restarted\n");
        }
    }
    mutex_unlock(&client_thread_mutex);
}

/**
 * Module init/exit.
 */
static int __init mynetfilter_init(void) {
    spin_lock_init(&list_lock);
    spin_lock_init(&logged_lock);

    /* initialize allowed_table */
    if (rhashtable_init(&allowed_table, &allowed_params))
        pr_warn("Failed to initialize allowed_table\n");

    // Initialise timer var for config_file.
    last_mtime_config_file.tv_sec = 0;
    last_mtime_config_file.tv_nsec = 0;

    // Initialise timer var for allowed_file.
    last_mtime_allowed_file.tv_sec = 0;
    last_mtime_allowed_file.tv_nsec = 0;

    // Initialise the char[] so it can be checked if something was added.
    strcpy(allowed_file_path, "\0");

    netfilter_ops.hook = packet_hook;
    netfilter_ops.pf = PF_INET;
    // netfilter_ops.hooknum = NF_INET_PRE_ROUTING;
    netfilter_ops.hooknum = NF_INET_LOCAL_IN;
    netfilter_ops.priority = NF_IP_PRI_FIRST;

    nf_register_net_hook(&init_net, &netfilter_ops);

    dbg_file = debugfs_create_file("packet_logs", 0444, NULL, NULL, &dbg_fops);

    /* Setup timer for periodic modification checks */
    timer_setup(&config_timer, config_timer_callback, 0);
    mod_timer(&config_timer,
              jiffies + msecs_to_jiffies(CONFIG_POLL_INTERVAL_MS));

    pr_info("Netfilter module loaded with on-demand config reload and periodic "
            "modification detection\n");
    return 0;
}

static void __exit mynetfilter_exit(void) {
    nf_unregister_net_hook(&init_net, &netfilter_ops);
    debugfs_remove(dbg_file);
    del_timer_sync(&config_timer);
    cancel_work_sync(&config_work);
    free_packet_list();

    /* free allowed_table entries */
    spin_lock(&allowed_lock);
    rhashtable_free_and_destroy(&allowed_table, allowed_free_fn, NULL);
    spin_unlock(&allowed_lock);

    mutex_lock(&client_server_info_mutex);
    if (atomic_read(&client_running)) {
        kthread_stop(client_thread);
        atomic_set(&client_running, 0);
    }
    mutex_unlock(&client_server_info_mutex);

    pr_info("Netfilter module unloaded\n");
}

module_init(mynetfilter_init);
module_exit(mynetfilter_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("PREDESCU THEODOR");
MODULE_DESCRIPTION(
    "Netfilter Module with Config Reload from Disk and Modification Detection");
