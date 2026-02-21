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

static u8 state = 3;

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

// For table access lookup.
static DEFINE_SPINLOCK(logged_lock); // Protect hash table access
static struct rhashtable logged_table;
static struct rhashtable_params logged_params = {
    .nelem_hint = 64, // Initial hint for number of elements
    .key_len = sizeof(struct logged_packet_key),
    .key_offset = offsetof(struct logged_packet, key),
    .head_offset = offsetof(struct logged_packet, node), // Required for rhashtable
    .hashfn = jhash,                                     // Use jhash as the default hash function
};

static LIST_HEAD(packet_list);
static spinlock_t list_lock;

static struct dentry *dbg_file;
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

static struct rhashtable allowed_table;
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

static DEFINE_SPINLOCK(allowed_lock);
// ============================================================

struct socket *conn_socket = NULL;
static struct task_struct *client_thread;
static atomic_t client_running = ATOMIC_INIT(0);
static DEFINE_MUTEX(client_thread_mutex);
#define SEND_BUF_SIZE 512
// ============================================================
#define MAX_SUPPORT_VECTORS 10000
#define NUM_FEATURES 6
#define SCALE 1000000      /* 6 decimal places */
typedef s64 fixed_point_t; /* 64-bit fixed point */

struct SVMModel {
    s64 scaler_mean[NUM_FEATURES];
    s64 scaler_std[NUM_FEATURES];
    s64 offset;
    int num_support_vectors;
    s64 support_vectors[MAX_SUPPORT_VECTORS][NUM_FEATURES];
    s64 dual_coefficients[MAX_SUPPORT_VECTORS];
    bool loaded;
};

static struct SVMModel svm_model = {0};
static DEFINE_SPINLOCK(svm_model_lock);
static struct timespec64 last_mtime_model_file;
// static char *model_bin_path = "/etc/model.bin";
// I do not have floats here, so I transform in int and then devide by `SCALE`

/**
 * To clear the table for logged information.
 */
static void rht_free_fn(void *head, void *arg) {
    kfree(container_of(head, struct logged_packet, node));
}

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

static bool ip_is_in_allowed_table(__be32 ip) {
    struct allowed_entry *ent;
    spin_lock(&allowed_lock);
    ent = rhashtable_lookup_fast(&allowed_table, &ip, allowed_params);
    spin_unlock(&allowed_lock);
    return ent ? true : false;
    ;
}

static bool ip_allows_port(__be32 ip, u16 port_host) {
    struct allowed_entry *ent;
    bool ok = false;
    spin_lock(&allowed_lock);
    ent = rhashtable_lookup_fast(&allowed_table, &ip, allowed_params);
    if (ent) {
        if (ent->port_count == 0) {
            ok = true; /* port wildcard */
        } else {
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

// static void free_packet_list_sent(void) {
//     struct packet_info *info, *tmp;
//
//     spin_lock(&list_lock);
//     list_for_each_entry_safe(info, tmp, &packet_list_sent, list) {
//         list_del(&info->list);
//         kfree(info);
//     }
//     spin_unlock(&list_lock);
// }
/**
 * Decide if this packet should be logged (same rules as dbg_show).
 * Returns true if it should be added to packet_list / sent to server.
 */
static bool should_log_packet(const struct packet_info *info) {
    bool in_allowed_ip_list = ip_is_in_allowed_table(info->saddr);
    bool in_allowed_port_list = ip_allows_port(info->saddr, ntohs(info->dport));

    const u8 local_state = READ_ONCE(state);

    // Same as dbg_show
    if (in_allowed_ip_list && in_allowed_port_list && (local_state == MONITORING || local_state == REACTIVE)) {
        return false;
    }

    if ((!in_allowed_ip_list || !in_allowed_port_list) && local_state == LISTENING) {
        return false;
    }

    if (local_state == DISABLED) {
        return false;
    }

    return true;
}

/**
 * Read a file and parse IP addresses
 * Returns: 0 on success, negative error on failure
 */
// static int load_allowed_file(void) {
//     struct file *filp;
//     loff_t pos = 0;
//     ssize_t bytes;
//     char buf[CONFIG_BUF_SIZE];
//     char *line, *end;
//     __be32 ip;
//     unsigned int a, b, c, d;
//
//     /* On each new read, reset it to not have overwrite problems and old
//      data still present. */
//     reset_in_memory_allowed_var();
//
//     if (allowed_file_path[0] == '\0') {
//         pr_info("No allowed file path specified\n");
//         return 0;
//     }
//
//     filp = filp_open(allowed_file_path, O_RDWR | O_CREAT, 0666);
//     if (IS_ERR(filp)) {
//         pr_err("Failed to open allowed file: %s (%ld)\n", allowed_file_path, PTR_ERR(filp));
//         return PTR_ERR(filp);
//     }
//
//     /* Force mode to 0666 regardless of umask */
//     inode_lock(file_inode(filp));
//     file_inode(filp)->i_mode = S_IFREG | 0666;
//     mark_inode_dirty(file_inode(filp));
//     inode_unlock(file_inode(filp));
//
//     bytes = kernel_read(filp, buf, CONFIG_BUF_SIZE - 1, &pos);
//     if (bytes < 0) {
//         pr_err("Failed to read allowed file: %zd\n", bytes);
//         filp_close(filp, NULL);
//         return bytes;
//     }
//
//     buf[bytes] = '\0';
//     pr_info("Allowed file loaded (%zd bytes):\n%s", bytes, buf);
//
//     /* We'll support two formats:
//      * 1) Per-IP lines: 1.2.3.4:80,443
//      * If sectioned format is used, the PORTS list will be applied to each IP.
//      */
//
//     /* Temporary storage for bare IPs and global ports */
//     __be32 tmp_ips[MAX_ALLOWED_DEFINITION_FILE];
//     int tmp_ip_count = 0;
//     u16 tmp_ports[MAX_ALLOWED_DEFINITION_FILE];
//     int tmp_port_count = 0;
//
//     line = buf;
//     while ((end = strstr(line, "\n")) != NULL) {
//         *end = '\0';
//
//         char *colon = strchr(line, ':');
//         if (colon) {
//             /* per-IP with ports */
//             *colon = '\0';
//             if (sscanf(line, "%u.%u.%u.%u", &a, &b, &c, &d) == 4) {
//                 ip = htonl((a << 24) | (b << 16) | (c << 8) | d);
//
//                 struct allowed_entry *ent = kzalloc(sizeof(*ent), GFP_KERNEL);
//                 if (!ent) {
//                     pr_err("oom allocating allowed_entry\n");
//                     line = end + 1;
//                     continue;
//                 }
//                 ent->ip = ip;
//                 ent->port_count = 0;
//
//                 char *ports_str = colon + 1;
//                 /* Read the port as a string. */
//                 char *tok;
//                 while ((tok = strsep(&ports_str, ",")) != NULL && ent->port_count < MAX_ALLOWED_DEFINITION_FILE) {
//                     u16 p = 0;
//                     /* Try to transform it to a u16. On success, add the port.*/
//                     if (sscanf(tok, "%hu", &p) == 1) {
//                         ent->ports[ent->port_count++] = p;
//                     }
//                 }
//
//                 spin_lock(&allowed_lock);
//                 if (rhashtable_insert_fast(&allowed_table, &ent->node, allowed_params) == 0)
//                     allowed_entry_count++;
//                 spin_unlock(&allowed_lock);
//                 pr_info("added ip %pI4 with %d ports", &ip, ent->port_count);
//             }
//         } else {
//             if (tmp_ip_count < MAX_ALLOWED_DEFINITION_FILE && sscanf(line, "%u.%u.%u.%u", &a, &b, &c, &d) == 4) {
//                 ip = htonl((a << 24) | (b << 16) | (c << 8) | d);
//                 tmp_ips[tmp_ip_count++] = ip;
//                 pr_info("queued ip %pI4", &ip);
//             }
//         }
//         line = end + 1;
//     }
//
//     /* If there are queued bare IPs, create entries with port_count==0 (allow
//      * any port).
//      */
//     for (int i = 0; i < tmp_ip_count; i++) {
//         struct allowed_entry *ent = kzalloc(sizeof(*ent), GFP_KERNEL);
//         if (!ent) {
//             pr_err("oom allocating allowed_entry for queued ip\n");
//             continue;
//         }
//         ent->ip = tmp_ips[i];
//         if (tmp_port_count > 0) {
//             ent->port_count = tmp_port_count;
//             for (int j = 0; j < tmp_port_count; j++)
//                 ent->ports[j] = tmp_ports[j];
//         } else {
//             ent->port_count = 0; /* means any port allowed for this IP */
//         }
//         spin_lock(&allowed_lock);
//         if (rhashtable_insert_fast(&allowed_table, &ent->node, allowed_params) == 0)
//             allowed_entry_count++;
//         spin_unlock(&allowed_lock);
//         pr_info("added queued ip %pI4 with %d ports", &ent->ip, ent->port_count);
//     }
//
//     /* print entries in allowed_table for inspection */
//     struct rhashtable_iter iter;
//     struct allowed_entry *ent;
//
//     pr_info("________________INSPECT_________________\nInformation added in "
//             "memory:");
//     rhashtable_walk_enter(&allowed_table, &iter);
//     while ((ent = rhashtable_walk_next(&iter)) != NULL) {
//         int j;
//         pr_info("IP: %pI4 ports:", &ent->ip);
//         if (ent->port_count == 0) {
//             pr_info("  any");
//         } else {
//             for (j = 0; j < ent->port_count; j++)
//                 pr_info("  %u", ent->ports[j]);
//         }
//     }
//     rhashtable_walk_exit(&iter);
//
//     filp_close(filp, NULL);
//     pr_info("Loaded allowed table entries\n");
//     return 0;
// }

/**
 * Read config file from disk
 * @return: number of bytes read on success (>=0), negative error on failure
 */
// static ssize_t load_config_from_file(void) {
//     struct file *filp;
//     loff_t pos = 0;
//     ssize_t bytes;
//     char *line, *end;
//     unsigned int a, b, c, d;
//     u16 parsed_port;
//
//     /* Open the file; If the file is not present, create it.  */
//     // filp = filp_open(CONFIG_FILE_PATH, O_RDWR | O_CREAT, 0666);
//     filp = filp_open(CONFIG_FILE_PATH, O_RDONLY, 0);
//
//     if (IS_ERR(filp)) {
//         pr_err("Failed to open or create config file: -%s- (%ld)\n", CONFIG_FILE_PATH, PTR_ERR(filp));
//         return PTR_ERR(filp);
//     }
//
//     /* Read up to CONFIG_BUF_SIZE-1 so we can NUL-terminate */
//     bytes = kernel_read(filp, config_buf, CONFIG_BUF_SIZE - 1, &pos);
//     if (bytes < 0) {
//         pr_err("Failed to read config file: %zd\n", bytes);
//         filp_close(filp, NULL);
//         return bytes;
//     }
//
//     config_buf[bytes] = '\0';
//     pr_info("Config loaded -%s-(%zd bytes):\n%s", CONFIG_FILE_PATH, bytes, config_buf);
//
//     // Reset allowed_file_path.
//     strcpy(allowed_file_path, "\0");
//
//     // Clear already saved information.
//     free_packet_list();
//
//     // Parse config lines
//     line = config_buf;
//     while ((end = strstr(line, "\n")) != NULL) {
//         *end = '\0';
//         if (sscanf(line, "server IP %u.%u.%u.%u", &a, &b, &c, &d) == 4) {
//
//             mutex_lock(&client_server_info_mutex);
//             server_ip = htonl((a << 24) | (b << 16) | (c << 8) | d);
//             pr_info("Parsed server IP: %pI4\n", &server_ip);
//             mutex_unlock(&client_server_info_mutex);
//         } else if (sscanf(line, "server port %hu", &parsed_port) == 1) {
//             mutex_lock(&client_server_info_mutex);
//             server_port = parsed_port;
//             mutex_unlock(&client_server_info_mutex);
//         } else if (strcmp(line, "Listening") == 0) {
//             state = LISTENING;
//         } else if (strcmp(line, "Monitoring") == 0) {
//             state = MONITORING;
//         } else if (strcmp(line, "Reactive") == 0) {
//             state = REACTIVE;
//         } else if (strcmp(line, "Disabled") == 0) {
//             state = DISABLED;
//         } else if (sscanf(line, "allowed_file %255s", allowed_file_path) == 1) {
//             // Ensure null termination
//             allowed_file_path[CONFIG_BUF_SIZE - 1] = '\0';
//         }
//         line = end + 1;
//     }
//
//     /* Update last_mtime_config_file on successful read */
//     last_mtime_config_file = inode_get_mtime(filp->f_inode);
//     // last_mtime_config_file = filp->f_inode->i_mtime;
//
//     filp_close(filp, NULL);
//     return bytes;
// }

// ========================================================
// Section for loading weights for anomaly detection
// ========================================================

// static int load_model_binary(void) {
//     struct file *filp;
//     loff_t pos = 0;
//     int i, j;
//     u32 num_features, num_vectors;
//     union {
//         u8 bytes[8];
//         s64 as_s64;
//     } converter;
//
//     filp = filp_open(model_bin_path, O_RDONLY, 0);
//     if (IS_ERR(filp))
//         return -1;
//
//     kernel_read(filp, &num_features, sizeof(u32), &pos);
//     if (num_features != NUM_FEATURES) {
//         filp_close(filp, NULL);
//         return -1;
//     }
//
//     /* Read scaler means (8 bytes, interpret as double) */
//     for (i = 0; i < NUM_FEATURES; i++) {
//         kernel_read(filp, converter.bytes, 8, &pos);
//         svm_model.scaler_mean[i] = converter.as_s64;
//     }
//
//     for (i = 0; i < NUM_FEATURES; i++) {
//         kernel_read(filp, converter.bytes, 8, &pos);
//         svm_model.scaler_std[i] = converter.as_s64;
//     }
//
//     kernel_read(filp, converter.bytes, 8, &pos);
//     svm_model.offset = converter.as_s64;
//
//     kernel_read(filp, &num_vectors, sizeof(u32), &pos);
//     if (num_vectors > MAX_SUPPORT_VECTORS) {
//         filp_close(filp, NULL);
//         return -1;
//     }
//
//     svm_model.num_support_vectors = num_vectors;
//
//     for (i = 0; i < num_vectors; i++) {
//         for (j = 0; j < NUM_FEATURES; j++) {
//             kernel_read(filp, converter.bytes, 8, &pos);
//             svm_model.support_vectors[i][j] = converter.as_s64;
//         }
//     }
//
//     for (i = 0; i < num_vectors; i++) {
//         kernel_read(filp, converter.bytes, 8, &pos);
//         svm_model.dual_coefficients[i] = converter.as_s64;
//     }
//
//     filp_close(filp, NULL);
//     pr_info("SVM Model loaded: %d support vectors\n", num_vectors);
//     return 0;
// }

/* Better exp approximation using Taylor series */
static s64 exp_approx_fixed(s64 x_unscaled) {
    /* Input: unscaled exponent (e.g., -0.5, -2, -5)
       Output: scaled result (e.g., 0.6*SCALE, 0.13*SCALE, 0.0067*SCALE) */

    if (x_unscaled >= 0) {
        return SCALE; /* e^0 = 1.0 */
    }
    if (x_unscaled < -10) {
        return 0; /* e^-10 ≈ 0 */
    }

    /* Approximate: e^x ≈ 1 / (1 - x + x²/2) for small x */
    s64 x2 = (x_unscaled * x_unscaled) / 2;
    s64 denom = SCALE - (x_unscaled * SCALE) + x2;

    if (denom <= 0) {
        return 0;
    }

    return (u64)SCALE * SCALE / denom;
}

static s64 rbf_kernel_fixed(s64 *x1, s64 *x2, s64 gamma) {
    s64 dist = 0;
    int i;
    for (i = 0; i < NUM_FEATURES; i++) {
        s64 diff = (x1[i] - x2[i]) / SCALE;
        dist += (diff * diff);
    }
    /* Pass unscaled exponent: -gamma * dist / SCALE */
    s64 exponent = -(gamma / SCALE) * dist; /* This is unscaled now */
    return exp_approx_fixed(exponent);
}

static int predict_anomaly(int sport, int dport, int protocol, int ttl, int total_len, int tcp_flags) {
    s64 features[NUM_FEATURES];
    s64 decision = 0;
    int i;
    s64 gamma = SCALE / NUM_FEATURES; /* Scaled gamma */

    /* Normalize: (x - mean) / std, then scale */
    features[0] = ((((s64)sport * SCALE) - svm_model.scaler_mean[0]) / svm_model.scaler_std[0]) * SCALE;
    features[1] = ((((s64)dport * SCALE) - svm_model.scaler_mean[1]) / svm_model.scaler_std[1]) * SCALE;
    features[2] = ((((s64)protocol * SCALE) - svm_model.scaler_mean[2]) / svm_model.scaler_std[2]) * SCALE;
    features[3] = ((((s64)ttl * SCALE) - svm_model.scaler_mean[3]) / svm_model.scaler_std[3]) * SCALE;
    features[4] = ((((s64)total_len * SCALE) - svm_model.scaler_mean[4]) / svm_model.scaler_std[4]) * SCALE;
    features[5] = ((((s64)tcp_flags * SCALE) - svm_model.scaler_mean[5]) / svm_model.scaler_std[5]) * SCALE;

    spin_lock(&svm_model_lock);

    if (!svm_model.loaded || svm_model.num_support_vectors == 0) {
        spin_unlock(&svm_model_lock);
        return 1;
    }

    for (i = 0; i < svm_model.num_support_vectors; i++) {
        s64 kernel_val = rbf_kernel_fixed(features, svm_model.support_vectors[i], gamma);
        decision += (svm_model.dual_coefficients[i] * kernel_val) / SCALE;
    }

    decision += svm_model.offset;
    spin_unlock(&svm_model_lock);

    return (decision < 0) ? -1 : 1;
}
// ========================================================

/** Workque for safer repetitive reading from a file. */
// static void config_work_func(struct work_struct *work);
// static DECLARE_WORK(config_work, config_work_func);

// static void config_timer_callback(struct timer_list *unused) {
//     schedule_work(&config_work); // defer to process context
//     mod_timer(&config_timer, jiffies + msecs_to_jiffies(CONFIG_POLL_INTERVAL_MS));
// }

// static void restart_client_thread_if_needed(void);

// static void config_work_func(struct work_struct *work) {
//     struct file *filp;
//     struct timespec64 current_mtime_config_file;
//     struct timespec64 current_mtime_allowed_file;
//     ssize_t ret;
//
//     bool update_allowed_file = false;
//
//     // ____________________________________________
//     // Check config file last modification.
//     filp = filp_open(CONFIG_FILE_PATH, O_RDONLY, 0);
//     if (IS_ERR(filp)) {
//         pr_err("Failed to open config file: %s (%ld)\n", CONFIG_FILE_PATH, PTR_ERR(filp));
//         return;
//     }
//
//     // Kernel version diff.
//     current_mtime_config_file = inode_get_mtime(file_inode(filp));
//     // current_mtime_config_file = file_inode(filp)->i_mtime;
//     filp_close(filp, NULL);
//
//     if (timespec64_compare(&current_mtime_config_file, &last_mtime_config_file) != 0) {
//         pr_info("Config file modification detected, reloading...\n");
//         ret = load_config_from_file();
//         pr_info("Config file modification response: %ld\n", ret);
//         if (ret >= 0) {
//             last_mtime_config_file = current_mtime_config_file;
//
//             restart_client_thread_if_needed();
//
//             update_allowed_file = true;
//         }
//     }
//
//     // ____________________________________________
//     if (allowed_file_path[0] == '\0') {
//         return;
//     }
//
//     filp = filp_open(allowed_file_path, O_RDWR | O_CREAT, 0644);
//
//     if (IS_ERR(filp)) {
//         pr_err("Failed to open allowed file: %256s (%ld)\n", allowed_file_path, PTR_ERR(filp));
//         return;
//     }
//
//     // Kernel version diff.
//     current_mtime_allowed_file = inode_get_mtime(file_inode(filp));
//     // current_mtime_allowed_file = file_inode(filp)->i_mtime;
//     filp_close(filp, NULL);
//
//     if (timespec64_compare(&current_mtime_allowed_file, &last_mtime_allowed_file) != 0) {
//         pr_info("Config allowed modification detected, reloading...\n");
//         update_allowed_file = true;
//     }
//
//     if (update_allowed_file) {
//         ret = load_allowed_file();
//         if (ret >= 0) {
//             last_mtime_allowed_file = current_mtime_allowed_file;
//         }
//     }
//
//     // ____________________________________________
//     struct timespec64 current_mtime_model_file;
//
//     filp = filp_open(model_bin_path, O_RDONLY, 0);
//     if (!IS_ERR(filp)) {
//         current_mtime_model_file = inode_get_mtime(file_inode(filp));
//         filp_close(filp, NULL);
//
//         if (timespec64_compare(&current_mtime_model_file, &last_mtime_model_file) != 0) {
//             pr_info("Model file modification detected, reloading...\n");
//
//             spin_lock(&svm_model_lock);
//             if (load_model_binary() == 0) {
//                 svm_model.loaded = true;
//                 last_mtime_model_file = current_mtime_model_file;
//                 pr_info("Model reloaded successfully\n");
//             } else {
//                 pr_err("Failed to load model\n");
//             }
//             spin_unlock(&svm_model_lock);
//         }
//     }
// }

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
    // === Add copy to permanent history (debugfs) ===
    struct packet_info *history = kmalloc(sizeof(*history), GFP_ATOMIC);
    if (history) {
        memcpy(history, info, sizeof(*info)); // copy all fields
        INIT_LIST_HEAD(&history->list);       // independent node

        // TODO: This will dissapear later, I will not log it localy, only send it all to the server.
        spin_lock(&list_lock);
        list_add_tail(&history->list, &packet_list);
        spin_unlock(&list_lock);
    } else {
        pr_warn("Failed to allocate history copy – skipping local log\n");
    }

    // spin_lock(&list_lock);
    // list_add_tail(&info->list, &packet_list_sent);
    // spin_unlock(&list_lock);

    // Send the info via the tcp connection to the server.
    // wake_up_interruptible(&packet_wq);
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

    mutex_lock(&client_server_info_mutex);
    const __be32 copy_server_ip = server_ip;
    const u16 copy_server_port = server_port;
    mutex_unlock(&client_server_info_mutex);

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

    /* In REACTIVE mode, only allow packets with daddr in allowed_ips
     and from the list of allowed ports.
     In the packet list will be packets that are also packets that are
     not blocked; it will be a filtering before printing it.*/
    if (local_state == REACTIVE || local_state == LISTENING) {
        bool should_drop = true;
        /* Check if source IP is known in allowed table */
        bool allowed_ip = ip_is_in_allowed_table(ip->saddr);

        /* If the IP is known, check whether the destination port is allowed
         * (use host-order port for comparison). If the entry has port_count==0,
         * it means any port is allowed for that IP.
         */
        bool allowed_port = false;
        if (ip->protocol == IPPROTO_TCP || ip->protocol == IPPROTO_UDP) {
            u16 dport_host = ntohs(info->dport);
            allowed_port = ip_allows_port(ip->saddr, dport_host);
        }

        if (allowed_ip && allowed_port) {
            should_drop = false;
        }

        if (should_drop && svm_model.loaded) {
            int prediction = predict_anomaly(ntohs(info->sport), ntohs(info->dport), info->protocol, info->ttl,
                                             info->total_len, info->tcp_flags);
            const int is_anomaly = (prediction == -1) ? 1 : 0;

            if (is_anomaly) {
                pr_info("ANOMALY: SRC=%pI4 DPORT=%u\n", &info->saddr, ntohs(info->dport));
                should_drop = false;
            }
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

/* Debugfs packet log read */
static int dbg_show(struct seq_file *m, void *v) {
    struct packet_info *info;
    struct logged_packet *lp;
    struct logged_packet_key key = {0};
    struct logged_packet *existing;

    // Initialize logged_table at the start of dbg_show.
    if (rhashtable_init(&logged_table, &logged_params)) {
        pr_err("Failed to initialize logged_table in dbg_show\n");
        return -ENOMEM; // Return error to indicate failure
    }

    spin_lock(&list_lock);
    list_for_each_entry(info, &packet_list, list) {
        if (!(should_log_packet(info))) {
            continue;
        }

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
        if (!existing && !(copy_server_ip == 0 && copy_server_port == 0 && info->daddr == copy_server_ip)) {
            seq_printf(m,
                       "PROTO=%u TTL=%u LEN=%u IFACE=%s\n"
                       "SRC=%pI4 SPORT=%u DST=%pI4 DPORT=%u\n"
                       "SRC_MAC=%pM DST_MAC=%pM TCP_FLAGS=%02x\n\n",
                       info->protocol, info->ttl, info->total_len, info->indev, &info->saddr, ntohs(info->sport),
                       &info->daddr, ntohs(info->dport), info->src_mac, info->dst_mac, info->tcp_flags);

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
// static ssize_t cfg_read(struct file *file, char __user *buf, size_t count, loff_t *ppos) {
//     ssize_t ret;
//
//     /* reload into global config_buf */
//     ret = load_config_from_file();
//     if (ret < 0)
//         return ret;
//
//     /* present the buffer to userspace via seq-like simple helper */
//     return simple_read_from_buffer(buf, count, ppos, config_buf, strlen(config_buf));
// }

// static const struct file_operations cfg_fops = {
//     .owner = THIS_MODULE,
//     .read = cfg_read,
// };

// ====================================================================================
// static int tcp_client_send(struct socket *sock, const char *buf, size_t len, unsigned long flags) {
//     struct msghdr msg = {
//         .msg_name = NULL, .msg_namelen = 0, .msg_control = NULL, .msg_controllen = 0, .msg_flags = flags};
//     struct kvec vec;
//     int written = 0;
//     int left = len;
//     int ret;
//
//     while (left > 0) {
//         vec.iov_base = (void *)(buf + written);
//         vec.iov_len = left;
//
//         ret = kernel_sendmsg(sock, &msg, &vec, 1, left);
//         if (ret < 0) {
//             if (ret == -ERESTARTSYS || (flags & MSG_DONTWAIT && ret == -EAGAIN))
//                 continue; // retry on signal or would-block
//             pr_err("send failed: %d\n", ret);
//             return ret;
//         }
//
//         written += ret;
//         left -= ret;
//     }
//
//     return written;
// }

// TODO: Not used rn
//  static int tcp_client_receive(struct socket *sock, char *buf, size_t max_len,
//                                unsigned long flags) {
//      struct msghdr msg = {.msg_name = NULL,
//                           .msg_namelen = 0,
//                           .msg_control = NULL,
//                           .msg_controllen = 0,
//                           .msg_flags = flags};
//      struct kvec vec;
//      int ret;
//
//      vec.iov_base = buf;
//      vec.iov_len = max_len;
//
//      ret = kernel_recvmsg(sock, &msg, &vec, 1, max_len, flags);
//      if (ret < 0) {
//          if (ret == -EAGAIN || ret == -ERESTARTSYS)
//              return -EAGAIN; // caller can retry
//          pr_err("recv failed: %d\n", ret);
//          return ret;
//      }
//
//      if (ret < max_len)
//          buf[ret] = '\0'; // null-terminate if string
//
//      return ret;
//  }

// static int tcp_client_thread(void *arg) {
//     mutex_lock(&client_server_info_mutex);
//     const __be32 copy_server_ip = server_ip;
//     const u16 copy_server_port = server_port;
//     mutex_unlock(&client_server_info_mutex);
//
//     if (copy_server_ip == 0 || copy_server_port == 0) {
//         atomic_set(&client_running, 0);
//         return -1;
//     }
//     struct sockaddr_in saddr;
//     int ret;
//
//     allow_signal(SIGTERM); // optional: allow kthread_stop to interrupt us
//
//     pr_info("client thread started\n");
//
//     ret = sock_create(PF_INET, SOCK_STREAM, IPPROTO_TCP, &conn_socket);
//     if (ret < 0) {
//         pr_err("sock_create failed: %d\n", ret);
//         goto out;
//     }
//
//     memset(&saddr, 0, sizeof(saddr));
//     saddr.sin_family = AF_INET;
//     saddr.sin_port = htons(copy_server_port);
//     saddr.sin_addr.s_addr = copy_server_ip;
//
//     conn_socket->sk->sk_rcvtimeo = msecs_to_jiffies(6000);
//     conn_socket->sk->sk_sndtimeo = msecs_to_jiffies(6000);
//
//     ret = conn_socket->ops->connect(conn_socket, (struct sockaddr *)&saddr, sizeof(saddr), 0);
//
//     if (ret && ret != -EINPROGRESS) {
//         pr_err("connect failed immediately: %d\n", ret);
//         goto out_sock;
//     }
//
//     if (ret == -EINPROGRESS) {
//         long timeout;
//
//         timeout = wait_event_interruptible_timeout(conn_socket->sk->sk_wq->wait,
//                                                    conn_socket->sk->sk_state != TCP_SYN_SENT ||
//                                                    kthread_should_stop(), msecs_to_jiffies(3000));
//
//         if (kthread_should_stop()) {
//             pr_info("connect aborted due to thread stop\n");
//             goto out_sock;
//         }
//         if (timeout <= 0) {
//             pr_err("connect timeout\n");
//             goto out_sock;
//         }
//
//         if (conn_socket->sk->sk_state != TCP_ESTABLISHED) {
//             pr_err("connect failed, state=%d\n", conn_socket->sk->sk_state);
//             goto out_sock;
//         }
//     }
//
//     pr_info("connected to server\n");
//
//     // Main loop – example: send once, receive once, then idle/sleep
//     while (!kthread_should_stop()) {
//         // Wait until there's something to send or timeout
//         wait_event_interruptible_timeout(packet_wq, kthread_should_stop(), msecs_to_jiffies(5000));
//
//         if (kthread_should_stop())
//             break;
//
//         struct packet_info *info, *tmp;
//         LIST_HEAD(local_list);
//         char send_buf[SEND_BUF_SIZE];
//         int sent_count = 0;
//
//         // Grab everything currently in the list (no filtering)
//         spin_lock_bh(&list_lock);
//         list_splice_init(&packet_list_sent,
//                          &local_list); // atomic move of whole list
//         spin_unlock_bh(&list_lock);
//
//         // Send each one
//         list_for_each_entry_safe(info, tmp, &local_list, list) {
//             int len;
//
//             // Use scnprintf (safer than snprintf in kernel) — same format as in
//             // dbg_show
//             len = scnprintf(send_buf, sizeof(send_buf),
//                             "PROTO=%u TTL=%u LEN=%u IFACE=%s "
//                             "SRC=%pI4 SPORT=%u DST=%pI4 DPORT=%u "
//                             "SRC_MAC=%pM DST_MAC=%pM TCP_FLAGS=%02x\n",
//                             info->protocol, info->ttl, info->total_len, info->indev, &info->saddr,
//                             ntohs(info->sport), &info->daddr, ntohs(info->dport), info->src_mac, info->dst_mac,
//                             info->tcp_flags);
//
//             if (len <= 0 || len >= sizeof(send_buf)) {
//                 pr_warn("format buffer too small or error\n");
//                 list_del(&info->list);
//                 kfree(info);
//                 continue;
//             }
//
//             int sent = tcp_client_send(conn_socket, send_buf, len, 0);
//             if (sent == len) {
//                 sent_count++;
//                 list_del(&info->list);
//                 kfree(info);
//             } else {
//                 list_move_tail(&info->list, &packet_list_sent);
//                 pr_warn("send failed (%d/%d bytes), retry later\n", sent, len);
//                 // Optional: break;   // stop this batch if connection is broken
//             }
//         }
//
//         if (sent_count > 0)
//             pr_info("tcp-client: sent %d packet log entries\n", sent_count);
//     }
//
// out_sock:
//     if (conn_socket)
//         sock_release(conn_socket);
//     conn_socket = NULL;
//
// out:
//     atomic_set(&client_running, 0);
//     pr_info("client thread exiting\n");
//     return 0;
// }

// static void restart_client_thread_if_needed(void) {
//     mutex_lock(&client_server_info_mutex);
//     const __be32 copy_server_ip = server_ip;
//     const u16 copy_server_port = server_port;
//
//     if (copy_server_ip == prev_server_ip && copy_server_port == prev_server_port) {
//         mutex_unlock(&client_server_info_mutex);
//         return;
//     }
//
//     pr_info("Server config changed → restarting client thread\n");
//
//     prev_server_ip = copy_server_ip;
//     prev_server_port = copy_server_port;
//
//     mutex_unlock(&client_server_info_mutex);
//     /* Stop old thread */
//     mutex_lock(&client_thread_mutex);
//     if (atomic_read(&client_running)) {
//         kthread_stop(client_thread);
//         atomic_set(&client_running, 0);
//     }
//
//     /* Start new thread ONLY if config is valid */
//     if (copy_server_ip != 0 && copy_server_port != 0) {
//         client_thread = kthread_run(tcp_client_thread, NULL, "tcp-client");
//         if (IS_ERR(client_thread)) {
//             pr_err("Failed to restart client thread: %ld\n", PTR_ERR(client_thread));
//             atomic_set(&client_running, 0);
//         } else {
//             atomic_set(&client_running, 1);
//             pr_info("Client thread restarted\n");
//         }
//     }
//     mutex_unlock(&client_thread_mutex);
// }

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
        WRITE_ONCE(state, new_state); // ← Forces write to memory
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

        // restart_client_thread_if_needed();
        return 0;
    }

    case IOCTL_ADD_WHITELIST: {
        pr_info("[OK] DAEMON requests a new pc to be added in the ruling.\n");
        struct allowed_entry_ioctl entry;
        struct allowed_entry *ent;

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

        spin_lock(&allowed_lock);
        rhashtable_insert_fast(&allowed_table, &ent->node, allowed_params);
        spin_unlock(&allowed_lock);

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

        spin_lock(&list_lock);
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
        spin_unlock(&list_lock);

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
    spin_lock_init(&list_lock);
    spin_lock_init(&logged_lock);

    /* initialize allowed_table */
    if (rhashtable_init(&allowed_table, &allowed_params)) {
        pr_warn("Failed to initialize allowed_table\n");
    }

    // Initialise timer var for detection model bin file.
    last_mtime_model_file.tv_sec = 0;
    last_mtime_model_file.tv_nsec = 0;

    // Initialise the char[] so it can be checked if something was added.
    // strcpy(allowed_file_path, "\0");

    netfilter_ops.hook = packet_hook;
    netfilter_ops.pf = PF_INET;
    // netfilter_ops.hooknum = NF_INET_PRE_ROUTING;
    netfilter_ops.hooknum = NF_INET_LOCAL_IN;
    netfilter_ops.priority = NF_IP_PRI_FIRST;

    nf_register_net_hook(&init_net, &netfilter_ops);

    dbg_file = debugfs_create_file("packet_logs", 0444, NULL, NULL, &dbg_fops);

    /* Setup timer for periodic modification checks */
    // timer_setup(&config_timer, config_timer_callback, 0);
    // mod_timer(&config_timer, jiffies + msecs_to_jiffies(CONFIG_POLL_INTERVAL_MS));
    /* Register ioctl device */

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
    misc_deregister(&mymodule_device);
    nf_unregister_net_hook(&init_net, &netfilter_ops);
    debugfs_remove(dbg_file);
    // del_timer_sync(&config_timer);
    // cancel_work_sync(&config_work);
    free_packet_list();
    // free_packet_list_sent();

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
MODULE_DESCRIPTION("Netfilter Module with Config Reload from Disk and Modification Detection");
