#ifndef TYPES_H
#define TYPES_H

#include <GL/gl.h>
#include <map>
#include <set>
#include <string>

// States available.
#define LISTENING 0
#define MONITORING 1
#define REACTIVE 2
#define DISABLED 3
#define NO_STATE 255

enum class Page { MainPage, Topology, ClientDetail };

struct MessageReceived {
    std::string pc_id;
    std::string timestamp;
    std::string src_ip;
    std::string dst_ip;
    int src_port;
    int dst_port;
    int protocol;
    int mode;
};

/**
 * The `current_mode` will not be received via the API, but it will be searched and created from `config_file`, when it
 * is first received.
 */
struct PCInfo {
    std::string pc_id = "";
    std::string updated_at = "";
    std::string config_file = "";
    std::string allowed_file = "";

    /* This will not be received via the API, it will be created when its received.*/
    int current_mode = NO_STATE;

    GLuint icon_texture_id;
    std::string name = "";
};

struct ConnectionStats {
    std::set<int> ports_out;
    std::set<int> protocols;
    std::set<int> ttls;
    std::set<int> packet_lens;
    std::set<int> tcp_flags;
    std::set<int> ports_in;
    std::set<std::string> mac_addr;

    // TODO: Might not be necesary.
    /** Used in the topology_map to map a connection as displayed or not */
    bool is_visible = true;
};

struct TopologyEntry {
    // key: source ip; value: general information comming from that source
    std::map<std::string, ConnectionStats> connection_dict;
    // All the ips used by this pc.
    std::set<std::string> topology_ip;
};

inline constexpr const char *MODES[] = {"LISTENING", "MONITORING", "REACTIVE", "DISABLED"};
#endif
