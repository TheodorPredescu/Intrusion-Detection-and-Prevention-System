#ifndef TOPOLOGY_H
#define TOPOLOGY_H

#include "imgui/imgui.h"
#include "types.h"
#include <map>
#include <string>

class Topology {
  private:
    inline static const double REFRESH_INTERVAL = 7.0;

    double previous_time = -REFRESH_INTERVAL;
    std::map<std::string, PCInfo> *pc_map = nullptr;
    std::map<std::string, TopologyEntry> topology_data_map;
    std::map<std::string, ImVec2> node_positions;

  public:
    bool topology_reset = false;

    void draw(const double &current_time);
};

#endif
