#ifndef MAIN_PAGE_H
#define MAIN_PAGE_H

#include "types.h"
#include <map>
#include <memory>
#include <string>
#include <vector>

class Dashboard {
  private:
    inline static const double REFRESH_INTERVAL = 5.0;

    double previous_time = -REFRESH_INTERVAL;
    float blink_time = 0.0f;
    bool is_context_menu_opened = false;
    bool training_activate = false;

    std::map<std::string, PCInfo> *pc_map = nullptr;
    std::vector<MessageReceived> *msg_history_vector = nullptr;
    std::string pc_context_menu_id_selected;
    // PCInfo const *pc_context_menu_selected = nullptr;

    std::unique_ptr<std::map<std::string, TopologyEntry>> training_topology_map = nullptr;
    std::map<std::string, int> training_pc_mode_before;

    void refresh_data();
    void ui_train_component();
    void draw_pc(const PCInfo &pc, const bool blink_visible);

  public:
    Dashboard() = default;

    void draw(const double &current_time);
};

#endif
