#ifndef PC_PAGE_H
#define PC_PAGE_H

#include "types.h"
#include <GL/gl.h>
#include <map>
#include <memory>
#include <string>
#include <vector>

class HostDetail {
  private:
    inline static const double REFRESH_INTERVAL = 5.0;

    double previous_time = -REFRESH_INTERVAL;

    PCInfo pc_selected_data;
    std::string last_pc_id = "";

    // Input field buffers
    char server_ip_buf[256] = "";
    char allowed_file_path_buf[512] = "";
    char server_port_buf[32] = "";
    char name_given_buf[256] = "";
    char icon_path_buf[512] = "";
    char icon_path_final[512] = "";
    char icon_path_buf_tmp[512] = "";
    GLuint selected_icon_texture_id = 0;
    GLuint selected_icon_texture_id_tmp = 0;

    bool request_update = false;

    // Tracked config changes
    // TODO: This might be better in a different form
    std::string changed_config_server_ip = "";
    std::string changed_config_server_port = "";
    int changed_config_mode = NO_STATE;
    std::string changed_config_allowed_file_path = "";
    bool changed_config_checker = false;

    // Tracked allowed file changes
    std::vector<std::string> changed_allowed_file;
    bool changed_allowed_file_checker = false;

    // Tracked general info changes
    std::string changed_general_name_given = "";
    bool changed_general_checker = false;

    std::vector<MessageReceived> *msg_history_vector = nullptr;
    std::unique_ptr<std::map<std::string, TopologyEntry>> msg_struct_info_map = nullptr;

    std::string config_before_training;
    std::string training_active_id;

    // Allowed list edit state
    int edit_idx = -1;
    char edit_line_buf[512] = "";
    std::vector<std::string> allowed_lines;
    bool discard_allowed_changes = false;

    void reset_config_modifications();
    void reset_allowed_modifications();
    void reset_general_user_info();
    void reset_modifications();

    std::string create_config_info_string();
    void update_new_frame(bool force_update);

  public:
    HostDetail() = default;

    int draw(const double &current_time);
};

#endif
