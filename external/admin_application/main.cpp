#include "imgui/backends/imgui_impl_glfw.h"
#include "imgui/backends/imgui_impl_opengl3.h"
#include "imgui/imgui.h"

#include <GL/gl.h>
#include <GLFW/glfw3.h>

#include <libssh/libssh.h>
#include <libssh/sftp.h>

#include <curl/curl.h>
#include <fcntl.h>
#include <sys/stat.h>

#include <cctype>
#include <chrono>
#include <cmath>
#include <cstdio>
#include <cstring>
#include <thread>

#include "dashboard.h"
#include "host_detail.h"
#include "topology.h"
#include "types.h"
#include "utils.h"

static const double TARGET_FPS = 45.0;
static const double TARGET_FRAME_TIME = 1.0 / TARGET_FPS;

int main() {
    HostDetail pc_page = HostDetail();
    Dashboard main_page = Dashboard();
    Topology topology = Topology();

    glfwInit();
    GLFWwindow *wnd = glfwCreateWindow(1400, 900, "Network Inspection App", nullptr, nullptr);
    glfwMakeContextCurrent(wnd);

    IMGUI_CHECKVERSION();
    ImGui::CreateContext();
    ImGui::StyleColorsDark();
    ImGui_ImplGlfw_InitForOpenGL(wnd, true);
    ImGui_ImplOpenGL3_Init("#version 150");

    page = Page::MainPage;

    while (!glfwWindowShouldClose(wnd)) {
        const double frame_start = glfwGetTime();

        glfwPollEvents();
        ImGui_ImplOpenGL3_NewFrame();
        ImGui_ImplGlfw_NewFrame();
        ImGui::NewFrame();

        ImGuiWindowFlags flags = ImGuiWindowFlags_NoDecoration | ImGuiWindowFlags_NoMove | ImGuiWindowFlags_NoResize |
                                 ImGuiWindowFlags_NoBringToFrontOnFocus;

        ImGui::SetNextWindowPos(ImVec2(0, 0));
        ImGui::SetNextWindowSize(ImGui::GetIO().DisplaySize);

        ImGui::Begin("##root", nullptr, flags);

        // Create the main top buttons.
        if (ImGui::Button("Main page")) {
            page = Page::MainPage;
        }
        ImGui::SameLine();
        if (ImGui::Button("Network Topology")) {
            page = Page::Topology;
            topology.topology_reset = true;
        }

        ImGui::Separator();

        // Based on the button pressed, draw the content of the page.
        switch (page) {
            case Page::MainPage:
                main_page.draw(frame_start);
                break;
            case Page::Topology:
                topology.draw(frame_start);
                break;
            case Page::ClientDetail:
                pc_page.draw(frame_start);
                break;
        }

        ImGui::End();

        ImGui::Render();
        int dw, dh;
        glfwGetFramebufferSize(wnd, &dw, &dh);
        glViewport(0, 0, dw, dh);
        glClearColor(0.05f, 0.05f, 0.08f, 1.0f);
        glClear(GL_COLOR_BUFFER_BIT);
        ImGui_ImplOpenGL3_RenderDrawData(ImGui::GetDrawData());
        glfwSwapBuffers(wnd);

        // Make the fps cap at `target_fps`.
        const double frame_end = glfwGetTime();
        const double frame_duration = frame_end - frame_start;
        if (frame_duration < TARGET_FRAME_TIME) {
            std::this_thread::sleep_for(std::chrono::duration<double>(TARGET_FRAME_TIME - frame_duration));
        }
    }

    ImGui_ImplOpenGL3_Shutdown();
    ImGui_ImplGlfw_Shutdown();
    ImGui::DestroyContext();
    glfwDestroyWindow(wnd);
    glfwTerminate();
    return 0;
}
