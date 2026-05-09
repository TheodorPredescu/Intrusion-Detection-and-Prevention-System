#!/bin/bash

#g++ admin_app.cpp   imgui/*.cpp     imgui/backends/imgui_impl_glfw.cpp     imgui/backends/imgui_impl_opengl3.cpp  database_handle.cpp  tcp_log_receiver.cpp -Iimgui -Iimgui/backends     -lglfw -lGL -lssh     -o application 
g++ -std=c++17 -Wall -g \
    admin_app.cpp \
    database_handle.cpp \
    tcp_log_receiver.cpp \
    imgui/*.cpp \
    imgui/backends/imgui_impl_glfw.cpp \
    imgui/backends/imgui_impl_opengl3.cpp \
    -I. -Iimgui -Iimgui/backends \
    -lglfw -lGL -lssh -lsqlite3 -lpthread -ldl \
    -lcurl -o application
