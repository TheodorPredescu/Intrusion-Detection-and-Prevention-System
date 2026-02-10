#!/bin/bash

g++ $1     imgui/*.cpp     imgui/backends/imgui_impl_glfw.cpp     imgui/backends/imgui_impl_opengl3.cpp     -Iimgui -Iimgui/backends     -lglfw -lGL -lssh     -o application 
