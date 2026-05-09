MAKEFLAGS += -j12

CXX = g++
CXXFLAGS = -std=c++17 -Wall -g -I. -Iimgui -Iimgui/backends 
# CXXFLAGS = -std=c++17 -Wall -g -I. -Iimgui -Iimgui/backends -I./imgui-node-editor
LIBS = -lglfw -lGL -lssh -lsqlite3 -lpthread -ldl -lcurl -lstdc++fs

SRC = main.cpp \
      $(wildcard imgui/*.cpp) \
      imgui/backends/imgui_impl_glfw.cpp \
      imgui/backends/imgui_impl_opengl3.cpp \
	  utils.cpp \
	  dashboard.cpp \
	  host_detail.cpp \
	  topology.cpp

OBJ = $(SRC:.cpp=.o) 

application: $(OBJ)
	$(CXX) $(OBJ) $(LIBS) -o application
	rm -f $(OBJ)

%.o: %.cpp
	$(CXX) $(CXXFLAGS) -c $< -o $@
