cmake_minimum_required(VERSION 3.22)
project(cam_injector)

set(CMAKE_CXX_STANDARD 17)

add_executable(cam_injector cam_injector.cpp)

target_compile_options(cam_injector PRIVATE -O2)

# dl for dlsym/dlopen used to locate remote dlopen address
target_link_libraries(cam_injector dl log)
