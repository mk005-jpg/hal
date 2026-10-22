cmake_minimum_required(VERSION 3.22)
project(cam_hook)

set(CMAKE_CXX_STANDARD 17)

# Build as a shared library injected into cameraserver via ptrace.
add_library(cam_hook SHARED
    libcam_hook.cpp
    inline_hook.cpp
)

target_compile_options(cam_hook PRIVATE
    -O2
    -fvisibility=hidden       # hide all symbols except __attribute__((visibility("default")))
    -fno-stack-protector      # avoid __stack_chk_guard PLT dependency
)

target_link_libraries(cam_hook log)

# No .so versioning suffix — push as libcam_hook.so directly
set_target_properties(cam_hook PROPERTIES
    OUTPUT_NAME "cam_hook"
    PREFIX      "lib"
    SUFFIX      ".so"
)
