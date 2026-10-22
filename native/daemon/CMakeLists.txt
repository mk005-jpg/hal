cmake_minimum_required(VERSION 3.22)
project(hal_inject_daemon)

set(CMAKE_CXX_STANDARD 17)

# libbpf — optional; supply via -DLIBBPF_DIR=<path to arm64 static build>
if(NOT DEFINED LIBBPF_DIR)
    message(WARNING "LIBBPF_DIR not set — building without eBPF support")
    set(USE_BPF OFF)
else()
    set(USE_BPF ON)
    include_directories(${LIBBPF_DIR}/include)
    link_directories(${LIBBPF_DIR}/lib64)
endif()

add_executable(hal_inject_daemon
    main.cpp
    bpf_loader.cpp
    cam_detect.cpp
    cam_maps.cpp
    mem_writer.cpp
)

if(USE_BPF)
    target_compile_definitions(hal_inject_daemon PRIVATE USE_BPF=1)
    target_link_libraries(hal_inject_daemon bpf elf z)
endif()

target_link_libraries(hal_inject_daemon log)
