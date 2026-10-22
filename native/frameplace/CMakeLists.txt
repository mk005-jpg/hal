cmake_minimum_required(VERSION 3.22)
project(frameplace)

set(CMAKE_CXX_STANDARD 17)

# Standalone device-side placement tool. Decode/scale/convert is delegated to
# ffmpeg at runtime (see build_push.sh prerequisites); this binary only builds
# the placement filter graph and execs ffmpeg with an argv array.
add_executable(frameplace frameplace.cpp)

target_compile_options(frameplace PRIVATE -O2)

target_link_libraries(frameplace log)
