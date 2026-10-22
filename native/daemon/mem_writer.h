#pragma once
#include <stdint.h>
#include <stddef.h>
#include <sys/types.h>
#include <string>
#include <vector>
#include "cam_maps.h"

// Frida-free fallback injection:
// Open /proc/<pid>/mem and overwrite camera buffer regions with the
// supplied frame data.  Must be called as root (CAP_SYS_PTRACE required).
//
// Returns the number of regions successfully written (0 = nothing written).
int write_frame_to_proc_mem(pid_t pid,
                             const std::vector<MapRegion> &regions,
                             const void *frame_data, size_t frame_len);

// Convenience: load frame file, find regions for back_dev_node in pid's
// maps, and write the frame to every matching region.
// jpeg_path: JPEG or NV21 file on device.
// Returns number of regions written.
int inject_frame_via_proc_mem(pid_t pid, const std::string &back_dev_node,
                               const std::string &jpeg_path);
