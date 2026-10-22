#pragma once
#include <stdint.h>
#include <stddef.h>
#include <sys/types.h>
#include <vector>
#include <string>

// A single writable mmap region in a process's address space,
// backed by a camera device node (e.g. /dev/video0).
struct MapRegion {
    uintptr_t vaddr;    // start virtual address in the target process
    size_t    length;   // byte length of the region
    uint64_t  offset;   // file offset (V4L2 buffer slot identifier)
};

// Scan /proc/<pid>/maps and return all writable regions whose backing
// file name contains dev_node_substr (e.g. "video0").
// Suitable for the /proc/PID/mem fallback injection path.
std::vector<MapRegion> find_cam_regions(pid_t pid, const char *dev_node_substr);
