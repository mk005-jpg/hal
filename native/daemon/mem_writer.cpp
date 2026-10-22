#include "mem_writer.h"
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <stdio.h>
#include <string.h>
#include <algorithm>

int write_frame_to_proc_mem(pid_t pid,
                             const std::vector<MapRegion> &regions,
                             const void *frame_data, size_t frame_len) {
    if (regions.empty() || !frame_data || frame_len == 0) return 0;

    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/mem", (int)pid);
    int fd = open(path, O_WRONLY);
    if (fd < 0) {
        perror("[mem_writer] open /proc/pid/mem");
        return 0;
    }

    int written = 0;
    for (const auto &r : regions) {
        size_t write_len = std::min(frame_len, r.length);
        ssize_t n = pwrite64(fd, frame_data, write_len, (off64_t)r.vaddr);
        if (n == (ssize_t)write_len) {
            ++written;
        } else {
            fprintf(stderr, "[mem_writer] pwrite64 to 0x%lx failed: %zd\n",
                    (unsigned long)r.vaddr, n);
        }
    }
    close(fd);
    return written;
}

int inject_frame_via_proc_mem(pid_t pid, const std::string &back_dev_node,
                               const std::string &jpeg_path) {
    // Find the device node substring to search for in maps
    // back_dev_node might be "/dev/video0" → search "video0"
    const char *dev_substr = strrchr(back_dev_node.c_str(), '/');
    dev_substr = dev_substr ? dev_substr + 1 : back_dev_node.c_str();

    auto regions = find_cam_regions(pid, dev_substr);
    if (regions.empty()) {
        // Fallback: search for any video device
        regions = find_cam_regions(pid, "video");
    }
    if (regions.empty()) return 0;

    // Load frame file
    int sfd = open(jpeg_path.c_str(), O_RDONLY);
    if (sfd < 0) return 0;
    struct stat st;
    if (fstat(sfd, &st) != 0 || st.st_size == 0) { close(sfd); return 0; }

    void *data = mmap(NULL, (size_t)st.st_size, PROT_READ, MAP_PRIVATE, sfd, 0);
    close(sfd);
    if (data == MAP_FAILED) return 0;

    int r = write_frame_to_proc_mem(pid, regions, data, (size_t)st.st_size);
    munmap(data, (size_t)st.st_size);
    return r;
}
