#pragma once
#include <cstdint>
#include <functional>
#include <string>

#define EV_OPEN   1
#define EV_CLOSE  2
#define EV_IOCTL  3

struct CamEvent {
    uint64_t ts_ns;
    uint32_t pid;
    uint32_t tid;
    uint8_t  ev_type;
    uint8_t  is_back_cam;
    int16_t  fd;
    char     path[64];
    char     comm[16];
};

using CamEventCb = std::function<void(const CamEvent&)>;

class BpfLoader {
public:
    explicit BpfLoader(const std::string& bpf_obj_path);
    ~BpfLoader();

    // Load and attach all probes.  Returns false on error.
    bool load();

    // Mark a specific (pid, fd) as back camera (called from cam_detect after
    // userspace confirms facing via VIDIOC_QUERYCAP).
    bool markBackCam(uint32_t pid, int fd, bool is_back);

    // Start polling ring buffer.  Calls cb on each event.
    // Blocking — run in a thread.
    void poll(CamEventCb cb);

    // Signal poll() to return.
    void stop();

private:
    std::string obj_path_;
    int         obj_fd_   = -1;
    int         rb_fd_    = -1;
    int         map_cam_fd_ = -1;
    bool        running_  = false;
};
