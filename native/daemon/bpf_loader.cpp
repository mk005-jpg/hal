#include "bpf_loader.h"
#include <cstdio>
#include <cstring>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <errno.h>

#ifdef USE_BPF
#include <sys/syscall.h>
#include <linux/bpf.h>
#include <linux/perf_event.h>
#include <bpf/libbpf.h>
#endif

// libbpf-based loader — links against libbpf.a from Android NDK or sysroot.
// When USE_BPF is not defined, all methods are stubs (eBPF tracking disabled).

#ifdef USE_BPF

BpfLoader::BpfLoader(const std::string &path) : obj_path_(path) {}

BpfLoader::~BpfLoader() { stop(); }

bool BpfLoader::load() {
    struct bpf_object *obj = bpf_object__open(obj_path_.c_str());
    if (libbpf_get_error(obj)) {
        fprintf(stderr, "[bpf] bpf_object__open(%s) failed: %s\n",
                obj_path_.c_str(), strerror(errno));
        return false;
    }

    if (bpf_object__load(obj) != 0) {
        fprintf(stderr, "[bpf] bpf_object__load failed: %s\n", strerror(errno));
        bpf_object__close(obj);
        return false;
    }

    // Attach all SEC("tracepoint/...") programs
    struct bpf_program *prog;
    bpf_object__for_each_program(prog, obj) {
        struct bpf_link *link = bpf_program__attach(prog);
        if (libbpf_get_error(link)) {
            fprintf(stderr, "[bpf] attach failed for %s: %s\n",
                    bpf_program__name(prog), strerror(errno));
            // non-fatal: continue loading other probes
        } else {
            fprintf(stderr, "[bpf] attached: %s\n", bpf_program__name(prog));
        }
    }

    // Get ring buffer map fd
    struct bpf_map *rb_map = bpf_object__find_map_by_name(obj, "events");
    if (rb_map) rb_fd_ = bpf_map__fd(rb_map);

    // Get cam_fd_map fd for marking back/front
    struct bpf_map *cam_map = bpf_object__find_map_by_name(obj, "cam_fd_map");
    if (cam_map) map_cam_fd_ = bpf_map__fd(cam_map);

    obj_fd_ = 1; // mark loaded (we don't save the obj pointer here for simplicity)
    return (rb_fd_ >= 0);
}

// cam_fd_key must match the BPF struct
struct cam_fd_key { uint32_t pid; int32_t fd; };

bool BpfLoader::markBackCam(uint32_t pid, int fd, bool is_back) {
    if (map_cam_fd_ < 0) return false;
    struct cam_fd_key k = { .pid = pid, .fd = fd };
    uint8_t v = is_back ? 1 : 0;
    return bpf_map_update_elem(map_cam_fd_, &k, &v, BPF_ANY) == 0;
}

static int ring_buf_callback(void *ctx, void *data, size_t size) {
    auto *cb = reinterpret_cast<CamEventCb*>(ctx);
    if (size < sizeof(CamEvent)) return 0;
    (*cb)(*reinterpret_cast<CamEvent*>(data));
    return 0;
}

void BpfLoader::poll(CamEventCb cb) {
    if (rb_fd_ < 0) return;
    running_ = true;

    struct ring_buffer *rb = ring_buffer__new(rb_fd_, ring_buf_callback, &cb, nullptr);
    if (!rb) {
        fprintf(stderr, "[bpf] ring_buffer__new failed\n");
        return;
    }

    while (running_) {
        int ret = ring_buffer__poll(rb, 200 /* ms */);
        if (ret < 0 && errno != EINTR) {
            fprintf(stderr, "[bpf] ring_buffer__poll error: %s\n", strerror(errno));
            break;
        }
    }
    ring_buffer__free(rb);
}

void BpfLoader::stop() { running_ = false; }

#else  // !USE_BPF — stub implementations

BpfLoader::BpfLoader(const std::string &path) : obj_path_(path) {}
BpfLoader::~BpfLoader() {}
bool BpfLoader::load()                                    { return false; }
bool BpfLoader::markBackCam(uint32_t, int, bool)          { return false; }
void BpfLoader::poll(CamEventCb)                          {}
void BpfLoader::stop()                                    { running_ = false; }

#endif  // USE_BPF
