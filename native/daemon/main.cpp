// hal_inject_daemon — Frida-free camera injection daemon
// Runs as root on Pixel 7a.
//
// Injection chain (no Frida anywhere):
//   PRIMARY   — cam_injector ptrace-loads libcam_hook.so into cameraserver.
//               libcam_hook.so uses an inline arm64 hook on
//               Camera3OutputStream::returnBuffer to replace back-camera
//               gralloc dmabufs with the injected frame.
//   FALLBACK  — /proc/PID/mem direct write into V4L2-device-backed mmap regions.
//               Active on a 30 ms pulse; only works when the HAL uses V4L2 MMAP
//               buffers directly (uncommon on Pixel 7a but included for coverage).
//
// Unix socket protocol (line-based, AF_UNIX /data/local/tmp/hal_inject/daemon.sock):
//   → SET_IMAGE <path>   copy image, generate NV21
//   → START              arm injection, (re-)inject libcam_hook.so
//   → STOP               disarm injection
//   → STATUS             JSON status line
//   → BACK_NODE          current back-camera device node
// Response: "OK\n" | "ERROR <msg>\n" | "STATUS <json>\n"

#include "bpf_loader.h"
#include "cam_detect.h"
#include "cam_maps.h"
#include "mem_writer.h"

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <dirent.h>
#include <pthread.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <errno.h>
#include <thread>
#include <atomic>
#include <string>
#include <mutex>
#include <sstream>

#define SOCK_PATH    "/data/local/tmp/hal_inject/daemon.sock"
#define CTRL_FILE    "/data/local/tmp/hal_inject/ctrl"
#define STATS_FILE   "/data/local/tmp/hal_inject/stats.json"
#define FRAME_JPEG   "/data/local/tmp/hal_inject/frame.jpg"
#define FRAME_NV21   "/data/local/tmp/hal_inject/frame.nv21"
#define BPF_OBJ      "/data/local/tmp/hal_inject/cam_track.bpf.o"
#define CAM_INJECTOR "/data/local/tmp/hal_inject/cam_injector"
#define CAM_HOOK_SO  "/data/local/tmp/hal_inject/libcam_hook.so"

static std::atomic<bool>  g_inject_active{false};
static std::atomic<bool>  g_hook_loaded{false};
static std::string        g_image_path;
static std::string        g_back_node;
static std::mutex         g_mu;

// ─── ctrl file ────────────────────────────────────────────────────────────

static void write_ctrl(const char *val) {
    int fd = open(CTRL_FILE, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) return;
    write(fd, val, strlen(val));
    close(fd);
}

// ─── Find PID of a process by name ────────────────────────────────────────

static pid_t find_pid(const char *name) {
    DIR *d = opendir("/proc");
    if (!d) return -1;
    struct dirent *e;
    pid_t found = -1;
    while ((e = readdir(d)) && found == -1) {
        if (e->d_type != DT_DIR) continue;
        char *end; long n = strtol(e->d_name, &end, 10);
        if (*end) continue;
        char path[64]; snprintf(path, sizeof(path), "/proc/%ld/cmdline", n);
        int fd = open(path, O_RDONLY);
        if (fd < 0) continue;
        char buf[256] = {}; read(fd, buf, sizeof(buf) - 1); close(fd);
        const char *bn = strrchr(buf, '/'); bn = bn ? bn + 1 : buf;
        if (!strcmp(bn, name) || !strcmp(buf, name)) found = (pid_t)n;
    }
    closedir(d);
    return found;
}

// ─── PRIMARY: ptrace injection of libcam_hook.so ──────────────────────────

static bool run_injector() {
    // cam_injector cameraserver /data/local/tmp/hal_inject/libcam_hook.so
    pid_t p = fork();
    if (p == 0) {
        const char *argv[] = { CAM_INJECTOR, "cameraserver", CAM_HOOK_SO, nullptr };
        execv(CAM_INJECTOR, const_cast<char **>(argv));
        _exit(1);
    }
    if (p < 0) return false;
    int status;
    waitpid(p, &status, 0);
    bool ok = WIFEXITED(status) && WEXITSTATUS(status) == 0;
    g_hook_loaded.store(ok);
    fprintf(stderr, "[daemon] cam_injector %s\n", ok ? "succeeded" : "FAILED");
    return ok;
}

// ─── FALLBACK: periodic /proc/PID/mem write ───────────────────────────────

static void fallback_mem_writer_loop() {
    while (g_inject_active.load()) {
        pid_t cam_pid = find_pid("cameraserver");
        if (cam_pid > 0 && !g_back_node.empty()) {
            inject_frame_via_proc_mem(cam_pid, g_back_node, FRAME_JPEG);
        }
        usleep(30000); // 30 ms ≈ 33 fps
    }
}

// ─── Socket command handler ───────────────────────────────────────────────

static void handle_client(int cfd) {
    char line[512] = {};
    ssize_t n = recv(cfd, line, sizeof(line) - 1, 0);
    if (n <= 0) { close(cfd); return; }
    for (int i = 0; i < n; i++)
        if (line[i] == '\n' || line[i] == '\r') line[i] = 0;

    std::string cmd(line);
    std::string resp = "OK\n";

    if (cmd.size() > 10 && cmd.substr(0, 9) == "SET_IMAGE") {
        std::string path = cmd.substr(10);
        {
            std::lock_guard<std::mutex> lk(g_mu);
            g_image_path = path;
        }
        std::string cp = "cp \"" + path + "\" " + FRAME_JPEG + " 2>/dev/null";
        system(cp.c_str());
        // Generate NV21 for YUV stream injection
        std::string ff =
            "ffmpeg -y -i " FRAME_JPEG
            " -vf scale=1920:1080 -pix_fmt nv21 " FRAME_NV21
            " 2>/dev/null";
        system(ff.c_str());

    } else if (cmd == "START") {
        write_ctrl("on");
        g_inject_active.store(true);
        // Try ptrace injection; if it fails, the fallback loop still runs
        run_injector();
        // Start fallback /proc/mem writer thread
        std::thread(fallback_mem_writer_loop).detach();
        resp = "OK\n";

    } else if (cmd == "STOP") {
        write_ctrl("off");
        g_inject_active.store(false);
        g_hook_loaded.store(false);
        resp = "OK\n";

    } else if (cmd == "STATUS") {
        // Read frame counter from stats file written by libcam_hook.so
        char sbuf[256] = "{}";
        int sfd = open(STATS_FILE, O_RDONLY);
        if (sfd >= 0) { read(sfd, sbuf, sizeof(sbuf) - 1); close(sfd); }
        // Strip trailing newline
        for (char *p = sbuf; *p; p++) if (*p == '\n') *p = 0;

        std::ostringstream oss;
        oss << "STATUS {"
            << "\"active\":"    << (g_inject_active.load() ? "true" : "false") << ","
            << "\"hook_loaded\":" << (g_hook_loaded.load() ? "true" : "false") << ","
            << "\"back_node\":\"" << g_back_node << "\","
            << "\"image\":\""   << g_image_path << "\","
            << "\"stats\":"     << sbuf
            << "}\n";
        resp = oss.str();

    } else if (cmd == "BACK_NODE") {
        resp = g_back_node + "\n";

    } else {
        resp = "ERROR unknown command\n";
    }

    send(cfd, resp.c_str(), resp.size(), 0);
    close(cfd);
}

// ─── BPF event handler ────────────────────────────────────────────────────

static void bpf_event_handler(const CamEvent &ev) {
    if (ev.ev_type == EV_OPEN && ev.is_back_cam) {
        fprintf(stderr, "[bpf] back cam opened pid=%u fd=%d (%s)\n",
                ev.pid, ev.fd, ev.comm);
        // Re-inject on each camera open in case cameraserver restarted
        if (g_inject_active.load()) run_injector();
    } else if (ev.ev_type == EV_CLOSE && ev.is_back_cam) {
        fprintf(stderr, "[bpf] back cam closed pid=%u fd=%d\n", ev.pid, ev.fd);
    }
}

// ─── Main ─────────────────────────────────────────────────────────────────

int main(int /*argc*/, char ** /*argv*/) {
    if (getuid() != 0) {
        fprintf(stderr, "[daemon] must run as root\n");
        return 1;
    }

    mkdir("/data/local/tmp/hal_inject", 0755);
    write_ctrl("off");

    g_back_node = primaryBackCamNode();
    fprintf(stderr, "[daemon] back camera node: %s\n", g_back_node.c_str());

    // Load eBPF program (non-fatal; injection still works without BPF tracking)
    BpfLoader bpf(BPF_OBJ);
    bool bpf_ok = bpf.load();
    if (!bpf_ok)
        fprintf(stderr, "[daemon] eBPF load failed (continuing)\n");

    std::thread([&]() {
        if (bpf_ok) bpf.poll(bpf_event_handler);
    }).detach();

    // Unix socket server
    int srv = socket(AF_UNIX, SOCK_STREAM, 0);
    if (srv < 0) { perror("socket"); return 1; }

    struct sockaddr_un sa = {};
    sa.sun_family = AF_UNIX;
    strncpy(sa.sun_path, SOCK_PATH, sizeof(sa.sun_path) - 1);
    unlink(SOCK_PATH);
    if (bind(srv, (struct sockaddr *)&sa, sizeof(sa)) < 0) { perror("bind"); return 1; }
    chmod(SOCK_PATH, 0666);
    listen(srv, 8);

    fprintf(stderr, "[daemon] listening on %s\n", SOCK_PATH);
    fprintf(stderr, "[daemon] injection paths:\n"
                    "  primary  : ptrace cam_injector → libcam_hook.so\n"
                    "  fallback : /proc/PID/mem write @ 30 ms\n"
                    "  frida    : DISABLED (crashes KYC SDKs)\n");

    while (true) {
        int cfd = accept(srv, nullptr, nullptr);
        if (cfd < 0) continue;
        std::thread([cfd]() { handle_client(cfd); }).detach();
    }
    return 0;
}
