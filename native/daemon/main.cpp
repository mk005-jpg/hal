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
//   → SET_IMAGE <path>   stage image, place it into the stream geometry
//   → PLACE <fit>        re-place the staged image with fit cover|contain|stretch
//   → START              arm injection, (re-)inject libcam_hook.so
//   → STOP               disarm injection
//   → STATUS             JSON status line
//   → BACK_NODE          current back-camera device node
// Response: "OK\n" | "ERROR <msg>\n" | "STATUS <json>\n"
//
// Frame placement is delegated to the `frameplace` tool (native/frameplace),
// which sizes frame.jpg / frame.nv21 to the exact stream geometry the hook
// publishes in geom.json and preserves aspect ratio (no more naive stretch).

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
#define FRAMEPLACE   "/data/local/tmp/hal_inject/frameplace"
#define STAGE_IMAGE  "/data/local/tmp/hal_inject/source.img"
#define GEOM_FILE    "/data/local/tmp/hal_inject/geom.json"
#define INJECT_DIR   "/data/local/tmp/hal_inject"

static std::atomic<bool>  g_inject_active{false};
static std::atomic<bool>  g_hook_loaded{false};
static std::atomic<bool>  g_fallback_running{false};
static std::string        g_image_path;
static std::string        g_fit = "cover";
static std::string        g_back_node;
static std::mutex         g_mu;
static std::mutex         g_injector_mu;   // serialises ptrace injection

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
    // Serialise: START and the BPF camera-open handler can both call this, and
    // two concurrent PTRACE_ATTACH on cameraserver would make one fail.
    std::lock_guard<std::mutex> lk(g_injector_mu);
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
            // V4L2 MMAP buffers hold raw frames, so feed the NV21 — writing the
            // JPEG here would drop compressed bytes into a raw YUV region.
            inject_frame_via_proc_mem(cam_pid, g_back_node, FRAME_NV21);
        }
        usleep(30000); // 30 ms ≈ 33 fps
    }
    g_fallback_running.store(false);
}

// ─── Frame placement (frameplace tool) ─────────────────────────────────────

// Copy src → dst without a shell (avoids metacharacter issues in paths).
static bool copy_file(const char *src, const char *dst) {
    int in = open(src, O_RDONLY);
    if (in < 0) return false;
    int out = open(dst, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (out < 0) { close(in); return false; }
    char buf[65536];
    ssize_t n;
    bool ok = true;
    while ((n = read(in, buf, sizeof(buf))) > 0) {
        ssize_t off = 0;
        while (off < n) {
            ssize_t w = write(out, buf + off, (size_t)(n - off));
            if (w <= 0) { ok = false; break; }
            off += w;
        }
        if (!ok) break;
    }
    if (n < 0) ok = false;
    close(in); close(out);
    return ok;
}

// Place the staged source image into the current stream geometry via the
// frameplace tool.  `fit` is cover|contain|stretch.  Falls back to a plain
// copy (legacy behaviour) if the frameplace binary isn't present.
static bool run_frameplace(const std::string &fit) {
    if (access(FRAMEPLACE, X_OK) != 0) {
        fprintf(stderr, "[daemon] frameplace missing — copying source verbatim\n");
        bool ok = copy_file(STAGE_IMAGE, FRAME_JPEG);
        return ok;
    }
    pid_t p = fork();
    if (p == 0) {
        const char *argv[] = {
            FRAMEPLACE, STAGE_IMAGE,
            "--geom", "auto",
            "--fit",  fit.c_str(),
            "--out-dir", INJECT_DIR,
            nullptr
        };
        execv(FRAMEPLACE, const_cast<char **>(argv));
        _exit(127);
    }
    if (p < 0) return false;
    int status;
    waitpid(p, &status, 0);
    bool ok = WIFEXITED(status) && WEXITSTATUS(status) == 0;
    fprintf(stderr, "[daemon] frameplace (fit=%s) %s\n",
            fit.c_str(), ok ? "ok" : "FAILED");
    return ok;
}

// The hook publishes the real stream geometry to geom.json only once frames
// start flowing — i.e. after START, which is after SET_IMAGE placed the frame
// at the default geometry.  START unlinks geom.json and launches this; when the
// hook writes a fresh one we re-place the staged image at the true geometry.
static void replace_on_geom_ready() {
    for (int i = 0; i < 40 && g_inject_active.load(); i++) {   // up to ~4 s
        struct stat stx;
        if (stat(GEOM_FILE, &stx) == 0 && stx.st_size > 0) {
            std::string fit;
            { std::lock_guard<std::mutex> lk(g_mu); fit = g_fit; }
            if (access(STAGE_IMAGE, R_OK) == 0) {
                fprintf(stderr, "[daemon] geom.json ready — re-placing at true geometry\n");
                run_frameplace(fit);
            }
            return;
        }
        usleep(100000); // 100 ms
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
        std::string fit;
        {
            std::lock_guard<std::mutex> lk(g_mu);
            g_image_path = path;
            fit = g_fit;
        }
        // Stage the source, then place it into the stream geometry with
        // aspect preserved (frameplace writes frame.jpg + frame.nv21).
        if (!copy_file(path.c_str(), STAGE_IMAGE)) {
            resp = "ERROR cannot read image\n";
        } else if (!run_frameplace(fit)) {
            resp = "ERROR frame placement failed\n";
        }

    } else if (cmd.size() >= 5 && cmd.substr(0, 5) == "PLACE") {
        // PLACE <fit>  — re-place the already-staged source with a new fit mode.
        std::string fit = (cmd.size() > 6) ? cmd.substr(6) : std::string("cover");
        if (fit != "cover" && fit != "contain" && fit != "stretch") {
            resp = "ERROR fit must be cover|contain|stretch\n";
        } else {
            { std::lock_guard<std::mutex> lk(g_mu); g_fit = fit; }
            if (access(STAGE_IMAGE, R_OK) != 0) {
                resp = "ERROR no staged image — SET_IMAGE first\n";
            } else if (!run_frameplace(fit)) {
                resp = "ERROR frame placement failed\n";
            }
        }

    } else if (cmd == "START") {
        write_ctrl("on");
        g_inject_active.store(true);
        // Force the hook to re-publish geometry for this session so the
        // reconcile below places the frame at the true stream dimensions.
        unlink(GEOM_FILE);
        // Try ptrace injection; if it fails, the fallback loop still runs
        run_injector();
        // Start the fallback /proc/mem writer thread once (guard against
        // duplicate threads if START is sent repeatedly without STOP).
        if (!g_fallback_running.exchange(true))
            std::thread(fallback_mem_writer_loop).detach();
        // Re-place at the real geometry as soon as the hook reports it.
        std::thread(replace_on_geom_ready).detach();
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
        std::string fit_now, img_now;
        { std::lock_guard<std::mutex> lk(g_mu); fit_now = g_fit; img_now = g_image_path; }
        oss << "STATUS {"
            << "\"active\":"    << (g_inject_active.load() ? "true" : "false") << ","
            << "\"hook_loaded\":" << (g_hook_loaded.load() ? "true" : "false") << ","
            << "\"back_node\":\"" << g_back_node << "\","
            << "\"image\":\""   << img_now << "\","
            << "\"fit\":\""     << fit_now << "\","
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
    // NOTE: ev.is_back_cam is unreliable — the BPF QUERYCAP front/back parse is
    // a stub that always reports 0, so gating on it (as the original code did)
    // meant re-injection never fired.  Re-inject on ANY /dev/video* open while
    // active instead; the hook self-gates by stream geometry.  A cooldown stops
    // repeated attaches when several processes open camera nodes at once.
    if (ev.ev_type == EV_OPEN) {
        if (!g_inject_active.load()) return;
        static std::atomic<uint64_t> last_ns{0};
        uint64_t now  = ev.ts_ns;
        uint64_t prev = last_ns.load();
        if (prev != 0 && now - prev < 1000000000ULL) return;  // 1 s cooldown
        last_ns.store(now);
        fprintf(stderr, "[bpf] camera opened pid=%u fd=%d (%s) — re-injecting\n",
                ev.pid, ev.fd, ev.comm);
        run_injector();
    } else if (ev.ev_type == EV_CLOSE) {
        fprintf(stderr, "[bpf] camera closed pid=%u fd=%d\n", ev.pid, ev.fd);
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
