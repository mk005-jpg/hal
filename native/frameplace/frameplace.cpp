// frameplace — camera-frame placement tool (Frida-free HAL inject toolkit).
//
// Takes an arbitrary source image and "places" it into the exact geometry of
// the target camera stream, then emits the two frame files consumed by the
// injection chain:
//
//   <out>/frame.jpg   — placed JPEG, used for BLOB (still-capture) streams
//   <out>/frame.nv21  — placed NV21, used for YCbCr_420_888 / YV12 streams
//
// Why this exists
// ---------------
// The old pipeline stretch-scaled the source to a fixed resolution
// (ffmpeg `scale=1920:1080`, or Bitmap.createScaledBitmap(1280,720)).  A
// stretched face/document has the wrong aspect ratio — an obvious tell to a
// liveness/KYC check and a correctness bug.  frameplace preserves aspect with
// a chosen fit mode, honours the sensor orientation, and sizes the output to
// the geometry the camera stream actually uses (see `--geom auto`).
//
// The pixel work (decode / scale / pad / crop / rotate / colour convert) is
// delegated to ffmpeg, which build_push.sh already lists as a device
// dependency.  The value here is the placement math and a safe, shell-free
// ffmpeg invocation (argv array via execvp — the source path is never passed
// through a shell, so paths with spaces or metacharacters can't break out).
//
// Build:  native/frameplace/CMakeLists.txt → frameplace (arm64-v8a)
// Usage:  frameplace <src-image> [options]
//   --geom WxH        target stream geometry (default 1280x720)
//   --geom auto       read geometry from <out>/geom.json (written by the hook),
//                     falling back to the default if that file is absent
//   --fit MODE        cover | contain | stretch           (default cover)
//                       cover   scale to fill, crop the overflow (no bars)
//                       contain scale to fit, pad the remainder (--pad colour)
//                       stretch ignore aspect (legacy behaviour)
//   --pos POS         center|top|bottom|left|right         (default center)
//                     placement of the image within cover-crop / contain-pad
//   --pad RRGGBB      pad colour for contain mode           (default 000000)
//   --rotate DEG      0 | 90 | 180 | 270 clockwise          (default 0)
//   --flip MODE       none | h | v | hv                     (default none)
//   --jpeg-quality N  1..100 (maps to ffmpeg -q:v)          (default 92)
//   --out-dir DIR     output directory                      (default
//                     /data/local/tmp/hal_inject)
//   --ffmpeg PATH     ffmpeg binary                         (default: PATH)
//   --jpeg-only       emit frame.jpg only (skip NV21)
//   --nv21-only       emit frame.nv21 only (skip JPEG)
//   -v                verbose (print the ffmpeg argv)
//
// No Frida anywhere.

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/wait.h>

#define DEFAULT_OUT "/data/local/tmp/hal_inject"
#define DEFAULT_W   1280
#define DEFAULT_H   720

namespace {

enum class Fit { Cover, Contain, Stretch };

struct Options {
    std::string src;
    std::string out_dir   = DEFAULT_OUT;
    std::string ffmpeg     = "ffmpeg";
    std::string pos        = "center";
    std::string pad        = "000000";
    int         width      = DEFAULT_W;
    int         height     = DEFAULT_H;
    int         rotate     = 0;      // 0/90/180/270 clockwise
    std::string flip       = "none"; // none/h/v/hv
    int         quality    = 92;
    Fit         fit        = Fit::Cover;
    bool        want_jpeg  = true;
    bool        want_nv21  = true;
    bool        verbose    = false;
};

void usage(const char *argv0) {
    fprintf(stderr,
        "frameplace — place a source image into the camera-stream geometry\n"
        "Usage: %s <src-image> [options]\n"
        "  --geom WxH|auto   target geometry (auto = read <out>/geom.json)\n"
        "  --fit cover|contain|stretch   (default cover)\n"
        "  --pos center|top|bottom|left|right   (default center)\n"
        "  --pad RRGGBB      pad colour for contain   (default 000000)\n"
        "  --rotate 0|90|180|270   clockwise          (default 0)\n"
        "  --flip none|h|v|hv                         (default none)\n"
        "  --jpeg-quality N  1..100                   (default 92)\n"
        "  --out-dir DIR     (default %s)\n"
        "  --ffmpeg PATH     ffmpeg binary            (default: from PATH)\n"
        "  --jpeg-only | --nv21-only\n"
        "  -v                verbose\n",
        argv0, DEFAULT_OUT);
}

// Parse "WxH" (or "WXH") into width/height. Returns false on malformed input.
bool parse_geom(const char *s, int *w, int *h) {
    int tw = 0, th = 0;
    char sep = 0;
    if (sscanf(s, "%d%c%d", &tw, &sep, &th) != 3) return false;
    if ((sep != 'x' && sep != 'X') || tw <= 0 || th <= 0) return false;
    *w = tw; *h = th;
    return true;
}

// Minimal, dependency-free reader for the geometry the hook publishes:
//   {"width":1280,"height":720,"format":35}
// Only width/height are needed; a missing/garbled file leaves the defaults.
bool read_geom_json(const std::string &path, int *w, int *h) {
    int fd = open(path.c_str(), O_RDONLY);
    if (fd < 0) return false;
    char buf[256] = {};
    ssize_t n = read(fd, buf, sizeof(buf) - 1);
    close(fd);
    if (n <= 0) return false;

    auto grab = [&](const char *key, int *out) -> bool {
        const char *p = strstr(buf, key);
        if (!p) return false;
        p += strlen(key);
        while (*p == ' ' || *p == ':' || *p == '\t') p++;
        int v = atoi(p);
        if (v <= 0) return false;
        *out = v;
        return true;
    };
    int tw = 0, th = 0;
    if (grab("\"width\"", &tw) && grab("\"height\"", &th)) {
        *w = tw; *h = th;
        return true;
    }
    return false;
}

// Build the ffmpeg -vf filter graph implementing orientation + placement.
// Orientation (rotate/flip) is applied first so the fit stage always produces
// the final WxH; the fit stage then makes the frame exactly width×height.
std::string build_filter(const Options &o) {
    std::string vf;

    // ── Orientation ──────────────────────────────────────────────────────
    switch (o.rotate) {
        case 90:  vf += "transpose=1,";            break; // 90° clockwise
        case 180: vf += "transpose=1,transpose=1,"; break;
        case 270: vf += "transpose=2,";            break; // 90° counter-clockwise
        default:  break;                                   // 0: no-op
    }
    if (o.flip == "h" || o.flip == "hv") vf += "hflip,";
    if (o.flip == "v" || o.flip == "hv") vf += "vflip,";

    const int W = o.width, H = o.height;
    char seg[256];

    // Position expressions for the leftover offset (ow/oh = output dims,
    // iw/ih = scaled input dims at this stage of the graph).
    auto pad_xy = [&](const char *ow, const char *oh,
                      const char *iw, const char *ih) -> std::string {
        std::string x, y;
        if      (o.pos == "left")   { x = "0"; }
        else if (o.pos == "right")  { x = std::string(ow) + "-" + iw; }
        else                        { x = std::string("(") + ow + "-" + iw + ")/2"; }
        if      (o.pos == "top")    { y = "0"; }
        else if (o.pos == "bottom") { y = std::string(oh) + "-" + ih; }
        else                        { y = std::string("(") + oh + "-" + ih + ")/2"; }
        return x + ":" + y;
    };

    switch (o.fit) {
        case Fit::Stretch:
            snprintf(seg, sizeof(seg), "scale=%d:%d", W, H);
            vf += seg;
            break;

        case Fit::Contain: {
            // Scale to fit inside WxH preserving aspect, then pad to WxH.
            snprintf(seg, sizeof(seg),
                     "scale=%d:%d:force_original_aspect_ratio=decrease,", W, H);
            vf += seg;
            std::string xy = pad_xy("ow", "oh", "iw", "ih");
            snprintf(seg, sizeof(seg),
                     "pad=%d:%d:%s:color=0x%s", W, H, xy.c_str(), o.pad.c_str());
            vf += seg;
            break;
        }

        case Fit::Cover: {
            // Scale to cover WxH preserving aspect, then crop to WxH.
            snprintf(seg, sizeof(seg),
                     "scale=%d:%d:force_original_aspect_ratio=increase,", W, H);
            vf += seg;
            std::string xy = pad_xy("iw", "ih", "ow", "oh"); // crop offset
            snprintf(seg, sizeof(seg), "crop=%d:%d:%s", W, H, xy.c_str());
            vf += seg;
            break;
        }
    }
    return vf;
}

// fork/exec ffmpeg with an argv array — never a shell, so src paths with
// spaces or shell metacharacters are passed verbatim and can't inject.
int run_ffmpeg(const Options &o, const std::vector<std::string> &extra_out) {
    std::vector<std::string> args = {
        o.ffmpeg, "-y", "-hide_banner", "-loglevel", "error",
        "-i", o.src,
        "-vf", build_filter(o),
        "-frames:v", "1",
    };
    args.insert(args.end(), extra_out.begin(), extra_out.end());

    if (o.verbose) {
        fprintf(stderr, "[frameplace] exec:");
        for (const auto &a : args) fprintf(stderr, " %s", a.c_str());
        fprintf(stderr, "\n");
    }

    std::vector<char *> argv;
    argv.reserve(args.size() + 1);
    for (auto &a : args) argv.push_back(const_cast<char *>(a.c_str()));
    argv.push_back(nullptr);

    pid_t pid = fork();
    if (pid < 0) { perror("fork"); return -1; }
    if (pid == 0) {
        execvp(o.ffmpeg.c_str(), argv.data());
        perror("execvp ffmpeg"); // only reached on failure
        _exit(127);
    }
    int status = 0;
    if (waitpid(pid, &status, 0) < 0) { perror("waitpid"); return -1; }
    if (!WIFEXITED(status)) return -1;
    return WEXITSTATUS(status);
}

} // namespace

int main(int argc, char **argv) {
    if (argc < 2) { usage(argv[0]); return 2; }

    Options o;
    bool geom_auto = false;

    for (int i = 1; i < argc; i++) {
        std::string a = argv[i];
        auto next = [&](const char *name) -> const char * {
            if (i + 1 >= argc) {
                fprintf(stderr, "frameplace: %s needs an argument\n", name);
                exit(2);
            }
            return argv[++i];
        };

        if (a == "-h" || a == "--help") { usage(argv[0]); return 0; }
        else if (a == "-v")             { o.verbose = true; }
        else if (a == "--jpeg-only")    { o.want_nv21 = false; }
        else if (a == "--nv21-only")    { o.want_jpeg = false; }
        else if (a == "--out-dir")      { o.out_dir = next("--out-dir"); }
        else if (a == "--ffmpeg")       { o.ffmpeg  = next("--ffmpeg"); }
        else if (a == "--pos")          { o.pos     = next("--pos"); }
        else if (a == "--pad")          { o.pad     = next("--pad"); }
        else if (a == "--flip")         { o.flip    = next("--flip"); }
        else if (a == "--jpeg-quality") { o.quality = atoi(next("--jpeg-quality")); }
        else if (a == "--rotate")       { o.rotate  = atoi(next("--rotate")); }
        else if (a == "--fit") {
            std::string f = next("--fit");
            if      (f == "cover")   o.fit = Fit::Cover;
            else if (f == "contain") o.fit = Fit::Contain;
            else if (f == "stretch") o.fit = Fit::Stretch;
            else { fprintf(stderr, "frameplace: bad --fit '%s'\n", f.c_str()); return 2; }
        }
        else if (a == "--geom") {
            std::string g = next("--geom");
            if (g == "auto") geom_auto = true;
            else if (!parse_geom(g.c_str(), &o.width, &o.height)) {
                fprintf(stderr, "frameplace: bad --geom '%s' (want WxH or auto)\n", g.c_str());
                return 2;
            }
        }
        else if (!a.empty() && a[0] == '-') {
            fprintf(stderr, "frameplace: unknown option '%s'\n", a.c_str());
            return 2;
        }
        else if (o.src.empty()) { o.src = a; }
        else { fprintf(stderr, "frameplace: unexpected argument '%s'\n", a.c_str()); return 2; }
    }

    if (o.src.empty())        { fprintf(stderr, "frameplace: no source image\n"); return 2; }
    if (!o.want_jpeg && !o.want_nv21) {
        fprintf(stderr, "frameplace: --jpeg-only and --nv21-only are mutually exclusive\n");
        return 2;
    }
    if (o.rotate != 0 && o.rotate != 90 && o.rotate != 180 && o.rotate != 270) {
        fprintf(stderr, "frameplace: --rotate must be 0/90/180/270\n"); return 2;
    }
    if (o.quality < 1)   o.quality = 1;
    if (o.quality > 100) o.quality = 100;

    if (geom_auto) {
        int w = o.width, h = o.height;
        if (read_geom_json(o.out_dir + "/geom.json", &w, &h)) {
            o.width = w; o.height = h;
            if (o.verbose)
                fprintf(stderr, "[frameplace] geom auto → %dx%d\n", w, h);
        } else if (o.verbose) {
            fprintf(stderr, "[frameplace] geom auto: no geom.json, using %dx%d\n",
                    o.width, o.height);
        }
    }

    mkdir(o.out_dir.c_str(), 0755);

    // ffmpeg -q:v is an inverse scale (2=best .. 31=worst); map 1..100 → 31..2.
    int qv = 31 - (o.quality * 29) / 100;
    if (qv < 2)  qv = 2;
    if (qv > 31) qv = 31;
    char qv_str[8];
    snprintf(qv_str, sizeof(qv_str), "%d", qv);

    int rc = 0;

    if (o.want_jpeg) {
        std::string jpg = o.out_dir + "/frame.jpg";
        int r = run_ffmpeg(o, { "-q:v", qv_str, jpg });
        if (r != 0) {
            fprintf(stderr, "[frameplace] JPEG placement failed (ffmpeg rc=%d)\n", r);
            rc = 1;
        } else {
            printf("[frameplace] frame.jpg  %dx%d fit=%s → %s\n",
                   o.width, o.height,
                   o.fit == Fit::Cover ? "cover" : o.fit == Fit::Contain ? "contain" : "stretch",
                   jpg.c_str());
        }
    }

    if (o.want_nv21) {
        std::string nv21 = o.out_dir + "/frame.nv21";
        int r = run_ffmpeg(o, { "-pix_fmt", "nv21", "-f", "rawvideo", nv21 });
        if (r != 0) {
            fprintf(stderr, "[frameplace] NV21 placement failed (ffmpeg rc=%d)\n", r);
            rc = 1;
        } else {
            printf("[frameplace] frame.nv21 %dx%d → %s\n",
                   o.width, o.height, nv21.c_str());
        }
    }

    return rc;
}
