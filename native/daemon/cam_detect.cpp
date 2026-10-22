#include "cam_detect.h"
#include <dirent.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <linux/videodev2.h>
#include <cstring>
#include <cstdio>
#include <algorithm>

// Returns true if the card name indicates a front-facing camera.
// Pixel 7a front cam driver names typically contain "front" or "selfie".
static bool isFrontByCard(const char *card) {
    std::string s(card);
    std::transform(s.begin(), s.end(), s.begin(), ::tolower);
    return (s.find("front") != std::string::npos ||
            s.find("selfie") != std::string::npos ||
            s.find("fc") != std::string::npos);
}

// On Pixel 7a the back camera nodes are the lower-numbered ones.
// Main back cam: /dev/video0 (IMX787 / Samsung GN1)
// Front cam:     /dev/video1 or /dev/video3
// Additionally check sysfs for "facing" if available.
static bool isFrontBySysfs(const std::string &dev_path) {
    // dev_path = /dev/videoN → get N
    char num_buf[8] = {};
    const char *p = dev_path.c_str() + strlen("/dev/video");
    snprintf(num_buf, sizeof(num_buf), "%s", p);

    char sysfs[256];
    snprintf(sysfs, sizeof(sysfs),
             "/sys/class/video4linux/video%s/device/facing", num_buf);

    int fd = open(sysfs, O_RDONLY);
    if (fd < 0) return false;
    char buf[16] = {};
    read(fd, buf, sizeof(buf) - 1);
    close(fd);
    return (strncmp(buf, "front", 5) == 0);
}

std::vector<CameraNode> detectCameraNodes() {
    std::vector<CameraNode> result;
    DIR *d = opendir("/dev");
    if (!d) return result;

    struct dirent *ent;
    while ((ent = readdir(d)) != nullptr) {
        if (strncmp(ent->d_name, "video", 5) != 0) continue;
        // skip non-numeric suffix
        bool alldig = true;
        for (int i = 5; ent->d_name[i]; i++)
            if (!isdigit(ent->d_name[i])) { alldig = false; break; }
        if (!alldig) continue;

        std::string path = std::string("/dev/") + ent->d_name;
        int fd = open(path.c_str(), O_RDONLY | O_NONBLOCK);
        if (fd < 0) continue;

        struct v4l2_capability cap = {};
        if (ioctl(fd, VIDIOC_QUERYCAP, &cap) == 0) {
            // Only include actual capture devices
            if (cap.device_caps & V4L2_CAP_VIDEO_CAPTURE) {
                CameraNode n;
                n.dev_path  = path;
                n.card_name = reinterpret_cast<char*>(cap.card);
                n.is_back   = !isFrontByCard(reinterpret_cast<char*>(cap.card)) &&
                               !isFrontBySysfs(path);
                result.push_back(n);
            }
        }
        close(fd);
    }
    closedir(d);

    // Sort by device number so video0 comes first
    std::sort(result.begin(), result.end(), [](const CameraNode &a, const CameraNode &b) {
        return a.dev_path < b.dev_path;
    });
    return result;
}

std::string primaryBackCamNode() {
    auto nodes = detectCameraNodes();
    for (auto &n : nodes)
        if (n.is_back) return n.dev_path;
    // Fallback: assume /dev/video0 is back on Pixel 7a if detection fails
    return "/dev/video0";
}
