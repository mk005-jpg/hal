#include "cam_maps.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

std::vector<MapRegion> find_cam_regions(pid_t pid, const char *dev_node_substr) {
    std::vector<MapRegion> result;
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/maps", (int)pid);

    FILE *f = fopen(path, "r");
    if (!f) return result;

    char line[512];
    while (fgets(line, sizeof(line), f)) {
        char perms[8], fname[256] = {};
        uint64_t start, end, offset;
        int fields = sscanf(line, "%lx-%lx %4s %lx %*x:%*x %*u %255s",
                            &start, &end, perms, &offset, fname);
        if (fields < 4) continue;

        // We need a writable region (perms[1]=='w') backed by the camera device.
        if (perms[1] != 'w') continue;
        if (!strstr(fname, dev_node_substr)) continue;

        MapRegion r;
        r.vaddr  = (uintptr_t)start;
        r.length = (size_t)(end - start);
        r.offset = offset;
        result.push_back(r);
    }
    fclose(f);
    return result;
}
