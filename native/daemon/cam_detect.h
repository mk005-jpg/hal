#pragma once
#include <string>
#include <vector>

struct CameraNode {
    std::string  dev_path;   // e.g. /dev/video0
    std::string  card_name;  // from VIDIOC_QUERYCAP.card
    bool         is_back;
};

// Enumerate all /dev/video* nodes and identify front vs back camera
// by querying their capabilities.
std::vector<CameraNode> detectCameraNodes();

// Return the device node path for the primary back camera (empty if not found).
std::string primaryBackCamNode();
