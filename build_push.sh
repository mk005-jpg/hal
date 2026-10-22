#!/usr/bin/env bash
# build_push.sh — Build all Frida-free HAL injection components and push to Pixel 7a.
# Run from E:\android pentesting\hal-inject\ (Git Bash or WSL on Windows).
#
# Prerequisites:
#   Android SDK + NDK r26+ in $ANDROID_HOME
#   eBPF toolchain (Linux/WSL): clang, bpftool, libbpf-dev
#   ffmpeg on device (for NV21 generation in daemon) or pre-generate offline
#
# NOTE: Frida is NOT used.  Injection is via:
#   PRIMARY  — cam_injector (ptrace) + libcam_hook.so (inline arm64 hook)
#   FALLBACK — /proc/PID/mem direct write (daemon)

set -e

DEVICE_DIR="/data/local/tmp/hal_inject"
NDK="${ANDROID_HOME}/ndk/26.3.11579264"
TOOLCHAIN="${NDK}/toolchains/llvm/prebuilt/linux-x86_64"

echo "=== 1. Build Android APK ==="
./gradlew assembleDebug
APK=$(find app/build/outputs/apk/debug -name "*.apk" | head -1)
echo "APK: $APK"

echo "=== 2. Build native daemon ==="
mkdir -p native/daemon/build
cmake -B native/daemon/build \
    -DCMAKE_TOOLCHAIN_FILE="${NDK}/build/cmake/android.toolchain.cmake" \
    -DANDROID_ABI=arm64-v8a \
    -DANDROID_PLATFORM=android-33 \
    -DANDROID_STL=c++_static \
    -S native/daemon
cmake --build native/daemon/build
DAEMON_BIN="native/daemon/build/hal_inject_daemon"

echo "=== 3. Build cam_injector (ptrace loader) ==="
mkdir -p native/injector/build
cmake -B native/injector/build \
    -DCMAKE_TOOLCHAIN_FILE="${NDK}/build/cmake/android.toolchain.cmake" \
    -DANDROID_ABI=arm64-v8a \
    -DANDROID_PLATFORM=android-33 \
    -DANDROID_STL=c++_static \
    -S native/injector
cmake --build native/injector/build
INJECTOR_BIN="native/injector/build/cam_injector"

echo "=== 4. Build libcam_hook.so (inline-hook library) ==="
mkdir -p native/hook/build
cmake -B native/hook/build \
    -DCMAKE_TOOLCHAIN_FILE="${NDK}/build/cmake/android.toolchain.cmake" \
    -DANDROID_ABI=arm64-v8a \
    -DANDROID_PLATFORM=android-33 \
    -DANDROID_STL=c++_static \
    -S native/hook
cmake --build native/hook/build
HOOK_SO="native/hook/build/libcam_hook.so"

echo "=== 5. Build eBPF object (Linux/WSL only) ==="
if command -v clang &>/dev/null && command -v bpftool &>/dev/null; then
    make -C native/bpf
    BPF_OBJ="native/bpf/cam_track.bpf.o"
else
    echo "SKIP: clang/bpftool not found — push pre-built BPF object manually"
    BPF_OBJ=""
fi

echo "=== 6. Push to device ==="
adb shell "su -c 'mkdir -p ${DEVICE_DIR}; chmod 777 ${DEVICE_DIR}'"

# Daemon
if [ -f "$DAEMON_BIN" ]; then
    adb push "$DAEMON_BIN" "${DEVICE_DIR}/hal_inject_daemon"
    adb shell "su -c 'chmod 755 ${DEVICE_DIR}/hal_inject_daemon'"
fi

# ptrace injector
if [ -f "$INJECTOR_BIN" ]; then
    adb push "$INJECTOR_BIN" "${DEVICE_DIR}/cam_injector"
    adb shell "su -c 'chmod 755 ${DEVICE_DIR}/cam_injector'"
fi

# inline-hook library
if [ -f "$HOOK_SO" ]; then
    adb push "$HOOK_SO" "${DEVICE_DIR}/libcam_hook.so"
    adb shell "su -c 'chmod 644 ${DEVICE_DIR}/libcam_hook.so'"
fi

# eBPF object
if [ -n "$BPF_OBJ" ] && [ -f "$BPF_OBJ" ]; then
    adb push "$BPF_OBJ" "${DEVICE_DIR}/cam_track.bpf.o"
fi

# APK install
adb install -r "$APK"

echo ""
echo "=== Done ==="
echo "On device (as root):"
echo "  1. Start daemon:   adb shell 'su -c ${DEVICE_DIR}/hal_inject_daemon &'"
echo "  2. Open HAL Inject app"
echo "  3. Pick image → tap START INJECTION"
echo ""
echo "Injection chain:"
echo "  PRIMARY  cam_injector ptrace-loads libcam_hook.so into cameraserver"
echo "           → inline hook on Camera3OutputStream::returnBuffer"
echo "           → replaces back-cam gralloc dmabuf with frame.jpg / frame.nv21"
echo "  FALLBACK /proc/cameraserver/mem write @ 30 ms into V4L2 device regions"
echo ""
echo "No Frida — no Frida server, no Frida strings, no frida-agent.so."
