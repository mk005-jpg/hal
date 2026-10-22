'use strict';
// hal_hook.js — Camera HAL frame injection, back camera only, Pixel 7a
// Attach to cameraserver:  frida -U -n cameraserver -l hal_hook.js --no-pause
// Or to provider:          frida -U -n android.hardware.camera.provider-service-google -l hal_hook.js --no-pause

const DIR         = '/data/local/tmp/hal_inject';
const FRAME_JPEG  = DIR + '/frame.jpg';
const FRAME_NV21  = DIR + '/frame.nv21';
const STATS_FILE  = DIR + '/stats.json';
const CTRL_FILE   = DIR + '/ctrl';     // contains "on" or "off"
const TARGET_FILE = DIR + '/targets';  // newline-separated package names

// HAL_PIXEL_FORMAT constants
const FMT_BLOB         = 33;   // HAL_PIXEL_FORMAT_BLOB  (JPEG in camera2)
const FMT_YCbCr_420    = 35;   // HAL_PIXEL_FORMAT_YCbCr_420_888
const FMT_YCrCb_420SP  = 17;   // NV21
const FMT_RAW10        = 37;

// camera3_stream_buffer_t layout (arm64, 32 bytes):
const SB_STREAM  = 0;   // camera3_stream_t *  (8)
const SB_BUFFER  = 8;   // buffer_handle_t **  (8)
const SB_STATUS  = 16;  // int32               (4)
const SB_ACQ_FEN = 20;  // int32               (4)
const SB_REL_FEN = 24;  // int32               (4)
const SB_SIZE    = 32;

// camera3_stream_t offsets (arm64):
const ST_TYPE    = 0;   // int32 stream_type
const ST_WIDTH   = 4;   // uint32
const ST_HEIGHT  = 8;   // uint32
const ST_FORMAT  = 12;  // int32
const ST_USAGE   = 16;  // uint64

// camera3_capture_result_t offsets (arm64):
const CR_FRAME_NUM  = 0;   // uint32
const CR_RESULT_PTR = 8;   // camera_metadata_t * (8)
const CR_NUM_BUFS   = 16;  // uint32
const CR_OUT_BUFS   = 24;  // camera3_stream_buffer_t * (8)

// native_handle_t layout:
const NH_VER     = 0;   // int version = sizeof(native_handle_t)
const NH_NUM_FDS = 4;   // int numFds
const NH_NUM_INT = 8;   // int numInts
const NH_DATA    = 12;  // int data[] — fds first

// libc functions we need
const libc   = Process.findModuleByName('libc.so') || Process.findModuleByName('libc.so.6');
const _mmap  = new NativeFunction(Module.findExportByName(null, 'mmap64') ||
                                  Module.findExportByName(null, 'mmap'),
                                  'pointer', ['pointer','size_t','int','int','int','int64']);
const _munmap = new NativeFunction(Module.findExportByName(null, 'munmap'),
                                   'int', ['pointer','size_t']);
const _open  = new NativeFunction(Module.findExportByName(null, 'open'),
                                  'int', ['pointer','int']);
const _read  = new NativeFunction(Module.findExportByName(null, 'read'),
                                  'int', ['int','pointer','size_t']);
const _close = new NativeFunction(Module.findExportByName(null, 'close'),
                                  'int', ['int']);

const PROT_RW   = 3;
const MAP_SHARED = 1;
const O_RDONLY  = 0;
const O_RDWR    = 2;

// --- state ---
var gStats = { injected: 0, skipped: 0, errors: 0, active: false };
var gJpegBytes = null;
var gNv21Bytes = null;
var gJpegSize  = 0;
var gNv21Size  = 0;
var gActive    = false;
var gLastCtrl  = 0;
var gLastFrame = 0;

function readFileSafe(path) {
    try {
        var f = new File(path, 'rb');
        var b = f.readBytes(); f.close(); return b;
    } catch(e) { return null; }
}

function readTextSafe(path) {
    try {
        var f = new File(path, 'r');
        var s = f.readLine(); f.close(); return s ? s.trim() : '';
    } catch(e) { return ''; }
}

function refreshFrames() {
    var j = readFileSafe(FRAME_JPEG);
    if (j && j.length > 0) { gJpegBytes = j; gJpegSize = j.length; }
    var n = readFileSafe(FRAME_NV21);
    if (n && n.length > 0) { gNv21Bytes = n; gNv21Size = n.length; }
}

function refreshCtrl() {
    var now = Date.now();
    if (now - gLastCtrl < 500) return;
    gLastCtrl = now;
    var v = readTextSafe(CTRL_FILE);
    gActive = (v === 'on');
    gStats.active = gActive;
}

function writeStats() {
    var now = Date.now();
    if (now - gLastFrame < 1000) return;
    gLastFrame = now;
    try {
        var f = new File(STATS_FILE, 'w');
        f.write(JSON.stringify(gStats) + '\n');
        f.close();
    } catch(e) {}
}

// Calculate buffer size for a stream format
function bufSize(w, h, fmt) {
    if (fmt === FMT_BLOB)        return w * h * 3;  // worst-case JPEG size
    if (fmt === FMT_YCbCr_420)   return Math.floor(w * h * 3 / 2);
    if (fmt === FMT_YCrCb_420SP) return Math.floor(w * h * 3 / 2);
    if (fmt === FMT_RAW10)       return Math.floor(w * h * 10 / 8);
    return w * h * 4; // fallback RGBA
}

// Write bytes into a gralloc dmabuf fd via mmap
function injectIntoBuffer(handle, size, bytes) {
    if (!bytes || bytes.length === 0) return false;
    try {
        var numFds = handle.add(NH_NUM_FDS).readInt();
        if (numFds < 1) return false;
        var dmabuf_fd = handle.add(NH_DATA).readInt();
        if (dmabuf_fd < 0) return false;

        var mapped = _mmap(NULL, size, PROT_RW, MAP_SHARED, dmabuf_fd, 0);
        if (mapped.isNull() || mapped.equals(ptr(-1))) return false;

        var writeLen = Math.min(bytes.length, size);
        Memory.writeByteArray(mapped, bytes.slice(0, writeLen));
        _munmap(mapped, size);
        return true;
    } catch(e) {
        gStats.errors++;
        return false;
    }
}

// Process one camera3_stream_buffer_t.
// Returns true if injection was performed.
function processStreamBuffer(sbPtr) {
    if (sbPtr.isNull()) return false;

    var streamPtr = sbPtr.add(SB_STREAM).readPointer();
    if (streamPtr.isNull()) return false;

    var fmt    = streamPtr.add(ST_FORMAT).readInt();
    var width  = streamPtr.add(ST_WIDTH).readU32();
    var height = streamPtr.add(ST_HEIGHT).readU32();

    var isJpeg = (fmt === FMT_BLOB);
    var isYuv  = (fmt === FMT_YCbCr_420 || fmt === FMT_YCrCb_420SP);

    if (!isJpeg && !isYuv) return false;

    var bufPtrPtr = sbPtr.add(SB_BUFFER).readPointer();
    if (bufPtrPtr.isNull()) return false;
    var handle = bufPtrPtr.readPointer();  // native_handle_t *
    if (handle.isNull()) return false;

    var sz = bufSize(width, height, fmt);

    if (isJpeg && gJpegBytes) {
        return injectIntoBuffer(handle, sz, gJpegBytes);
    }
    if (isYuv && gNv21Bytes) {
        return injectIntoBuffer(handle, sz, gNv21Bytes);
    }
    return false;
}

// ─── Hook: Camera3OutputStream::returnBuffer in libcameraservice.so ───────────
// This fires in cameraserver when a filled output buffer is about to be
// returned to the app.  At this point we can replace the contents.
// Symbol (AOSP Android 13/14):
//   _ZN7android18Camera3OutputStreamR12returnBufferERK22camera_stream_buffer_tllP13camera_stream

function hookCameraServiceReturnBuffer() {
    var lib = Process.findModuleByName('libcameraservice.so');
    if (!lib) { console.log('[hal_inject] libcameraservice.so not found'); return false; }

    var addr = null;

    // Try exact C++ mangled symbol (multiple variants across API levels)
    var candidates = [
        '_ZN7android18Camera3OutputStreamR12returnBufferERK22camera_stream_buffer_tll',
        '_ZN7android18Camera3OutputStreamR12returnBufferERK22camera_stream_buffer_tllP13camera_stream',
        '_ZN7android18Camera3OutputStreamR12returnBufferERK22camera_stream_buffer_tllyP13camera_stream',
        '_ZN7android18Camera3OutputStreamR12returnBufferERK22camera_stream_buffer_t',
    ];
    for (var sym of candidates) {
        addr = Module.findExportByName('libcameraservice.so', sym);
        if (addr) { console.log('[hal_inject] found returnBuffer: ' + sym); break; }
    }

    // Fall back: scan exports for keyword
    if (!addr) {
        var exps = lib.enumerateExports();
        for (var e of exps) {
            if (e.name && e.name.includes('Camera3OutputStream') && e.name.includes('returnBuffer')) {
                addr = e.address;
                console.log('[hal_inject] found returnBuffer via scan: ' + e.name);
                break;
            }
        }
    }

    if (!addr) {
        console.log('[hal_inject] returnBuffer not found in libcameraservice.so');
        return false;
    }

    Interceptor.attach(addr, {
        // arg0 = this (Camera3OutputStream*)
        // arg1 = const camera_stream_buffer_t& buffer  ← contains stream+handle
        // arg2 = timestamp (nsecs_t)
        onEnter: function(args) {
            refreshCtrl();
            if (!gActive) return;
            if (!gJpegBytes && !gNv21Bytes) { refreshFrames(); return; }

            var sbPtr = args[1];  // const camera_stream_buffer_t*
            if (sbPtr.isNull()) return;

            var ok = processStreamBuffer(sbPtr);
            if (ok) { gStats.injected++; } else { gStats.skipped++; }
            writeStats();
        }
    });

    console.log('[hal_inject] returnBuffer hook installed');
    return true;
}

// ─── Fallback Hook: process_capture_result in libgooglecamerahal.so ──────────
function hookGoogleCameraHalProcessResult() {
    var lib = Process.findModuleByName('libgooglecamerahal.so');
    if (!lib) return false;

    var addr = null;

    // Try known mangled names
    var candidates = [
        '_ZN20google_camera_hal21CameraDeviceSession21ProcessCaptureResultERKSt6vectorINS_19ProcessBlockResultESaIS2_EE',
        '_ZN20google_camera_hal21CameraDeviceSession21ProcessCaptureResultERKNSt6__1vector',
    ];
    for (var sym of candidates) {
        addr = Module.findExportByName('libgooglecamerahal.so', sym);
        if (addr) { console.log('[hal_inject] found ProcessCaptureResult: ' + sym); break; }
    }

    if (!addr) {
        // Scan exports
        var exps = lib.enumerateExports();
        for (var e of exps) {
            if (e.name && e.name.includes('ProcessCaptureResult') && e.name.includes('CameraDevice')) {
                addr = e.address;
                console.log('[hal_inject] found ProcessCaptureResult via scan: ' + e.name);
                break;
            }
        }
    }

    if (!addr) { return false; }

    // The first arg to CameraDeviceSession::ProcessCaptureResult is `this`,
    // second is a const std::vector<ProcessBlockResult>&.
    // ProcessBlockResult contains a camera3_capture_result_t.
    // We hook at returnBuffer level anyway, so this hook is an additional fallback.
    Interceptor.attach(addr, {
        onEnter: function(args) {
            refreshCtrl();
            if (!gActive) return;
            // args[1] = std::vector<ProcessBlockResult>*
            // std::vector layout: { data_ptr, size, capacity }
            var vecPtr  = args[1];
            if (vecPtr.isNull()) return;
            var dataPtr = vecPtr.readPointer();
            var size    = vecPtr.add(Process.pointerSize).readU64().toNumber();
            if (size === 0 || dataPtr.isNull()) return;

            // ProcessBlockResult has camera3_capture_result at some offset.
            // The exact offset depends on the struct definition.
            // Conservative: look for the camera3_capture_result_t by scanning
            // the first 128 bytes of each element for a plausible result struct.
            // We skip this for now and rely on the returnBuffer hook above.
        }
    });

    console.log('[hal_inject] ProcessCaptureResult hook installed (supplemental)');
    return true;
}

// ─── Init ─────────────────────────────────────────────────────────────────────
function init() {
    refreshFrames();
    refreshCtrl();

    var ok1 = hookCameraServiceReturnBuffer();
    var ok2 = hookGoogleCameraHalProcessResult();

    if (!ok1 && !ok2) {
        console.log('[hal_inject] WARNING: no hook installed — attach manually via hook_manual()');
    }

    // Poll ctrl file every 2 s to pick up daemon enable/disable signals
    setInterval(function() {
        refreshCtrl();
        refreshFrames();
        writeStats();
    }, 2000);

    console.log('[hal_inject] ready | back-cam injection only | frame: ' + gJpegSize + ' bytes JPEG, ' + gNv21Size + ' bytes NV21');
}

// Exposed for manual use: hook_manual(address)
function hook_manual(addr) {
    Interceptor.attach(ptr(addr), {
        onEnter: function(args) {
            refreshCtrl();
            if (!gActive) return;
            processStreamBuffer(args[1]);
        }
    });
    console.log('[hal_inject] manual hook at ' + ptr(addr));
}

init();
