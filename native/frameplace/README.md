# frameplace — camera-frame placement tool

Places an arbitrary source image into the **exact geometry of the target
camera stream** and writes the two frame files the injection chain consumes:

| File         | Used by (libcam_hook.so)                    |
|--------------|---------------------------------------------|
| `frame.jpg`  | BLOB streams (still capture, `format == 33`)|
| `frame.nv21` | YCbCr_420_888 / YV12 preview & analysis     |

## Why

The original pipeline stretch-scaled the source to a fixed size
(`ffmpeg scale=1920:1080`, `Bitmap.createScaledBitmap(1280,720)`). A stretched
face or document has the wrong aspect ratio — an obvious tell to a
liveness/KYC check and a plain correctness bug. `frameplace` preserves aspect
with a chosen fit mode, honours sensor orientation, and sizes the output to the
geometry the stream actually uses.

## Geometry

`libcam_hook.so` publishes the geometry of the stream it replaces to
`geom.json`:

```json
{"width":1280,"height":720,"format":35}
```

`frameplace --geom auto` reads that file, so placement matches the live stream
without hard-coding a resolution. If the file is absent it falls back to
`1280x720` (override with `--geom WxH`).

## Usage

```
frameplace <src-image> [options]
  --geom WxH|auto   target geometry (auto = read <out>/geom.json)
  --fit  MODE       cover | contain | stretch            (default cover)
                      cover   scale to fill, crop overflow (no bars)
                      contain scale to fit, pad remainder  (--pad colour)
                      stretch ignore aspect (legacy)
  --pos  POS        center|top|bottom|left|right          (default center)
  --pad  RRGGBB     pad colour for contain mode           (default 000000)
  --rotate DEG      0|90|180|270 clockwise                (default 0)
  --flip MODE       none|h|v|hv                           (default none)
  --jpeg-quality N  1..100                                (default 92)
  --out-dir DIR     output directory       (default /data/local/tmp/hal_inject)
  --ffmpeg PATH     ffmpeg binary                         (default: from PATH)
  --jpeg-only | --nv21-only
  -v                verbose (print the ffmpeg argv)
```

Example (place a portrait photo into a 1280×720 preview, filling the frame):

```
frameplace /sdcard/face.jpg --geom auto --fit cover
```

## Implementation

Pixel work (decode / scale / pad / crop / rotate / colour convert) is delegated
to **ffmpeg**, already listed as a device prerequisite in `build_push.sh`. This
binary only builds the placement filter graph and execs ffmpeg via an `argv`
array — never a shell — so source paths with spaces or shell metacharacters are
passed verbatim and cannot inject.

## Integration

* `build_push.sh` builds `frameplace` (arm64-v8a) and pushes it to
  `/data/local/tmp/hal_inject/frameplace`.
* The daemon runs it on `SET_IMAGE` (stages the source, then places it) and on
  the `PLACE <fit>` command (re-place with a different fit mode).
* The app exposes the fit modes (cover/contain/stretch) and a
  **placement-reference** screenshot overlay to align the frame with the target
  app's face/document guide.

No Frida anywhere.
