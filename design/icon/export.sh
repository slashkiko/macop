#!/usr/bin/env bash
# Regenerate every SVG, then rasterise the PNG deliverables and the .iconset.
# Requires python3, Node.js, and the dependencies installed by `npm ci`.
set -euo pipefail
cd "$(dirname "$0")"

fail() {
  printf 'icon export: %s\n' "$1" >&2
  exit 1
}

for command in python3 node; do
  command -v "$command" >/dev/null 2>&1 || fail "required command is unavailable: $command"
done
node -e 'require("playwright")' >/dev/null 2>&1 \
  || fail "Playwright is unavailable. Run npm ci in design/icon first."
chromium_path="$(node -e 'const { chromium } = require("playwright"); process.stdout.write(chromium.executablePath())')" \
  || fail "unable to resolve the Playwright Chromium executable."
[[ -x "$chromium_path" ]] \
  || fail "Playwright Chromium is unavailable. Run npm run install-browser in design/icon first."

python3 build.py
# The .iconset is a shipped resource: build-auth-app.sh turns it into the app's
# .icns. It lives with the app, not with the generator, so regenerating the
# design updates the product in one step.
iconset="$(cd .. && cd .. && pwd)/Resources/MacopAuth/MacopAuth.iconset"
rm -rf png "$iconset"
mkdir -p png "$iconset"

MACOP_ICONSET="$iconset" python3 - > .jobs.json <<'PY'
import json
ICON, MARK = "svg/macop-icon.svg", "svg/macop-mark.svg"
MONO, WORD = "svg/macop-mark-mono.svg", "svg/macop-wordmark.svg"
LOCK, STACK = "svg/macop-lockup.svg", "svg/macop-lockup-stacked.svg"
DARK, LIGHT = "#161A24", "#FFFFFF"
jobs = [[ICON, f"png/macop-icon-{s}.png", s] for s in (1024, 512, 256, 128, 64, 32, 16)]
# Apple .iconset: every slot rendered from the vector, never upscaled.
import os
ICONSET = os.environ["MACOP_ICONSET"]
for name, s in [("icon_16x16", 16), ("icon_16x16@2x", 32), ("icon_32x32", 32),
                ("icon_32x32@2x", 64), ("icon_128x128", 128), ("icon_128x128@2x", 256),
                ("icon_256x256", 256), ("icon_256x256@2x", 512), ("icon_512x512", 512),
                ("icon_512x512@2x", 1024)]:
    jobs.append([ICON, f"{ICONSET}/{name}.png", s])
jobs += [
    [MARK, "png/macop-mark-512.png", 512],
    [MONO, "png/macop-mark-mono-dark-512.png", 512, None, None, DARK],
    [MONO, "png/macop-mark-mono-light-512.png", 512, None, None, LIGHT],
    [WORD, "png/macop-wordmark-1200.png", 1200, None, None, DARK],
    [LOCK, "png/macop-lockup-1600.png", 1600, None, None, DARK],
    [LOCK, "png/macop-lockup-1600-reversed.png", 1600, None, None, LIGHT],
    [STACK, "png/macop-lockup-stacked-900.png", 900, None, None, DARK],
]
print(json.dumps(jobs))
PY

node raster.js --batch .jobs.json
rm -f .jobs.json

# One 256px sample of the neutral field, for the preview sheet.
mkdir -p png/themes
for t in $(python3 -c "import build; print(' '.join(build.THEMES))"); do
  MACOP_THEME="$t" python3 -c "
import os, build, importlib
importlib.reload(build)
open('svg/theme-%s.svg' % os.environ['MACOP_THEME'], 'w').write(build.app_icon())"
  node raster.js "svg/theme-$t.svg" "png/themes/$t-256.png" 256
done
echo "README images ->"
node docshots.js

echo "keyway contrast ->"
node check-contrast.js

echo "done."
