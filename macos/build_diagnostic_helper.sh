#!/bin/sh
set -eu

OUTPUT="$TARGET_BUILD_DIR/$CONTENTS_FOLDER_PATH/Helpers/haos_diagnostic_helper"
mkdir -p "$(dirname "$OUTPUT")"
/usr/bin/clang++ -std=c++17 -O2 -arch arm64 -arch x86_64 \
  "$PROJECT_DIR/diagnostic_helper/haos_diagnostic_helper.cpp" \
  -o "$OUTPUT"
chmod 755 "$OUTPUT"

# Executables inside Contents/Helpers must already be signed before Xcode seals
# the parent app. The release workflow replaces this build signature with the
# Developer ID + hardened-runtime signature before notarization.
if [ "${CODE_SIGNING_ALLOWED:-NO}" = "YES" ]; then
  /usr/bin/codesign --force --sign "${EXPANDED_CODE_SIGN_IDENTITY:--}" "$OUTPUT"
fi
