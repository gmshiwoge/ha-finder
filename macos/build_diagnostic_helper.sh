#!/bin/sh
set -eu

OUTPUT="$TARGET_BUILD_DIR/$UNLOCALIZED_RESOURCES_FOLDER_PATH/haos_diagnostic_helper"
mkdir -p "$(dirname "$OUTPUT")"
/usr/bin/clang++ -std=c++17 -O2 -arch arm64 -arch x86_64 \
  "$PROJECT_DIR/diagnostic_helper/haos_diagnostic_helper.cpp" \
  -o "$OUTPUT"
chmod 755 "$OUTPUT"
