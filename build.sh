#// Copyright (c) 2024-2025 Qualcomm Innovation Center, Inc. All rights reserved.
#// SPDX-License-Identifier: BSD-3-Clause-Clear

cmake -DCMAKE_C_COMPILER="/usr/bin/gcc"   \
      -DCMAKE_CXX_COMPILER="/usr/bin/g++" \
      -DCMAKE_BUILD_TYPE="Debug"          \
      -DCMAKE_BUILD_TARGET_ARCH="arm64"   \
      -DBUILD_TARGET_TOGETHER="1"         \
      CMakeLists.txt                      \
      -B output/arm64
make -C output/arm64 -j8


cmake -DCMAKE_C_COMPILER="/usr/bin/gcc"   \
      -DCMAKE_CXX_COMPILER="/usr/bin/g++" \
      -DCMAKE_BUILD_TYPE="Debug"          \
      -DCMAKE_C_FLAGS="-m32"              \
      -DCMAKE_CXX_FLAGS="-m32"            \
      -DCMAKE_BUILD_TARGET_ARCH="arm"     \
      -DBUILD_TARGET_TOGETHER="1"         \
      CMakeLists.txt                      \
      -B output/arm
make -C output/arm -j8
