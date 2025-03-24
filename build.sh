# Copyright (c) 2024-2025 Qualcomm Innovation Center, Inc. All rights reserved.
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2 and
# only version 2 as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# SPDX-License-Identifier: GPL-2.0-only

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
