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

cmake_minimum_required(VERSION 3.21.1)
project(plugins)

string(TOUPPER "${CMAKE_BUILD_TARGET_ARCH}" BUILD_TARGET_ARCH)
add_definitions(-D${BUILD_TARGET_ARCH})
add_definitions(-D__LITTLE_ENDIAN)
add_definitions(-D_FILE_OFFSET_BITS=64)
set(CMAKE_CXX_STANDARD 14)
set(CMAKE_CXX_STANDARD_REQUIRED True)
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -rdynamic -Wall")

include_directories(.)

if (CMAKE_BUILD_TARGET_ARCH STREQUAL "arm64")
set(CMAKE_LIBRARY_ARCHITECTURE x86_64-linux-gnu)
elseif(CMAKE_BUILD_TARGET_ARCH STREQUAL "arm")
set(CMAKE_LIBRARY_ARCHITECTURE i386-linux-gnu)
endif()

if(CMAKE_HOST_SYSTEM_PROCESSOR MATCHES "arm" OR CMAKE_HOST_SYSTEM_PROCESSOR MATCHES "aarch64")
add_compile_definitions(IS_ARM)
endif()

find_package(PkgConfig REQUIRED)
# sudo apt-get install libzstd-dev libzstd-dev:i386
pkg_check_modules(ZSTD REQUIRED libzstd)
if(NOT ZSTD_FOUND)
    message(FATAL_ERROR "ZSTD library not found")
endif()
# sudo apt-get install libelf-dev libelf-dev:i386
pkg_check_modules(ELF REQUIRED libelf)
if(NOT ELF_FOUND)
    message(FATAL_ERROR "ELF library not found")
endif()

set(PLUGIN_SOURCES
    plugin.cpp)

if(DEFINED BUILD_TARGET_TOGETHER)
add_definitions(-DBUILD_TARGET_TOGETHER)
list(APPEND PLUGIN_SOURCES
    plugins.cpp
    lib/lzo/lzo1x_decompress_safe.c
    lib/lz4/lz4_decompress.c
    binder/binder.cpp
    memory/cma.cpp
    memory/reserved.cpp
    memory/memblock.cpp
    memory/iomem.cpp
    memory/vmalloc.cpp
    memory/dmabuf/cmd_buf.cpp
    memory/dmabuf/dmabuf.cpp
    memory/dmabuf/heap.cpp
    memory/dmabuf/dma_heap.cpp
    memory/dmabuf/ion_heap.cpp
    memory/buddy.cpp
    memory/slub.cpp
    memory/zraminfo.cpp
    memory/zram.cpp
    memory/swapinfo.cpp
    memory/swap.cpp
    procrank/procrank.cpp
    devicetree/dts.cpp
    devicetree/devicetree.cpp
    pageowner/pageowner.cpp
    workqueue/workqueue.cpp
    partition/filesystem.cpp
    property/propinfo.cpp
    property/prop.cpp
    logcat/Logcat_parser.cpp
    logcat/logcat.cpp
    logcat/logcatS.cpp
    logcat/logcatR.cpp
    device_driver/dd.cpp
    rtb/rtb.cpp
    cpu/cpuinfo.cpp
    coredump/coredump.cpp
    coredump/core.cpp
    thermal/thermal.cpp
    memory/meminfo.cpp
    watchdog/wdt.cpp
    pagecache/pageinfo.cpp
    debugimage/debugimage.cpp
    debugimage/image_parser.cpp
    debugimage/cpu32_ctx.cpp
    debugimage/cpu64_ctx_v13.cpp
    debugimage/cpu64_ctx_v14.cpp
    debugimage/cpu64_ctx_v20.cpp
    ipc/ipc.cpp
    regulator/regulator.cpp
    icc/icc.cpp
    clock/clock.cpp
    pstore/pstore.cpp
    sysinfo/sys.cpp)
add_library(plugins SHARED ${PLUGIN_SOURCES})
if (CMAKE_BUILD_TARGET_ARCH STREQUAL "arm64")
    target_sources(plugins PRIVATE coredump/arm/arm64.cpp
                                coredump/arm/compat.cpp)
elseif (CMAKE_BUILD_TARGET_ARCH STREQUAL "arm")
    target_sources(plugins PRIVATE coredump/arm/arm.cpp)
endif()

set_target_properties(plugins PROPERTIES PREFIX "")
target_link_libraries(plugins ${ELF_LIBRARIES} ${ZSTD_LIBRARIES})
else()
# =================== build dmabuf ===================
add_library(dmabuf SHARED
            ${PLUGIN_SOURCES}
            memory/dmabuf/cmd_buf.cpp
            memory/dmabuf/dmabuf.cpp
            memory/dmabuf/heap.cpp
            memory/dmabuf/dma_heap.cpp
            memory/dmabuf/ion_heap.cpp)
set_target_properties(dmabuf PROPERTIES PREFIX "")

# =================== build binder ===================
add_library(binder SHARED
            ${PLUGIN_SOURCES}
            binder/binder.cpp)
set_target_properties(binder PROPERTIES PREFIX "")

# =================== build cma ===================
add_library(cma SHARED
            ${PLUGIN_SOURCES}
            memory/cma.cpp)
set_target_properties(cma PROPERTIES PREFIX "")

# =================== build slub ===================
add_library(slub SHARED
            ${PLUGIN_SOURCES}
            memory/slub.cpp)
set_target_properties(slub PROPERTIES PREFIX "")

# =================== build pageowner ===================
add_library(pageowner SHARED
            ${PLUGIN_SOURCES}
            pageowner/pageowner.cpp)
set_target_properties(pageowner PROPERTIES PREFIX "")

# =================== build procrank ===================
add_library(procrank SHARED
            ${PLUGIN_SOURCES}
            memory/zraminfo.cpp
            memory/swapinfo.cpp
            procrank/procrank.cpp
            lib/lzo/lzo1x_decompress_safe.c
            lib/lz4/lz4_decompress.c)
set_target_properties(procrank PROPERTIES PREFIX "")
target_link_libraries(procrank ${ELF_LIBRARIES} ${ZSTD_LIBRARIES})

# =================== build dts ===================
add_library(dts SHARED
            ${PLUGIN_SOURCES}
            devicetree/dts.cpp
            devicetree/devicetree.cpp)
set_target_properties(dts PROPERTIES PREFIX "")

# =================== build memblock ===================
add_library(memblock SHARED
            ${PLUGIN_SOURCES}
            memory/memblock.cpp)
set_target_properties(memblock PROPERTIES PREFIX "")

# =================== build wq ===================
add_library(wq SHARED
            ${PLUGIN_SOURCES}
            workqueue/workqueue.cpp)
set_target_properties(wq PROPERTIES PREFIX "")

# =================== build reserved ===================
add_library(reserved SHARED
            ${PLUGIN_SOURCES}
            memory/reserved.cpp
            devicetree/devicetree.cpp)
set_target_properties(reserved PROPERTIES PREFIX "")

# =================== build iomem ===================
add_library(iomem SHARED
            ${PLUGIN_SOURCES}
            memory/iomem.cpp)
set_target_properties(iomem PROPERTIES PREFIX "")

# =================== build vmalloc ===================
add_library(vmalloc SHARED
            ${PLUGIN_SOURCES}
            memory/vmalloc.cpp)
set_target_properties(vmalloc PROPERTIES PREFIX "")

# =================== build buddy ===================
add_library(buddy SHARED
            ${PLUGIN_SOURCES}
            memory/buddy.cpp)
set_target_properties(buddy PROPERTIES PREFIX "")

# =================== build rtb ===================
add_library(rtb SHARED
            ${PLUGIN_SOURCES}
            rtb/rtb.cpp)
set_target_properties(rtb PROPERTIES PREFIX "")

# =================== build zram ===================
add_library(zram SHARED
            ${PLUGIN_SOURCES}
            memory/zraminfo.cpp
            memory/zram.cpp
            lib/lzo/lzo1x_decompress_safe.c
            lib/lz4/lz4_decompress.c)
set_target_properties(zram PROPERTIES PREFIX "")
target_link_libraries(zram)

# =================== build swap ===================
add_library(swap SHARED
            ${PLUGIN_SOURCES}
            memory/zraminfo.cpp
            memory/swapinfo.cpp
            memory/swap.cpp
            lib/lzo/lzo1x_decompress_safe.c
            lib/lz4/lz4_decompress.c)
set_target_properties(swap PROPERTIES PREFIX "")
target_link_libraries(swap ${ELF_LIBRARIES})

# =================== build prop ===================
add_library(prop SHARED
            ${PLUGIN_SOURCES}
            memory/zraminfo.cpp
            memory/swapinfo.cpp
            property/propinfo.cpp
            property/prop.cpp
            lib/lzo/lzo1x_decompress_safe.c
            lib/lz4/lz4_decompress.c)
set_target_properties(prop PROPERTIES PREFIX "")
target_link_libraries(prop ${ELF_LIBRARIES})

# =================== build logcat ===================
add_library(logcat SHARED
            ${PLUGIN_SOURCES}
            memory/zraminfo.cpp
            memory/swapinfo.cpp
            property/propinfo.cpp
            logcat/Logcat_parser.cpp
            logcat/logcat.cpp
            logcat/logcatS.cpp
            logcat/logcatR.cpp
            lib/lzo/lzo1x_decompress_safe.c
            lib/lz4/lz4_decompress.c)
set_target_properties(logcat PROPERTIES PREFIX "")
target_link_libraries(logcat ${ELF_LIBRARIES} ${ZSTD_LIBRARIES})

# =================== build dd ===================
add_library(dd SHARED
            ${PLUGIN_SOURCES}
            device_driver/dd.cpp)
set_target_properties(dd PROPERTIES PREFIX "")

# =================== build cpuinfo ===================
add_library(cpuinfo SHARED
            ${PLUGIN_SOURCES}
            cpu/cpuinfo.cpp)
set_target_properties(cpuinfo PROPERTIES PREFIX "")
# =================== build core ===================
add_library(core SHARED
            ${PLUGIN_SOURCES}
            memory/zraminfo.cpp
            memory/swapinfo.cpp
            coredump/coredump.cpp
            coredump/core.cpp
            lib/lzo/lzo1x_decompress_safe.c
            lib/lz4/lz4_decompress.c)
if (CMAKE_BUILD_TARGET_ARCH STREQUAL "arm64")
    target_sources(core PRIVATE coredump/arm/arm64.cpp
                                coredump/arm/compat.cpp)
elseif (CMAKE_BUILD_TARGET_ARCH STREQUAL "arm")
    target_sources(core PRIVATE coredump/arm/arm.cpp)
endif()
set_target_properties(core PROPERTIES PREFIX "")
target_link_libraries(core ${ELF_LIBRARIES})
# =================== build thermal ===================
add_library(tm SHARED
            ${PLUGIN_SOURCES}
            thermal/thermal.cpp)
set_target_properties(tm PROPERTIES PREFIX "")

# =================== build meminfo ===================
add_library(meminfo SHARED
            ${PLUGIN_SOURCES}
            devicetree/devicetree.cpp
            memory/meminfo.cpp)
set_target_properties(meminfo PROPERTIES PREFIX "")

# =================== build watchdog ===================
add_library(wdt SHARED
            ${PLUGIN_SOURCES}
            watchdog/wdt.cpp)
set_target_properties(wdt PROPERTIES PREFIX "")

# =================== build pagecache ===================
add_library(cache SHARED
            ${PLUGIN_SOURCES}
            pagecache/pageinfo.cpp)
set_target_properties(cache PROPERTIES PREFIX "")

# =================== build debugimage ===================
add_library(dbi SHARED
            ${PLUGIN_SOURCES}
            debugimage/debugimage.cpp
            debugimage/image_parser.cpp
            debugimage/cpu32_ctx.cpp
            debugimage/cpu64_ctx_v13.cpp
            debugimage/cpu64_ctx_v14.cpp
            debugimage/cpu64_ctx_v20.cpp)
set_target_properties(dbi PROPERTIES PREFIX "")

# =================== build IPC log ===================
add_library(ipc SHARED
            ${PLUGIN_SOURCES}
            ipc/ipc.cpp)
set_target_properties(ipc PROPERTIES PREFIX "")

# =================== build regulator ===================
add_library(reg SHARED
            ${PLUGIN_SOURCES}
            regulator/regulator.cpp)
set_target_properties(reg PROPERTIES PREFIX "")

# =================== build icc ===================
add_library(icc SHARED
            ${PLUGIN_SOURCES}
            icc/icc.cpp)
set_target_properties(icc PROPERTIES PREFIX "")

# =================== build clock ===================
add_library(ccf SHARED
            ${PLUGIN_SOURCES}
            clock/clock.cpp)
set_target_properties(ccf PROPERTIES PREFIX "")

# =================== build pstore ===================
add_library(pstore SHARED
            ${PLUGIN_SOURCES}
            pstore/pstore.cpp)
set_target_properties(pstore PROPERTIES PREFIX "")

# =================== build sys ===================
add_library(sys SHARED
            ${PLUGIN_SOURCES}
            sysinfo/sys.cpp)
set_target_properties(sys PROPERTIES PREFIX "")
endif()
