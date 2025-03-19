#// Copyright (c) 2024-2025 Qualcomm Innovation Center, Inc. All rights reserved.
#// SPDX-License-Identifier: BSD-3-Clause-Clear

cmake_minimum_required(VERSION 3.21.1)
project(plugins)

string(TOUPPER "${CMAKE_BUILD_TARGET_ARCH}" BUILD_TARGET_ARCH)
add_definitions(-D${BUILD_TARGET_ARCH})
add_definitions(-D__LITTLE_ENDIAN)
set(CMAKE_CXX_STANDARD 14)
set(CMAKE_CXX_STANDARD_REQUIRED True)
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -rdynamic -Wall")

include_directories(.)

if (CMAKE_BUILD_TARGET_ARCH STREQUAL "arm64")
set(CMAKE_LIBRARY_ARCHITECTURE x86_64-linux-gnu)
elseif(CMAKE_BUILD_TARGET_ARCH STREQUAL "arm")
set(CMAKE_LIBRARY_ARCHITECTURE i386-linux-gnu)
endif()

find_package(PkgConfig REQUIRED)
# sudo apt-get install liblzo2-dev liblzo2-dev:i386
pkg_check_modules(LZO2 REQUIRED lzo2)
if(NOT LZO2_FOUND)
    message(FATAL_ERROR "LZO2 library not found")
endif()
# sudo apt-get install liblz4-dev liblz4-dev:i386
pkg_check_modules(LZ4 REQUIRED liblz4)
if(NOT LZ4_FOUND)
    message(FATAL_ERROR "LZ4 library not found")
endif()
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
    plugin.cpp
    logger/log.cpp)

if(DEFINED BUILD_TARGET_TOGETHER)
add_definitions(-DBUILD_TARGET_TOGETHER)
list(APPEND PLUGIN_SOURCES
    plugins.cpp
    binder/binder.cpp
    memory/cma.cpp
    memory/reserved.cpp
    memory/memblock.cpp
    memory/iomem.cpp
    memory/vmalloc.cpp
    memory/dmabuf.cpp
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
    thermal/thermal.cpp)
add_library(plugins SHARED ${PLUGIN_SOURCES})
if (CMAKE_BUILD_TARGET_ARCH STREQUAL "arm64")
    target_sources(plugins PRIVATE coredump/arm/arm64.cpp
                                coredump/arm/compat.cpp)
elseif (CMAKE_BUILD_TARGET_ARCH STREQUAL "arm")
    target_sources(plugins PRIVATE coredump/arm/arm.cpp)
endif()

set_target_properties(plugins PROPERTIES PREFIX "")
target_link_libraries(plugins ${LZO2_LIBRARIES} ${LZ4_LIBRARIES} ${ELF_LIBRARIES} ${ZSTD_LIBRARIES})
else()
# =================== build dmabuf ===================
add_library(dmabuf SHARED
            ${PLUGIN_SOURCES}
            memory/dmabuf.cpp)
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
            procrank/procrank.cpp)
set_target_properties(procrank PROPERTIES PREFIX "")
target_link_libraries(procrank ${LZO2_LIBRARIES} ${LZ4_LIBRARIES})

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
            memory/zram.cpp)
set_target_properties(zram PROPERTIES PREFIX "")
target_link_libraries(zram ${LZO2_LIBRARIES} ${LZ4_LIBRARIES})

# =================== build swap ===================
add_library(swap SHARED
            ${PLUGIN_SOURCES}
            memory/zraminfo.cpp
            memory/swapinfo.cpp
            memory/swap.cpp)
set_target_properties(swap PROPERTIES PREFIX "")
target_link_libraries(swap ${LZO2_LIBRARIES} ${LZ4_LIBRARIES} ${ELF_LIBRARIES})

# =================== build prop ===================
add_library(prop SHARED
            ${PLUGIN_SOURCES}
            memory/zraminfo.cpp
            memory/swapinfo.cpp
            property/propinfo.cpp
            property/prop.cpp)
set_target_properties(prop PROPERTIES PREFIX "")
target_link_libraries(prop ${LZO2_LIBRARIES} ${LZ4_LIBRARIES} ${ELF_LIBRARIES})

# =================== build logcat ===================
add_library(logcat SHARED
            ${PLUGIN_SOURCES}
            memory/zraminfo.cpp
            memory/swapinfo.cpp
            property/propinfo.cpp
            logcat/Logcat_parser.cpp
            logcat/logcat.cpp
            logcat/logcatS.cpp
            logcat/logcatR.cpp)
set_target_properties(logcat PROPERTIES PREFIX "")
target_link_libraries(logcat ${LZO2_LIBRARIES} ${LZ4_LIBRARIES} ${ELF_LIBRARIES} ${ZSTD_LIBRARIES})

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
            coredump/core.cpp)
if (CMAKE_BUILD_TARGET_ARCH STREQUAL "arm64")
    target_sources(core PRIVATE coredump/arm/arm64.cpp
                                coredump/arm/compat.cpp)
elseif (CMAKE_BUILD_TARGET_ARCH STREQUAL "arm")
    target_sources(core PRIVATE coredump/arm/arm.cpp)
endif()
set_target_properties(core PROPERTIES PREFIX "")
target_link_libraries(core ${LZO2_LIBRARIES} ${LZ4_LIBRARIES} ${ELF_LIBRARIES})
# =================== build thermal ===================
add_library(tm SHARED
            ${PLUGIN_SOURCES}
            thermal/thermal.cpp)
set_target_properties(tm PROPERTIES PREFIX "")
endif()
