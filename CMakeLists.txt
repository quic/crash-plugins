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
	memory/buddy.cpp
	memory/slub.cpp
	memory/zraminfo.cpp
        memory/zram.cpp
	memory/swapinfo.cpp
	memory/swap.cpp
        procrank/procrank.cpp
        devicetree/dts.cpp
        devicetree/devicetree.cpp
        workqueue/workqueue.cpp
	partition/filesystem.cpp
	rtb/rtb.cpp)
add_library(plugins SHARED ${PLUGIN_SOURCES})
set_target_properties(plugins PROPERTIES PREFIX "")
target_link_libraries(plugins ${LZO2_LIBRARIES} ${LZ4_LIBRARIES})
else()
add_library(binder SHARED
            ${PLUGIN_SOURCES}
            binder/binder.cpp)
set_target_properties(binder PROPERTIES PREFIX "")

add_library(cma SHARED
            ${PLUGIN_SOURCES}
            memory/cma.cpp)
set_target_properties(cma PROPERTIES PREFIX "")

add_library(slub SHARED
            ${PLUGIN_SOURCES}
            memory/slub.cpp)
set_target_properties(slub PROPERTIES PREFIX "")
add_library(procrank SHARED
            ${PLUGIN_SOURCES}
            memory/zraminfo.cpp
            memory/swapinfo.cpp
            procrank/procrank.cpp)
set_target_properties(procrank PROPERTIES PREFIX "")
target_link_libraries(procrank ${LZO2_LIBRARIES} ${LZ4_LIBRARIES})

add_library(dts SHARED
            ${PLUGIN_SOURCES}
            devicetree/dts.cpp
            devicetree/devicetree.cpp)
set_target_properties(dts PROPERTIES PREFIX "")

add_library(memblock SHARED
            ${PLUGIN_SOURCES}
            memory/memblock.cpp)
set_target_properties(memblock PROPERTIES PREFIX "")

add_library(wq SHARED
            ${PLUGIN_SOURCES}
            workqueue/workqueue.cpp)
set_target_properties(wq PROPERTIES PREFIX "")

add_library(reserved SHARED
            ${PLUGIN_SOURCES}
            memory/reserved.cpp
            devicetree/devicetree.cpp)
set_target_properties(reserved PROPERTIES PREFIX "")

add_library(iomem SHARED
            ${PLUGIN_SOURCES}
            memory/iomem.cpp)
set_target_properties(iomem PROPERTIES PREFIX "")

add_library(vmalloc SHARED
            ${PLUGIN_SOURCES}
            memory/vmalloc.cpp)
set_target_properties(vmalloc PROPERTIES PREFIX "")

add_library(buddy SHARED
            ${PLUGIN_SOURCES}
            memory/buddy.cpp)
set_target_properties(buddy PROPERTIES PREFIX "")

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
set_target_properties(buddy PROPERTIES PREFIX "")
endif()
