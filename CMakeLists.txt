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
include_directories(lib)

set(PLUGIN_SOURCES
    plugin.cpp
    logger/log.cpp)

if (CMAKE_BUILD_TARGET_ARCH STREQUAL "arm64")
list(APPEND PLUGIN_SOURCES
        pagetable/arm/pagetable64.cpp)
elseif(CMAKE_BUILD_TARGET_ARCH STREQUAL "arm")
list(APPEND PLUGIN_SOURCES
        pagetable/arm/pagetable32.cpp)
endif()

if(DEFINED BUILD_TARGET_TOGETHER)
add_definitions(-DBUILD_TARGET_TOGETHER)
list(APPEND PLUGIN_SOURCES
            plugins.cpp
            binder/binder.cpp
	    memory/cma.cpp
            procrank/procrank.cpp)
add_library(plugins SHARED ${PLUGIN_SOURCES})
set_target_properties(plugins PROPERTIES PREFIX "")
else()
add_library(binder SHARED
            ${PLUGIN_SOURCES}
            binder/binder.cpp)
set_target_properties(binder PROPERTIES PREFIX "")

add_library(cma SHARED
            ${PLUGIN_SOURCES}
            memory/cma.cpp)
set_target_properties(cma PROPERTIES PREFIX "")
add_library(procrank SHARED
            ${PLUGIN_SOURCES}
            procrank/procrank.cpp)
set_target_properties(procrank PROPERTIES PREFIX "")
endif()
