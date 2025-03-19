:<<!
Copyright (c) 2024-2025 Qualcomm Innovation Center, Inc. All rights reserved.
SPDX-License-Identifier: BSD-3-Clause-Clear
!

#!/bin/bash

###############################################################################################################################################
#         1. Run the command 'ulimit -c unlimited' before generating your core dump. This setting is only valid for the current bash session. #
#         2. Retrieve your coredump output path by executing 'cat /proc/sys/kernel/core_pattern'.                                             #
###############################################################################################################################################
CORE_PATH=<coredump path>
LATEST_CORE_FILE=$(ls -t ${CORE_PATH} | head -n 1)
CORE_DUMP=${CORE_PATH}/${LATEST_CORE_FILE}
CRASH_UTILITY_SYM_PATH=<crash_utility symbol path>
GDB_PATH=<x86-64-gdb path>
GDB_CMD_PATH=<cmd.gdb path>
ELF_HEADER=$(od -An -t x1 -N 16 "$CORE_DUMP")
IS_ARM=$(echo $ELF_HEADER | awk '{print $5}')
CRASH_PLUGIN_ARM_SYM=<crash-plugin symbols path>
CRASH_PLUGIN_ARM64_SYM=<crash-plugin symbols path>
function debug_crash_plugin(){
    sed -i '1{/^\/\//d};2{/^\/\//d}' ${GDB_CMD_PATH}
    if [ "$IS_ARM" == "02" ]; then
        sed -i '/^set solib-search-path/ s|set solib-search-path.*|set solib-search-path '"${CRASH_PLUGIN_ARM64_SYM}"'|' ${GDB_CMD_PATH}
        ${GDB_PATH} -x ${GDB_CMD_PATH} ${CRASH_UTILITY_SYM_PATH} ${CORE_DUMP}
    elif [ "$IS_ARM" == "01" ]; then
        sed -i '/^set solib-search-path/ s|set solib-search-path.*|set solib-search-path '"${CRASH_PLUGIN_ARM_SYM}"'|' ${GDB_CMD_PATH}
        ${GDB_PATH} -x ${GDB_CMD_PATH} ${CRASH_UTILITY_SYM_PATH} ${CORE_DUMP}
    else
        echo "Unknown architecture"
    fi
}

debug_crash_plugin