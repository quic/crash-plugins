/**
 * Copyright (c) 2024-2025 Qualcomm Innovation Center, Inc. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 and
 * only version 2 as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#ifndef CPU_INFO_DEFS_H_
#define CPU_INFO_DEFS_H_

#include "plugin.h"

struct cpu_policy{
    ulong addr;
    uint32_t cluster;
    uint32_t cur;
    uint32_t min;
    uint32_t max;
    std::string gov_name;
    std::vector<ulong> freq_table;
};

class CpuInfo : public PaserPlugin {
public:
    CpuInfo();
    std::vector<std::shared_ptr<cpu_policy>> cpu_infos;
    void print_cpu_policy();
    void print_freq_table();
    void parser_cpu_policy();
    void cmd_main(void) override;
    DEFINE_PLUGIN_INSTANCE(CpuInfo)
};

#endif // CPU_INFO_DEFS_H_
