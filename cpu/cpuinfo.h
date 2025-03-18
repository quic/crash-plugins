// Copyright (c) 2024-2025 Qualcomm Innovation Center, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause-Clear

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
