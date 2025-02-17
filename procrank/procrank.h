// Copyright (c) 2024-2025 Qualcomm Innovation Center, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause-Clear

#ifndef PROCRANK_DEFS_H_
#define PROCRANK_DEFS_H_
#include "plugin.h"

struct procrank{
    ulong vss;
    ulong rss;
    ulong pss;
    ulong uss;
    ulong swap;
    ulong pid;
    // char comm[TASK_COMM_LEN+1];
    std::string cmdline;
};

class Procrank : public PaserPlugin {
public:
    Procrank();
    void cmd_main(void) override;
    void parser_process_memory();
    std::shared_ptr<procrank> parser_vma(ulong& vma_addr, ulong& task_addr);
    DEFINE_PLUGIN_INSTANCE(Procrank)

private:
    std::vector<std::shared_ptr<procrank>> procrank_list;
};
#endif // PROCRANK_DEFS_H_
