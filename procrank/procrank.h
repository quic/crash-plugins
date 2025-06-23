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

#ifndef PROCRANK_DEFS_H_
#define PROCRANK_DEFS_H_
#include "plugin.h"
#include "memory/swapinfo.h"
#include "../utils/utask.h"

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

class Procrank : public ParserPlugin {
private:
    std::shared_ptr<UTask> task_ptr;

public:
    Procrank();
    Procrank(std::shared_ptr<Swapinfo> swap);
    void init_command();
    void cmd_main(void) override;
    void parser_process_memory();
    void parser_process_name();
    std::shared_ptr<procrank> parser_vma(std::shared_ptr<vma_struct> vma_ptr);
    DEFINE_PLUGIN_INSTANCE(Procrank)

private:
    std::shared_ptr<Swapinfo> swap_ptr;
    std::vector<std::shared_ptr<procrank>> procrank_list;
};
#endif // PROCRANK_DEFS_H_
