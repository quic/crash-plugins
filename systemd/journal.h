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

#ifndef JOURNAL_DEFS_H_
#define JOURNAL_DEFS_H_

#include "plugin.h"
#include "utils/utask.h"

class Journal : public ParserPlugin {
private:
    ulong max_pfn;
    ulong min_low_pfn;
    std::shared_ptr<UTask> task_ptr = nullptr;
    std::shared_ptr<Swapinfo> swap_ptr;
    struct task_context *tc_systemd_journal = nullptr;

public:
    Journal(std::shared_ptr<Swapinfo> swap);
    Journal();
    void init_command();
    bool page_buddy(ulong page_addr);
    int page_count(ulong page_addr);
    void parser_journal_log();
    void parser_journal_log_from_pagecache();
    void cmd_main(void) override;
    DEFINE_PLUGIN_INSTANCE(Journal)
};

#endif // JOURNAL_DEFS_H_
