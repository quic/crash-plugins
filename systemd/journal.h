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
#include <systemd/sd-journal.h>

class Journal : public ParserPlugin {
private:
    std::unordered_map<std::string, std::vector<std::shared_ptr<vma_struct>>> log_vma_list;
    std::unordered_map<std::string, ulong> log_inode_list;
    static const int DUMP_LOG = 1 << 1;
    static const int LIST_LOG = 1 << 2;
    static const int SHOW_LOG = 1 << 3;
    static const int FROM_VMA = 1 << 1;
    static const int FROM_CACHE = 1 << 2;
    std::shared_ptr<UTask> task_ptr = nullptr;
    std::shared_ptr<Swapinfo> swap_ptr;
    struct task_context *tc_systemd_journal = nullptr;
    void get_journal_vma_list();
    bool write_vma_to_file(std::vector<std::shared_ptr<vma_struct>> vma_list, FILE* logfile);
    void get_journal_inode_list();
    bool write_pagecache_to_file(ulong i_mapping, FILE* logfile);

public:
    Journal(std::shared_ptr<Swapinfo> swap);
    Journal();
    void init_command();
    void dump_journal_log_from_vma();
    void dump_journal_log_from_pagecache();
    void print_journal_log_from_vma();
    void print_journal_log_from_pagecache();
    void show_journal_log_from_vma(std::string name);
    void show_journal_log_from_pagecache(std::string name);
    void display_journal_log(char* filepath);
    void cmd_main(void) override;
    DEFINE_PLUGIN_INSTANCE(Journal)
};

#endif // JOURNAL_DEFS_H_
