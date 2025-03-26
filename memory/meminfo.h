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

#ifndef MEMINFO_DEFS_H_
#define MEMINFO_DEFS_H_

#include <map>
#include <cmath>
#include "plugin.h"
#include "buddy.h"

#define LRU_BASE 0
#define LRU_ACTIVE 1
#define LRU_FILE 2

class Meminfo : public PaserPlugin {
private:
    std::map<std::string, ulong> enumerator;
    ulong totalram_addr;
    ulong vm_node_addr;
    ulong vm_zone_addr;
    ulong totalreserveram_addr;
    ulong blockdev_superblock_addr;
    ulong total_swap_pages_addr;
    ulong nr_swapfiles_addr;
    ulong swap_info_addr;
    ulong nr_swap_pages_addr;
    ulong nr_vmalloc_pages_addr;
    ulong sysctl_overcommit_addr;
    ulong hstates_addr;
    ulong vm_committed_addr;
    ulong cpu_online_mask_addr;
    ulong per_cpu_offset_addr;
    ulong nr_cpu_ids_addr;
    ulong pcpu_nr_units_addr;
    ulong pcpu_nr_populated_addr;
    ulong totalcma_pages_addr;


    void parameters_init(void);
    ulong get_bytes_from_page_count(ulong cnt);
    ulong get_node_state_pages(const char*);
    ulong get_node_state_pages(const char*, ulong);
    ulong get_zone_state_pages(const char*);
    ulong get_zone_state_pages(const char*, ulong);
    ulong get_wmark_low(void);
    ulong get_available(ulong, ulong);
    ulong get_blockdev_nr_pages(void);
    ulong get_to_be_unused_nr_pages(void);
    ulong get_vm_commit_pages(void);
    ulong get_mm_committed_pages(void);
    ulong get_vmalloc_total(void);

public:
    Meminfo();
    void cmd_main(void) override;
    void print_all(void);
    DEFINE_PLUGIN_INSTANCE(Meminfo)
};


#endif // MEMINFO_DEFS_H_
