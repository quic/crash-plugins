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

#ifndef PAGE_OWNER_DEFS_H_
#define PAGE_OWNER_DEFS_H_

#include "plugin.h"

/* from mm/page_ext.c */
#define PAGE_EXT_INVALID    (0x1)

/* from lib/stackdepot.c */
#define DEPOT_STACK_ALIGN    4

union handle_parts {
    uint handle;
    struct {
        uint pool_index    : 21;
        uint offset    : 10;
        uint valid    : 1;
    } v1;
    struct {
        uint pool_index : 16;
        uint offset    : 10;
        uint valid    : 1;
        uint extra    : 5;
    } v2;    /* 6.1 and later */
    struct {
        uint pool_index : 17;
        uint offset    : 10;
        uint extra    : 5;
    } v3;    /* 6.8 and later */
};

struct page_owner {
    ulong addr;
    ulong pfn;
    unsigned short order;
    short last_migrate_reason;
    unsigned int gfp_mask;
    unsigned int handle;
    unsigned int free_handle;
    unsigned long long ts_nsec;
    unsigned long long free_ts_nsec;
    size_t pid;
    size_t tgid;
    std::string comm;
};

struct process_info {
    ulong total_cnt;
    ulong total_size;
};

struct stack_info {
    unsigned int handle;
    ulong total_cnt;
    ulong total_size;
    std::unordered_map<size_t, std::shared_ptr<page_owner>> owner_list; //<pfn, page_owner>
};

class Pageowner : public PaserPlugin {
private:
    static const int INPUT_PFN = 0x0001;
    static const int INPUT_PYHS = 0x0002;
    static const int INPUT_PAGE = 0x0004;
public:
    std::unordered_map<size_t, std::shared_ptr<page_owner>> owner_map; //<pfn, page_owner>
    std::unordered_map<unsigned int, std::shared_ptr<stack_info>> handle_map; //<handle,stack_info>
    std::set<ulong> page_owner_page_list;
    std::set<ulong> stack_record_page_list;
    Pageowner();
    bool debug;
    int page_ext_size;
    int depot_index;
    ulong stack_slabs;
    ulong max_pfn;
    ulong min_low_pfn;
    size_t ops_offset;
    long PAGE_EXT_OWNER;
    long PAGE_EXT_OWNER_ALLOCATED;
    void cmd_main(void) override;
    bool is_enable_pageowner();
    void parser_all_pageowners();
    std::shared_ptr<page_owner> parser_page_owner(ulong addr);
    ulong parser_stack_record(uint handle,uint* stack_len, ulong* page_addr);
    void print_stack(ulong entries,uint nr_size);
    ulong get_entry(ulong base, ulong pfn);
    bool page_ext_invalid(ulong page_ext);
    ulong lookup_page_ext(ulong page);
    ulong get_page_owner(ulong page_ext);
    void print_all_page_owner(bool alloc);
    void print_page_owner(std::string addr,int flags);
    void print_page_owner(std::shared_ptr<page_owner> owner_ptr, bool is_free);
    void print_total_size_by_handle();
    void print_total_size_by_pid(std::unordered_map<size_t, std::shared_ptr<page_owner>> owner_list);
    void print_memory_info();
    DEFINE_PLUGIN_INSTANCE(Pageowner)
};

#endif // PAGE_OWNER_DEFS_H_
