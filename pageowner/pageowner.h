/**
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
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

class Pageowner : public ParserPlugin {
private:
    enum AddressType {
        ADDR_PFN,
        ADDR_PHYSICAL,
        ADDR_PAGE,
        ADDR_VIRTUAL,
        ADDR_UNKNOWN
    };
    static const int INPUT_PFN = 0x0001;
    static const int INPUT_PYHS = 0x0002;
    static const int INPUT_PAGE = 0x0004;
    static const int INPUT_VADDR = 0x0008;
    bool debug = false;
    int page_ext_size;
    size_t ops_offset;
    long PAGE_EXT_OWNER;
    long PAGE_EXT_OWNER_ALLOCATED;
    std::unordered_map<size_t, std::shared_ptr<page_owner>> owner_map; //<pfn, page_owner>
    std::unordered_map<unsigned int, std::shared_ptr<stack_info>> handle_map; //<handle,stack_info>
    std::set<ulong> page_owner_page_list;
    std::set<ulong> stack_record_page_list;

    bool is_enable_pageowner();
    void parser_all_pageowners();
    std::shared_ptr<page_owner> parser_page_owner(ulong addr);
    ulong get_entry(ulong base, ulong pfn);
    bool page_ext_invalid(ulong page_ext);
    ulong lookup_page_ext(ulong page);
    ulong get_page_owner(ulong page_ext);
    void print_page_owner(const std::string& addr,int flags);
    bool is_page_allocated(std::shared_ptr<page_owner> owner_ptr);
    void print_sorted_allocation_summary();
    void print_process_memory_summary(std::unordered_map<size_t, std::shared_ptr<page_owner>> owner_list);
    void print_memory_info();
    void print_all_allocated_pages();
    void print_all_freed_pages();
    void print_page_owner_entry(std::shared_ptr<page_owner> owner_ptr, bool is_free,
                               size_t entry_num, size_t total_entries);
    ulong vaddr_to_pfn(ulong vaddr);
    void print_page_owner_detailed(std::shared_ptr<page_owner> owner_ptr, bool is_free);
    void print_page_owner_auto(const std::string& addr_str);
    AddressType detect_address_type(ulonglong addr);
    bool is_page_address(ulonglong addr);
    bool is_physical_address(ulonglong addr);
    bool is_user_virtual_address(ulonglong addr);

public:
    Pageowner();
    void cmd_main(void) override;
    void init_offset(void) override;
    void init_command(void) override;
    DEFINE_PLUGIN_INSTANCE(Pageowner)
};

#endif // PAGE_OWNER_DEFS_H_
