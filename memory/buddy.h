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

#ifndef BUDDY_DEFS_H_
#define BUDDY_DEFS_H_

#include "plugin.h"

enum zone_watermarks {
    WMARK_MIN,
    WMARK_LOW,
    WMARK_HIGH,
    NR_WMARK
};

struct free_area {
    ulong addr;
    std::vector<std::vector<ulong>> free_list;
    unsigned long nr_free;
};

struct zone {
    ulong addr;
    unsigned long _watermark[3];
    unsigned long watermark_boost;
    long lowmem_reserve[3];
    unsigned long start_pfn;
    unsigned long managed_pages;
    unsigned long spanned_pages;
    unsigned long present_pages;
    unsigned long cma_pages;
    std::string name;
    std::vector<std::shared_ptr<free_area>> free_areas;
    std::vector<ulong> vm_stat;
};

struct pglist_data {
    ulong addr;
    std::vector<std::shared_ptr<zone>> zone_list;
    unsigned long start_pfn;
    unsigned long present_pages;
    unsigned long spanned_pages;
    int id;
    unsigned long totalreserve_pages;
    std::vector<ulong> vm_stat;
};

class Buddy : public ParserPlugin {
public:
    std::vector<std::shared_ptr<pglist_data>> node_list;
    std::vector<std::string> migratetype_names;
    int min_free_kbytes;
    int user_min_free_kbytes;
    int watermark_scale_factor;
    Buddy();

    void cmd_main(void) override;
    void parser_buddy_info();
    std::shared_ptr<pglist_data> parser_node_info(ulong addr);
    std::shared_ptr<zone> parser_zone_info(ulong addr);
    std::vector<std::shared_ptr<free_area>> parser_free_area(ulong addr);
    std::vector<std::vector<ulong>> parser_free_list(ulong addr);
    void get_migratetype_names();
    void print_buddy_info();
    void print_memory_node();
    void print_memory_zone(std::string addr);
    void print_node_info(std::shared_ptr<pglist_data> node_ptr);
    void print_zone_info(std::shared_ptr<zone> zone_ptr);
    DEFINE_PLUGIN_INSTANCE(Buddy)
};


#endif // BUDDY_DEFS_H_
