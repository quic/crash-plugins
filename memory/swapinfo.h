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

#ifndef SWAP_INFO_DEFS_H_
#define SWAP_INFO_DEFS_H_

#include "plugin.h"
#include "memory/zraminfo.h"

struct swap_extent {
    struct rb_node rb_node;
    unsigned long start_page;
    unsigned long nr_pages;
    unsigned long long start_block;
};

struct swap_info {
    ulong addr;
    ulong swap_space;
    unsigned int pages;
    unsigned int inuse_pages;
    ulong bdev;
    std::string swap_file;
};

class Swapinfo : public ParserPlugin {
private:
    int nr_swap;
    char* uread_memory(ulonglong task_addr,ulonglong uvaddr,int len, const std::string& note);
    char* do_swap_page(ulonglong task_addr,ulonglong uvaddr);
    void parser_swap_info();
    std::shared_ptr<swap_info> get_swap_info(ulonglong pte_val);
    ulong get_zram_addr(std::shared_ptr<swap_info> swap_ptr, ulonglong pte_val);
    ulong lookup_swap_cache(ulonglong pte_val);
    bool uread_bool(ulonglong task_addr,ulonglong uvaddr,const std::string& note);
    int uread_int(ulonglong task_addr,ulonglong uvaddr,const std::string& note);
    uint uread_uint(ulonglong task_addr,ulonglong uvaddr,const std::string& note);
    long uread_long(ulonglong task_addr,ulonglong uvaddr,const std::string& note);
    ulong uread_ulong(ulonglong task_addr,ulonglong uvaddr,const std::string& note);
    ulonglong uread_ulonglong(ulonglong task_addr,ulonglong uvaddr,const std::string& note);
    ushort uread_ushort(ulonglong task_addr,ulonglong uvaddr,const std::string& note);
    short uread_short(ulonglong task_addr,ulonglong uvaddr,const std::string& note);
    ulong uread_pointer(ulonglong task_addr,ulonglong uvaddr,const std::string& note);
    unsigned char uread_byte(ulonglong task_addr,ulonglong uvaddr,const std::string& note);
    ulonglong pte_handle_index(std::shared_ptr<swap_info> swap_ptr, ulonglong pte_val);

protected:
    bool debug = false;
    std::shared_ptr<Zraminfo> zram_ptr;
    std::vector<std::shared_ptr<swap_info>> swap_list;

public:
    Swapinfo();
    bool is_zram_enable();
    Swapinfo(std::shared_ptr<Zraminfo> zram);
    ~Swapinfo();
    void init_command();
    void cmd_main(void) override;
    bool uread_buffer(ulonglong task_addr, ulonglong uvaddr, char *result, int len, const std::string &note);
    std::string uread_cstring(ulonglong task_addr,ulonglong uvaddr,int len, const std::string& note);
    bool is_swap_pte(ulong pte);
};

#endif // SWAP_INFO_DEFS_H_
