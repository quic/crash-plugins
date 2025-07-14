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

#ifndef ZRAM_DRV_DEFS_H_
#define ZRAM_DRV_DEFS_H_

#include "plugin.h"
extern "C" {
#include "lib/lzo/lzo.h"
#include "lib/lz4/lz4.h"
}

#define OBJ_ALLOCATED_TAG   1
#define FULLNESS_BITS       2
#define CLASS_BITS          8
#define ISOLATED_BITS       3
#define MAGIC_VAL_BITS      8

struct zram_table_entry {
    union {
        unsigned long handle;
        unsigned long element;
    };
    unsigned long flags;
};

struct zram_stats {
    ulonglong compr_data_size;
    ulonglong num_reads;
    ulonglong num_writes;
    ulonglong failed_reads;
    ulonglong failed_writes;
    ulonglong invalid_io;
    ulonglong notify_free;
    ulonglong same_pages;
    ulonglong huge_pages;
    ulonglong huge_pages_since;
    ulonglong pages_stored;
    ulonglong max_used_pages;
    ulonglong writestall;
    ulonglong miss_free;
};

struct zs_pool_stats {
    atomic_long_t pages_compacted;
};

struct zobj {
    int id;
    ulong start;
    ulong end;
    ulong handle_addr;
    ulong pfn;
    union{
        int next;
        int index;
    };
    bool is_free;
};

struct pageinfo {
    ulong addr;
    std::vector<std::shared_ptr<zobj>> obj_list;
};

struct zpage {
    ulong addr;
    struct zspage zspage;
    int obj_index;
    std::vector<std::shared_ptr<pageinfo>> page_list;
};

struct size_class {
    ulong addr;
    std::vector<std::vector<std::shared_ptr<zpage>>> fullness_list;
    bool zspage_parser;
    int size;
    int objs_per_zspage;
    int pages_per_zspage;
    unsigned int index;
    std::vector<ulong> stats;
};

struct zs_pool {
    ulong addr;
    std::string name;
    std::vector<std::shared_ptr<size_class>> class_list;
    ulonglong pages_allocated;
    struct zs_pool_stats stats;
    int isolated_pages;
    bool destroying;
};

struct zram {
    ulong addr;
    ulong table;
    std::shared_ptr<zs_pool> mem_pool;
    std::string zcomp_name;
    std::string disk_name;
    ulong limit_pages;
    struct zram_stats stats;
    ulonglong disksize;
    std::string compressor;
    bool claim;
};

enum zs_stat_type {
    CLASS_EMPTY,
    CLASS_ALMOST_EMPTY,
    CLASS_ALMOST_FULL,
    CLASS_FULL,
    OBJ_ALLOCATED,
    OBJ_USED,
    NR_ZS_STAT_TYPE,
};

class Zraminfo : public ParserPlugin {
private:
    bool debug = false;
    int ZRAM_FLAG_SHIFT;
    int ZRAM_FLAG_SAME_BIT;
    int ZRAM_FLAG_WB_BIT;
    int ZRAM_COMP_PRIORITY_BIT1;
    int ZRAM_COMP_PRIORITY_MASK;

    std::shared_ptr<zram> parser_zram(ulong addr);
    std::shared_ptr<zs_pool> parser_mem_pool(ulong addr);
    std::shared_ptr<size_class> parser_size_class(ulong addr);
    std::shared_ptr<zpage> parser_zpage(ulong addr,std::shared_ptr<size_class> class_ptr);
    void parser_pages(ulong first_page,std::shared_ptr<size_class> class_ptr,std::shared_ptr<zpage> page_ptr);
    void parser_obj(ulong page_addr,std::shared_ptr<size_class> class_ptr,std::shared_ptr<zpage> page_ptr);
    std::shared_ptr<zobj> parser_obj(int obj_id, ulong handle_addr,physaddr_t start,physaddr_t end);
    void handle_to_location(ulong handle, ulong* pfn, int* obj_idx);
    bool read_table_entry(std::shared_ptr<zram> zram_ptr, ulonglong index, struct zram_table_entry* entry);
    char* read_object(std::shared_ptr<zram> zram_ptr,struct zram_table_entry entry,int& read_len, bool& huge_obj);
    bool get_zspage(ulong page,struct zspage* zp);
    int get_class_id(struct zspage& zspage_s);
    int decompress(std::string comp_name,char* source, char* dest,int compressedSize, int maxDecompressedSize);
    int lzo1x_decompress(char *source, char *dest, int compressedSize, int maxDecompressedSize);
    int lz4_decompress(char *source, char *dest, int compressedSize, int maxDecompressedSize);

public:
    std::vector<std::shared_ptr<zram>> zram_list;
    int group_cnt;

    Zraminfo();
    void parser_zrams();
    void parser_zpage(std::shared_ptr<size_class> class_ptr);
    char* read_zram_page(ulong zram_addr, ulonglong index);
    bool is_zram_enable();
    void cmd_main(void) override;
    void init_offset(void) override;
    void init_command(void) override;
};

#endif // ZRAM_DRV_DEFS_H_
