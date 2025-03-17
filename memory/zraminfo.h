// Copyright (c) 2024-2025 Qualcomm Innovation Center, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause-Clear

#ifndef ZRAM_DRV_DEFS_H_
#define ZRAM_DRV_DEFS_H_

#include "plugin.h"
#include <lz4.h>
#include <lzo/lzoconf.h>
#include <lzo/lzo1x.h> 

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

struct zs_size_stat {
    unsigned long objs[6];
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
    std::vector<std::shared_ptr<zpage>> fullness_list[4];
    bool zspage_parser;
    int size;
    int objs_per_zspage;
    int pages_per_zspage;
    unsigned int index;
    struct zs_size_stat stats;
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

class Zraminfo : public PaserPlugin {
protected:
    bool debug = false;
public:
    std::vector<std::shared_ptr<zram>> zram_list;
    Zraminfo();

    int group_cnt;
    int ZRAM_FLAG_SHIFT;
    int ZRAM_FLAG_SAME_BIT;
    int ZRAM_FLAG_WB_BIT;
    int ZRAM_COMP_PRIORITY_BIT1;
    int ZRAM_COMP_PRIORITY_MASK;

    void cmd_main(void) override;
    bool is_zram_enable();
    void parser_zrams();
    void init_offset();
    std::shared_ptr<zram> parser_zram(ulong addr);
    void enable_debug(bool on);
    std::shared_ptr<zs_pool> parser_mem_pool(ulong addr);
    std::shared_ptr<size_class> parser_size_class(ulong addr);
    void parser_zpage(std::shared_ptr<size_class> class_ptr);
    std::shared_ptr<zpage> parser_zpage(ulong addr,std::shared_ptr<size_class> class_ptr);
    void parser_pages(ulong first_page,std::shared_ptr<size_class> class_ptr,std::shared_ptr<zpage> page_ptr);
    void parser_obj(ulong page_addr,std::shared_ptr<size_class> class_ptr,std::shared_ptr<zpage> page_ptr);
    std::shared_ptr<zobj> parser_obj(int obj_id, ulong handle_addr,physaddr_t start,physaddr_t end);
    void handle_to_location(ulong handle, ulong* pfn, int* obj_idx);
    char* read_zram_page(ulong zram_addr, ulonglong index);
    bool read_table_entry(std::shared_ptr<zram> zram_ptr, ulonglong index, struct zram_table_entry* entry);
    char* read_object(std::shared_ptr<zram> zram_ptr,struct zram_table_entry entry,int& read_len, bool& huge_obj);
    bool get_zspage(ulong page,struct zspage* zp);
    int get_class_id(struct zspage& zspage_s);
    int decompress(std::string comp_name,char* source, char* dest,int compressedSize, int maxDecompressedSize);
};

#endif // ZRAM_DRV_DEFS_H_
