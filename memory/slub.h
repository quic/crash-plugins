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

#ifndef SLUB_DEFS_H_
#define SLUB_DEFS_H_

#include "plugin.h"
// #include <unordered_set>

/* Poison */
#define SLAB_RED_ZONE 0x400
#define SLAB_POISON 0x800
#define SLAB_STORE_USER 0x10000
#define OBJECT_POISON 0x80000000
#define SLAB_KMALLOC 0x00001000
#define SLUB_RED_INACTIVE 0xbb
#define SLUB_RED_ACTIVE 0xcc
#define POISON_INUSE 0x5a
#define POISON_FREE 0x6b
#define POISON_END 0xa5

#define TRACK_ALLOC 0
#define TRACK_FREE 1

/* from lib/stackdepot.c */
#define DEPOT_STACK_ALIGN    4

union handle_parts_v {
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

struct obj {
    int index;
    /*
    +--------------+------------+
    | red left zone|            |
    +--------------+------------+
    ^              < -obj size- >
    |
    start
    */
    ulong start;
    ulong end;
    bool is_free;
};

struct slab {
    ulong first_page;
    unsigned int order;
    unsigned int inuse;
    unsigned int totalobj;
    unsigned int freeobj;
    std::vector<std::shared_ptr<obj>> obj_list;
};

struct kmem_cache_cpu {
    ulong addr;
    ulong freeobj;
    unsigned long tid;
    std::shared_ptr<slab> cur_slab;
    std::vector<std::shared_ptr<slab>> partial;
};

struct kmem_cache_node {
    ulong addr;
    unsigned long nr_partial;
    std::vector<std::shared_ptr<slab>> partial;
    ulong nr_slabs;
    ulong total_objects;
    std::vector<std::shared_ptr<slab>> full;
};

struct kmem_cache {
    ulong addr;
    std::vector<std::shared_ptr<kmem_cache_cpu>> cpu_slabs;
    unsigned int flags;
    unsigned long min_partial;
    unsigned int size;
    unsigned int object_size;
    unsigned int offset;
    unsigned int cpu_partial;
    unsigned int oo;
    int per_slab_obj;
    int page_order;
    unsigned int max;
    unsigned int min;
    unsigned int allocflags;
    int refcount;
    unsigned int inuse;
    unsigned int align;
    unsigned int red_left_pad;
    unsigned long random;
    std::string name;
    unsigned int useroffset;
    unsigned int usersize;
    size_t total_size;
    size_t total_nr_slabs;
    size_t total_nr_objs;
    std::vector<std::shared_ptr<kmem_cache_node>> node_list;
};

struct track { // see __kmem_obj_info in slub.c
    unsigned long trackp;
    std::string frame;
    int cpu;
    int pid;
    unsigned long when;
    std::shared_ptr<kmem_cache> kmem_cache_ptr;
    ulong obj_addr;
};

class Slub : public ParserPlugin {
private:
    std::vector<std::shared_ptr<kmem_cache>> cache_list;
    std::unordered_map<std::string, std::vector<std::shared_ptr<track>>> alloc_trace_map;
    std::unordered_map<std::string, std::vector<std::shared_ptr<track>>> free_trace_map;
    ulong max_pfn;
    ulong depot_index;
    ulong stack_slabs;
    // std::unordered_set<size_t> unique_hash;

    void parser_slab_caches();
    std::vector<std::shared_ptr<kmem_cache_node>> parser_kmem_cache_node(std::shared_ptr<kmem_cache> cache_ptr, ulong node_addr);
    std::vector<std::shared_ptr<kmem_cache_cpu>> parser_kmem_cache_cpu(std::shared_ptr<kmem_cache> cache_ptr, ulong cpu_addr);
    std::vector<std::shared_ptr<slab>> parser_slab_from_list(std::shared_ptr<kmem_cache> cache_ptr, ulong head_addr);
    std::shared_ptr<slab> parser_slab(std::shared_ptr<kmem_cache> cache_ptr, ulong slab_page_addr);
    void print_slab_caches();
    void print_slab_summary_info();
    void print_slab_info(std::shared_ptr<slab> slab_ptr);
    void print_slab_cache_info(std::string addr);
    void print_slab_cache(std::shared_ptr<kmem_cache> cache_ptr);
    /* Poison */
    unsigned int get_info_end(std::shared_ptr<kmem_cache> cache_ptr);
    bool freeptr_outside_object(std::shared_ptr<kmem_cache> cache_ptr);
    ulong fixup_red_left(std::shared_ptr<kmem_cache> cache_ptr, ulong object_start_addr);
    ulong memchr_inv(ulong start_addr, uint8_t c, size_t bytes);
    ulong check_bytes8(ulong start, uint8_t value, size_t bytes);
    bool slub_debug_orig_size(std::shared_ptr<kmem_cache> cache_ptr);
    unsigned int get_orig_size(std::shared_ptr<kmem_cache> cache_ptr);
    ulong restore_red_left(std::shared_ptr<kmem_cache> cache_ptr, ulong object_start);
    bool check_valid_pointer(std::shared_ptr<kmem_cache> cache_ptr, ulong page_addr, ulong object_start);
    unsigned int size_from_object(std::shared_ptr<kmem_cache> cache_ptr);
    int check_pad_bytes(std::shared_ptr<kmem_cache> cache_ptr, ulong page_addr, ulong obj_start);
    int check_bytes_and_report(std::shared_ptr<kmem_cache> cache_ptr, ulong page_addr, ulong obj_start, std::string what, ulong start, uint8_t value, size_t bytes);
    void print_section(std::string text, ulong page_addr, size_t length);
    void print_trailer(std::shared_ptr<kmem_cache> cache_ptr, ulong page_addr, ulong obj_start);
    void print_page_info(ulong slab_page_addr);
    int object_err(std::shared_ptr<kmem_cache> cache_ptr, ulong slab_page_addr, ulong object_start, std::string reason);
    int check_object_poison(std::shared_ptr<kmem_cache> cache_ptr, std::shared_ptr<slab> slab_ptr);
    void print_slub_poison(ulong kmem_cache_addr = 0);
    int check_object(std::shared_ptr<kmem_cache> cache_ptr, ulong first_page, ulong start_addr, uint8_t val);
    ulong get_free_pointer(std::shared_ptr<kmem_cache> cache_ptr, ulong object_start_addr);
    /*Trace*/
    std::string extract_callstack(ulong frames_addr);
    void parser_track_map(std::unordered_map<std::string, std::vector<std::shared_ptr<track>>> map, bool is_free);
    void print_all_slub_trace(size_t stack_id = 0);
    void parser_slub_trace();
    void print_slub_trace(std::string is_free);
    ulong parser_stack_record(uint page_owner_handle, uint& stack_len);
    void parser_track(ulong track_addr, std::shared_ptr<track> &track_ptr);
    ulong get_track(std::shared_ptr<kmem_cache> cache_ptr, ulong object_start_addr, uint8_t track_type);
    void parser_obj_track(std::shared_ptr<kmem_cache> cache_ptr, ulong object_start_addr, uint8_t track_type);
    void parser_slab_track(std::shared_ptr<kmem_cache> cache_ptr, std::shared_ptr<slab> slab_ptr);

public:
    Slub();
    void cmd_main(void) override;
    void init_offset(void) override;
    void init_command(void) override;
    DEFINE_PLUGIN_INSTANCE(Slub)
};

#endif // SLUB_DEFS_H_
