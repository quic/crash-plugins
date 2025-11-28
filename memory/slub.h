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

#ifndef SLUB_DEFS_H_
#define SLUB_DEFS_H_

#include "plugin.h"
// #include <unordered_set>

/* Poison */
#define SLUB_RED_INACTIVE 0xbb
#define SLUB_RED_ACTIVE 0xcc
#define POISON_INUSE 0x5a
#define POISON_FREE 0x6b
#define POISON_END 0xa5

#define TRACK_ALLOC 0
#define TRACK_FREE 1

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

struct SlubCheckResult {
    std::string cache_name;
    ulong cache_addr;
    int total_objects = 0;
    int checked_objects = 0;
    int corrupted_objects = 0;
    std::vector<std::string> errors;
    bool overall_result = true;

    int redzone_errors = 0;
    int poison_errors = 0;
    int freeptr_errors = 0;
    int padding_errors = 0;
};

struct ObjectCheckResult {
    int left_redzone_errors = 0;
    int right_redzone_errors = 0;
    int redzone_errors = 0;
    int poison_errors = 0;
    int freeptr_errors = 0;
    int padding_errors = 0;
    std::vector<std::string> details;
};

class Slub : public ParserPlugin {
private:
    bool trace_parsed = false;
    std::vector<std::shared_ptr<kmem_cache>> cache_list;
    std::unordered_map<std::string, std::vector<std::shared_ptr<track>>> alloc_trace_map;
    std::unordered_map<std::string, std::vector<std::shared_ptr<track>>> free_trace_map;
    size_t max_name_len = 0;
    uint SLAB_RED_ZONE;
    uint SLAB_POISON;
    uint SLAB_STORE_USER;
    uint OBJECT_POISON;
    uint SLAB_KMALLOC;

    // basic func
    void func_call(const std::string& input_str, const std::string& param_name, std::function<void(const std::string&)> func);
    void parser_slab_caches();
    std::vector<std::shared_ptr<kmem_cache_node>> parser_kmem_cache_node(std::shared_ptr<kmem_cache> cache_ptr, ulong node_addr);
    std::vector<std::shared_ptr<kmem_cache_cpu>> parser_kmem_cache_cpu(std::shared_ptr<kmem_cache> cache_ptr, ulong cpu_addr);
    std::vector<std::shared_ptr<slab>> parser_slab_from_list(std::shared_ptr<kmem_cache> cache_ptr, ulong head_addr);
    std::shared_ptr<slab> parser_slab(std::shared_ptr<kmem_cache> cache_ptr, ulong slab_page_addr);

    // print func
    void print_slab_caches();
    void print_slab_summary_info();

    void print_slab_info(std::shared_ptr<slab> slab_ptr);
    void print_slab_cache_info(std::string addr);
    void print_slab_cache(std::shared_ptr<kmem_cache> cache_ptr);

    void print_slub_trace(std::string is_free);
    void print_all_slub_trace(size_t stack_id = 0);
    void print_trace_results(const std::unordered_map<std::string, std::vector<std::shared_ptr<track>>>& trace_map,
                             bool is_free,
                             const std::string& filter_type = "");
    void print_stack_details(size_t stack_id);
    void print_cache_specific_trace(std::string cache_identifier);

    void print_slub_poison(ulong kmem_cache_addr = 0);
    void print_cache_check_result(const SlubCheckResult& result, bool show_all_errors = false);
    void print_corruption_summary(const std::vector<SlubCheckResult>& results);
    std::string print_object_layout(std::shared_ptr<kmem_cache> cache_ptr, std::shared_ptr<obj> obj_ptr,
                            const ObjectCheckResult& obj_result);

    void print_object_trace_by_addr(std::string addr_str);
    void print_object_stack_trace(std::shared_ptr<kmem_cache> cache_ptr, std::shared_ptr<slab> slab_ptr, std::shared_ptr<obj> obj_ptr);

    // Poison
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
    ulong get_free_pointer(std::shared_ptr<kmem_cache> cache_ptr, ulong object_start_addr);
    void check_cache_corruption(std::shared_ptr<kmem_cache> cache_ptr, SlubCheckResult& result);
    void check_slab_list_corruption(std::shared_ptr<kmem_cache> cache_ptr,
                                   const std::vector<std::shared_ptr<slab>>& slab_list,
                                   SlubCheckResult& result);
    void check_single_slab_corruption(std::shared_ptr<kmem_cache> cache_ptr,
                                     std::shared_ptr<slab> slab_ptr,
                                     SlubCheckResult& result);
    bool check_object_detailed(std::shared_ptr<kmem_cache> cache_ptr, ulong page_addr,
                              ulong object_start_addr, uint8_t val, ObjectCheckResult& obj_result);
    bool check_bytes_and_report_detailed(std::shared_ptr<kmem_cache> cache_ptr, ulong page_addr,
                                        ulong obj_start, std::string what, ulong start,
                                        uint8_t value, size_t bytes, ObjectCheckResult& obj_result);
    bool check_pad_bytes_detailed(std::shared_ptr<kmem_cache> cache_ptr, ulong page_addr,
                                 ulong obj_start, ObjectCheckResult& obj_result);

    // Trace
    std::string extract_callstack(ulong frames_addr);
    std::shared_ptr<kmem_cache> find_cache_by_identifier(const std::string& identifier);

    void parser_slub_trace();
    void parser_track(ulong track_addr, std::shared_ptr<track> &track_ptr);
    ulong get_track(std::shared_ptr<kmem_cache> cache_ptr, ulong object_start_addr, uint8_t track_type);
    void parse_cache_traces(std::shared_ptr<kmem_cache> cache_ptr,
                           std::unordered_map<std::string, std::vector<std::shared_ptr<track>>>& alloc_map,
                           std::unordered_map<std::string, std::vector<std::shared_ptr<track>>>& free_map);
    void parse_slab_list_traces(std::shared_ptr<kmem_cache> cache_ptr,
                               const std::vector<std::shared_ptr<slab>>& slab_list,
                               std::unordered_map<std::string, std::vector<std::shared_ptr<track>>>& alloc_map,
                               std::unordered_map<std::string, std::vector<std::shared_ptr<track>>>& free_map);
    void parse_single_slab_traces(std::shared_ptr<kmem_cache> cache_ptr,
                                 std::shared_ptr<slab> slab_ptr,
                                 std::unordered_map<std::string, std::vector<std::shared_ptr<track>>>& alloc_map,
                                 std::unordered_map<std::string, std::vector<std::shared_ptr<track>>>& free_map);

    // find obj by va and print stack
    std::shared_ptr<obj> find_object_by_addr(ulong target_addr, std::shared_ptr<kmem_cache> &found_cache, std::shared_ptr<slab> &found_slab);
    std::shared_ptr<obj> find_object_in_slab(std::shared_ptr<slab> slab_ptr, ulong target_addr);

public:
    Slub();
    void cmd_main(void) override;
    void init_offset(void) override;
    void init_command(void) override;
    DEFINE_PLUGIN_INSTANCE(Slub)
};

#endif // SLUB_DEFS_H_
