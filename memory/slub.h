// Copyright (c) 2024-2025 Qualcomm Innovation Center, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause-Clear

#ifndef SLUB_DEFS_H_
#define SLUB_DEFS_H_

#include "plugin.h"

struct obj {
    int index;
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

class Slub : public PaserPlugin {
public:
    std::vector<std::shared_ptr<kmem_cache>> cache_list;
    Slub();
    ulong max_pfn;
    void cmd_main(void) override;
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
    DEFINE_PLUGIN_INSTANCE(Slub)
};

#endif // SLUB_DEFS_H_
