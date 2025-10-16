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

#include "slub.h"

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wpointer-arith"

#ifndef BUILD_TARGET_TOGETHER
DEFINE_PLUGIN_COMMAND(Slub)
#endif

void Slub::cmd_main(void) {
    int c;
    std::string optarg_str;
    if (argcnt < 2) {
        cmd_usage(pc->curcmd, SYNOPSIS);
        return;
    }
    if (cache_list.size() == 0){
        parser_slab_caches();
    }
    while ((c = getopt(argcnt, args, "asc:pP:t:lT:L:v:")) != EOF) {
        if (optarg) {
            optarg_str.assign(optarg);
        }
        switch(c) {
            case 's':
                print_slab_summary_info();
                break;
            case 'a':
                print_slab_caches();
                break;
            case 'c':
                print_slab_cache_info(optarg_str);
                break;
            case 'p':
                print_slub_poison();
                break;
            case 'P':
                func_call(optarg_str, "kmem_cache_addr", [this](const std::string& s) {
                    print_slub_poison(std::stoul(s, nullptr, 16));
                });
                break;
            case 't':
                print_slub_trace(optarg_str);
                break;
            case 'l':
                print_all_slub_trace();
                break;
            case 'L':
                print_cache_specific_trace(optarg_str);
                break;
            case 'T':
                func_call(optarg_str, "stack_id", [this](const std::string& s) {
                    print_all_slub_trace(std::stoul(s));
                });
                break;
            case 'v':
                print_object_trace_by_addr(optarg_str);
                break;
            default:
                argerrs++;
                break;
        }
    }
    if (argerrs) {
        cmd_usage(pc->curcmd, SYNOPSIS);
    }
}

void Slub::init_offset(void) {
    field_init(kmem_cache, cpu_slab);
    field_init(kmem_cache, flags);
    field_init(kmem_cache, min_partial);
    field_init(kmem_cache, size);
    field_init(kmem_cache, reciprocal_size);
    field_init(kmem_cache, object_size);
    field_init(kmem_cache, offset);
    field_init(kmem_cache, cpu_partial);
    field_init(kmem_cache, oo);
    field_init(kmem_cache, max);
    field_init(kmem_cache, min);
    field_init(kmem_cache, allocflags);
    field_init(kmem_cache, refcount);
    field_init(kmem_cache, inuse);
    field_init(kmem_cache, align);
    field_init(kmem_cache, red_left_pad);
    field_init(kmem_cache, name);
    field_init(kmem_cache, random);
    field_init(kmem_cache, list);
    field_init(kmem_cache, useroffset);
    field_init(kmem_cache, usersize);
    field_init(kmem_cache, node);
    field_init(kmem_cache_node, nr_partial);
    field_init(kmem_cache_node, partial);
    field_init(kmem_cache_node, nr_slabs);
    field_init(kmem_cache_node, total_objects);
    field_init(kmem_cache_node, full);
    field_init(kmem_cache_cpu, freelist);
    field_init(kmem_cache_cpu, tid);
    field_init(kmem_cache_cpu, page);
    field_init(kmem_cache_cpu, partial);
    field_init(kmem_cache_cpu, slab);
    field_init(track, addrs);
    field_init(track, addr);
    field_init(track, cpu);
    field_init(track, pid);
    field_init(track, when);
    field_init(stack_record, next);
    field_init(stack_record, size);
    field_init(stack_record, handle);
    field_init(stack_record, entries);
    field_init(slab, slab_list);
    field_init(slab, counters);
    field_init(slab, freelist);
    field_init(slab, next);
    field_init(track, handle);
    field_init(page, slab_list);
    field_init(page, _mapcount);
    field_init(page, freelist);
    field_init(page, next);
    field_init(page, slab_list);
    field_init(page, counters);
    field_init(page, freelist);
    field_init(page, next);
    field_init(page, flags);

    struct_init(slab);
    struct_init(page);
    struct_init(kmem_cache);
    struct_init(kmem_cache_node);
    struct_init(kmem_cache_cpu);
    struct_init(atomic_t);
    struct_init(track);
    struct_init(stack_record);
    if (get_enumerator_list("_slab_flag_bits").size() > 0){
        SLAB_RED_ZONE = 1U << read_enum_val("_SLAB_RED_ZONE");
        SLAB_POISON = 1U << read_enum_val("_SLAB_POISON");
        SLAB_STORE_USER = 1U << read_enum_val("_SLAB_STORE_USER");
        OBJECT_POISON = 1U << read_enum_val("_SLAB_OBJECT_POISON");
        SLAB_KMALLOC = 1U << read_enum_val("_SLAB_KMALLOC");
    }else{
        SLAB_RED_ZONE = 0x400;
        SLAB_POISON = 0x800;
        SLAB_STORE_USER = 0x10000;
        OBJECT_POISON = 0x80000000;
        SLAB_KMALLOC = 0x00001000;
    }
}

void Slub::init_command(void) {
    cmd_name = "slub";
    help_str_list={
        "slub",                            /* command name */
        "dump slub information",        /* short description */
        "-a \n"
            "  slub -c <kmem_cache_addr>\n"
            "  slub -s\n"
            "  slub -p\n"
            "  slub -P <kmem_cache_addr>\n"
            "  slub -t <A | F>\n"
            "  slub -l\n"
            "  slub -L <kmem_cache_addr>/<kmem_cache_name>\n"
            "  slub -T <stack_id>\n"
            "  slub -v <virtual_addr>\n"
            "  This command provides comprehensive SLUB allocator analysis including\n"
            "  cache information, memory corruption detection, and allocation tracing.",
        "\n",
        "EXAMPLES",
        "  Display all SLUB caches with detailed information:",
        "    %s> slub -a",
        "    kmem_cache:0xffffff80030c6000 inode_cache",
        "       kmem_cache_node:0xffffff80030c5700 nr_partial:280 nr_slabs:6291 total_objects:106947",
        "           slab:0xfffffffe0057f800 order:2 VA:[0xffffff8015fe0000~0xffffff8015fe4000] totalobj:17 inuse:3 freeobj:14",
        "               obj[00001] VA:[0xffffff8015fe0000~0xffffff8015fe03a0] status:freed",
        "               obj[00002] VA:[0xffffff8015fe03a0~0xffffff8015fe0740] status:alloc",
        "\n",
        "  Display specific cache information:",
        "    %s> slub -c 0xffffff80030c6000",
        "    Shows detailed slab and object information for the specified cache",
        "\n",
        "  Display memory usage summary:",
        "    %s> slub -s",
        "    kmem_cache        name                      slabs slab_size    per_slab_obj total_objs obj_size   pad_size align_size total_size",
        "    ffffff80030c6000  inode_cache               6310  (4)16K       17           107270     920        16       928        94.93Mb",
        "    ffffff80030c4500  vm_area_struct            7350  (1)4K        17           124950     232        8        240        28.60Mb",
        "\n",
        "  Perform memory corruption check on all caches:",
        "    %s> slub -p",
        "    SLUB Memory Corruption Check",
        "    ===============================================================",
        "    CACHE: inode_cache (0xffffff80030c6000)",
        "      Objects: 107270 total, 107270 checked",
        "      Result: CLEAN - No corruption detected",
        "      Status: PASS",
        "\n",
        "  Perform detailed corruption check on specific cache:",
        "    %s> slub -P 0xffffff80030c6000",
        "    Shows detailed corruption analysis with memory layout for each corrupted object",
        "\n",
        "  Display allocation/free traces sorted by memory usage:",
        "    %s> slub -t A/F",
        "    stack_id:12856162743170019396 Allocated:164 times kmem_cache:kmalloc-64 size:41.00KB",
        "       [<ffffffff811d4c5a>] __kmalloc+0x12a/0x1b0",
        "       [<ffffffff812a8f3c>] seq_buf_alloc+0x2c/0x60",
        "\n",
        "  Display all allocation and free traces:",
        "    %s> slub -l",
        "    Shows both allocation and free traces for all caches with STORE_USER enabled",
        "\n",
        "  Display traces for specific cache:",
        "    %s> slub -L kmalloc-64/0xffffff80030c6000",
        "    Shows allocation/free traces only for the specified cache",
        "\n",
        "  Display statistics for specific stack trace:",
        "    %s> slub -T 12856162743170019396",
        "    Pid       Freq      Size",
        "    1234      50110     17.20MB",
        "    5678      25055     8.60MB",
        "\n",
        "  Find object by virtual address and show trace:",
        "    %s> slub -v 0xffffff881fc10010",
        "    ================================================================================",
        "    SLUB Object Analysis for Address: 0xffffff881fc10010",
        "    ================================================================================",
        "    KMEM_CACHE:",
        "       Address     : 0xffffff80030c6000",
        "       Name        : inode_cache",
        "    TARGET OBJECT:",
        "       Index       : 1",
        "       Status      : FREED",
        "    STACK TRACE:",
        "       Type        : FREE",
        "       PID         : 123",
        "       Call Stack  :",
        "          [<ffffffff811d4c5a>] kfree+0x12a/0x1b0",
        "\n",
        "NOTES",
        "  - Memory corruption detection requires SLUB debug flags (RED_ZONE, POISON, STORE_USER)",
        "  - Stack tracing requires SLAB_STORE_USER flag to be enabled in the cache",
        "  - Use -P for detailed corruption analysis of specific problematic caches",
        "  - Virtual address lookup (-v) searches through all SLUB objects system-wide",
        "\n",
    };
}

Slub::Slub(){}

void Slub::func_call(const std::string& input_str,
                const std::string& param_name,
                std::function<void(const std::string&)> func) {
    try {
        func(input_str);
    } catch (const std::exception& e) {
        PRINT("Invalid %s: %s\n", param_name.c_str(), input_str.c_str());
        argerrs++;
    }
}

std::shared_ptr<slab> Slub::parser_slab(std::shared_ptr<kmem_cache> cache_ptr, ulong slab_page_addr){
    int count = 0;
    unsigned int obj_index = 0;
    ulong freelist = 0;
    void *page_buf = nullptr;
    if (!is_kvaddr(slab_page_addr)){
        return nullptr;
    }
    if (struct_size(slab) != -1){
        page_buf = read_struct(slab_page_addr,"slab");
    }else{
        page_buf = read_struct(slab_page_addr,"page");
    }
    if(page_buf == nullptr) return nullptr;
    std::shared_ptr<slab> slab_ptr = std::make_shared<slab>();
    if (struct_size(slab) != -1){
        count = ULONG(page_buf + field_offset(slab,counters));
        freelist = ULONG(page_buf + field_offset(slab,freelist));
    } else {
        count = ULONG(page_buf + field_offset(page,counters)); // _mapcount
        freelist = ULONG(page_buf + field_offset(page,freelist));
    }
    FREEBUF(page_buf);
    slab_ptr->totalobj = (count >> 16) & 0x00007FFF;
    slab_ptr->inuse = count & 0x0000FFFF;
    slab_ptr->freeobj = slab_ptr->totalobj - slab_ptr->inuse;
    slab_ptr->order = cache_ptr->page_order;
    slab_ptr->first_page = slab_page_addr;
    // get all free obj status
    int obj_free[slab_ptr->totalobj] = {0};
    physaddr_t slab_paddr = page_to_phy(slab_page_addr);
    ulong slab_vaddr = phy_to_virt(slab_paddr);
    ulong fobj = freelist;
    while (is_kvaddr(fobj)){
        obj_index = (fobj - slab_vaddr) / cache_ptr->size;
        if (obj_index < 0 || obj_index >= slab_ptr->totalobj || obj_free[obj_index] == 1){
            /* obj_free[obj_index] == 1: start of fobj pointed to end of fobj, end of fobj pointed to start of fobj*/
            PRINT("Invalid obj_index: %d\n", obj_index);
            break;
        }
        obj_free[obj_index] = 1;
        fobj = get_free_pointer(cache_ptr, fobj);
    }
    for (ulong obj_addr = slab_vaddr; obj_addr < slab_vaddr + slab_ptr->totalobj * cache_ptr->size; obj_addr += cache_ptr->size) {
        int obj_index = (obj_addr - slab_vaddr) / cache_ptr->size;

        std::shared_ptr<obj> obj_ptr = std::make_shared<obj>();
        obj_ptr->index = obj_index + 1;
        obj_ptr->start = obj_addr;
        obj_ptr->end = obj_addr + cache_ptr->size;
        obj_ptr->is_free = (obj_free[obj_index] == 1 ? true : false);
        slab_ptr->obj_list.push_back(obj_ptr);
    }
    return slab_ptr;
}

std::vector<std::shared_ptr<slab>> Slub::parser_slab_from_list(std::shared_ptr<kmem_cache> cache_ptr, ulong head_addr){
    std::vector<std::shared_ptr<slab>> slab_list;
    std::vector<ulong> temp_list;
    int offset = 0;
    if (struct_size(slab) == -1){
        offset = field_offset(page,slab_list);
    }else{
        offset = field_offset(slab,slab_list);
    }
    std::vector<ulong> page_list = for_each_list(head_addr,offset);
    for (const auto& slab_page_addr : page_list) {
        if (std::find(temp_list.begin(), temp_list.end(), slab_page_addr) != temp_list.end()) continue;
        temp_list.push_back(slab_page_addr);
        std::shared_ptr<slab> slab_ptr = parser_slab(cache_ptr,slab_page_addr);
        slab_list.push_back(slab_ptr);
    }
    return slab_list;
}

std::vector<std::shared_ptr<kmem_cache_node>> Slub::parser_kmem_cache_node(std::shared_ptr<kmem_cache> cache_ptr, ulong node_addr){
    std::vector<std::shared_ptr<kmem_cache_node>> node_list;
    int node_cnt = field_size(kmem_cache,node)/sizeof(void *);
    for (int i = 0; i < node_cnt; i++){
        ulong addr = read_pointer((node_addr + i * sizeof(void *)),"kmem_cache_node addr");
        if (!is_kvaddr(addr))continue;
        void *node_buf = read_struct(addr,"kmem_cache_node");
        if(node_buf == nullptr) continue;
        std::shared_ptr<kmem_cache_node> node_ptr = std::make_shared<kmem_cache_node>();
        node_ptr->addr = addr;
        node_ptr->nr_partial = ULONG(node_buf + field_offset(kmem_cache_node,nr_partial));
        node_ptr->nr_slabs = ULONG(node_buf + field_offset(kmem_cache_node,nr_slabs));
        node_ptr->total_objects = ULONG(node_buf + field_offset(kmem_cache_node,total_objects));
        FREEBUF(node_buf);
        ulong partial_addr = addr + field_offset(kmem_cache_node,partial);
        node_ptr->partial = parser_slab_from_list(cache_ptr,partial_addr);
        ulong full_addr = addr + field_offset(kmem_cache_node,full);
        node_ptr->full = parser_slab_from_list(cache_ptr,full_addr);
        node_list.push_back(node_ptr);
    }
    return node_list;
}

std::vector<std::shared_ptr<kmem_cache_cpu>> Slub::parser_kmem_cache_cpu(std::shared_ptr<kmem_cache> cache_ptr, ulong cpu_addr){
    std::vector<std::shared_ptr<kmem_cache_cpu>> cpu_list;
    if ((kt->flags & SMP) && (kt->flags & PER_CPU_OFF)) {
        for (size_t i = 0; i < NR_CPUS; i++) {
            if (!kt->__per_cpu_offset[i])
                continue;
            ulong addr = cpu_addr + kt->__per_cpu_offset[i];
            if (!is_kvaddr(addr)) continue;
            void *cpu_buf = read_struct(addr,"kmem_cache_cpu");
            if(cpu_buf == nullptr) continue;
            std::shared_ptr<kmem_cache_cpu> cpu_ptr = std::make_shared<kmem_cache_cpu>();
            cpu_ptr->addr = addr;
            cpu_ptr->tid = ULONG(cpu_buf + field_offset(kmem_cache_cpu,tid));
            ulong cur_slab_addr = 0;
            if (struct_size(slab) != -1){
                cur_slab_addr = ULONG(cpu_buf + field_offset(kmem_cache_cpu,slab));
            }else{
                cur_slab_addr = ULONG(cpu_buf + field_offset(kmem_cache_cpu,page));
            }
            cpu_ptr->cur_slab = parser_slab(cache_ptr,cur_slab_addr);
            ulong partial_addr = ULONG(cpu_buf + field_offset(kmem_cache_cpu,partial));
            ulong slab_page_addr = partial_addr;
            while (is_kvaddr(slab_page_addr)){
                std::shared_ptr<slab> slab_ptr = parser_slab(cache_ptr,slab_page_addr);
                cpu_ptr->partial.push_back(slab_ptr);
                if (struct_size(slab) != -1){
                    slab_page_addr = read_structure_field(slab_page_addr,"slab","next");
                }else{
                    slab_page_addr = read_structure_field(slab_page_addr,"page","next");
                }
            }
            FREEBUF(cpu_buf);
            cpu_list.push_back(cpu_ptr);
        }
    }
    return cpu_list;
}

void Slub::parser_slab_caches(){
    cache_list.clear();
    if (!depot_index){
        PRINT("cannot get depot_index\n");
        return;
    }
    if (!stack_slabs){
        PRINT("cannot get stack_{pools|slabs}\n");
        return;
    }
    if (!csymbol_exists("slab_caches")){
        PRINT("slab_caches doesn't exist in this kernel!\n");
        return;
    }
    ulong slab_caches_addr = csymbol_value("slab_caches");
    if (!is_kvaddr(slab_caches_addr)){
        PRINT("invaild slab_caches addr: %#lx!\n",slab_caches_addr);
        return;
    }
    int offset = field_offset(kmem_cache,list);
    for (const auto& cache_addr : for_each_list(slab_caches_addr,offset)) {
        void *cache_buf = read_struct(cache_addr,"kmem_cache");
        if(cache_buf == nullptr) continue;
        std::shared_ptr<kmem_cache> cache_ptr = std::make_shared<kmem_cache>();
        cache_ptr->addr = cache_addr;
        cache_ptr->flags = UINT(cache_buf + field_offset(kmem_cache,flags));
        cache_ptr->min_partial = ULONG(cache_buf + field_offset(kmem_cache,min_partial));
        cache_ptr->size = UINT(cache_buf + field_offset(kmem_cache,size));
        cache_ptr->object_size = UINT(cache_buf + field_offset(kmem_cache,object_size));
        cache_ptr->offset = UINT(cache_buf + field_offset(kmem_cache,offset));
        cache_ptr->cpu_partial = UINT(cache_buf + field_offset(kmem_cache,cpu_partial));
        cache_ptr->oo = UINT(cache_buf + field_offset(kmem_cache,oo));
        cache_ptr->per_slab_obj = cache_ptr->oo & 0x0000FFFF;
        cache_ptr->page_order = cache_ptr->oo >> 16;
        cache_ptr->max = UINT(cache_buf + field_offset(kmem_cache,max));
        cache_ptr->min = UINT(cache_buf + field_offset(kmem_cache,min));
        cache_ptr->allocflags = UINT(cache_buf + field_offset(kmem_cache,allocflags));
        cache_ptr->refcount = INT(cache_buf + field_offset(kmem_cache,refcount));
        cache_ptr->inuse = UINT(cache_buf + field_offset(kmem_cache,inuse));
        cache_ptr->align = UINT(cache_buf + field_offset(kmem_cache,align));
        cache_ptr->red_left_pad = UINT(cache_buf + field_offset(kmem_cache,red_left_pad));
        cache_ptr->useroffset = UINT(cache_buf + field_offset(kmem_cache,useroffset));
        cache_ptr->usersize = UINT(cache_buf + field_offset(kmem_cache,usersize));
        cache_ptr->name = read_cstring(ULONG(cache_buf + field_offset(kmem_cache,name)),64, "kmem_cache_name");
        cache_ptr->random = ULONG(cache_buf + field_offset(kmem_cache,random));
        ulong node_addr = cache_addr + field_offset(kmem_cache,node);
        cache_ptr->node_list = parser_kmem_cache_node(cache_ptr,node_addr);
        ulong cpu_slab_addr = ULONG(cache_buf + field_offset(kmem_cache,cpu_slab));
        cache_ptr->cpu_slabs = parser_kmem_cache_cpu(cache_ptr,cpu_slab_addr);
        FREEBUF(cache_buf);
        cache_list.push_back(cache_ptr);
    }
    for (const auto& cache_ptr : cache_list) {
        max_name_len = std::max(max_name_len, cache_ptr->name.length());
        for (const auto& node_ptr : cache_ptr->node_list) {
            // count by kernel
            cache_ptr->total_nr_slabs += node_ptr->nr_slabs;
            cache_ptr->total_nr_objs += node_ptr->total_objects;
        }
        for (const auto& cpu_ptr : cache_ptr->cpu_slabs) {
            for (const auto& slab_ptr : cpu_ptr->partial) {
                cache_ptr->total_nr_slabs += 1;
                cache_ptr->total_nr_objs += slab_ptr->totalobj;
            }
            if (cpu_ptr->cur_slab != nullptr){
                cache_ptr->total_nr_slabs += 1;
                cache_ptr->total_nr_objs += cpu_ptr->cur_slab->totalobj;
            }
        }
        cache_ptr->total_size = cache_ptr->total_nr_objs * cache_ptr->size;
    }
    max_name_len += 5;
    LOGD("Total kmem_cache: %zd\n", cache_list.size());
}

/* Poison */
unsigned int Slub::size_from_object(std::shared_ptr<kmem_cache> cache_ptr){
    if (cache_ptr->flags & SLAB_RED_ZONE) {
        return cache_ptr->size - cache_ptr->red_left_pad;
    }
    return cache_ptr->size;
}

bool Slub::check_valid_pointer(std::shared_ptr<kmem_cache> cache_ptr, ulong page_addr, ulong object_start){
    if(!is_kvaddr(object_start))
        return true;
    ulong slab_vaddr = phy_to_virt(page_to_phy(page_addr));
    ulong object = restore_red_left(cache_ptr, object_start);
    ulong count;
    if (struct_size(slab) == -1){
        count = read_ulong(page_addr + field_offset(page, counters), "page counters");
    } else {
        count = read_ulong(page_addr + field_offset(slab, counters), "slab counters");
    }
    ulong objects = (count >> 16) & 0x00007FFF;
    if((object < slab_vaddr) || (object >= slab_vaddr + objects * cache_ptr->size) || ((object - slab_vaddr) % cache_ptr->size))
        return false;
    return true;
}

ulong Slub::restore_red_left(std::shared_ptr<kmem_cache> cache_ptr, ulong object_start){
    if (cache_ptr->flags & SLAB_RED_ZONE) {
        object_start -= cache_ptr->red_left_pad;
    }
    return object_start;
}

unsigned int Slub::get_orig_size(std::shared_ptr<kmem_cache> cache_ptr){
    if(!slub_debug_orig_size(cache_ptr))
        return cache_ptr->object_size;
    unsigned int p = get_info_end(cache_ptr);
    p += struct_size(track) * 2;
    return p;
}

bool Slub::slub_debug_orig_size(std::shared_ptr<kmem_cache> cache_ptr){
    return (cache_ptr->flags & SLAB_STORE_USER) && (cache_ptr->flags & SLAB_KMALLOC);
}

ulong Slub::check_bytes8(ulong start, uint8_t value, size_t bytes){
    while (bytes) {
        if (read_byte(start,"check_bytes8") != value) {
            return start;
        }
        start++;
        bytes--;
    }
    return 0;
}

/**
 * Finds the first byte in the specified memory region that is not equal to the given value.
 * @param start_addr The starting memory address.
 * @param c The byte value to compare against.
 * @param bytes The size of the memory region (in bytes).
 * @return The address of the first byte that is not equal to c; returns 0 if all bytes are equal to c.
 */
ulong Slub::memchr_inv(ulong start_addr, uint8_t c, size_t bytes) {
    if (bytes == 0) return 0;
    uint8_t value = c;
    if (bytes <= 16) {
        return check_bytes8(start_addr, value, bytes);
    }
    uint64_t value64 = value;
    value64 |= value64 << 8;
    value64 |= value64 << 16;
    value64 |= value64 << 32;
    ulong prefix = start_addr & 7;
    if (prefix) {
        prefix = 8 - prefix;
        if (prefix > bytes) prefix = bytes;

        ulong r = check_bytes8(start_addr, value, prefix);
        if (r) return r;
        start_addr += prefix;
        bytes -= prefix;
    }
    while (bytes >= 8) {
        if (read_ulonglong(start_addr, "memchr_inv") != value64) {
            return check_bytes8(start_addr, value, 8);
        }
        start_addr += 8;
        bytes -= 8;
    }
    return check_bytes8(start_addr, value, bytes);
}

// return addr is real obj addr, not include left zone
ulong Slub::fixup_red_left(std::shared_ptr<kmem_cache> cache_ptr, ulong object_start_addr){
    if(cache_ptr->flags & SLAB_RED_ZONE){
        object_start_addr += cache_ptr->red_left_pad;
    }
    return object_start_addr;
}

bool Slub::freeptr_outside_object(std::shared_ptr<kmem_cache> cache_ptr){
    return cache_ptr->offset >= cache_ptr->inuse;
}

unsigned int Slub::get_info_end(std::shared_ptr<kmem_cache> cache_ptr){
    if(freeptr_outside_object(cache_ptr)){
        return cache_ptr->inuse + sizeof(void *);
    } else {
        return cache_ptr->inuse;
    }
}

ulong Slub::get_free_pointer(std::shared_ptr<kmem_cache> cache_ptr, ulong object_start_addr){
    ulong ptr_addr = object_start_addr + cache_ptr->offset;
    ulong ptr = read_pointer(ptr_addr, "obj freeptr");
    if (BITS64()){
        ptr_addr = swap64(ptr_addr, 1);
    }else{
        ptr_addr = swap32(ptr_addr, 1);
    }
    if (get_config_val("CONFIG_SLAB_FREELIST_HARDENED") == "y") {
        return ptr ^ cache_ptr->random ^ ptr_addr;
    } else {
        return ptr;
    }
}

/* Slub Trace*/
std::string Slub::extract_callstack(ulong frames_addr){
    struct syment *sp;
    ulong offset;
    std::ostringstream oss;
    if (is_kvaddr(frames_addr)){
        sp = value_search(frames_addr, &offset);
        if (sp){
            oss << "   [<" << std::hex << frames_addr << ">] " << sp->name << "+" << std::hex << offset << std::dec << "\n";
        } else {
            oss << "   [<" << std::hex << frames_addr << ">] Unknown, Maybe should load module symbol\n";
        }
    }
    return oss.str();
}

void Slub::parser_slub_trace() {
    if (trace_parsed) return;
    alloc_trace_map.clear();
    free_trace_map.clear();
    std::ostringstream oss;
    for (const auto& cache_ptr : cache_list) {
        if ((cache_ptr->flags & SLAB_STORE_USER) == 0) {
            continue;
        }
        parse_cache_traces(cache_ptr, alloc_trace_map, free_trace_map);
        oss.str("");
        oss.clear();
        oss << std::left << std::setw(max_name_len) << cache_ptr->name << "Done\n";
        PRINT("%s", oss.str().c_str());
    }
    trace_parsed = true;
}

void Slub::parse_cache_traces(std::shared_ptr<kmem_cache> cache_ptr,
                             std::unordered_map<std::string, std::vector<std::shared_ptr<track>>>& alloc_map,
                             std::unordered_map<std::string, std::vector<std::shared_ptr<track>>>& free_map) {
    // slab in node
    for (const auto& node_ptr : cache_ptr->node_list) {
        parse_slab_list_traces(cache_ptr, node_ptr->partial, alloc_map, free_map);
        parse_slab_list_traces(cache_ptr, node_ptr->full, alloc_map, free_map);
    }
    // slab in cpu
    for (const auto& cpu_ptr : cache_ptr->cpu_slabs) {
        parse_slab_list_traces(cache_ptr, cpu_ptr->partial, alloc_map, free_map);
        if (cpu_ptr->cur_slab) {
            parse_single_slab_traces(cache_ptr, cpu_ptr->cur_slab, alloc_map, free_map);
        }
    }
}

void Slub::parse_slab_list_traces(std::shared_ptr<kmem_cache> cache_ptr,
                                 const std::vector<std::shared_ptr<slab>>& slab_list,
                                 std::unordered_map<std::string, std::vector<std::shared_ptr<track>>>& alloc_map,
                                 std::unordered_map<std::string, std::vector<std::shared_ptr<track>>>& free_map) {
    for (const auto& slab_ptr : slab_list) {
        parse_single_slab_traces(cache_ptr, slab_ptr, alloc_map, free_map);
    }
}

void Slub::parse_single_slab_traces(std::shared_ptr<kmem_cache> cache_ptr,
                                   std::shared_ptr<slab> slab_ptr,
                                   std::unordered_map<std::string, std::vector<std::shared_ptr<track>>>& alloc_map,
                                   std::unordered_map<std::string, std::vector<std::shared_ptr<track>>>& free_map) {
    for (const auto& obj : slab_ptr->obj_list) {
        auto track_ptr = std::make_shared<track>();
        track_ptr->kmem_cache_ptr = cache_ptr;
        track_ptr->obj_addr = obj->start;
        track_ptr->trackp = get_track(cache_ptr, obj->start, obj->is_free ? TRACK_FREE : TRACK_ALLOC);
        parser_track(track_ptr->trackp, track_ptr);

        if (!track_ptr->frame.empty()) {
            if (obj->is_free) {
                free_map[track_ptr->frame].push_back(track_ptr);
            } else {
                alloc_map[track_ptr->frame].push_back(track_ptr);
            }
        }
    }
}

void Slub::print_trace_results(const std::unordered_map<std::string, std::vector<std::shared_ptr<track>>>& trace_map,
                               bool is_free,
                               const std::string& filter_type) {
    if (trace_map.empty()) return;
    // sort by times
    std::vector<std::pair<std::string, std::vector<std::shared_ptr<track>>>> sorted_traces(trace_map.begin(), trace_map.end());
    // Sort callstacks by mem, highest first
    std::sort(sorted_traces.begin(), sorted_traces.end(),
              [](const auto& a, const auto& b) {
                    if (a.second.empty() || b.second.empty()) return false;
                    size_t size_a = a.second.size() * a.second[0]->kmem_cache_ptr->size;
                    size_t size_b = b.second.size() * b.second[0]->kmem_cache_ptr->size;
                    return size_a > size_b;
              });
    for (const auto& trace_pair : sorted_traces) {
        const auto& frame = trace_pair.first;
        const auto& track_vec = trace_pair.second;
        if (track_vec.empty()) continue;
        size_t hash_value = std::hash<std::string>{}(frame);
        size_t total_size = track_vec.size() * track_vec[0]->kmem_cache_ptr->size;
        PRINT("stack_id:%zu %s:%zd times kmem_cache:%s size:%s\n",
                hash_value,
                is_free ? "Freed" : "Allocated",
                track_vec.size(),
                track_vec[0]->kmem_cache_ptr->name.c_str(),
                csize(total_size).c_str());
        PRINT("%s \n", track_vec[0]->frame.c_str());
    }
}

void Slub::print_slub_trace(std::string trace_type) {
    parser_slub_trace();
    if (trace_type == "A" || trace_type == "a") {
        print_trace_results(alloc_trace_map, false);
    } else if (trace_type == "F" || trace_type == "f") {
        print_trace_results(free_trace_map, true);
    } else {
        PRINT("Invalid trace type: %s (use A for alloc, F for free)\n", trace_type.c_str());
    }
}

void Slub::print_all_slub_trace(size_t stack_id) {
    parser_slub_trace();
    if (stack_id == 0) {
        // all trace
        print_trace_results(alloc_trace_map, false);
        print_trace_results(free_trace_map, true);
    } else {
        print_stack_details(stack_id);
    }
}

void Slub::print_cache_specific_trace(std::string cache_identifier) {
    auto target_cache = find_cache_by_identifier(cache_identifier);
    if (!target_cache) {
        PRINT("Cache not found: %s\n", cache_identifier.c_str());
        return;
    }
    if ((target_cache->flags & SLAB_STORE_USER) == 0) {
        return;
    }
    std::unordered_map<std::string, std::vector<std::shared_ptr<track>>> local_alloc_map;
    std::unordered_map<std::string, std::vector<std::shared_ptr<track>>> local_free_map;

    PRINT("%s Parsing\n", target_cache->name.c_str());
    parse_cache_traces(target_cache, local_alloc_map, local_free_map);
    PRINT("%s Done\n", target_cache->name.c_str());

    print_trace_results(local_alloc_map, false);
    print_trace_results(local_free_map, true);
}

std::shared_ptr<kmem_cache> Slub::find_cache_by_identifier(const std::string& identifier) {
    // find cache by addr
    try {
        ulong cache_addr = std::stoul(identifier, nullptr, 16);
        for (const auto& cache_ptr : cache_list) {
            if (cache_ptr->addr == cache_addr) {
                return cache_ptr;
            }
        }
    } catch (...) {
        // find cache by name
        for (const auto& cache_ptr : cache_list) {
            if (cache_ptr->name == identifier) {
                return cache_ptr;
            }
        }
    }
    return nullptr;
}

/* Print Slub Trace*/
void Slub::print_stack_details(size_t stack_id) {
    parser_slub_trace();
    /**
     * search for a specific stack_id in trace maps
     */
    auto find_by_hash = [&](const auto& trace_map) -> std::pair<std::string, std::vector<std::shared_ptr<track>>> {
         for (const auto& trace_pair : trace_map) {
            const auto& frame = trace_pair.first; // Call stack string
            const auto& tracks = trace_pair.second;  // Track records for this call stack
            if (std::hash<std::string>{}(frame) == stack_id) {
                return {frame, tracks};
            }
        }
        return {"", {}};
    };
    auto result = find_by_hash(alloc_trace_map);
    if (result.first.empty()) {
        // If not found in alloc map, search in free trace map
        result = find_by_hash(free_trace_map);
    }
    if (result.first.empty()) {
        PRINT("No such stack_id: %zu\n", stack_id);
        return;
    }
    /**
     * Key: PID (Process ID)
     * Value: pair<freq, total_size>
     */
    std::map<int, std::pair<int, size_t>> pid_stats; // pid -> {count, total_size}
    for (const auto& track_ptr : result.second) {
        pid_stats[track_ptr->pid].first++;
        pid_stats[track_ptr->pid].second += track_ptr->kmem_cache_ptr->size;
    }
    /**
     * Use multimap to sort by freq
     * Key: freq
     * Value: pair<pid, size>
     */
    std::multimap<int, std::pair<int, size_t>, std::greater<int>> freq_sorted_stats;
    for (const auto& pid_pair : pid_stats) {
        const auto& pid = pid_pair.first;
        const auto& stats = pid_pair.second;
        int freq = stats.first;
        size_t size = stats.second;
        // Use freq as key for automatic sort
        freq_sorted_stats.emplace(freq, std::make_pair(pid, size));
    }
    // Output sorted by freq
    std::ostringstream oss;
    oss << std::left << std::setw(10) << "Pid"
        << std::setw(10) << "Freq"
        << std::setw(15) << "Size" << "\n";
    for (const auto& entry : freq_sorted_stats) {
        int freq = entry.first;
        int pid = entry.second.first;
        size_t size = entry.second.second;
        oss << std::left << std::setw(10) << pid
            << std::setw(10) << freq
            << std::setw(15) << csize(size) << "\n";
    }
    PRINT("%s", oss.str().c_str());
}

void Slub::parser_track(ulong track_addr, std::shared_ptr<track>& track_ptr){
    void* track_buf = read_struct(track_addr, "track");
    track_ptr->cpu = UINT(track_buf + field_offset(track, cpu));
    track_ptr->pid = std::max(0U, UINT(track_buf + field_offset(track, pid)));
    track_ptr->when = ULONG(track_buf + field_offset(track, when));
    FREEBUF(track_buf);
    if (field_offset(track, handle) != -1 /*&&
    (get_config_val("CONFIG_STACKDEPOT") == "y") &&
    read_pointer(csymbol_value("stack_depot_disabled"), "stack_depot_disabled") == 0*/){
        ulong handle_parts_addr = track_addr + field_offset(track, handle);
        uint handle = read_uint(handle_parts_addr, "track handle");
        std::shared_ptr<stack_record_t> record_ptr = get_stack_record(handle);
        if (record_ptr != nullptr){
            track_ptr->frame += get_call_stack(record_ptr);
        }
    } else {
        ulong track_addrs_addr = track_addr + field_offset(track, addrs);
        uint frame_size = field_size(track, addrs) / sizeof(unsigned long);
        if(is_kvaddr(track_addrs_addr) && frame_size <= 16){
            for(uint i = 0; i < frame_size; i++){
                ulong frame_addr = read_pointer(track_addrs_addr + sizeof(unsigned long) * i, "frame_addr");
                if(is_kvaddr(frame_addr)){
                    track_ptr->frame += extract_callstack(frame_addr);
                }
            }
        }
    }
}

ulong Slub::get_track(std::shared_ptr<kmem_cache> cache_ptr, ulong object_start_addr, uint8_t track_type){
    unsigned int track_size = struct_size(track);
    return object_start_addr + cache_ptr->red_left_pad + get_info_end(cache_ptr) + track_type * track_size;
}

/* Print Poison Info*/
void Slub::print_slub_poison(ulong kmem_cache_addr){
    std::vector<SlubCheckResult> results;
    bool is_single_cache = (kmem_cache_addr != 0);

    PRINT("SLUB Memory Corruption Check\n");
    PRINT("===============================================================\n");

    for (const auto& cache_ptr : cache_list) {
        if (kmem_cache_addr != 0 && cache_ptr->addr != kmem_cache_addr) {
            continue;
        }
        SlubCheckResult result;
        result.cache_name = cache_ptr->name;
        result.cache_addr = cache_ptr->addr;

        check_cache_corruption(cache_ptr, result);
        results.push_back(result);

        // For single cache (-P), show all errors; for all caches (-p), limit errors
        print_cache_check_result(result, is_single_cache);
    }
    // Only display summary for -p option (all caches), not for -P option (single cache)
    if (!is_single_cache) {
        print_corruption_summary(results);
    }
}

void Slub::check_cache_corruption(std::shared_ptr<kmem_cache> cache_ptr, SlubCheckResult& result) {
    // Check if corruption detection is supported
    if ((cache_ptr->flags & (SLAB_RED_ZONE | SLAB_POISON | SLAB_STORE_USER)) == 0) {
        result.errors.push_back("No corruption detection enabled (missing debug flags)");
        return;
    }
    // Traverse all slabs for checking
    for (const auto& node_ptr : cache_ptr->node_list) {
        check_slab_list_corruption(cache_ptr, node_ptr->partial, result);
        check_slab_list_corruption(cache_ptr, node_ptr->full, result);
    }
    for (const auto& cpu_ptr : cache_ptr->cpu_slabs) {
        check_slab_list_corruption(cache_ptr, cpu_ptr->partial, result);
        if (cpu_ptr->cur_slab) {
            check_single_slab_corruption(cache_ptr, cpu_ptr->cur_slab, result);
        }
    }
    result.overall_result = (result.corrupted_objects == 0);
}

void Slub::check_slab_list_corruption(std::shared_ptr<kmem_cache> cache_ptr,
                                     const std::vector<std::shared_ptr<slab>>& slab_list,
                                     SlubCheckResult& result) {
    for (const auto& slab_ptr : slab_list) {
        check_single_slab_corruption(cache_ptr, slab_ptr, result);
    }
}

void Slub::check_single_slab_corruption(std::shared_ptr<kmem_cache> cache_ptr,
                                       std::shared_ptr<slab> slab_ptr,
                                       SlubCheckResult& result) {
    if (!slab_ptr) return;
    for (const auto& obj : slab_ptr->obj_list) {
        result.total_objects++;
        result.checked_objects++;

        ObjectCheckResult obj_result;
        bool obj_ok = check_object_detailed(cache_ptr, slab_ptr->first_page,
                                           obj->start, obj->is_free ? SLUB_RED_INACTIVE : SLUB_RED_ACTIVE,
                                           obj_result);

        if (!obj_ok) {
            result.corrupted_objects++;
            result.overall_result = false;
            result.redzone_errors += obj_result.redzone_errors;
            result.poison_errors += obj_result.poison_errors;
            result.freeptr_errors += obj_result.freeptr_errors;
            result.padding_errors += obj_result.padding_errors;

            std::ostringstream oss;
            ulong obj_with_redzone = obj->start;
            ulong obj_data_start = fixup_red_left(cache_ptr, obj->start);
            oss << "Object corruption detected: ";
            oss << "Index: " << std::dec << obj->index;
            oss << " | Full Object: " << std::hex << obj_with_redzone;
            oss << " | Data Start: " << std::hex << obj_data_start;
            oss << " | Size: " << std::dec << cache_ptr->size << " bytes";
            // if (cache_ptr->flags & SLAB_RED_ZONE) {
            //     oss << " (Red Zone: " << cache_ptr->red_left_pad << " bytes)";
            // }
            result.errors.push_back(oss.str());
            // Add memory layout
            result.errors.push_back(print_object_layout(cache_ptr, obj, obj_result));
            // Add aligned error details
            for (const auto& detail : obj_result.details) {
                result.errors.push_back("        " + detail);
            }
        }
    }
}

bool Slub::check_object_detailed(std::shared_ptr<kmem_cache> cache_ptr, ulong page_addr,
                                ulong object_start_addr, uint8_t val, ObjectCheckResult& obj_result) {
    ulong object = fixup_red_left(cache_ptr, object_start_addr);
    ulong p = object;
    ulong endobject = object + cache_ptr->object_size;
    bool ret = true;
    // Red Zone check
    if (cache_ptr->flags & SLAB_RED_ZONE) {
        // Left Red Zone check
        if (!check_bytes_and_report_detailed(cache_ptr, page_addr, object, "Left Redzone",
                                            object - cache_ptr->red_left_pad, val, cache_ptr->red_left_pad, obj_result)) {
            ret = false;
            obj_result.left_redzone_errors++;
            obj_result.redzone_errors++;
        }
        // Right Red Zone check
        if (!check_bytes_and_report_detailed(cache_ptr, page_addr, object, "Right Redzone",
                                            endobject, val, cache_ptr->inuse - cache_ptr->object_size, obj_result)) {
            ret = false;
            obj_result.right_redzone_errors++;
            obj_result.redzone_errors++;
        }
        // kmalloc Redzone check
        if(slub_debug_orig_size(cache_ptr) && val == SLUB_RED_ACTIVE){
            unsigned int orig_size_offset = get_orig_size(cache_ptr);
            unsigned int orig_size = read_int(object + orig_size_offset, "orig_size");
            if(cache_ptr->object_size > orig_size &&
                !check_bytes_and_report_detailed(cache_ptr, page_addr, object, "kmalloc Redzone",
                                                p + orig_size, val, cache_ptr->object_size - orig_size, obj_result)){
                ret = false;
                obj_result.redzone_errors++;
            }
        }
    } else {
        // Alignment padding check when no red zone
        if((cache_ptr->flags & SLAB_POISON) && (cache_ptr->object_size < cache_ptr->inuse)){
            if (!check_bytes_and_report_detailed(cache_ptr, page_addr, object, "Alignment padding",
                                                endobject, POISON_INUSE, cache_ptr->inuse - cache_ptr->object_size, obj_result)) {
                ret = false;
                obj_result.padding_errors++;
            }
        }
    }
    // Poison check
    if (cache_ptr->flags & SLAB_POISON) {
        if ((val != SLUB_RED_ACTIVE) && (cache_ptr->flags & OBJECT_POISON)) {
            // Main object poison check
            if (!check_bytes_and_report_detailed(cache_ptr, page_addr, object, "Object Poison",
                                                p, POISON_FREE, cache_ptr->object_size - 1, obj_result)) {
                ret = false;
                obj_result.poison_errors++;
            }
            // End poison byte check
            if (!check_bytes_and_report_detailed(cache_ptr, page_addr, object, "End Poison",
                                                p + cache_ptr->object_size - 1, POISON_END, 1, obj_result)) {
                ret = false;
                obj_result.poison_errors++;
            }
        }
        // Padding check
        if (!check_pad_bytes_detailed(cache_ptr, page_addr, p, obj_result)) {
            ret = false;
            obj_result.padding_errors++;
        }
    }
    // Free Pointer check
    if ((freeptr_outside_object(cache_ptr) || (val != SLUB_RED_ACTIVE)) &&
        !check_valid_pointer(cache_ptr, page_addr, get_free_pointer(cache_ptr, p))) {
        ret = false;
        obj_result.freeptr_errors++;
        // Get detailed free pointer information
        ulong freeptr = get_free_pointer(cache_ptr, p);
        ulong freeptr_addr = p + cache_ptr->offset;
        std::ostringstream oss;
        oss << "Free pointer corruption: addr=" << std::hex << freeptr_addr
            << ", value=" << std::hex << freeptr << " (invalid)";
        obj_result.details.push_back(oss.str());
    }
    return ret;
}

bool Slub::check_bytes_and_report_detailed(std::shared_ptr<kmem_cache> cache_ptr, ulong page_addr,
                                          ulong obj_start, std::string what, ulong start,
                                          uint8_t value, size_t bytes, ObjectCheckResult& obj_result) {
    ulong fault = memchr_inv(start, value, bytes);
    if (!is_kvaddr(fault)) {
        return true;
    }
    // Get the actual corrupted byte value
    uint8_t actual_byte = read_byte(fault, "check_bytes_and_report_detailed");
    // Calculate offset from slab start for better debugging
    ulong slab_vaddr = phy_to_virt(page_to_phy(page_addr));
    ulong offset_in_slab = fault - slab_vaddr;
    // Find the end of corruption
    ulong end = start + bytes;
    while (end > fault && read_byte(end - 1, "check_bytes_and_report_detailed") == value) {
        end -= 1;
    }
    std::ostringstream oss;
    oss << what << " corruption: " << std::hex << fault << "-" << (end - 1)
        << " @offset=" << offset_in_slab
        << ". Expected: 0x" << std::hex << (int)value
        << ", Found: 0x" << std::hex << (int)actual_byte;
    obj_result.details.push_back(oss.str());
    return false;
}

bool Slub::check_pad_bytes_detailed(std::shared_ptr<kmem_cache> cache_ptr, ulong page_addr,
                                   ulong obj_start, ObjectCheckResult& obj_result) {
    unsigned int off = get_info_end(cache_ptr);
    if (cache_ptr->flags & SLAB_STORE_USER) {
        off += 2 * struct_size(track);
        if(cache_ptr->flags & SLAB_KMALLOC){
            off += sizeof(unsigned int);
        }
    }
    if(size_from_object(cache_ptr) == off){
        return true;
    }
    return check_bytes_and_report_detailed(cache_ptr, page_addr, obj_start, "Object Padding",
                                          obj_start + off, POISON_INUSE,
                                          size_from_object(cache_ptr) - off, obj_result);
}

std::string Slub::print_object_layout(std::shared_ptr<kmem_cache> cache_ptr,
                                      std::shared_ptr<obj> obj_ptr,
                                      const ObjectCheckResult& obj_result) {
    std::ostringstream oss;
    oss << "    Object Memory Layout:" << std::hex << "[" << obj_ptr->start << " - " << obj_ptr->start + cache_ptr->size << "]";
    if (cache_ptr->flags & SLAB_RED_ZONE) {
        // Left Red Zone
        oss << "\n            [" << std::hex << obj_ptr->start << "] Left Red Zone  ("
            << std::dec << cache_ptr->red_left_pad << " bytes)";
        if (obj_result.left_redzone_errors > 0) {
            oss << " <-- CORRUPTED";
        }
        // Object Data
        ulong data_start = fixup_red_left(cache_ptr, obj_ptr->start);
        oss << "\n            [" << std::hex << data_start << "] Object Data    ("
            << std::dec << cache_ptr->object_size << " bytes)";
        if (obj_result.poison_errors > 0) {
            oss << " <-- CORRUPTED";
        }
        // Free Pointer (if inside object)
        if (!freeptr_outside_object(cache_ptr)) {
            ulong freeptr_addr = data_start + cache_ptr->offset;
            oss << "\n            [" << std::hex << freeptr_addr << "] Free Pointer   ("
                << std::dec << sizeof(void*) << " bytes)";
            if (obj_result.freeptr_errors > 0) {
                oss << " <-- CORRUPTED";
            }
        }
        // Right Red Zone
        ulong right_redzone = data_start + cache_ptr->object_size;
        oss << "\n            [" << std::hex << right_redzone << "] Right Red Zone ("
            << std::dec << (cache_ptr->inuse - cache_ptr->object_size) << " bytes)";
        if (obj_result.right_redzone_errors > 0) {
            oss << " <-- CORRUPTED";
        }
        // Free Pointer (if outside object)
        if (freeptr_outside_object(cache_ptr)) {
            ulong freeptr_addr = data_start + cache_ptr->offset;
            oss << "\n            [" << std::hex << freeptr_addr << "] Free Pointer   ("
                << std::dec << sizeof(void*) << " bytes)";
            if (obj_result.freeptr_errors > 0) {
                oss << " <-- CORRUPTED";
            }
        }
    } else {
        // No Red Zone case
        oss << "\n            [" << std::hex << obj_ptr->start << "] Object Data    ("
            << std::dec << cache_ptr->object_size << " bytes)";
        if (obj_result.poison_errors > 0) {
            oss << " <-- CORRUPTED";
        }
        // Free Pointer
        ulong freeptr_addr = obj_ptr->start + cache_ptr->offset;
        oss << "\n            [" << std::hex << freeptr_addr << "] Free Pointer   ("
            << std::dec << sizeof(void*) << " bytes)";
        if (obj_result.freeptr_errors > 0) {
            oss << " <-- CORRUPTED";
        }
    }
    // Track Info
    if (cache_ptr->flags & SLAB_STORE_USER) {
        ulong track_start = obj_ptr->start + cache_ptr->red_left_pad + get_info_end(cache_ptr);
        oss << "\n            [" << std::hex << track_start << "] Track Info     ("
            << std::dec << (2 * struct_size(track)) << " bytes)";
        // Original size info for kmalloc caches
        if (slub_debug_orig_size(cache_ptr)) {
            ulong orig_size_addr = track_start + 2 * struct_size(track);
            oss << "\n            [" << std::hex << orig_size_addr << "] Original Size  ("
                << std::dec << sizeof(unsigned int) << " bytes)";
        }
    }
    // Padding Area
    if (obj_result.padding_errors > 0) {
        unsigned int off = get_info_end(cache_ptr);
        if (cache_ptr->flags & SLAB_STORE_USER) {
            off += 2 * struct_size(track);
            if (cache_ptr->flags & SLAB_KMALLOC) {
                off += sizeof(unsigned int);
            }
        }
        if (size_from_object(cache_ptr) > off) {
            ulong padding_start = obj_ptr->start + cache_ptr->red_left_pad + off;
            ulong padding_size = size_from_object(cache_ptr) - off;
            oss << "\n            [" << std::hex << padding_start << "] Padding Area   ("
                << std::dec << padding_size << " bytes) <-- CORRUPTED";
        }
    }
    return oss.str();
}

void Slub::print_cache_check_result(const SlubCheckResult& result, bool show_all_errors) {
    PRINT("CACHE: %s (%#lx)\n", result.cache_name.c_str(), result.cache_addr);
    if (result.total_objects == 0) {
        PRINT("  No objects to check\n");
        PRINT("  Status: SKIPPED\n\n");
        return;
    }
    PRINT("  Objects: %d total, %d checked\n",
            result.total_objects, result.checked_objects);
    if (result.overall_result) {
        PRINT("  Result: CLEAN - No corruption detected\n");
    } else {
        PRINT("  Result: CORRUPTED - %d objects affected\n", result.corrupted_objects);
        if (result.redzone_errors > 0) {
            PRINT("    Red Zone violations: %d\n", result.redzone_errors);
        }
        if (result.poison_errors > 0) {
            PRINT("    Poison pattern errors: %d\n", result.poison_errors);
        }
        if (result.freeptr_errors > 0) {
            PRINT("    Free pointer corruptions: %d\n", result.freeptr_errors);
        }
        if (result.padding_errors > 0) {
            PRINT("    Padding violations: %d\n", result.padding_errors);
        }
    }
    if (!result.errors.empty()) {
        PRINT("  Error Details:\n");
        if (show_all_errors) {
            // Show all errors when using -P option
            for (const auto& error : result.errors) {
                PRINT("    %s\n", error.c_str());
            }
        } else {
            // Show limited errors for -p option
            int shown = 0;
            for (const auto& error : result.errors) {
                if (shown >= 9) {
                    PRINT("    ... and %zu more errors\n", result.errors.size() - 9);
                    break;
                }
                PRINT("    %s\n", error.c_str());
                shown++;
            }
        }
    }
    PRINT("  Status: %s\n\n", result.overall_result ? "PASS" : "FAIL");
}

void Slub::print_corruption_summary(const std::vector<SlubCheckResult>& results) {
    PRINT("CORRUPTION CHECK SUMMARY\n");
    PRINT("===============================================================\n");

    int total_caches = results.size();
    int clean_caches = 0;
    int corrupted_caches = 0;
    // Collect corrupted cache information
    std::vector<std::pair<std::string, ulong>> corrupted_cache_info;
    for (const auto& result : results) {
        if (result.overall_result) {
            clean_caches++;
        } else {
            corrupted_caches++;
            // Store corrupted cache info
            corrupted_cache_info.push_back({result.cache_name, result.cache_addr});
        }
    }
    PRINT("Overall Status: %s\n",
            corrupted_caches == 0 ? "SYSTEM CLEAN" : "CORRUPTION DETECTED");
    PRINT("Statistics:\n");
    PRINT("  Caches: %d total (%d clean, %d corrupted)\n",
            total_caches, clean_caches, corrupted_caches);
    // Display corrupted cache details
    if (!corrupted_cache_info.empty()) {
        PRINT("  Corrupted Caches:\n");
        for (const auto& cache_info : corrupted_cache_info) {
            PRINT("    - %s (%#lx)\n", cache_info.first.c_str(), cache_info.second);
        }
    }
    PRINT("\n");
    if (corrupted_caches > 0) {
        PRINT("RECOMMENDATION: Investigate corrupted caches immediately!\n");
        PRINT("Use the following commands for detailed analysis:\n");
        for (const auto& cache_info : corrupted_cache_info) {
            PRINT("  slub -P %#lx  # %s\n", cache_info.second, cache_info.first.c_str());
        }
    } else {
        PRINT("All SLUB caches are healthy - no memory corruption detected.\n");
    }
    PRINT("===============================================================\n");
}

/* Print Slub Info */
void Slub::print_slab_info(std::shared_ptr<slab> slab_ptr){
    physaddr_t paddr = page_to_phy(slab_ptr->first_page);
    ulong slab_vaddr = phy_to_virt(paddr);
    PRINT("       slab:%#lx order:%d VA:[%#lx~%#lx] totalobj:%d inuse:%d freeobj:%d\n",
            slab_ptr->first_page,
            slab_ptr->order,
            slab_vaddr, (slab_vaddr + (power(2, slab_ptr->order) * page_size)),
            slab_ptr->totalobj,
            slab_ptr->inuse,
            slab_ptr->freeobj);
    std::ostringstream oss;
    for (const auto& obj_ptr : slab_ptr->obj_list) {
        oss << "           obj[" << std::setw(5) << std::setfill('0') << std::dec << obj_ptr->index << "]"
            << "VA:[0x" << std::hex << obj_ptr->start
            << "~0x" << std::hex << obj_ptr->end << "]"
            << " status:" << (obj_ptr->is_free ? "freed":"alloc")
            << "\n";
    }
    PRINT("%s \n", oss.str().c_str());
}

void Slub::print_slab_caches(){
    for (const auto& cache_ptr : cache_list) {
        print_slab_cache(cache_ptr);
    }
}

void Slub::print_slab_cache(std::shared_ptr<kmem_cache> cache_ptr){
    PRINT("kmem_cache:%#lx %s\n",cache_ptr->addr,cache_ptr->name.c_str());
    for (const auto& node_ptr : cache_ptr->node_list) {
        PRINT("   kmem_cache_node:%#lx nr_partial:%ld nr_slabs:%ld total_objects:%ld\n",
                node_ptr->addr,node_ptr->nr_partial,node_ptr->nr_slabs,node_ptr->total_objects);
        for (const auto& slab_ptr : node_ptr->partial) {
            print_slab_info(slab_ptr);
        }
        for (const auto& slab_ptr : node_ptr->full) {
            print_slab_info(slab_ptr);
        }
    }
    for (size_t i = 0; i < cache_ptr->cpu_slabs.size(); i++){
        std::shared_ptr<kmem_cache_cpu> cpu_ptr = cache_ptr->cpu_slabs[i];
        PRINT("   kmem_cache_cpu[%zu]:%#lx\n",i,cpu_ptr->addr);
        for (const auto& slab_ptr : cpu_ptr->partial) {
            print_slab_info(slab_ptr);
        }
        if (cpu_ptr->cur_slab != nullptr){
            print_slab_info(cpu_ptr->cur_slab);
        }
    }
    PRINT("\n");
}

void Slub::print_slab_cache_info(std::string addr){
    unsigned long number = std::stoul(addr, nullptr, 16);
    if (number <= 0){
        return;
    }
    for (const auto& cache_ptr : cache_list) {
        if (cache_ptr->addr != number) {
            continue;
        }
        print_slab_cache(cache_ptr);
    }
}

void Slub::print_slab_summary_info(){
    std::sort(cache_list.begin(), cache_list.end(),[&](const std::shared_ptr<kmem_cache>& a, const std::shared_ptr<kmem_cache>& b){
        return a->total_size > b->total_size;
    });
    std::ostringstream oss;
    oss << std::left << std::setw(VADDR_PRLEN) << "kmem_cache" << " "
        << std::left << std::setw(max_name_len) << "name" << " "
        << std::left << std::setw(5) << "slabs" << " "
        << std::left << std::setw(10) << "slab_size" << " "
        << std::left << std::setw(12) << "per_slab_obj" << " "
        << std::left << std::setw(10) << "total_objs" << " "
        << std::left << std::setw(10) << "obj_size" << " "
        << std::left << std::setw(8) << "pad_size" << " "
        << std::left << std::setw(8) << "align_size" << " "
        << "total_size" << "\n";
    for (const auto& cache_ptr : cache_list) {
        int page_cnt = 1U << cache_ptr->page_order;
        oss << std::left << std::setw(VADDR_PRLEN) << std::hex << cache_ptr->addr << " "
            << std::left << std::setw(max_name_len) << cache_ptr->name << " "
            << std::left << std::setw(5) << std::dec << cache_ptr->total_nr_slabs << " "
            << std::left << std::setw(10) << csize(page_cnt * page_size) << " "
            << std::left << std::setw(12) << std::dec << cache_ptr->per_slab_obj << " "
            << std::left << std::setw(10) << std::dec << cache_ptr->total_nr_objs << " "
            << std::left << std::setw(10) << csize(cache_ptr->object_size) << " "
            << std::left << std::setw(8) << std::dec << cache_ptr->red_left_pad << " "
            << std::left << std::setw(8) << csize(cache_ptr->size) << " "
            << std::left << std::setw(12) << csize(cache_ptr->total_size)
            << "\n";
    }
    PRINT("%s \n", oss.str().c_str());
}

/**
 * Find the object by virtual address and print the stack trace.
 */
void Slub::print_object_trace_by_addr(std::string addr_str) {
    ulong target_addr;
    try {
        target_addr = std::stoul(addr_str, nullptr, 16);
    } catch (const std::exception& e) {
        PRINT("Invalid virtual address: %s\n", addr_str.c_str());
        return;
    }
    if (!is_kvaddr(target_addr)) {
        PRINT("Invalid virtual address %#lx\n", target_addr);
        return;
    }
    std::shared_ptr<kmem_cache> found_cache;
    std::shared_ptr<slab> found_slab;
    std::shared_ptr<obj> found_obj = find_object_by_addr(target_addr, found_cache, found_slab);
    if (!found_obj) {
        PRINT("Address %#lx not found in any SLUB object\n", target_addr);
        return;
    }

    ulong offset_in_obj = target_addr - found_obj->start;

    PRINT("================================================================================\n");
    PRINT("SLUB Object Analysis for Address: %#lx\n", target_addr);
    PRINT("================================================================================\n");

    PRINT("KMEM_CACHE:\n");
    PRINT("   Address     : %#lx\n", found_cache->addr);
    PRINT("   Name        : %s\n", found_cache->name.c_str());
    PRINT("   Object Size : %u bytes\n", found_cache->object_size);
    PRINT("   Total Size  : %u bytes\n", found_cache->size);
    PRINT("   Flags       : %#x%s\n", found_cache->flags,
            (found_cache->flags & SLAB_STORE_USER) ? " (STORE_USER enabled)" : " (no trace)");

    PRINT("\n");

    ulong slab_start = phy_to_virt(page_to_phy(found_slab->first_page));
    ulong slab_end = slab_start + (power(2, found_slab->order) * page_size);
    PRINT("SLAB:\n");
    PRINT("   Page Address: %#lx\n", found_slab->first_page);
    PRINT("   Order       : %u (%s)\n", found_slab->order, csize(power(2, found_slab->order) * page_size).c_str());
    PRINT("   VA Range    : [%#lx ~ %#lx]\n", slab_start, slab_end);
    PRINT("   Total Objs  : %u\n", found_slab->totalobj);
    PRINT("   In Use      : %u\n", found_slab->inuse);
    PRINT("   Free        : %u\n", found_slab->freeobj);

    PRINT("\n");

    PRINT("TARGET OBJECT:\n");
    PRINT("   Index       : %d\n", found_obj->index);
    PRINT("   VA Range    : [%#lx ~ %#lx] (%s)\n",
            found_obj->start, found_obj->end, csize(found_obj->end - found_obj->start).c_str());
    PRINT("   Status      : %s\n", found_obj->is_free ? "FREED" : "ALLOCATED");
    PRINT("   Target Addr : %#lx\n", target_addr);
    PRINT("   Offset      : +%#lx (%lu bytes from object start)\n", offset_in_obj, offset_in_obj);

    PRINT("\n");

    print_object_stack_trace(found_cache, found_slab, found_obj);

    PRINT("================================================================================\n");
}

void Slub::print_object_stack_trace(std::shared_ptr<kmem_cache> cache_ptr,
                                   std::shared_ptr<slab> slab_ptr,
                                   std::shared_ptr<obj> obj_ptr) {
    if ((cache_ptr->flags & SLAB_STORE_USER) == 0) {
        PRINT("STACK TRACE:\n");
        PRINT("   Not available (SLAB_STORE_USER not enabled)\n");
        return;
    }

    auto track_ptr = std::make_shared<track>();
    track_ptr->kmem_cache_ptr = cache_ptr;
    track_ptr->obj_addr = obj_ptr->start;

    uint8_t track_type = obj_ptr->is_free ? TRACK_FREE : TRACK_ALLOC;
    track_ptr->trackp = get_track(cache_ptr, obj_ptr->start, track_type);
    parser_track(track_ptr->trackp, track_ptr);

    PRINT("STACK TRACE:\n");
    if (!track_ptr->frame.empty()) {
        PRINT("   Type        : %s\n", obj_ptr->is_free ? "FREE" : "ALLOC");
        PRINT("   PID         : %d\n", track_ptr->pid);
        PRINT("   CPU         : %d\n", track_ptr->cpu);
        PRINT("   Timestamp   : %lu\n", track_ptr->when);
        PRINT("   Call Stack  :\n");
        std::istringstream iss(track_ptr->frame);
        std::string line;
        while (std::getline(iss, line)) {
            if (!line.empty()) {
                size_t start = line.find_first_not_of(" \t");
                if (start != std::string::npos) {
                    line = line.substr(start);
                }
                PRINT("      %s\n", line.c_str());
            }
        }
    } else {
        PRINT("   No stack trace available\n");
    }
}

std::shared_ptr<obj> Slub::find_object_by_addr(ulong target_addr,
                                               std::shared_ptr<kmem_cache>& found_cache,
                                               std::shared_ptr<slab>& found_slab) {
    for (const auto& cache_ptr : cache_list) {
        for (const auto& node_ptr : cache_ptr->node_list) {
            for (const auto& slab_ptr : node_ptr->partial) {
                auto obj = find_object_in_slab(slab_ptr, target_addr);
                if (obj) {
                    found_cache = cache_ptr;
                    found_slab = slab_ptr;
                    return obj;
                }
            }
            for (const auto& slab_ptr : node_ptr->full) {
                auto obj = find_object_in_slab(slab_ptr, target_addr);
                if (obj) {
                    found_cache = cache_ptr;
                    found_slab = slab_ptr;
                    return obj;
                }
            }
        }
        for (const auto& cpu_ptr : cache_ptr->cpu_slabs) {
            for (const auto& slab_ptr : cpu_ptr->partial) {
                auto obj = find_object_in_slab(slab_ptr, target_addr);
                if (obj) {
                    found_cache = cache_ptr;
                    found_slab = slab_ptr;
                    return obj;
                }
            }
            if (cpu_ptr->cur_slab) {
                auto obj = find_object_in_slab(cpu_ptr->cur_slab, target_addr);
                if (obj) {
                    found_cache = cache_ptr;
                    found_slab = cpu_ptr->cur_slab;
                    return obj;
                }
            }
        }
    }
    return nullptr;
}

std::shared_ptr<obj> Slub::find_object_in_slab(std::shared_ptr<slab> slab_ptr, ulong target_addr) {
    if (!slab_ptr) return nullptr;
    for (const auto& obj_ptr : slab_ptr->obj_list) {
        if (target_addr >= obj_ptr->start && target_addr < obj_ptr->end) {
            return obj_ptr;
        }
    }
    return nullptr;
}

#pragma GCC diagnostic pop
