// Copyright (c) 2024-2025 Qualcomm Innovation Center, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause-Clear

#include "slub.h"

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wpointer-arith"

#ifndef BUILD_TARGET_TOGETHER
DEFINE_PLUGIN_COMMAND(Slub)
#endif

void Slub::cmd_main(void) {
    int c;
    std::string cppString;
    if (argcnt < 2) cmd_usage(pc->curcmd, SYNOPSIS);
    if (cache_list.size() == 0){
        parser_slab_caches();
    }
    while ((c = getopt(argcnt, args, "asc:pP:t:lT:")) != EOF) {
        switch(c) {
            case 's':
                print_slab_summary_info();
                break;
            case 'a':
                print_slab_caches();
                break;
            case 'c':
                cppString.assign(optarg);
                print_slab_cache_info(cppString);
                break;
            case 'p':
                print_slub_poison();
                break;
            case 'P':
                cppString.assign(optarg);
                try {
                    ulong kmem_cache_addr = std::stoul(cppString, nullptr, 16);
                    print_slub_poison(kmem_cache_addr);
                } catch (...) {
                    fprintf(fp, "invaild kmem_cache_addr %s\n", cppString.c_str());
                }
                break;
            case 't':
                cppString.assign(optarg);
                print_slub_trace(cppString);
                break;
            case 'l':
                print_all_slub_trace();
                break;
            case 'T':
                cppString.assign(optarg);
                try {
                    size_t stack_id = std::stoul(cppString);
                    print_all_slub_trace(stack_id);
                } catch (...) {
                    fprintf(fp, "invaild stack_id %s\n", cppString.c_str());
                }
                break;
            default:
                argerrs++;
                break;
        }
    }
    if (argerrs)
        cmd_usage(pc->curcmd, SYNOPSIS);
}

Slub::Slub(){
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
    cmd_name = "slub";
    help_str_list={
        "slub",                            /* command name */
        "dump slub information",        /* short description */
        "-a \n"
            "  slub -s\n"
            "  slub -c <cache addr>\n"
            "  This command dumps the slab info.",
        "\n",
        "EXAMPLES",
        "  Display all slab info:",
        "    %s> slub -a",
        "    kmem_cache:0xffffff80030c6000 inode_cache",
        "       kmem_cache_node:0xffffff80030c5700 nr_partial:280 nr_slabs:6291 total_objects:106947",
        "           slab:0xfffffffe0057f800 order:2 VA:[0xffffff8015fe0000~0xffffff8015fe4000] totalobj:17 inuse:3 freeobj:14",
        "               obj[0] VA:[0xffffff8015fe0000~0xffffff8015fe03a0] free:true",
        "               obj[1] VA:[0xffffff8015fe03a0~0xffffff8015fe0740] free:false",
        "\n",
        "  Display specified slab info by kmem_cache addr:",
        "    %s> slub -c 0xffffff80030c6000",
        "    kmem_cache:0xffffff80030c6000 inode_cache",
        "       kmem_cache_node:0xffffff80030c5700 nr_partial:280 nr_slabs:6291 total_objects:106947",
        "           slab:0xfffffffe0057f800 order:2 VA:[0xffffff8015fe0000~0xffffff8015fe4000] totalobj:17 inuse:3 freeobj:14",
        "               obj[0] VA:[0xffffff8015fe0000~0xffffff8015fe03a0] free:true",
        "               obj[1] VA:[0xffffff8015fe03a0~0xffffff8015fe0740] free:false",
        "\n",
        "  Display slab memory info:",
        "    %s> slub -s",
        "    kmem_cache        name                      slabs ssize      obj/s   objs       osize      padsize alignsize  totalsize",
        "    ffffff80030c6000  inode_cache               6310  (4)16K     17      107270     920        0       928        94.93Mb",
        "    ffffff80030c4500  vm_area_struct            7350  (1)4K      17      124950     232        0       240        28.60Mb",
        "    ffffff80030c6300  dentry                    7218  (1)4K      17      122706     232        0       240        28.09Mb",
        "\n",
        "  Display all poison info:",
        "    %s> slub -p",
        "    kmem_cache_name           Poison_Result",
        "    kmem_cache                PASS",
        "    kmem_cache_node           FAIL",
        "\n",
        "  Display the poison info by given the kmem_cache address:",
        "    %s> slub -P kmem_cache_addr",
        "    kmem_cache_name           Poison_Result",
        "    kmem_cache_node           FAIL/PASS",
        "\n",
        "  Display the slub alloc or free trace",
        "    %s> slub -t <A | F>",
        "    stack_id:12856162743170019396 Allocated:164 kmem_cache:kmalloc-64 size:41.00KB",
        "       callstack",
        "\n",
        "  Display the all of slub trace, include alloc and free",
        "    %s> slub -l",
        "    stack_id:12856162743170019396 Allocated:164 kmem_cache:kmalloc-64 size:41.00KB",
        "       callstack",
        "\n",
        "  Display the slub trace by given the stack_id:",
        "    %s> slub -T stack_id",
        "    pid:1 freq:50110 size:17.20MB",
        "\n",
    };
    initialize();

    if (csymbol_exists("depot_index")){
        depot_index = read_int(csymbol_value("depot_index"),"depot_index");
    }else if (csymbol_exists("pool_index")){
        depot_index = read_int(csymbol_value("pool_index"),"pool_index");
    }
    if (csymbol_exists("stack_slabs")){
        stack_slabs = csymbol_value("stack_slabs");
    }else if (csymbol_exists("stack_pools")){/* 6.3 and later */
        stack_slabs = csymbol_value("stack_pools");
    }
    if (!stack_slabs){
        fprintf(fp, "cannot get stack_{pools|slabs}\n");
    }
}

std::shared_ptr<slab> Slub::parser_slab(std::shared_ptr<kmem_cache> cache_ptr, ulong slab_page_addr){
    int count = 0;
    int obj_index = 0;
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
    // fprintf(fp, "slab_page_addr:%#lx \n", slab_page_addr);
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
            fprintf(fp, "Invalid obj_index: %d\n", obj_index);
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
    for (size_t i = 0; i < node_cnt; i++){
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
    if (csymbol_exists("max_pfn")){
        max_pfn = read_ulong(csymbol_value("max_pfn"),"max_pfn");
    }
    if (!csymbol_exists("slab_caches")){
        fprintf(fp, "slab_caches doesn't exist in this kernel!\n");
        return;
    }
    ulong slab_caches_addr = csymbol_value("slab_caches");
    if (!is_kvaddr(slab_caches_addr)) return;
    int offset = field_offset(kmem_cache,list);
    std::vector<ulong> list = for_each_list(slab_caches_addr,offset);
    for (const auto& cache_addr : list) {
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
}

/* Poison */
int Slub::object_err(std::shared_ptr<kmem_cache> cache_ptr, ulong slab_page_addr, ulong object_start, std::string reason){
    fprintf(fp, "object_err:%s \n", reason.c_str());
    print_trailer(cache_ptr, slab_page_addr, object_start);
    return 0;
}

void Slub::print_page_info(ulong slab_page_addr){
    ulong count;
    if (struct_size(slab) == -1){
        count = read_ulong(slab_page_addr + field_offset(page, counters), "page counters");
    } else {
        count = read_ulong(slab_page_addr + field_offset(slab, counters), "slab counters");
    }
    ulong inuse = count & 0x0000FFFF;
    ulong objects = (count >> 16) & 0x00007FFF;
    ulong freelist;
    if (struct_size(slab) == -1){
        freelist = read_pointer(slab_page_addr + field_offset(page, freelist), "page freelist");
    } else {
        freelist = read_pointer(slab_page_addr + field_offset(slab, freelist), "slab freelist");
    }
    ulong flags = read_ulong(slab_page_addr + field_offset(page, flags), "page flags");
    fprintf(fp, "INFO: Slab:%#lx objects=%ld used=%ld fp=%#lx flags=%#lx \n", slab_page_addr, objects, inuse, freelist, flags);
}

void Slub::print_section(std::string text, ulong page_addr, size_t length){
    char* buf = (char*)read_memory(page_addr, length, "print_section");
    fprintf(fp, "%s \n", text.c_str());
    fprintf(fp, "%s \n", hexdump(page_addr, buf, length).c_str());
    FREEBUF(buf);
}

void Slub::print_trailer(std::shared_ptr<kmem_cache> cache_ptr, ulong slab_page_addr, ulong obj_start){
    ulong slab_vaddr = phy_to_virt(page_to_phy(slab_page_addr));
    print_page_info(slab_page_addr);
    fprintf(fp, "Object %#lx @offset=%#lx fp=%#lx\n", obj_start, obj_start - slab_vaddr, get_free_pointer(cache_ptr, obj_start));
    if (cache_ptr->flags & SLAB_STORE_USER) {
        print_section("Redzone  ", obj_start - cache_ptr->red_left_pad, cache_ptr->red_left_pad);
    } else if(obj_start > slab_vaddr + 16){
        print_section("Bytes b4 ", obj_start - 16, 16);
    }
    print_section("Object   ", obj_start, cache_ptr->red_left_pad < 4096 ? cache_ptr->red_left_pad : 4096);
    if (cache_ptr->flags & SLAB_RED_ZONE) {
        print_section("Redzone  ", obj_start + cache_ptr->object_size, cache_ptr->inuse - cache_ptr->object_size);
    }
    unsigned int off = get_info_end(cache_ptr);
    if (cache_ptr->flags & SLAB_STORE_USER) {
        off += 2 * struct_size(track);
    }
    if (off != size_from_object(cache_ptr)){
        print_section("Padding  ", obj_start + off, size_from_object(cache_ptr) - off);
    }
}
int Slub::check_bytes_and_report(std::shared_ptr<kmem_cache> cache_ptr, ulong page_addr, ulong obj_start, std::string what, ulong start, uint8_t value, size_t bytes){
    ulong slab_vaddr = phy_to_virt(page_to_phy(page_addr));
    ulong fault = memchr_inv(start, value, bytes);

    if(!is_kvaddr(fault))
        return 1;
    ulong end = start + bytes;
    while (end > fault && read_byte(end - 1, "check_bytes_and_report") == value){
        end -= 1;
    }
    fprintf(fp, "%s overwritten %#lx - %#lx @offset=%#lx. First byte %x instead of %x slab_addr %#lx\n",
        what.c_str(), fault, end - 1, fault - slab_vaddr, read_byte(fault, "check_bytes_and_report log"), value, slab_vaddr);
    print_trailer(cache_ptr, page_addr, obj_start);
    return 0;
}

int Slub::check_pad_bytes(std::shared_ptr<kmem_cache> cache_ptr, ulong page_addr, ulong obj_start){
    unsigned int off = get_info_end(cache_ptr);
    if (cache_ptr->flags & SLAB_STORE_USER) {
        off += 2 * struct_size(track);
        if(cache_ptr->flags & SLAB_KMALLOC){
            off += sizeof(unsigned int);
        }
    }
    if(size_from_object(cache_ptr) == off){
        return 1;
    }
    return check_bytes_and_report(cache_ptr, page_addr, obj_start, "Object padding", obj_start + off, POISON_INUSE, size_from_object(cache_ptr) - off);
}

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
    if(object < slab_vaddr | object >= slab_vaddr + objects * cache_ptr->size | (object - slab_vaddr) % cache_ptr->size)
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
ulong Slub::memchr_inv(ulong start_addr, uint8_t c, size_t bytes){
    uint8_t value = c;
    uint64_t value64;
    size_t words, prefix;

    if (bytes <= 16) {
        return check_bytes8(start_addr, value, bytes);
    }

    value64 = value;
    if((get_config_val("CONFIG_ARCH_HAS_FAST_MULTIPLIER") == "y") && (get_config_val("CONFIG_ARM64") == "y")){
        value64 *= 0x0101010101010101ULL;
    } else if(get_config_val("CONFIG_ARCH_HAS_FAST_MULTIPLIER") == "y"){
        value64 *= 0x01010101;
        value64 |= value64 << 32;
    } else {
        value64 |= value64 << 8;
        value64 |= value64 << 16;
        value64 |= value64 << 32;
    }

    prefix = start_addr % 8;
    if (prefix) {
        prefix = 8 - prefix;
        ulong r = check_bytes8(start_addr, value, prefix);
        if (r) {
            return r;
        }
        start_addr += prefix;
        bytes -= prefix;
    }

    words = bytes / 8;

    while (words) {
        if (read_ulonglong(start_addr, "memchr_inv") != value64) {
            return check_bytes8(start_addr, value, 8);
        }
        start_addr += 8;
        words--;
    }

    return check_bytes8(start_addr, value, bytes % 8);
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

void Slub::parser_track_map(std::unordered_map<std::string, std::vector<std::shared_ptr<track>>> map, bool is_free){
    std::vector<std::pair<std::string, std::vector<std::shared_ptr<track>>>> sorted_trace_map(map.begin(), map.end());
    std::sort(sorted_trace_map.begin(), sorted_trace_map.end(),[&](const std::pair<std::string, std::vector<std::shared_ptr<track>>>& a, const std::pair<std::string, std::vector<std::shared_ptr<track>>>& b){
        return a.second.size() > b.second.size();
    });
    for (auto it = sorted_trace_map.begin(); it != sorted_trace_map.end(); ++it) {
        const auto& frame = it->first;
        const auto& track_vec = it->second;
        size_t hash_value = std::hash<std::string>{}(frame);
        // if (unique_hash.find(hash_value) == unique_hash.end()) {
        //     unique_hash.insert(hash_value);
        // } else {
        //     fprintf(fp, "free hash exist track_addr:%#lx stack_id:%zu \n", track_vec[0]->addr, hash_value);
        // }
        fprintf(fp, "stack_id:%zu %s:%zd times kmem_cache:%s size:%s\n", hash_value, is_free ? "Freed":"Allocated", track_vec.size(), track_vec[0]->kmem_cache_ptr->name.c_str(), csize(track_vec.size() * track_vec[0]->kmem_cache_ptr->size).c_str());
        fprintf(fp, "%s \n", track_vec[0]->frame.c_str());
    }
}

void Slub::print_slub_trace(std::string is_free){
    parser_slub_trace();
    if(is_free == "A" || is_free == "a"){
        parser_track_map(alloc_trace_map, 0);
    } else if(is_free == "F" || is_free == "f"){
        parser_track_map(free_trace_map, 1);
    } else {
        fprintf(fp, "pls check your input args %s\n", is_free.c_str());
    }
}

void Slub::print_all_slub_trace(size_t stack_id){
    parser_slub_trace();

    if(stack_id == 0){
        parser_track_map(alloc_trace_map, 0);
        parser_track_map(free_trace_map, 1);
    } else { // search
        auto findByHash = [&](size_t hashValue) -> std::pair<std::string, std::vector<std::shared_ptr<track>>> {
            for (auto it = alloc_trace_map.begin(); it != alloc_trace_map.end(); ++it) {
                size_t keyHash = std::hash<std::string>{}(it->first);
                if (keyHash == hashValue) {
                    return {it->first, it->second};
                }
            }
            for (auto it = free_trace_map.begin(); it != free_trace_map.end(); ++it) {
                size_t keyHash = std::hash<std::string>{}(it->first);
                if (keyHash == hashValue) {
                    return {it->first, it->second};
                }
            }
            return {"", {}};
        };

        auto result = findByHash(stack_id);
        if (!result.first.empty()) {
            std::sort(result.second.begin(), result.second.end(), [&](const std::shared_ptr<track>& a, const std::shared_ptr<track>& b) {
                return a->pid < b->pid;
            });

            int current_pid = result.second[0]->pid;
            int count = 0;
            size_t  total_size = 0;
            std::ostringstream oss;
            oss << std::left << std::setw(10) << "Pid" << std::setw(10) << "Freq" << std::setw(15) << "Size";
            fprintf(fp, "%s \n", oss.str().c_str());
            for (const auto& track_ptr : result.second) {
                if (track_ptr->pid == current_pid) {
                    ++count;
                    total_size += track_ptr->kmem_cache_ptr->size;
                } else {
                    std::ostringstream oss_data;
                    oss_data << std::left << std::setw(10) << current_pid << std::setw(10) << count << std::setw(15) << csize(total_size);
                    fprintf(fp, "%s \n", oss_data.str().c_str());
                    // for (const auto& t : result.second) {
                    //     if (t->pid == current_pid) {
                    //         fprintf(fp, "cpu:%d when:%lu \n", t->cpu, t->when);
                    //     }
                    // }
                    current_pid = track_ptr->pid;
                    count = 1;
                    total_size = track_ptr->kmem_cache_ptr->size;
                }
            }
            std::ostringstream oss_end;
            oss_end << std::left << std::setw(10) << current_pid << std::setw(10) << count << std::setw(15) << csize(total_size);
            fprintf(fp, "%s \n", oss_end.str().c_str());
        } else {
            fprintf(fp, "No such stack_id or run slub -t\n");
        }
    }
}

ulong Slub::parser_stack_record(uint page_owner_handle, uint& stack_len){
    ulong offset;
    ulong slabindex;
    union handle_parts_v parts = {.handle = page_owner_handle};
    if (THIS_KERNEL_VERSION >= LINUX(6, 8, 0)){
        offset = parts.v3.offset << DEPOT_STACK_ALIGN;
        slabindex = parts.v3.pool_index;
    }
    else if (THIS_KERNEL_VERSION >= LINUX(6, 1, 0)){
        offset = parts.v2.offset << DEPOT_STACK_ALIGN;
        slabindex = parts.v2.pool_index;
    }
    else{
        offset = parts.v1.offset << DEPOT_STACK_ALIGN;
        slabindex = parts.v1.pool_index;
    }
    if (slabindex > depot_index)
        return 0;
    ulong page_addr = read_pointer(stack_slabs + slabindex * sizeof(void *), "stack_record_page");
    if (!is_kvaddr(page_addr))
        return 0;

    ulong stack_record_addr = page_addr + offset;
    void *record_buf = read_struct(stack_record_addr, "stack_record");
    if (!record_buf){
        return 0;
    }
    stack_len = UINT(record_buf + field_offset(stack_record, size));
    uint record_handle = UINT(record_buf + field_offset(stack_record, handle));
    if (record_handle != page_owner_handle){
        FREEBUF(record_buf);
        return 0;
    }
    FREEBUF(record_buf);
    return stack_record_addr + field_offset(stack_record, entries);
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
        uint handle_parts = read_uint(handle_parts_addr, "track handle");
        uint nr_size = 0;
        ulong entries = parser_stack_record(handle_parts, nr_size);
        for(uint i = 0; i < nr_size; i++){
            if(is_kvaddr(entries)){
                ulong frame_addr = read_pointer(entries + sizeof(unsigned long) * i, "frame_addr handle");
                if(is_kvaddr(frame_addr)){
                    track_ptr->frame += extract_callstack(frame_addr);
                }
            }
        }
    } else {
        ulong track_addrs_addr = track_addr + field_offset(track, addrs);
        uint frame_size = field_size(track, addrs) / sizeof(unsigned long);
        for(uint i = 0; i < frame_size; i++){
            if(is_kvaddr(track_addrs_addr)){
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

void Slub::parser_obj_track(std::shared_ptr<kmem_cache> cache_ptr, ulong object_start_addr, uint8_t track_type){
    auto track_ptr = std::make_shared<track>();
    track_ptr->kmem_cache_ptr = cache_ptr;
    track_ptr->obj_addr = object_start_addr;
    track_ptr->trackp = get_track(cache_ptr, object_start_addr, track_type);
    parser_track(track_ptr->trackp, track_ptr);

    if(!track_ptr->frame.empty()){
        if(!track_type){
            alloc_trace_map[track_ptr->frame].push_back(track_ptr);
        } else {
            free_trace_map[track_ptr->frame].push_back(track_ptr);
        }
    }
}

void Slub::parser_slab_track(std::shared_ptr<kmem_cache> cache_ptr, std::shared_ptr<slab> slab_ptr){
    /*
    we only parser the alloc and free track of the slab object.
    */
   for(const auto& obj : slab_ptr->obj_list){
        parser_obj_track(cache_ptr, obj->start, obj->is_free ? TRACK_FREE : TRACK_ALLOC);
   }
}

/* Print Slub Trace*/
void Slub::parser_slub_trace(){
    if (!alloc_trace_map.empty() && !free_trace_map.empty()){
        return;
    }
    for (const auto& cache_ptr : cache_list) {
        if((cache_ptr->flags & SLAB_STORE_USER) == 0){
            continue;
        }
        for (const auto& node_ptr : cache_ptr->node_list) {
            for (const auto& slab_ptr : node_ptr->partial) {
                parser_slab_track(cache_ptr, slab_ptr);
            }
            for (const auto& slab_ptr : node_ptr->full) {
                parser_slab_track(cache_ptr, slab_ptr);
            }
        }
        for (size_t i = 0; i < cache_ptr->cpu_slabs.size(); i++){
            std::shared_ptr<kmem_cache_cpu> cpu_ptr = cache_ptr->cpu_slabs[i];
            for (const auto& slab_ptr : cpu_ptr->partial) {
                parser_slab_track(cache_ptr, slab_ptr);
            }
            if (cpu_ptr->cur_slab){
                parser_slab_track(cache_ptr, cpu_ptr->cur_slab);
            }
        }
    }
}

/* Print Poison Info*/
int Slub::check_object(std::shared_ptr<kmem_cache> cache_ptr, ulong page_addr, ulong object_start_addr, uint8_t val){
    ulong object = fixup_red_left(cache_ptr, object_start_addr); // the address of real object
    ulong p = object;
    ulong endobject = object + cache_ptr->object_size;
    int ret = 1;
    if(cache_ptr->flags & SLAB_RED_ZONE){
        // check the Left Redzone
        if(!check_bytes_and_report(cache_ptr, page_addr, object, "Left Redzone", object - cache_ptr->red_left_pad, val, cache_ptr->red_left_pad)){
            ret = 0;
        }
        // check the Right Redzone
        if(!check_bytes_and_report(cache_ptr, page_addr, object, "Right Redzone", endobject, val, cache_ptr->inuse - cache_ptr->object_size)){
            ret = 0;
        }
        // check the kmalloc Redzone
        if(slub_debug_orig_size(cache_ptr) && val == SLUB_RED_ACTIVE){
            unsigned int orig_size_offset = get_orig_size(cache_ptr);
            int orig_size = read_int(object + orig_size_offset, "orig_size");
            if(cache_ptr->object_size > orig_size &&
            !check_bytes_and_report(cache_ptr, page_addr, object, "kmalloc Redzone", p + orig_size, val, cache_ptr->object_size - orig_size)){
                ret = 0;
            }
        }
    } else {
        // check Alignment padding
        if((cache_ptr->flags & SLAB_POISON) && (cache_ptr->object_size < cache_ptr->inuse)){
            check_bytes_and_report(cache_ptr, page_addr, object, "Alignment padding", endobject, POISON_INUSE, cache_ptr->inuse - cache_ptr->object_size);
        }
    }
    if(cache_ptr->flags & SLAB_POISON){
        if((val != SLUB_RED_ACTIVE) && (cache_ptr->flags & OBJECT_POISON) &&
        // check Poison
        (!check_bytes_and_report(cache_ptr, page_addr, object, "Poison", p, POISON_FREE, cache_ptr->object_size - 1) ||
        // check End Poison
        !check_bytes_and_report(cache_ptr, page_addr, object, "End Poison", p + cache_ptr->object_size - 1, POISON_END, 1))){
            ret = 0;
        }
        // obj padding
        if(!check_pad_bytes(cache_ptr, page_addr, p)){
            ret = 0;
        }
    }

    if((freeptr_outside_object(cache_ptr) || (val != SLUB_RED_ACTIVE)) &&
    !check_valid_pointer(cache_ptr, page_addr, get_free_pointer(cache_ptr, p))){
        object_err(cache_ptr, page_addr, p, "Freepointer corrupt");
        ret = 0;
    }
    return ret;
}

int Slub::check_object_poison(std::shared_ptr<kmem_cache> cache_ptr, std::shared_ptr<slab> slab_ptr){
    int ret = 1;
    for(const auto& obj : slab_ptr->obj_list){
        ret &= check_object(cache_ptr, slab_ptr->first_page, obj->start, obj->is_free ? SLUB_RED_INACTIVE : SLUB_RED_ACTIVE);
    }
    return ret;
}

void Slub::print_slub_poison(ulong kmem_cache_addr){
    int ret = 1;
    std::ostringstream oss_hd;
    oss_hd << std::left << std::setw(25) << "kmem_cache_name" << " "
        << std::setw(4) << "Poison_Result";
    fprintf(fp, "%s \n", oss_hd.str().c_str());
    for (const auto& cache_ptr : cache_list) {
        if(kmem_cache_addr != 0 && cache_ptr->addr != kmem_cache_addr){
                continue;
        }
        for (const auto& node_ptr : cache_ptr->node_list) {
            for (const auto& slab_ptr : node_ptr->partial) {
                ret &= check_object_poison(cache_ptr, slab_ptr);
            }
            for (const auto& slab_ptr : node_ptr->full) {
                ret &= check_object_poison(cache_ptr, slab_ptr);
            }
        }
        for (size_t i = 0; i < cache_ptr->cpu_slabs.size(); i++){
            std::shared_ptr<kmem_cache_cpu> cpu_ptr = cache_ptr->cpu_slabs[i];
            for (const auto& slab_ptr : cpu_ptr->partial) {
                ret &= check_object_poison(cache_ptr, slab_ptr);
            }
            if (cpu_ptr->cur_slab){
                ret &= check_object_poison(cache_ptr, cpu_ptr->cur_slab);
            }
        }
        std::ostringstream oss;
        oss << std::left << std::setw(25) << cache_ptr->name << " " << std::setw(4) << (ret ? "PASS" : "FAIL");
        fprintf(fp, "%s \n", oss.str().c_str());
        ret = 1;
    }
}

/* Print Slub Info */
void Slub::print_slab_info(std::shared_ptr<slab> slab_ptr){
    physaddr_t paddr = page_to_phy(slab_ptr->first_page);
    ulong slab_vaddr = phy_to_virt(paddr);
    fprintf(fp, "       slab:%#lx order:%d VA:[%#lx~%#lx] totalobj:%d inuse:%d freeobj:%d\n",
            slab_ptr->first_page,
            slab_ptr->order,
            slab_vaddr, (slab_vaddr + (power(2, slab_ptr->order) * page_size)),
            slab_ptr->totalobj,
            slab_ptr->inuse,
            slab_ptr->freeobj);
    for (const auto& obj_ptr : slab_ptr->obj_list) {
        std::ostringstream oss;
        oss << "           obj[" << std::setw(5) << std::setfill('0') << obj_ptr->index << "]"
            << "VA:[0x" << std::hex << obj_ptr->start
            << "~0x" << std::hex << obj_ptr->end << "]"
            << " status:" << (obj_ptr->is_free ? "freed":"alloc");
        fprintf(fp, "%s \n",oss.str().c_str());
    }
}

void Slub::print_slab_caches(){
    for (const auto& cache_ptr : cache_list) {
        print_slab_cache(cache_ptr);
    }
}

void Slub::print_slab_cache(std::shared_ptr<kmem_cache> cache_ptr){
    fprintf(fp, "kmem_cache:%#lx %s\n",cache_ptr->addr,cache_ptr->name.c_str());
    for (const auto& node_ptr : cache_ptr->node_list) {
        fprintf(fp, "   kmem_cache_node:%#lx nr_partial:%ld nr_slabs:%ld total_objects:%ld\n",
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
        fprintf(fp, "   kmem_cache_cpu[%zu]:%#lx\n",i,cpu_ptr->addr);
        for (const auto& slab_ptr : cpu_ptr->partial) {
            print_slab_info(slab_ptr);
        }
        if (cpu_ptr->cur_slab != nullptr){
            print_slab_info(cpu_ptr->cur_slab);
        }
    }
    fprintf(fp, "\n");
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
    size_t max_len = 0;
    for (const auto& cache_ptr : cache_list) {
        max_len = std::max(max_len,cache_ptr->name.size());
    }
    std::ostringstream oss_hd;
    oss_hd << std::left << std::setw(VADDR_PRLEN) << "kmem_cache" << " "
        << std::left << std::setw(max_len) << "name" << " "
        << std::left << std::setw(5) << "slabs" << " "
        << std::left << std::setw(10) << "slab_size" << " "
        << std::left << std::setw(12) << "per_slab_obj" << " "
        << std::left << std::setw(10) << "total_objs" << " "
        << std::left << std::setw(10) << "obj_size" << " "
        << std::left << std::setw(8) << "pad_size" << " "
        << std::left << std::setw(8) << "align_size" << " "
        << "total_size";
    fprintf(fp, "%s \n",oss_hd.str().c_str());
    for (const auto& cache_ptr : cache_list) {
        int page_cnt = 1U << cache_ptr->page_order;
        std::ostringstream oss;
        oss << std::left << std::setw(VADDR_PRLEN) << std::hex << cache_ptr->addr << " "
            << std::left << std::setw(max_len) << cache_ptr->name << " "
            << std::left << std::setw(5) << std::dec << cache_ptr->total_nr_slabs << " "
            << std::left << std::setw(10) << csize(page_cnt * page_size) << " "
            << std::left << std::setw(12) << std::dec << cache_ptr->per_slab_obj << " "
            << std::left << std::setw(10) << std::dec << cache_ptr->total_nr_objs << " "
            << std::left << std::setw(10) << csize(cache_ptr->object_size) << " "
            << std::left << std::setw(8) << std::dec << cache_ptr->red_left_pad << " "
            << std::left << std::setw(8) << csize(cache_ptr->size) << " "
            << std::left << csize(cache_ptr->total_size);
        fprintf(fp, "%s \n",oss.str().c_str());
    }
}
#pragma GCC diagnostic pop
