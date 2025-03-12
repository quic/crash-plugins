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
    while ((c = getopt(argcnt, args, "asc:")) != EOF) {
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
            default:
                argerrs++;
                break;
        }
    }
    if (argerrs)
        cmd_usage(pc->curcmd, SYNOPSIS);
}

Slub::Slub(){
    field_init(kmem_cache,cpu_slab);
    field_init(kmem_cache,flags);
    field_init(kmem_cache,min_partial);
    field_init(kmem_cache,size);
    field_init(kmem_cache,object_size);
    field_init(kmem_cache,offset);
    field_init(kmem_cache,cpu_partial);
    field_init(kmem_cache,oo);
    field_init(kmem_cache,max);
    field_init(kmem_cache,min);
    field_init(kmem_cache,allocflags);
    field_init(kmem_cache,refcount);
    field_init(kmem_cache,inuse);
    field_init(kmem_cache,align);
    field_init(kmem_cache,red_left_pad);
    field_init(kmem_cache,name);
    field_init(kmem_cache,random);
    field_init(kmem_cache,list);
    field_init(kmem_cache,useroffset);
    field_init(kmem_cache,usersize);
    field_init(kmem_cache,node);
    field_init(kmem_cache_node,nr_partial);
    field_init(kmem_cache_node,partial);
    field_init(kmem_cache_node,nr_slabs);
    field_init(kmem_cache_node,total_objects);
    field_init(kmem_cache_node,full);
    field_init(kmem_cache_cpu,freelist);
    field_init(kmem_cache_cpu,tid);
    field_init(kmem_cache_cpu,page);
    field_init(kmem_cache_cpu,partial);
    if (THIS_KERNEL_VERSION > LINUX(6,1,0)){
        field_init(slab,slab_list);
        field_init(slab,counters);
        field_init(slab,freelist);
        field_init(slab,next);
        struct_init(slab);
    }else if(THIS_KERNEL_VERSION <= LINUX(4,14,0)){
        field_init(page,slab_list);
        field_init(page,_mapcount);
        field_init(page,freelist);
        field_init(page,next);
        struct_init(page);
    }else{
        field_init(page,slab_list);
        field_init(page,counters);
        field_init(page,freelist);
        field_init(page,next);
        struct_init(page);
    }
    struct_init(kmem_cache);
    struct_init(kmem_cache_node);
    struct_init(kmem_cache_cpu);
    struct_init(atomic_t);
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
    };
    initialize();
}

std::shared_ptr<slab> Slub::parser_slab(std::shared_ptr<kmem_cache> cache_ptr, ulong slab_page_addr){
    int count = 0;
    int obj_index = 0;
    ulong freelist = 0;
    void *page_buf = nullptr;
    if (!is_kvaddr(slab_page_addr)){
        return nullptr;
    }
    if (THIS_KERNEL_VERSION > LINUX(6,1,0)){
        page_buf = read_struct(slab_page_addr,"slab");
    }else{
        page_buf = read_struct(slab_page_addr,"page");
    }
    if(page_buf == nullptr) return nullptr;
    std::shared_ptr<slab> slab_ptr = std::make_shared<slab>();
    // fprintf(fp, "slab_page_addr:0x%lx \n", slab_page_addr);
    if (THIS_KERNEL_VERSION > LINUX(6,1,0)){
        count = ULONG(page_buf + field_offset(slab,counters));
        freelist = ULONG(page_buf + field_offset(slab,freelist));
    }else if(THIS_KERNEL_VERSION <= LINUX(4,14,0)){
        count = ULONG(page_buf + field_offset(page,_mapcount));
        freelist = ULONG(page_buf + field_offset(page,freelist));
    }else{
        count = ULONG(page_buf + field_offset(page,counters));
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
    // fprintf(fp, "slab_paddr:0x%llx \n", (ulonglong)slab_paddr);
    ulong slab_vaddr = phy_to_virt(slab_paddr);
    // fprintf(fp, "slab_vaddr:0x%lx \n", slab_vaddr);
    ulong fobj = freelist;
    // fprintf(fp, "fobj:0x%lx \n", fobj);
    while (is_kvaddr(fobj)){
        obj_index = (fobj - slab_vaddr) / cache_ptr->size;
        // fprintf(fp, "obj_index:%d \n", obj_index);
        if (obj_index < 0 || obj_index >= slab_ptr->totalobj){
            break;
        }
        obj_free[obj_index] = 1;
        ulong ptr = fobj + cache_ptr->offset;
        // fprintf(fp, "ptr:0x%lx \n", ptr);
        ulong swap_ptr = 0;
        if (BITS64()){
            swap_ptr = swap64(ptr,1);
        }else{
            swap_ptr = swap32(ptr,1);
        }
        // fprintf(fp, "swap_ptr:0x%lx \n", swap_ptr);
        ulong val = read_pointer(ptr,"obj freeptr");
        // fprintf(fp, "val:0x%lx \n", val);
        if (get_config_val("CONFIG_SLAB_FREELIST_HARDENED") == "y") {
        #ifdef ARM64
            fobj = val ^ cache_ptr->random ^ swap_ptr;
        #else
            fobj = val ^ cache_ptr->random ^ swap_ptr;
        #endif
        }else{
            fobj = val;
        }
    }
    ulong obj_addr = slab_vaddr;
    // fprintf(fp, "totalobj:%d \n", slab_ptr->totalobj);
    ulong slab_total_size = slab_ptr->totalobj * cache_ptr->size;
    // fprintf(fp, "slab_total_size:%ld \n", slab_total_size);
    while (obj_addr < slab_vaddr + slab_total_size){
        obj_index = (obj_addr - slab_vaddr) / cache_ptr->size;
        obj_index += 1;
        // fprintf(fp, "obj_index:%d \n", obj_index);
        if (obj_index < 0 || obj_index > slab_ptr->totalobj){
            continue;
        }
        // fprintf(fp, "obj_addr:0x%lx \n", obj_addr);
        std::shared_ptr<obj> obj_ptr = std::make_shared<obj>();
        obj_ptr->index = obj_index;
        obj_ptr->start = obj_addr;
        obj_ptr->end = obj_addr + cache_ptr->size;
        obj_ptr->is_free = (obj_free[obj_index]== 1 ? true:false);
        slab_ptr->obj_list.push_back(obj_ptr);
        obj_addr += cache_ptr->size;
    }
    return slab_ptr;
}

std::vector<std::shared_ptr<slab>> Slub::parser_slab_from_list(std::shared_ptr<kmem_cache> cache_ptr, ulong head_addr){
    std::vector<std::shared_ptr<slab>> slab_list;
    std::vector<ulong> temp_list;
    int offset = 0;
    if (THIS_KERNEL_VERSION < LINUX(6,1,0)){
        offset = field_offset(page,slab_list);
    }else{
        offset = field_offset(slab,slab_list);
    }
    std::vector<ulong> page_list = for_each_list(head_addr,offset);
    for (const auto& slab_page_addr : page_list) {
        // fprintf(fp, "       page_addr:0x%lx \n", slab_page_addr);
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
        // fprintf(fp, "  node_addr:0x%lx \n", addr);
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
            // fprintf(fp, "  cpu_addr:0x%lx \n", addr);
            std::shared_ptr<kmem_cache_cpu> cpu_ptr = std::make_shared<kmem_cache_cpu>();
            cpu_ptr->addr = addr;
            cpu_ptr->tid = ULONG(cpu_buf + field_offset(kmem_cache_cpu,tid));
            ulong cur_slab_addr = 0;
            if (THIS_KERNEL_VERSION > LINUX(6,1,0)){
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
                if (THIS_KERNEL_VERSION > LINUX(6,1,0)){
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
        // fprintf(fp, "kmem_cache:0x%lx \n", cache_addr);
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

void Slub::print_slab_info(std::shared_ptr<slab> slab_ptr){
    physaddr_t paddr = page_to_phy(slab_ptr->first_page);
    ulong slab_vaddr = phy_to_virt(paddr);
    fprintf(fp, "       slab:0x%lx order:%d VA:[0x%lx~0x%lx] totalobj:%d inuse:%d freeobj:%d\n",
        slab_ptr->first_page,
        slab_ptr->order,
        slab_vaddr,(slab_vaddr + (power(2, slab_ptr->order) * page_size)),
        slab_ptr->totalobj,
        slab_ptr->inuse,
        slab_ptr->freeobj
    );
    for (const auto& obj_ptr : slab_ptr->obj_list) {
        std::ostringstream oss;
        oss << "           obj[" << std::setw(5) << std::setfill('0') << obj_ptr->index << "]"
            << "VA:[" << std::hex << obj_ptr->start
            << "~" << std::hex << obj_ptr->end << "]"
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
    fprintf(fp, "kmem_cache:0x%lx %s\n",cache_ptr->addr,cache_ptr->name.c_str());
    for (const auto& node_ptr : cache_ptr->node_list) {
        fprintf(fp, "   kmem_cache_node:0x%lx nr_partial:%ld nr_slabs:%ld total_objects:%ld\n",
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
        fprintf(fp, "   kmem_cache_cpu[%zu]:0x%lx\n",i,cpu_ptr->addr);
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
