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


#include "meminfo.h"

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wpointer-arith"

#ifndef BUILD_TARGET_TOGETHER
DEFINE_PLUGIN_COMMAND(Meminfo)
#endif // !BUILD_TARGET_TOGETHER

void Meminfo::cmd_main(void) {
    int c;
    if (argcnt < 2) cmd_usage(pc->curcmd, SYNOPSIS);
    if (node_page_state.empty() or zone_page_state.empty()){
        parse_meminfo();
    }
    while ((c = getopt(argcnt, args, "a")) != EOF) {
        switch(c) {
            case 'a':
                print_meminfo();
                break;
            default:
                argerrs++;
                break;
        }
    }
    if (argerrs)
        cmd_usage(pc->curcmd, SYNOPSIS);
}

Meminfo::Meminfo(){
    struct_init(page);
    struct_init(zone);
    field_init(zone, _watermark);
    field_init(zone, watermark_boost);
    field_init(pglist_data, node_zones);
    field_init(super_block, s_inodes);
    field_init(inode, i_mapping);
    field_init(inode, i_sb_list);
    field_init(address_space, nrpages);
    field_init(swap_info_struct, flags);
    field_init(swap_info_struct, inuse_pages);
    field_init(percpu_counter, count);
    field_init(percpu_counter, counters);
    if (get_config_val("CONFIG_HUGETLB_PAGE") == "y") {
        struct_init(hstate);
        field_init(hstate, order);
        field_init(hstate, nr_huge_pages);
    }
    cmd_name = "meminfo";
    help_str_list={
        "meminfo",                            /* command name */
        "dump all memory info",        /* short description */
        "\n",
        "EXAMPLES",
        "  Display whole memory info:",
        "    %s> memory -a",
        " ",
        "    MemTotal:        11445568 KB",
        "    MemFree:          9862060 KB",
        "    MemAvailable:    10147000 KB",
        "    ... ...",
        "    Active(anon):        2892 KB",
        "    Inactive(anon):    114068 KB",
        "",
    };
    initialize();
}

void Meminfo::parse_meminfo(void){
    const char* enum_names[] = {
        "LRU_UNEVICTABLE",
        "LRU_ACTIVE_ANON",
        "LRU_ACTIVE_FILE",
        "LRU_INACTIVE_ANON",
        "LRU_INACTIVE_FILE",
        "NR_MLOCK",
        "NR_SHMEM",
        "NR_BOUNCE",
        "NR_LRU_BASE",
        "NR_LRU_LISTS",
        "NR_PAGETABLE",
        "NR_SWAPCACHE",
        "NR_WRITEBACK",
        "NR_FILE_DIRTY",
        "NR_FILE_PAGES",
        "NR_FREE_PAGES",
        "NR_ANON_MAPPED",
        "NR_FILE_MAPPED",
        "NR_FREE_CMA_PAGES",
        "NR_WRITEBACK_TEMP",
        "NR_KERNEL_STACK_KB",
        "NR_KERNEL_SCS_KB",
        "NR_SLAB_RECLAIMABLE_B",
        "NR_SLAB_UNRECLAIMABLE_B",
        "NR_KERNEL_MISC_RECLAIMABLE",
        "NR_ANON_THPS",
        "NR_SHMEM_THPS",
        "NR_SHMEM_PMDMAPPED",
        "NR_FILE_THPS",
        "NR_FILE_PMDMAPPED",
        "NR_VM_NODE_STAT_ITEMS",
        "NR_VM_ZONE_STAT_ITEMS",
        "WMARK_LOW",
        "SWP_USED",
        "SWP_WRITEOK"
    };

    for (size_t i = 0; i < sizeof(enum_names) / sizeof(enum_names[0]); ++i) {
        long numa_cnt = -1;
        enumerator_value(const_cast<char*>(enum_names[i]), &numa_cnt);
        enums.insert(std::make_pair(enum_names[i], numa_cnt));
    }

    for (const auto& pair : enums) {
        if (pair.second < 0){
            fprintf(fp, "Cannot iter enums[%s]!\n", pair.first.c_str());
        }
        // fprintf(fp, "enums[%s] = %ld\n", pair.first.c_str(), pair.second);
    }

    std::vector<std::string> param_names = {
        "vm_node_stat",
        "vm_zone_stat",
        "vm_committed_as",
        "nr_cpu_ids",
        "nr_swapfiles",
        "nr_swap_pages",
        "nr_vmalloc_pages",
        "pcpu_nr_units",
        "pcpu_nr_populated",
        "swap_info",
        "_totalram_pages",
        "totalcma_pages",
        "total_swap_pages",
        "totalreserve_pages",
        "blockdev_superblock",
        "sysctl_overcommit_kbytes",
        "sysctl_overcommit_ratio",
        "__cpu_online_mask",
        "__cpu_dying_mask",
        "__per_cpu_offset"
    };
    if (get_config_val("CONFIG_HUGETLB_PAGE") == "y"){
        param_names.push_back("hstates");
        param_names.push_back("hugetlb_max_hstate");
        param_names.push_back("default_hstate_idx");
    }

    for (const auto& name : param_names){
        ulong param_addr = 0x0;
        if (csymbol_exists(name.c_str())) {
            param_addr = csymbol_value(name.c_str());
        }
        g_param.insert(std::make_pair(name.c_str(), param_addr));
    }

    for (const auto& pair : g_param){
        if (pair.second == 0x0){
            fprintf(fp, "Cannot iter g_param[%s]!\n", pair.first.c_str());
        }
        // fprintf(fp, "g_param[%s] = 0x%lx\n", pair.first.c_str(), pair.second);
    }

    long* node_page_list = (long *)read_memory(g_param["vm_node_stat"], sizeof(ulong) * enums["NR_VM_NODE_STAT_ITEMS"], "");
    if (get_config_val("CONFIG_SMP") == "y")
        for (size_t i = 0; i < enums["NR_VM_NODE_STAT_ITEMS"]; ++i)
            node_page_list[i] = node_page_list[i]<0?0:node_page_list[i];
    node_page_state.resize(enums["NR_VM_NODE_STAT_ITEMS"]);
    std::copy(node_page_list, node_page_list + enums["NR_VM_NODE_STAT_ITEMS"], node_page_state.begin());

    long* zone_page_list = (long *)read_memory(g_param["vm_zone_stat"], sizeof(ulong) * enums["NR_VM_ZONE_STAT_ITEMS"], "");
    if (get_config_val("CONFIG_SMP") == "y")
        for (size_t i = 0; i < enums["NR_VM_ZONE_STAT_ITEMS"]; ++i)
            zone_page_list[i] = zone_page_list[i]<0?0:zone_page_list[i];
    zone_page_state.resize(enums["NR_VM_ZONE_STAT_ITEMS"]);
    std::copy(zone_page_list, zone_page_list + enums["NR_VM_ZONE_STAT_ITEMS"], zone_page_state.begin());

    FREEBUF(node_page_list);
    FREEBUF(zone_page_list);
}

bool Meminfo::is_digits(const std::string& str) {
    std::regex pattern(R"(\d+)");
    return std::regex_match(str, pattern);
}

ulong Meminfo::get_wmark_low(void){
    ulong wmark_low = 0;
    for (size_t n = 0; n < vt->numnodes; n++) {
        struct node_table *nt = &vt->node_table[n];
        ulong node_zones = nt->pgdat + field_offset(pglist_data, node_zones);

        for (size_t i = 0; i < vt->nr_zones; i++) {
            ulong zone_addr = (node_zones + (i * struct_size(zone)));
            void *zone_buf = read_struct(zone_addr, "zone");
            ulong watermark_low_offset = field_offset(zone, _watermark) + enums["WMARK_LOW"] * sizeof(ulong);
            ulong watermark_low = ULONG(zone_buf + watermark_low_offset);
            ulong watermark_boost = ULONG(zone_buf + field_offset(zone, watermark_boost));
            wmark_low += (watermark_low + watermark_boost);
        }
    }
    return wmark_low;
}

ulong Meminfo::get_available(ulong freeram)
{
	ulong wmark_low = get_wmark_low();
    ulong totalreserveram = read_ulong(g_param["totalreserve_pages"], "read from totalreserve_pages");
    long available = freeram - totalreserveram;

    ulong pagecache = node_page_state[enums["NR_SHMEM"] + enums["LRU_ACTIVE_FILE"]]
         + node_page_state[enums["NR_SHMEM"] + enums["LRU_INACTIVE_FILE"]];
	pagecache -= min(pagecache / 2, wmark_low);
	available += pagecache;

    ulong reclaimable = node_page_state[enums["NR_SLAB_RECLAIMABLE_B"]] + node_page_state[enums["NR_KERNEL_MISC_RECLAIMABLE"]];
    available += reclaimable - min(reclaimable / 2, wmark_low);

    return (available < 0)?0:available;;
}

ulong Meminfo::get_blockdev_nr_pages(void){
    ulong list_addr = read_ulong(g_param["blockdev_superblock"], "blockdev_superblock") + field_offset(super_block, s_inodes);
    std::vector<ulong> inodes_list = for_each_list(list_addr, field_offset(inode, i_sb_list));
    long ret = 0;
    for (const auto& inode_addr : inodes_list) {
        ulong i_mapping_addr = read_ulong(inode_addr + field_offset(inode, i_mapping), "get i_mapping addr");
        ret += read_ulong(i_mapping_addr + field_offset(address_space, nrpages), "get nrpages");
    }
    return ret;
}

ulong Meminfo::get_to_be_unused_nr_pages(void){
    long ret = 0;
    ulong nr_swapfiles = read_uint(g_param["nr_swapfiles"], "read from nr_swapfiles");
    for (size_t type = 0; type < nr_swapfiles; type++){
        ulong swap_info = read_pointer(g_param["swap_info"] + type * sizeof(void *), "swap_info_struct addr");
        ulong swap_info_flag = read_ulong(swap_info + field_offset(swap_info_struct, flags), "get swap_info flag");
        if ((swap_info_flag & enums["SWP_USED"]) && !(swap_info_flag & enums["SWP_WRITEOK"])){
            ret += read_ulong(swap_info + field_offset(swap_info_struct, inuse_pages), "get swap_info inuse_pages");
        }
    }
    return ret;
}

ulong Meminfo::get_vm_commit_pages(ulong totalram_pg){
    long allowed = 0;
    ulong overcommit = read_uint(g_param["sysctl_overcommit_kbytes"], "read from sysctl_overcommit_kbytes");
    if (overcommit){
        allowed = overcommit >> (PAGESHIFT() - 10);
    } else{
        ulong hugetlb_pg = 0;
        if (get_config_val("CONFIG_HUGETLB_PAGE") == "y") {
            int hugetlb_max_hstate = read_int(g_param["hugetlb_max_hstate"], "read hugetlb_max_hstate");
            for (int i=0; i < hugetlb_max_hstate; i++){
                ulong h = g_param["hstates"] + i * struct_size(hstate);
                ulong nr_huge_pages = read_ulong(h + field_offset(hstate, nr_huge_pages), "read nr_huge_pages");
                ulong page_per_huge_page = 1UL << read_ulong(h + field_offset(hstate, order), "read order");
                hugetlb_pg += nr_huge_pages + page_per_huge_page;
            }
        }
        allowed = (totalram_pg - hugetlb_pg) * read_int(g_param["sysctl_overcommit_ratio"], "") / 100;
    }
    allowed += read_ulong(g_param["nr_swap_pages"], "read nr_swap_pages");
    return allowed;
}

ulong Meminfo::get_mm_committed_pages(void){
    ulong allowed = read_ulong(g_param["vm_committed_as"] + field_offset(percpu_counter, count), "get percpu_counter count");
    std::string config_nr_cpus = get_config_val("CONFIG_NR_CPUS");
    uint nr_cpus = 1;  // Default
    if (is_digits(config_nr_cpus)){
        nr_cpus = std::stoi(config_nr_cpus);
    }

    ulong cpu_online_mask = read_ulong(g_param["__cpu_online_mask"], "get cpu_online_mask");
    ulong nr_cpu_ids = read_uint(g_param["nr_cpu_ids"], "get nr_cpu_ids");
    for (int cpu = 0; cpu < nr_cpu_ids; ++cpu) {
        if (cpu_online_mask & (1UL << cpu)) {
            ulong per_cpu_offset = read_ulong(g_param["__per_cpu_offset"] + sizeof(ulong)*cpu, "get __per_cpu_offset[cpu]");
            uint temp = read_uint(g_param["vm_committed_as"] + per_cpu_offset + field_offset(percpu_counter, counters), 
                "get percpu_counter->counters for specific cpu");
            allowed += temp;
        }
    }
    return allowed;
}

ulong Meminfo::get_vmalloc_total(void){
    if (get_config_val("CONFIG_MMU") == "y") {
        std::string config_arm64_va_bits = get_config_val("CONFIG_ARM64_VA_BITS");
        ulong arm64_va_bits = is_digits(config_arm64_va_bits)?std::stoi(config_arm64_va_bits):39;   // Default:39
        ulong struct_page_max_shift = static_cast<ulong>(std::ceil(std::log2(struct_size(page))));
        ulong vmemmap_shift = PAGESHIFT() - struct_page_max_shift;
        ulong vmemmap_start = -(1UL << (arm64_va_bits - vmemmap_shift));
        ulong vmalloc_end = vmemmap_start - 0x10000000;     // SZ_256M

        ulong modules_vaddr = -(1UL << ((arm64_va_bits > 48 ? 48 : arm64_va_bits) - 1));
        // SZ_2G: 0x80000000,  SZ_128M: 0x80000000
        ulong modules_vsize = (THIS_KERNEL_VERSION < LINUX(6, 6, 0))?0x80000000:0x08000000;
        ulong vmalloc_start = modules_vaddr + modules_vsize;

        return (vmalloc_end - vmalloc_start);
    } else {
        return 0;
    }
}

void Meminfo::print_meminfo(void){
    ulong totalram_pg = read_ulong(g_param["_totalram_pages"], "read from _totalram_pages");
    ulong freeram_pg = zone_page_state[enums["NR_FREE_PAGES"]];
    ulong available_pg = get_available(freeram_pg);
    ulong blockdev_pg = get_blockdev_nr_pages();
    ulong swap_cached_pg = node_page_state[enums["NR_SWAPCACHE"]];
    ulong cached_pg = node_page_state[enums["NR_FILE_PAGES"]] - swap_cached_pg - blockdev_pg;
    ulong active_aon_pg = node_page_state[enums["NR_LRU_BASE"] + enums["LRU_ACTIVE_ANON"]];
    ulong inactive_aon_pg = node_page_state[enums["NR_LRU_BASE"] + enums["LRU_INACTIVE_ANON"]];
    ulong active_file_pg = node_page_state[enums["NR_LRU_BASE"] + enums["LRU_ACTIVE_FILE"]];
    ulong inactive_file_pg = node_page_state[enums["NR_LRU_BASE"] + enums["LRU_INACTIVE_FILE"]];
    ulong active_pg = active_aon_pg + active_file_pg;
    ulong inactive_pg = inactive_aon_pg + inactive_file_pg;
    ulong unevictable_pg = node_page_state[enums["NR_LRU_BASE"] + enums["LRU_UNEVICTABLE"]];
    ulong mlocked_pg = zone_page_state[enums["NR_MLOCK"]];
    ulong totalswap_pg = get_to_be_unused_nr_pages() + read_ulong(g_param["total_swap_pages"], "read total_swap_pages");
    ulong freeswap_pg = get_to_be_unused_nr_pages() + read_ulong(g_param["nr_swap_pages"], "read nr_swap_pages");
    ulong dirty_pg = node_page_state[enums["NR_FILE_DIRTY"]];
    ulong writeback_pg = node_page_state[enums["NR_WRITEBACK"]];
    ulong anon_pg = node_page_state[enums["NR_ANON_MAPPED"]];
    ulong mapped_pg = node_page_state[enums["NR_FILE_MAPPED"]];
    ulong sharedram_pg = node_page_state[enums["NR_SHMEM"]];
    ulong slab_reclaimable_pg = node_page_state[enums["NR_SLAB_RECLAIMABLE_B"]];
    ulong slab_unreclaim_pg = node_page_state[enums["NR_SLAB_UNRECLAIMABLE_B"]];
    ulong kreclaimable_pg = slab_reclaimable_pg + node_page_state[enums["NR_KERNEL_MISC_RECLAIMABLE"]];
    ulong slab_pg = slab_unreclaim_pg + slab_reclaimable_pg;
    ulong kernelstack_bytes = node_page_state[enums["NR_KERNEL_STACK_KB"]] * 1024;
    ulong shadowstack_bytes = 0;
    if (get_config_val("CONFIG_SHADOW_CALL_STACK") == "y") {
        shadowstack_bytes = node_page_state[enums["NR_KERNEL_SCS_KB"]] * 1024;
    }
    ulong pagetables_pg = node_page_state[enums["NR_PAGETABLE"]];
    ulong bounce_pg = zone_page_state[enums["NR_BOUNCE"]];

    ulong writebacktmp_pg = node_page_state[enums["NR_WRITEBACK_TEMP"]];
    ulong vm_commit_pg = get_vm_commit_pages(totalram_pg);
    ulong mm_committed_pg = get_mm_committed_pages();
    ulong vmalloc_total_bytes = get_vmalloc_total();
    ulong vmalloc_used_pg = read_ulong(g_param["nr_vmalloc_pages"], "");
    ulong pcpu_nr_pg = read_uint(g_param["pcpu_nr_units"], "nr_units") * read_ulong(g_param["pcpu_nr_populated"], "");
    ulong anon_huge_pg = 0, shmem_huge_pg = 0, shmem_pmd_mapped_pg = 0, file_huge_pg = 0, file_pmd_mapped_pg = 0;
    if (get_config_val("CONFIG_TRANSPARENT_HUGEPAGE") == "y") {
        anon_huge_pg = node_page_state[enums["NR_ANON_THPS"]];
        shmem_huge_pg = node_page_state[enums["NR_SHMEM_THPS"]];
        shmem_pmd_mapped_pg = node_page_state[enums["NR_SHMEM_PMDMAPPED"]];
        file_huge_pg = node_page_state[enums["NR_FILE_THPS"]];
        file_pmd_mapped_pg = node_page_state[enums["NR_FILE_PMDMAPPED"]];
    }
    ulong cma_total_pg = 0, cma_free_pg = 0;
    if (get_config_val("CONFIG_CMA") == "y") {
        cma_total_pg = read_ulong(g_param["totalcma_pages"], "totalcma_pages");
        cma_free_pg = zone_page_state[enums["NR_FREE_CMA_PAGES"]];
    }

    std::ostringstream oss;
    oss << std::left << "MemTotal:       " << std::setw(12) << std::right << csize(totalram_pg * page_size, KB, 0) << "\n"
        << std::left << "MemFree:        " << std::setw(12) << std::right << csize(freeram_pg * page_size, KB, 0) << "\n"
        << std::left << "MemAvailable:   " << std::setw(12) << std::right << csize(available_pg * page_size, KB, 0) << "\n"
        << std::left << "Buffers:        " << std::setw(12) << std::right << csize(blockdev_pg * page_size, KB, 0) << "\n"
        << std::left << "Cached:         " << std::setw(12) << std::right << csize(cached_pg * page_size, KB, 0) << "\n"
        << std::left << "SwapCached:     " << std::setw(12) << std::right << csize(swap_cached_pg * page_size, KB, 0) << "\n"
        << std::left << "Active:         " << std::setw(12) << std::right << csize(active_pg * page_size, KB, 0) << "\n"
        << std::left << "Inactive:       " << std::setw(12) << std::right << csize(inactive_pg * page_size, KB, 0) << "\n"
        << std::left << "Active(anon):   " << std::setw(12) << std::right << csize(active_aon_pg * page_size, KB, 0) << "\n"
        << std::left << "Inactive(anon): " << std::setw(12) << std::right << csize(inactive_aon_pg * page_size, KB, 0) << "\n"
        << std::left << "Active(file):   " << std::setw(12) << std::right << csize(active_file_pg * page_size, KB, 0) << "\n"
        << std::left << "Inactive(file): " << std::setw(12) << std::right << csize(inactive_file_pg * page_size, KB, 0) << "\n"
        << std::left << "Unevictable:    " << std::setw(12) << std::right << csize(unevictable_pg * page_size, KB, 0) << "\n"
        << std::left << "Mlocked:        " << std::setw(12) << std::right << csize(mlocked_pg * page_size, KB, 0) << "\n"
        << std::left << "SwapTotal:      " << std::setw(12) << std::right << csize(totalswap_pg * page_size, KB, 0) << "\n"
        << std::left << "SwapFree:       " << std::setw(12) << std::right << csize(freeswap_pg * page_size, KB, 0) << "\n"
        << std::left << "Dirty:          " << std::setw(12) << std::right << csize(dirty_pg * page_size, KB, 0) << "\n"
        << std::left << "Writeback:      " << std::setw(12) << std::right << csize(writeback_pg * page_size, KB, 0) << "\n"
        << std::left << "AnonPages:      " << std::setw(12) << std::right << csize(anon_pg * page_size, KB, 0) << "\n"
        << std::left << "Mapped:         " << std::setw(12) << std::right << csize(mapped_pg * page_size, KB, 0) << "\n"
        << std::left << "Shmem:          " << std::setw(12) << std::right << csize(sharedram_pg * page_size, KB, 0) << "\n"
        << std::left << "KReclaimable:   " << std::setw(12) << std::right << csize(kreclaimable_pg * page_size, KB, 0) << "\n"
        << std::left << "Slab:           " << std::setw(12) << std::right << csize(slab_pg * page_size, KB, 0) << "\n"
        << std::left << "SReclaimable:   " << std::setw(12) << std::right << csize(slab_reclaimable_pg * page_size, KB, 0) << "\n"
        << std::left << "SUnreclaim:     " << std::setw(12) << std::right << csize(slab_unreclaim_pg * page_size, KB, 0) << "\n"
        << std::left << "KernelStack:    " << std::setw(12) << std::right << csize(kernelstack_bytes, KB, 0) << "\n";
    if (get_config_val("CONFIG_SHADOW_CALL_STACK") == "y") {
        oss << std::left << "ShadowCallStack:" << std::setw(12) << std::right << csize(shadowstack_bytes, KB, 0) << "\n";
    }
    oss << std::left << "PageTables:     " << std::setw(12) << std::right << csize(pagetables_pg * page_size, KB, 0) << "\n"
        << std::left << "NFS_Unstable:   " << std::setw(12) << std::right << csize(0, KB, 0) << "\n"
        << std::left << "Bounce:         " << std::setw(12) << std::right << csize(bounce_pg * page_size, KB, 0) << "\n"
        << std::left << "WritebackTmp:   " << std::setw(12) << std::right << csize(writebacktmp_pg * page_size, KB, 0) << "\n"
        << std::left << "CommitLimit:    " << std::setw(12) << std::right << csize(vm_commit_pg * page_size, KB, 0) << "\n"
        << std::left << "VmallocTotal:   " << std::setw(12) << std::right << csize(vmalloc_total_bytes, KB, 0) << "\n"
        << std::left << "VmallocUsed:    " << std::setw(12) << std::right << csize(vmalloc_used_pg * page_size, KB, 0) << "\n"
        << std::left << "VmallocChunk:   " << std::setw(12) << std::right << csize(0, KB, 0) << "\n"
        << std::left << "Percpu:         " << std::setw(12) << std::right << csize(pcpu_nr_pg * page_size, KB, 0) << "\n";
    if (get_config_val("CONFIG_TRANSPARENT_HUGEPAGE") == "y") {
        oss << std::left << "AnonHugePages:  " << std::setw(12) << std::right << csize(anon_huge_pg * page_size, KB, 0) << "\n"
            << std::left << "ShmemHugePages: " << std::setw(12) << std::right << csize(shmem_huge_pg * page_size, KB, 0) << "\n"
            << std::left << "ShmemPmdMapped: " << std::setw(12) << std::right << csize(shmem_pmd_mapped_pg * page_size, KB, 0) << "\n"
            << std::left << "FileHugePages:  " << std::setw(12) << std::right << csize(file_huge_pg * page_size, KB, 0) << "\n"
            << std::left << "FilePmdMapped:  " << std::setw(12) << std::right << csize(file_pmd_mapped_pg * page_size, KB, 0) << "\n";
    }
    if (get_config_val("CONFIG_CMA") == "y") {
        oss << std::left << "CmaTotal:       " << std::setw(12) << std::right << csize(cma_total_pg * page_size, KB, 0) << "\n"
            << std::left << "CmaFree:        " << std::setw(12) << std::right << csize(cma_free_pg * page_size, KB, 0) << "\n";
    }
    fprintf(fp, "%s \n",oss.str().c_str());
}

#pragma GCC diagnostic pop
