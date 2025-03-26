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
    std::string cppString;
    if (argcnt != 1) cmd_usage(pc->curcmd, SYNOPSIS);
    else print_all();
    if (argerrs)
        cmd_usage(pc->curcmd, SYNOPSIS);
}

Meminfo::Meminfo(){
    cmd_name = "meminfo";
    help_str_list={
        "meminfo",                            /* command name */
        "dump all memory info",        /* short description */
        "\n",
        "EXAMPLES",
        "  Display whole memory info:",
        "    %s> memory",
        "",
        "    MemTotal:        11445568 KB",
        "    MemFree:          9862060 KB",
        "    MemAvailable:    10147000 KB",
        "    Buffers:            23152 KB",
        "    Cached:            414872 KB",
        "    SwapCached:             0 KB",
        "    Active:             66296 KB",
        "    Inactive:          450680 KB",
        "    Active(anon):        2892 KB",
        "    Inactive(anon):    114068 KB",
        "",
    };
    initialize();
    parameters_init();
}

void Meminfo::parameters_init(void){
    struct_init(page);
    struct_init(zone);
    field_init(zone, _watermark);
    field_init(zone, watermark_boost);

    struct_init(pglist_data);
    field_init(pglist_data, node_zones);

    struct_init(super_block);
    field_init(super_block, s_inodes);

    struct_init(inode);
    field_init(inode, i_mapping);
    field_init(inode, i_sb_list);
    struct_init(address_space);
    field_init(address_space, nrpages);

    struct_init(swap_info_struct);
    field_init(swap_info_struct, flags);
    field_init(swap_info_struct, inuse_pages);

    struct_init(percpu_counter);
    field_init(percpu_counter, count);
    field_init(percpu_counter, counters);

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
        "NR_SLAB_RECLAIMABLE_B",
        "NR_SLAB_UNRECLAIMABLE_B",
        "NR_KERNEL_MISC_RECLAIMABLE",
        "WMARK_LOW",
        "SWP_USED",
        "SWP_WRITEOK"
    };

    for (size_t i = 0; i < sizeof(enum_names) / sizeof(enum_names[0]); ++i) {
        long numa_cnt = -1;
        enumerator_value(const_cast<char*>(enum_names[i]), &numa_cnt);
        enumerator.insert(std::make_pair(enum_names[i], numa_cnt));
    }

    for (const auto& pair : enumerator) {
        if (pair.second < 0){
            fprintf(fp, "Cannot iter enumerator[%s]!\n", pair.first.c_str());
        }
        // fprintf(fp, "enumerator[%s] = %ld\n", pair.first.c_str(), pair.second);
    }

    std::map<std::string, ulong*> symbol_map = {
        {"vm_node_stat", &vm_node_addr},
        {"vm_zone_stat", &vm_zone_addr},
        {"vm_committed_as", &vm_committed_addr},
        {"nr_cpu_ids", &nr_cpu_ids_addr},
        {"nr_swapfiles", &nr_swapfiles_addr},
        {"nr_swap_pages", &nr_swap_pages_addr},
        {"nr_vmalloc_pages", &nr_vmalloc_pages_addr},
        {"pcpu_nr_units", &pcpu_nr_units_addr},
        {"pcpu_nr_populated", &pcpu_nr_populated_addr},
        {"swap_info", &swap_info_addr},
        {"_totalram_pages", &totalram_addr},
        {"totalcma_pages", &totalcma_pages_addr},
        {"total_swap_pages", &total_swap_pages_addr},
        {"totalreserve_pages", &totalreserveram_addr},
        {"blockdev_superblock", &blockdev_superblock_addr},
        {"sysctl_overcommit_kbytes", &sysctl_overcommit_addr},
        {"__cpu_online_mask", &cpu_online_mask_addr},
        {"__per_cpu_offset", &per_cpu_offset_addr}
    };

    for (const auto& pair : symbol_map) {
        if (!csymbol_exists(pair.first.c_str())) {
            fprintf(fp, "%s doesn't exist in this kernel!\n", pair.first.c_str());
            continue;
        }
        *pair.second = csymbol_value(pair.first.c_str());
        // fprintf(fp, "symbol map [%s][0x%lx]!\n", pair.first.c_str(), *pair.second);
    }
}

ulong Meminfo::get_bytes_from_page_count(ulong cnt){
    return cnt * PAGESIZE();
}

ulong Meminfo::get_node_state_pages(const char* enum_name){
    ulong offset = enumerator[enum_name] * sizeof(long);
    long size = read_long(vm_node_addr + offset, "read from vm_node_stat");
    if (get_config_val("CONFIG_SMP") == "y") {
        return (size < 0)?0:size;
    } else {
        return size;
    }
}

ulong Meminfo::get_node_state_pages(const char* enum_name, ulong enum_offset){
    ulong offset = (enumerator[enum_name] + enum_offset) * sizeof(long);
    long size = read_long(vm_node_addr + offset, "read from vm_node_addr");
    if (get_config_val("CONFIG_SMP") == "y") {
        return (size < 0)?0:size;
    } else {
        return size;
    }
}

ulong Meminfo::get_zone_state_pages(const char* enum_name){
    ulong offset = enumerator[enum_name] * sizeof(long);
    long size = read_long(vm_zone_addr + offset, "read from vm_zone_stat");
    if (get_config_val("CONFIG_SMP") == "y") {
        return (size < 0)?0:size;
    } else {
        return size;
    }
}

ulong Meminfo::get_zone_state_pages(const char* enum_name, ulong enum_offset){
    ulong offset = (enumerator[enum_name] + enum_offset) * sizeof(long);
    long size = read_long(vm_zone_addr + offset, "read from vm_zone_stat");
    if (get_config_val("CONFIG_SMP") == "y") {
        return (size < 0)?0:size;
    } else {
        return size;
    }
}

ulong Meminfo::get_wmark_low(void){
    ulong wmark_low = 0;
    for (size_t n = 0; n < vt->numnodes; n++) {
        struct node_table *nt = &vt->node_table[n];
        ulong node_zones = nt->pgdat + field_offset(pglist_data, node_zones);

        for (size_t i = 0; i < vt->nr_zones; i++) {
            ulong zone_addr = (node_zones + (i * struct_size(zone)));
            void *zone_buf = read_struct(zone_addr, "zone");
            ulong watermark_low_offset = field_offset(zone, _watermark) + enumerator["WMARK_LOW"] * sizeof(ulong);
            ulong watermark_low = ULONG(zone_buf + watermark_low_offset);
            ulong watermark_boost = ULONG(zone_buf + field_offset(zone, watermark_boost));
            wmark_low += (watermark_low + watermark_boost);
        }
    }
    return wmark_low;
}

ulong Meminfo::get_available(ulong vm_node_addr, ulong freeram)
{
    ulong* pages = new ulong[enumerator["NR_LRU_LISTS"]];
	for (size_t lru = LRU_BASE; lru < enumerator["NR_LRU_LISTS"]; lru++){
		pages[lru] = get_node_state_pages("NR_SHMEM", lru);
    }

	ulong wmark_low = get_wmark_low();
    ulong totalreserveram = read_ulong(totalreserveram_addr, "read from totalreserve_pages");
    long available = freeram - totalreserveram;

    ulong pagecache = pages[enumerator["LRU_ACTIVE_FILE"]] + pages[enumerator["LRU_INACTIVE_FILE"]];
	pagecache -= min(pagecache / 2, wmark_low);
	available += pagecache;

    ulong reclaimable = get_node_state_pages("NR_SLAB_RECLAIMABLE_B") + get_node_state_pages("NR_KERNEL_MISC_RECLAIMABLE");
    available += reclaimable - min(reclaimable / 2, wmark_low);

    return (available < 0)?0:available;;
}

ulong Meminfo::get_blockdev_nr_pages(void){
    ulong list_addr = read_ulong(blockdev_superblock_addr, "blockdev_superblock") + field_offset(super_block, s_inodes);
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
    ulong nr_swapfiles = read_uint(nr_swapfiles_addr, "read from nr_swapfiles");
    for (size_t type = 0; type < nr_swapfiles; type++){
        ulong swap_info = read_pointer(swap_info_addr + type * sizeof(void *), "swap_info_struct addr");
        ulong swap_info_flag = read_ulong(swap_info + field_offset(swap_info_struct, flags), "get swap_info flag");
        if ((swap_info_flag & enumerator["SWP_USED"]) && !(swap_info_flag & enumerator["SWP_WRITEOK"])){
            ret += read_ulong(swap_info + field_offset(swap_info_struct, inuse_pages), "get swap_info inuse_pages");
        }
    }
    return ret;
}

ulong Meminfo::get_vm_commit_pages(void){
    long allowed = 0;
    ulong overcommit = read_uint(sysctl_overcommit_addr, "read from sysctl_overcommit_kbytes");
    if (overcommit){
        allowed = overcommit >> (PAGESHIFT() - 10);
    } else{
        // To be update for read from hstate...
    }
    allowed += read_ulong(nr_swap_pages_addr, "read nr_swap_pages");
    return allowed;
}

ulong Meminfo::get_mm_committed_pages(void){
    ulong allowed = read_ulong(vm_committed_addr + field_offset(percpu_counter, count), "get percpu_counter count");
    ulong cpu_online_mask = read_ulong(cpu_online_mask_addr, "get cpu_online_mask");
    ulong nr_cpu_ids = read_ulong(nr_cpu_ids_addr, "get nr_cpu_ids");
    for (int cpu = 0; cpu < nr_cpu_ids; ++cpu) {
        if (cpu_online_mask & (1UL << cpu)) {
            ulong per_cpu_offset = read_ulong(per_cpu_offset_addr + sizeof(ulong)*cpu, "get __per_cpu_offset[cpu]");
            uint temp = read_uint(vm_committed_addr + per_cpu_offset + field_offset(percpu_counter, counters), "get percpu_counter->counters for specific cpu");
            allowed += temp;
        }
    }
    return allowed;
}

ulong Meminfo::get_vmalloc_total(void){
    if (get_config_val("CONFIG_MMU") == "y") {
        ulong arm64_va_bits = std::stoi(get_config_val("CONFIG_ARM64_VA_BITS"));
        ulong struct_page_max_shift = static_cast<ulong>(std::ceil(std::log2(struct_size(page))));
        ulong vmemmap_shift = PAGESHIFT() - struct_page_max_shift;
        ulong vmemmap_start = -(1UL << (arm64_va_bits - vmemmap_shift));
        ulong vmalloc_end = vmemmap_start - 0x10000000;     // SZ_256M

        ulong modules_vaddr = -(1UL << ((arm64_va_bits > 48 ? 48 : arm64_va_bits) - 1));
        ulong vmalloc_start = modules_vaddr + 0x08000000;   // SZ_128M

        return (vmalloc_end - vmalloc_start);
    } else {
        return 0;
    }
}

void Meminfo::print_all(void){
    ulong totalram_pg = read_ulong(totalram_addr, "read from _totalram_pages");
    ulong freeram_pg = get_zone_state_pages("NR_FREE_PAGES");
    ulong available_pg = get_available(vm_node_addr, freeram_pg);
    ulong blockdev_pg = get_blockdev_nr_pages();
    ulong swap_cached_pg = get_node_state_pages("NR_SWAPCACHE");
    ulong cached_pg = get_node_state_pages("NR_FILE_PAGES") - swap_cached_pg - blockdev_pg;
    ulong* pages = new ulong[enumerator["NR_LRU_LISTS"]];
    for (size_t lru = LRU_BASE; lru < enumerator["NR_LRU_LISTS"]; lru++){
		pages[lru] = get_node_state_pages("NR_LRU_BASE", lru);
    }
    ulong active_aon_pg = pages[enumerator["LRU_ACTIVE_ANON"]];
    ulong inactive_aon_pg = pages[enumerator["LRU_INACTIVE_ANON"]];
    ulong active_file_pg = pages[enumerator["LRU_ACTIVE_FILE"]];
    ulong inactive_file_pg = pages[enumerator["LRU_INACTIVE_FILE"]];
    ulong active_pg = active_aon_pg + active_file_pg;
    ulong inactive_pg = inactive_aon_pg + inactive_file_pg;
    ulong unevictable_pg = pages[enumerator["LRU_UNEVICTABLE"]];
    ulong mlocked_pg = get_zone_state_pages("NR_MLOCK");
    ulong totalswap_pg = get_to_be_unused_nr_pages() + read_ulong(total_swap_pages_addr, "read total_swap_pages");
    ulong freeswap_pg = get_to_be_unused_nr_pages() + read_ulong(nr_swap_pages_addr, "read nr_swap_pages");
    ulong dirty_pg = get_node_state_pages("NR_FILE_DIRTY");
    ulong writeback_pg = get_node_state_pages("NR_WRITEBACK");
    ulong anon_pg = get_node_state_pages("NR_ANON_MAPPED");
    ulong mapped_pg = get_node_state_pages("NR_FILE_MAPPED");
    ulong sharedram_pg = get_node_state_pages("NR_SHMEM");
    ulong slab_reclaimable_pg = get_node_state_pages("NR_SLAB_RECLAIMABLE_B");
    ulong slab_unreclaim_pg = get_node_state_pages("NR_SLAB_UNRECLAIMABLE_B");
    ulong kreclaimable_pg = slab_reclaimable_pg + get_node_state_pages("NR_KERNEL_MISC_RECLAIMABLE");
    ulong slab_pg = slab_unreclaim_pg + slab_reclaimable_pg;
    ulong kernelstack_bytes = get_node_state_pages("NR_KERNEL_STACK_KB") * 1024;
    ulong pagetables_pg = get_node_state_pages("NR_PAGETABLE");
    ulong bounce_pg = get_zone_state_pages("NR_BOUNCE");
    ulong writebacktmp_pg = get_node_state_pages("NR_WRITEBACK_TEMP");
    ulong vm_commit_pg = get_vm_commit_pages();
    ulong mm_committed_pg = get_mm_committed_pages();
    ulong vmalloc_total_bytes = get_vmalloc_total();
    ulong vmalloc_used_pg = read_ulong(nr_vmalloc_pages_addr, "read nr_vmalloc_pages");
    ulong pcpu_nr_pg = read_uint(pcpu_nr_units_addr, "nr_units") * read_ulong(pcpu_nr_populated_addr, "nr_populated");
    ulong cma_total_pg = read_ulong(totalcma_pages_addr, "totalcma_pages");
    ulong cma_free_pg = get_zone_state_pages("NR_FREE_CMA_PAGES");

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
        << std::left << "Slab:           " << std::setw(12) << std::right << csize(slab_pg * page_size, KB, 0) << "\n"
        << std::left << "SReclaimable:   " << std::setw(12) << std::right << csize(slab_reclaimable_pg * page_size, KB, 0) << "\n"
        << std::left << "SUnreclaim:     " << std::setw(12) << std::right << csize(slab_unreclaim_pg * page_size, KB, 0) << "\n"
        << std::left << "KernelStack:    " << std::setw(12) << std::right << csize(kernelstack_bytes, KB, 0) << "\n"
        << std::left << "PageTables:     " << std::setw(12) << std::right << csize(pagetables_pg * page_size, KB, 0) << "\n"
        << std::left << "NFS_Unstable:   " << std::setw(12) << std::right << csize(0, KB, 0) << "\n"
        << std::left << "Bounce:         " << std::setw(12) << std::right << csize(bounce_pg * page_size, KB, 0) << "\n"
        << std::left << "WritebackTmp:   " << std::setw(12) << std::right << csize(writebacktmp_pg * page_size, KB, 0) << "\n"
        << std::left << "CommitLimit:    " << std::setw(12) << std::right << csize(vm_commit_pg * page_size, KB, 0) << "\n"
        << std::left << "Committed_AS:   " << std::setw(12) << std::right << csize(mm_committed_pg * page_size, KB, 0) << "\n"
        << std::left << "VmallocTotal:   " << std::setw(12) << std::right << csize(vmalloc_total_bytes, KB, 0) << "\n"
        << std::left << "VmallocUsed:    " << std::setw(12) << std::right << csize(vmalloc_used_pg * page_size, KB, 0) << "\n"
        << std::left << "VmallocChunk:   " << std::setw(12) << std::right << csize(0, KB, 0) << "\n"
        << std::left << "Percpu:         " << std::setw(12) << std::right << csize(pcpu_nr_pg * page_size, KB, 0) << "\n";
    if (get_config_val("CONFIG_CMA") == "y") {
        oss << std::left << "CmaTotal:       " << std::setw(12) << std::right << csize(cma_total_pg * page_size, KB, 0) << "\n"
            << std::left << "CmaFree:        " << std::setw(12) << std::right << csize(cma_free_pg * page_size, KB, 0) << "\n";
    }
    fprintf(fp, "%s \n",oss.str().c_str());
}

#pragma GCC diagnostic pop
