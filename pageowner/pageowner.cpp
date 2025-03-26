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

#include "pageowner.h"

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wpointer-arith"

#ifndef BUILD_TARGET_TOGETHER
DEFINE_PLUGIN_COMMAND(Pageowner)
#endif

void Pageowner::cmd_main(void) {
    int c;
    std::string cppString;
    if (argcnt < 2) cmd_usage(pc->curcmd, SYNOPSIS);
    if(!is_enable_pageowner())return;
    if(owner_map.size() == 0){
        parser_all_pageowners();
    }
    while ((c = getopt(argcnt, args, "afn:p:P:tm")) != EOF) {
        switch(c) {
            case 'a': //all alloc page_owner info
                print_all_page_owner(true);
                break;
            case 'f': //all free page_owner info
                print_all_page_owner(false);
                break;
            case 'n': //print the page_owner info for specific pfn
                cppString.assign(optarg);
                print_page_owner(cppString,INPUT_PFN);
                break;
            case 'p': //print the page_owner info for specific phys address
                cppString.assign(optarg);
                print_page_owner(cppString,INPUT_PYHS);
                break;
            case 'P': //print the page_owner info for specific page
                cppString.assign(optarg);
                print_page_owner(cppString,INPUT_PAGE);
                break;
            case 't': //sort the page_owner info by total alloc count
                print_total_size_by_handle();
                break;
            case 'm': //print all memory info
                print_memory_info();
                break;
            default:
                argerrs++;
                break;
        }
    }
    if (argerrs)
        cmd_usage(pc->curcmd, SYNOPSIS);
}

bool Pageowner::is_enable_pageowner(){
    if(get_config_val("CONFIG_PAGE_OWNER") != "y"){
        fprintf(fp, "page_owner is disabled\n");
        return false;
    }
    if (!csymbol_exists("page_owner_inited")){
        fprintf(fp, "page_owner is disabled\n");
        return false;
    }
    int inited;
    try_get_symbol_data(TO_CONST_STRING("page_owner_inited"), sizeof(int), &inited);
    if (inited != 1){
        fprintf(fp, "cannot find page_owner_inited\n");
        return false;
    }
    return true;
}

Pageowner::Pageowner(){
    debug = false;
    field_init(page_owner,order);
    field_init(page_owner,last_migrate_reason);
    field_init(page_owner,gfp_mask);
    field_init(page_owner,handle);
    field_init(page_owner,free_handle);
    field_init(page_owner,ts_nsec);
    field_init(page_owner,free_ts_nsec);
    field_init(page_owner,pid);
    field_init(page_owner,tgid);
    field_init(page_owner,comm);
    field_init(page_owner,free_pid);
    field_init(page_owner,free_tgid);
    struct_init(page_owner);
    if(get_config_val("CONFIG_SPARSEMEM") == "y"){
        field_init(mem_section,page_ext);
    }else{
        field_init(pglist_data,node_page_ext);
    }
    field_init(page_ext,flags);
    struct_init(page_ext);

    field_init(page_ext_operations,offset);
    field_init(page_ext_operations,size);
    struct_init(page_ext_operations);

    field_init(stack_record,next);
    field_init(stack_record,size);
    field_init(stack_record,handle);
    field_init(stack_record,entries);
    struct_init(stack_record);
    cmd_name = "pageowner";
    help_str_list={
        "pageowner",                            /* command name */
        "dump page owner information",        /* short description */
        "-a \n"
            "  pageowner -f \n"
            "  pageowner -t \n"
            "  pageowner -n <pfn>\n"
            "  pageowner -p <phys addr>\n"
            "  pageowner -P <Page addr>\n"
            "  pageowner -m \n"
            "  This command dumps the pageowner info.",
        "\n",
        "EXAMPLES",
        "  Display alloc stack for every page:",
        "    %s> pageowner -a",
        "    page_owner:0xffffff800737ff48 PFN:0xbfffc-0xbfffd Page:0xfffffffe01ffff00  Order:0 stack_record:0xffffff805febaac0 PID:1877 ts_nsec:84522428174",
        "          [<ffffffde2edb039c>] post_alloc_hook+0x20c",
        "          [<ffffffde2edb3064>] prep_new_page+0x28",
        "          [<ffffffde2edb46a4>] get_page_from_freelist+0x12ac",
        "          [<ffffffde2edb320c>] __alloc_pages+0xd8",
        "          [<ffffffde2bf61b9c>] zs_malloc+0x200",
        "          [<ffffffde2bf718e4>] zram_bvec_rw+0x2a8",
        "          [<ffffffde2bf7140c>] zram_rw_page.4e8b0154c58fc8baa75c3124f9a25b1c+0x9c",
        "          [<ffffffde2f0ddba4>] bdev_write_page+0x88",
        "          [<ffffffde2edc21cc>] __swap_writepage+0x64",
        "          [<ffffffde2edc2120>] swap_writepage+0x50",
        "          [<ffffffde2ed55dbc>] shrink_page_list+0xd18",
        "          [<ffffffde2ed56cb0>] reclaim_pages+0x1fc",
        "          [<ffffffde2edc132c>] madvise_cold_or_pageout_pte_range.50c4f95024e08bb75653a011da8190a2+0x79c",
        "          [<ffffffde2eda4f44>] walk_pgd_range+0x324",
        "          [<ffffffde2eda4a34>] walk_page_range+0x1cc",
        "          [<ffffffde2edbfe40>] madvise_vma_behavior.50c4f95024e08bb75653a011da8190a2+0x900",
        "\n",
        "  Display free stack for every page:",
        "    %s> pageowner -f",
        "    page_owner:0xffffff800737ff48 PFN:0xbfffc-0xbfffd Page:0xfffffffe01ffff00  Order:0 stack_record:0xffffff805febaca0 PID:1877 free_ts_nsec:84514802444",
        "          [<ffffffde2edb11a0>] free_unref_page_prepare+0x2d8",
        "          [<ffffffde2edb1634>] free_unref_page_list+0xa0",
        "          [<ffffffde2ed56528>] shrink_page_list+0x1484",
        "          [<ffffffde2ed56cb0>] reclaim_pages+0x1fc",
        "          [<ffffffde2edc132c>] madvise_cold_or_pageout_pte_range.50c4f95024e08bb75653a011da8190a2+0x79c",
        "          [<ffffffde2eda4f44>] walk_pgd_range+0x324",
        "          [<ffffffde2eda4a34>] walk_page_range+0x1cc",
        "          [<ffffffde2edbfe40>] madvise_vma_behavior.50c4f95024e08bb75653a011da8190a2+0x900",
        "          [<ffffffde2edbf354>] do_madvise+0x168",
        "          [<ffffffde2edc015c>] __arm64_sys_process_madvise+0x150",
        "          [<ffffffde2eab6ad4>] invoke_syscall+0x5c",
        "          [<ffffffde2eab69d8>] el0_svc_common+0x94",
        "          [<ffffffde2eab68e4>] do_el0_svc+0x24",
        "          [<ffffffde2fa5dd2c>] el0_svc+0x30",
        "          [<ffffffde2fa5dcb0>] el0t_64_sync_handler+0x68",
        "          [<ffffffde2ea11624>] el0t_64_sync+0x1b4",
        "\n",
        "  Display the alloc and free stack for specific pfn:",
        "    %s> pageowner -n 0x4000e",
        "    page_owner:0xffffff80038002a8 PFN:0x4000e-0x4000f Page:0xfffffffe00000380  Order:0 stack_record:0xffffff80086b6eb0 PID:1 ts_nsec:3200156311",
        "          [<ffffffde2edb039c>] post_alloc_hook+0x20c",
        "          [<ffffffde2edb3064>] prep_new_page+0x28",
        "          [<ffffffde2edb46a4>] get_page_from_freelist+0x12ac",
        "          [<ffffffde2edb320c>] __alloc_pages+0xd8",
        "          [<ffffffde2ed49210>] page_cache_ra_unbounded+0x130",
        "          [<ffffffde2ed49754>] do_page_cache_ra+0x3c",
        "          [<ffffffde2ed3b718>] do_sync_mmap_readahead+0x188",
        "          [<ffffffde2ed3abc0>] filemap_fault+0x280",
        "          [<ffffffde2ed98b7c>] __do_fault+0x6c",
        "          [<ffffffde2ed98288>] handle_pte_fault+0x1b4",
        "          [<ffffffde2ed94820>] do_handle_mm_fault+0x4a0",
        "          [<ffffffde2fa97488>] do_page_fault.edea7eadbbe8ee1d4acc94c9444fd9d5+0x520",
        "          [<ffffffde2fa96f50>] do_translation_fault.edea7eadbbe8ee1d4acc94c9444fd9d5+0x44",
        "          [<ffffffde2eacbd90>] do_mem_abort+0x64",
        "          [<ffffffde2fa5ddf4>] el0_da+0x48",
        "          [<ffffffde2fa5dce0>] el0t_64_sync_handler+0x98",
        "",
        "    page_owner:0xffffff80038002a8 PFN:0x4000e-0x4000f Page:0xfffffffe00000380  Order:0 stack_record:0xffffff80086b5350 PID:1 free_ts_nsec:3033067977",
        "          [<ffffffde2edb11a0>] free_unref_page_prepare+0x2d8",
        "          [<ffffffde2edb1634>] free_unref_page_list+0xa0",
        "          [<ffffffde2ed4e808>] release_pages+0x510",
        "          [<ffffffde2ed4e8b8>] __pagevec_release+0x34",
        "          [<ffffffde2ed64b54>] shmem_undo_range+0x210",
        "          [<ffffffde2ed6a9d0>] shmem_evict_inode.ac7d038029138368f3a468e11f4adc2c+0x12c",
        "          [<ffffffde2ee4152c>] evict+0xd4",
        "          [<ffffffde2ee3ed64>] iput+0x244",
        "          [<ffffffde2ee25f1c>] do_unlinkat+0x1ac",
        "          [<ffffffde2ee2605c>] __arm64_sys_unlinkat+0x48",
        "          [<ffffffde2eab6ad4>] invoke_syscall+0x5c",
        "          [<ffffffde2eab6a08>] el0_svc_common+0xc4",
        "          [<ffffffde2eab68e4>] do_el0_svc+0x24",
        "          [<ffffffde2fa5dd2c>] el0_svc+0x30",
        "          [<ffffffde2fa5dcb0>] el0t_64_sync_handler+0x68",
        "          [<ffffffde2ea11624>] el0t_64_sync+0x1b4",
        "\n",
        "  Display the alloc and free stack for specific physic address:",
        "    %s> pageowner -p 0x4000e000",
        "    page_owner:0xffffff80038002a8 PFN:0x4000e-0x4000f Page:0xfffffffe00000380  Order:0 stack_record:0xffffff80086b6eb0 PID:1 ts_nsec:3200156311",
        "          [<ffffffde2edb039c>] post_alloc_hook+0x20c",
        "          [<ffffffde2edb3064>] prep_new_page+0x28",
        "          [<ffffffde2edb46a4>] get_page_from_freelist+0x12ac",
        "          [<ffffffde2edb320c>] __alloc_pages+0xd8",
        "          [<ffffffde2ed49210>] page_cache_ra_unbounded+0x130",
        "          [<ffffffde2ed49754>] do_page_cache_ra+0x3c",
        "          [<ffffffde2ed3b718>] do_sync_mmap_readahead+0x188",
        "          [<ffffffde2ed3abc0>] filemap_fault+0x280",
        "          [<ffffffde2ed98b7c>] __do_fault+0x6c",
        "          [<ffffffde2ed98288>] handle_pte_fault+0x1b4",
        "          [<ffffffde2ed94820>] do_handle_mm_fault+0x4a0",
        "          [<ffffffde2fa97488>] do_page_fault.edea7eadbbe8ee1d4acc94c9444fd9d5+0x520",
        "          [<ffffffde2fa96f50>] do_translation_fault.edea7eadbbe8ee1d4acc94c9444fd9d5+0x44",
        "          [<ffffffde2eacbd90>] do_mem_abort+0x64",
        "          [<ffffffde2fa5ddf4>] el0_da+0x48",
        "          [<ffffffde2fa5dce0>] el0t_64_sync_handler+0x98",
        "",
        "    page_owner:0xffffff80038002a8 PFN:0x4000e-0x4000f Page:0xfffffffe00000380  Order:0 stack_record:0xffffff80086b5350 PID:1 free_ts_nsec:3033067977",
        "          [<ffffffde2edb11a0>] free_unref_page_prepare+0x2d8",
        "          [<ffffffde2edb1634>] free_unref_page_list+0xa0",
        "          [<ffffffde2ed4e808>] release_pages+0x510",
        "          [<ffffffde2ed4e8b8>] __pagevec_release+0x34",
        "          [<ffffffde2ed64b54>] shmem_undo_range+0x210",
        "          [<ffffffde2ed6a9d0>] shmem_evict_inode.ac7d038029138368f3a468e11f4adc2c+0x12c",
        "          [<ffffffde2ee4152c>] evict+0xd4",
        "          [<ffffffde2ee3ed64>] iput+0x244",
        "          [<ffffffde2ee25f1c>] do_unlinkat+0x1ac",
        "          [<ffffffde2ee2605c>] __arm64_sys_unlinkat+0x48",
        "          [<ffffffde2eab6ad4>] invoke_syscall+0x5c",
        "          [<ffffffde2eab6a08>] el0_svc_common+0xc4",
        "          [<ffffffde2eab68e4>] do_el0_svc+0x24",
        "          [<ffffffde2fa5dd2c>] el0_svc+0x30",
        "          [<ffffffde2fa5dcb0>] el0t_64_sync_handler+0x68",
        "          [<ffffffde2ea11624>] el0t_64_sync+0x1b4",
        "\n",
        "  Display the alloc and free stack for specific page address:",
        "    %s> pageowner -P 0xfffffffe00000380",
        "    page_owner:0xffffff80038002a8 PFN:0x4000e-0x4000f Page:0xfffffffe00000380  Order:0 stack_record:0xffffff80086b6eb0 PID:1 ts_nsec:3200156311",
        "          [<ffffffde2edb039c>] post_alloc_hook+0x20c",
        "          [<ffffffde2edb3064>] prep_new_page+0x28",
        "          [<ffffffde2edb46a4>] get_page_from_freelist+0x12ac",
        "          [<ffffffde2edb320c>] __alloc_pages+0xd8",
        "          [<ffffffde2ed49210>] page_cache_ra_unbounded+0x130",
        "          [<ffffffde2ed49754>] do_page_cache_ra+0x3c",
        "          [<ffffffde2ed3b718>] do_sync_mmap_readahead+0x188",
        "          [<ffffffde2ed3abc0>] filemap_fault+0x280",
        "          [<ffffffde2ed98b7c>] __do_fault+0x6c",
        "          [<ffffffde2ed98288>] handle_pte_fault+0x1b4",
        "          [<ffffffde2ed94820>] do_handle_mm_fault+0x4a0",
        "          [<ffffffde2fa97488>] do_page_fault.edea7eadbbe8ee1d4acc94c9444fd9d5+0x520",
        "          [<ffffffde2fa96f50>] do_translation_fault.edea7eadbbe8ee1d4acc94c9444fd9d5+0x44",
        "          [<ffffffde2eacbd90>] do_mem_abort+0x64",
        "          [<ffffffde2fa5ddf4>] el0_da+0x48",
        "          [<ffffffde2fa5dce0>] el0t_64_sync_handler+0x98",
        "",
        "    page_owner:0xffffff80038002a8 PFN:0x4000e-0x4000f Page:0xfffffffe00000380  Order:0 stack_record:0xffffff80086b5350 PID:1 free_ts_nsec:3033067977",
        "          [<ffffffde2edb11a0>] free_unref_page_prepare+0x2d8",
        "          [<ffffffde2edb1634>] free_unref_page_list+0xa0",
        "          [<ffffffde2ed4e808>] release_pages+0x510",
        "          [<ffffffde2ed4e8b8>] __pagevec_release+0x34",
        "          [<ffffffde2ed64b54>] shmem_undo_range+0x210",
        "          [<ffffffde2ed6a9d0>] shmem_evict_inode.ac7d038029138368f3a468e11f4adc2c+0x12c",
        "          [<ffffffde2ee4152c>] evict+0xd4",
        "          [<ffffffde2ee3ed64>] iput+0x244",
        "          [<ffffffde2ee25f1c>] do_unlinkat+0x1ac",
        "          [<ffffffde2ee2605c>] __arm64_sys_unlinkat+0x48",
        "          [<ffffffde2eab6ad4>] invoke_syscall+0x5c",
        "          [<ffffffde2eab6a08>] el0_svc_common+0xc4",
        "          [<ffffffde2eab68e4>] do_el0_svc+0x24",
        "          [<ffffffde2fa5dd2c>] el0_svc+0x30",
        "          [<ffffffde2fa5dcb0>] el0t_64_sync_handler+0x68",
        "          [<ffffffde2ea11624>] el0t_64_sync+0x1b4",
        "\n",
        "  Display the alloc memory size for every stack:",
        "    %s> pageowner -t",
        "    Allocated 19147 times, Total memory: 74.79MB",
        "        [<ffffffd4d55b039c>] post_alloc_hook+0x20c",
        "        [<ffffffd4d55b3064>] prep_new_page+0x28",
        "        [<ffffffd4d55b46a4>] get_page_from_freelist+0x12ac",
        "        [<ffffffd4d55b320c>] __alloc_pages+0xd8",
        "        [<ffffffd4d5549210>] page_cache_ra_unbounded+0x130",
        "        [<ffffffd4d5549754>] do_page_cache_ra+0x3c",
        "        [<ffffffd4d553b718>] do_sync_mmap_readahead+0x188",
        "        [<ffffffd4d553abc0>] filemap_fault+0x280",
        "        [<ffffffd4d5598b7c>] __do_fault+0x6c",
        "        [<ffffffd4d5598288>] handle_pte_fault+0x1b4",
        "        [<ffffffd4d5594820>] do_handle_mm_fault+0x4a0",
        "        [<ffffffd4d6297488>] do_page_fault.edea7eadbbe8ee1d4acc94c9444fd9d5+0x520",
        "        [<ffffffd4d6296f50>] do_translation_fault.edea7eadbbe8ee1d4acc94c9444fd9d5+0x44",
        "        [<ffffffd4d52cbd90>] do_mem_abort+0x64",
        "        [<ffffffd4d625ddf4>] el0_da+0x48",
        "        [<ffffffd4d625ebe0>] el0t_32_sync_handler+0x78",
        "        -------------------------------------------------",
        "        PID      Comm                 Times      Size",
        "        3867     binder:1067_18       3920       15.31MB",
        "        712      main                 2188       8.55MB",
        "        3791     unknow               1324       5.17MB",
        "        2023     ndroid.systemui      1035       4.04MB",
        "\n",
        "  Display the alloc memory size for every process:",
        "    %s> pageowner -m",
        "        PID      Comm                 Times      Size",
        "                 page_owner                      20.80MB",
        "                 stack_record                    308KB",
        "        3772     memtester            179573     701.46MB",
        "        1        init                 19078      104.62MB",
        "        712      main                 14640      58.88MB",
        "        1881     CachedAppOptimi      13552      52.98MB",
        "        68       kswapd0              11550      45.20MB",
        "        960      unknow               8262       32.44MB",
        "        4268     ndroid.settings      6485       25.36MB",
        "        1023     RenderEngine         5437       23.99MB",
        "        1067     system_server        5199       22.14MB",
        "        3867     binder:1067_18       4468       17.72MB",
        "        2023     ndroid.systemui      4195       16.64MB",
        "\n",
    };
    initialize();
}

void Pageowner::print_page_owner(std::string addr,int flags){
    ulonglong number = std::stoul(addr, nullptr, 16);
    if (number <= 0)return;
    ulong pfn = 0;
    if (flags == INPUT_PFN){
        pfn = number;
    }else if (flags == INPUT_PYHS){
        fprintf(fp, "hello \n");
        pfn = phy_to_pfn(number);
    }else if (flags == INPUT_PAGE){
        pfn = page_to_pfn(number);
    }
    if(pfn < min_low_pfn || pfn > max_pfn){
        fprintf(fp, "invaild pfn\n");
        return;
    }
    ulong page = pfn_to_page(pfn);
    if (!is_kvaddr(page))
        return;
    ulong page_ext = lookup_page_ext(page);
    if (!is_kvaddr(page_ext))
        return;
    ulong page_ext_flags = read_ulong(page_ext + field_offset(page_ext, flags), "page_ext_flags");
    if (!((page_ext_flags & (1UL << PAGE_EXT_OWNER)) != 0))
        return;
    if (!((page_ext_flags & (1UL << PAGE_EXT_OWNER_ALLOCATED)) != 0))
        return;
    ulong page_owner_addr = get_page_owner(page_ext);
    std::shared_ptr<page_owner> owner_ptr = parser_page_owner(page_owner_addr);
    owner_ptr->pfn = pfn;
    if(owner_ptr->handle > 0){
        print_page_owner(owner_ptr,false);
    }
    if(owner_ptr->free_handle > 0){
        print_page_owner(owner_ptr,true);
    }
}

void Pageowner::print_page_owner(std::shared_ptr<page_owner> owner_ptr, bool is_free){
    uint nr_size = 0;
    ulong stack_record_addr = 0;
    ulong entries = 0;
    ulong end_pfn = owner_ptr->pfn + power(2, owner_ptr->order);
    ulong page = pfn_to_page(owner_ptr->pfn);
    if (!is_free){
        entries = parser_stack_record(owner_ptr->handle,&nr_size,&stack_record_addr);
        fprintf(fp, "page_owner:%#lx PFN:%#lx~%#lx Page:%#lx Order:%d stack_record:%#lx PID:%zu ts_nsec:%lld\n",
            owner_ptr->addr,owner_ptr->pfn,end_pfn,page,owner_ptr->order,stack_record_addr,owner_ptr->pid,owner_ptr->ts_nsec);
        print_stack(entries,nr_size);
        fprintf(fp, "\n");
    }else{
        entries = parser_stack_record(owner_ptr->free_handle,&nr_size,&stack_record_addr);
        fprintf(fp, "page_owner:%#lx PFN:%#lx~%#lx Page:%#lx Order:%d stack_record:%#lx PID:%zu free_ts_nsec:%lld\n",
        owner_ptr->addr,owner_ptr->pfn,end_pfn,page,owner_ptr->order,stack_record_addr,owner_ptr->pid,owner_ptr->free_ts_nsec);
        print_stack(entries,nr_size);
        fprintf(fp, "\n");
    }
}

void Pageowner::print_memory_info(){
    std::ostringstream oss_hd;
    oss_hd << std::left << std::setw(8) << "PID" << " "
        << std::left << std::setw(20) << "Comm" << " "
        << std::left << std::setw(10) << "Times" << " "
        << std::left << std::setw(10) << "Size";
    fprintf(fp, "%s \n",oss_hd.str().c_str());

    ulong page_owner_size = page_owner_page_list.size()*page_size;
    std::ostringstream oss;
    oss << std::left << std::setw(8) << "" << " "
        << std::left << std::setw(20) << "page_owner" << " "
        << std::left << std::setw(10) << "" << " "
        << std::left << std::setw(10) << csize(page_owner_size);
    fprintf(fp, "%s \n",oss.str().c_str());

    ulong stack_record_size = stack_record_page_list.size()*page_size;
    oss.str("");
    oss << std::left << std::setw(8) << "" << " "
    << std::left << std::setw(20) << "stack_record" << " "
    << std::left << std::setw(10) << "" << " "
    << std::left << std::setw(10) << csize(stack_record_size);
    fprintf(fp, "%s \n",oss.str().c_str());

    std::unordered_map<size_t, std::shared_ptr<process_info>> process_map; //<pid,process_info>
    for (const auto& pair : owner_map) {
        ulong pfn = pair.first;
        std::shared_ptr<page_owner> owner_ptr = pair.second;
        if(owner_ptr->handle <= 0 || owner_ptr->pid <= 0) continue;
        std::shared_ptr<process_info> proc_ptr;
        if (process_map.find(owner_ptr->pid) != process_map.end()) { //exists
            proc_ptr = process_map[owner_ptr->pid];
            proc_ptr->total_cnt += 1;
            proc_ptr->total_size += power(2, owner_ptr->order) * page_size;
        } else {
            proc_ptr = std::make_shared<process_info>();
            proc_ptr->total_cnt = 1;
            proc_ptr->total_size = power(2, owner_ptr->order) * page_size;
            process_map[owner_ptr->pid] = proc_ptr;
        }
    }
    //sort
    std::vector<std::pair<unsigned int, std::shared_ptr<process_info>>> process_vec(process_map.begin(), process_map.end());
    std::sort(process_vec.begin(), process_vec.end(),[&](const std::pair<unsigned int, std::shared_ptr<process_info>>& a, const std::pair<unsigned int, std::shared_ptr<process_info>>& b){
        return a.second->total_cnt > b.second->total_cnt;
    });
    int print_cnt = 50; //only print top 50
    for (size_t i = 0; i < process_vec.size() && i < print_cnt; i++){
        size_t pid = process_vec[i].first;
        std::string name = "unknow";
        struct task_context *tc = pid_to_context(pid);
        if (tc){
            name = std::string(tc->comm);
        }
        std::shared_ptr<process_info> proc_ptr = process_vec[i].second;
        std::ostringstream oss;
        oss << std::left << std::setw(8) << pid << " "
            << std::left << std::setw(20) << name << " "
            << std::left << std::setw(10) << proc_ptr->total_cnt << " "
            << std::left << std::setw(10) << csize(proc_ptr->total_size);
        fprintf(fp, "%s \n",oss.str().c_str());
    }
}

void Pageowner::print_total_size_by_handle(){
    if (handle_map.size() == 0){
        for (const auto& pair : owner_map) {
            ulong pfn = pair.first;
            std::shared_ptr<page_owner> owner_ptr = pair.second;
            if(owner_ptr->handle <= 0) continue;
            std::shared_ptr<stack_info> stack_ptr;
            if (handle_map.find(owner_ptr->handle) != handle_map.end()) { //exists
                stack_ptr = handle_map[owner_ptr->handle];
                stack_ptr->total_cnt += 1;
                stack_ptr->total_size += power(2, owner_ptr->order) * page_size;
                stack_ptr->owner_list[pfn] = owner_ptr;
            } else {
                stack_ptr = std::make_shared<stack_info>();
                stack_ptr->total_cnt = 1;
                stack_ptr->total_size = power(2, owner_ptr->order) * page_size;
                stack_ptr->handle = owner_ptr->handle;
                handle_map[owner_ptr->handle] = stack_ptr;
                stack_ptr->owner_list[pfn] = owner_ptr;
            }
        }
    }
    //sort
    std::vector<std::pair<unsigned int, std::shared_ptr<stack_info>>> handle_vec(handle_map.begin(), handle_map.end());
    std::sort(handle_vec.begin(), handle_vec.end(),[&](const std::pair<unsigned int, std::shared_ptr<stack_info>>& a, const std::pair<unsigned int, std::shared_ptr<stack_info>>& b){
        return a.second->total_cnt > b.second->total_cnt;
    });
    for (const auto& pair : handle_vec) {
        unsigned int handle = pair.first;
        std::shared_ptr<stack_info> stack_ptr = pair.second;
        fprintf(fp, "Allocated %ld times, Total memory: %s\n", stack_ptr->total_cnt, csize(stack_ptr->total_size).c_str());
        uint nr_size = 0;
        ulong stack_record_addr = 0;
        ulong entries = parser_stack_record(handle,&nr_size,&stack_record_addr);
        print_stack(entries,nr_size);
        print_total_size_by_pid(stack_ptr->owner_list);
        fprintf(fp, "\n");
    }
}

void Pageowner::print_total_size_by_pid(std::unordered_map<size_t, std::shared_ptr<page_owner>> owner_list){
    std::unordered_map<size_t, std::shared_ptr<process_info>> process_map; //<pid,process_info>
    for (const auto& pair : owner_list) {
        ulong pfn = pair.first;
        std::shared_ptr<page_owner> owner_ptr = pair.second;
        if(owner_ptr->pid <= 0) continue;
        // fprintf(fp, "pid:%zu, handle:%ld order:%d\n",owner_ptr->pid,(ulong)owner_ptr->handle,owner_ptr->order);
        std::shared_ptr<process_info> proc_ptr;
        if (process_map.find(owner_ptr->pid) != process_map.end()) { //exists
            proc_ptr = process_map[owner_ptr->pid];
            proc_ptr->total_cnt += 1;
            proc_ptr->total_size += power(2, owner_ptr->order) * page_size;
        } else {
            proc_ptr = std::make_shared<process_info>();
            proc_ptr->total_cnt = 1;
            proc_ptr->total_size = power(2, owner_ptr->order) * page_size;
            process_map[owner_ptr->pid] = proc_ptr;
        }
    }
    //sort
    std::vector<std::pair<unsigned int, std::shared_ptr<process_info>>> process_vec(process_map.begin(), process_map.end());
    std::sort(process_vec.begin(), process_vec.end(),[&](const std::pair<unsigned int, std::shared_ptr<process_info>>& a, const std::pair<unsigned int, std::shared_ptr<process_info>>& b){
        return a.second->total_cnt > b.second->total_cnt;
    });
    fprintf(fp, "      -------------------------------------------------\n");
    std::ostringstream oss_hd;
    oss_hd << std::left << "      " << std::setw(8) << "PID" << " "
        << std::left << std::setw(20) << "Comm" << " "
        << std::left << std::setw(10) << "Times" << " "
        << std::left << std::setw(10) << "Size";
    fprintf(fp, "%s \n",oss_hd.str().c_str());
    int print_cnt = 20; //only print top 20
    for (size_t i = 0; i < process_vec.size() && i < print_cnt; i++){
        size_t pid = process_vec[i].first;
        std::string name = "unknow";
        struct task_context *tc = pid_to_context(pid);
        if (tc){
            name = std::string(tc->comm);
        }
        std::shared_ptr<process_info> proc_ptr = process_vec[i].second;
        std::ostringstream oss;
        oss << std::left << "      " << std::setw(8) << pid << " "
            << std::left << std::setw(20) << name << " "
            << std::left << std::setw(10) << proc_ptr->total_cnt << " "
            << std::left << std::setw(10) << csize(proc_ptr->total_size);
        fprintf(fp, "%s \n",oss.str().c_str());
    }
}

void Pageowner::print_stack(ulong entries,uint nr_size){
    struct syment *sp;
    ulong offset;
    if (is_kvaddr(entries)){
        for (size_t i = 0; i < nr_size; i++) {
            ulong bt_addr = read_ulong(entries + i * sizeof(void *),"stack_record entries");
            ulong offset;
            sp = value_search(bt_addr, &offset);
            if (sp) {
                fprintf(fp, "      [<%lx>] %s+%#lx\n", bt_addr, sp->name, offset);
            } else {
                fprintf(fp, "      [<%lx>] %p\n", bt_addr, sp);
            }
        }
    }
}

void Pageowner::print_all_page_owner(bool alloc){
    for (const auto& pair : owner_map) {
        std::shared_ptr<page_owner> owner_ptr = pair.second;
        if(alloc){
            if(owner_ptr->handle <= 0) continue;
            print_page_owner(owner_ptr,false);
        }else{
            if(owner_ptr->free_handle <= 0) continue;
            print_page_owner(owner_ptr,true);
        }
    }
}

std::shared_ptr<page_owner> Pageowner::parser_page_owner(ulong addr){
    if (!is_kvaddr(addr))return nullptr;
    // fprintf(fp, "page_owner:%lx\n", addr);
    void *page_owner_buf = read_struct(addr, "page_owner");
    if (page_owner_buf == nullptr)return nullptr;
    std::shared_ptr<page_owner> owner_ptr = std::make_shared<page_owner>();
    owner_ptr->addr = addr;
    owner_ptr->order = SHORT(page_owner_buf + field_offset(page_owner, order));
    owner_ptr->handle = UINT(page_owner_buf + field_offset(page_owner, handle));
    owner_ptr->free_handle = UINT(page_owner_buf + field_offset(page_owner, free_handle));
    owner_ptr->last_migrate_reason = SHORT(page_owner_buf + field_offset(page_owner, last_migrate_reason));
    owner_ptr->ts_nsec = ULONG(page_owner_buf + field_offset(page_owner, ts_nsec));
    owner_ptr->free_ts_nsec = ULONG(page_owner_buf + field_offset(page_owner, free_ts_nsec));
    owner_ptr->gfp_mask = INT(page_owner_buf + field_offset(page_owner, gfp_mask));
    owner_ptr->pid = INT(page_owner_buf + field_offset(page_owner, pid));
    if (field_offset(page_owner, comm) > 0){
        owner_ptr->comm = read_cstring(addr + field_offset(page_owner, comm),64,"page_owner_comm");
    }
    if (field_offset(page_owner, tgid) > 0){
        owner_ptr->tgid = INT(page_owner_buf + field_offset(page_owner, tgid));
    }else{
        struct task_context *tc = pid_to_context(owner_ptr->pid);
        if (tc){
            owner_ptr->tgid = task_tgid(tc->task);
            owner_ptr->comm = std::string(tc->comm);
        }
    }
    FREEBUF(page_owner_buf);
    return owner_ptr;
}

ulong Pageowner::parser_stack_record(uint page_owner_handle,uint* stack_len, ulong* sr_addr){
    ulong offset;
    ulong slabindex;
    union handle_parts parts = { .handle = page_owner_handle };
    if (THIS_KERNEL_VERSION >= LINUX(6,8,0)) {
        offset = parts.v3.offset << DEPOT_STACK_ALIGN;
        slabindex = parts.v3.pool_index;
    }else if (THIS_KERNEL_VERSION >= LINUX(6,1,0)) {
        offset = parts.v2.offset << DEPOT_STACK_ALIGN;
        slabindex = parts.v2.pool_index;
    } else {
        offset = parts.v1.offset << DEPOT_STACK_ALIGN;
        slabindex = parts.v1.pool_index;
    }
    if (slabindex > depot_index) return 0;
    ulong page_addr = read_pointer(stack_slabs + slabindex * sizeof(void *),"stack_record_page");
    if (!is_kvaddr(page_addr))return 0;
    ulong page_start = page_addr & page_mask;
    stack_record_page_list.insert(page_start);

    ulong stack_record_addr = page_addr + offset;
    *sr_addr = stack_record_addr;
    void *record_buf = read_struct(stack_record_addr, "stack_record");
    if (record_buf == nullptr) return 0;
    *stack_len = UINT(record_buf + field_offset(stack_record, size));
    uint record_handle = UINT(record_buf + field_offset(stack_record, handle));
    ulong entries = stack_record_addr + field_offset(stack_record, entries);
    if (debug){
        fprintf(fp, "stack_record:%lx page_owner_handle:%ld record_handle:%ld\n", stack_record_addr, (ulong)page_owner_handle,(ulong)record_handle);
    }
    FREEBUF(record_buf);
    return entries;
}

void Pageowner::parser_all_pageowners(){
    if (!is_enable_pageowner()){
        return;
    }
    if (csymbol_exists("page_ext_size")) {/* 5.4 and later */
        try_get_symbol_data(TO_CONST_STRING("page_ext_size"), sizeof(ulong), &page_ext_size);
    }else if (csymbol_exists("extra_mem") && struct_size(page_ext)) {
        ulong extra_mem;
        if (try_get_symbol_data(TO_CONST_STRING("extra_mem"), sizeof(ulong), &extra_mem)){
            page_ext_size = struct_size(page_ext) + extra_mem;
        }
    }
    if (page_ext_size <= 0){
        fprintf(fp, "cannot get page_ext_size value\n");
        return;
    }
    // fprintf(fp, "page_ext_size:%d\n", page_ext_size);
    if (csymbol_exists("page_owner_ops")){
        ulong ops_addr = csymbol_value("page_owner_ops");
        // fprintf(fp, "ops_addr:%lx\n", ops_addr);
        ops_offset = read_ulong(ops_addr + field_offset(page_ext_operations,offset),"page_owner_ops.offset");
    }
    if (ops_offset < 0){
        fprintf(fp, "cannot get ops_offset value\n");
        return;
    }
    // fprintf(fp, "ops_offset:%zu\n", ops_offset);
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
        return;
    }
    ulong page_start = stack_slabs & page_mask;
    stack_record_page_list.insert(page_start);
    page_start = (stack_slabs + depot_index * sizeof(void *)) & page_mask;
    stack_record_page_list.insert(page_start);
    /* max_pfn */
    if (csymbol_exists("max_pfn")){
        try_get_symbol_data(TO_CONST_STRING("max_pfn"), sizeof(ulong), &max_pfn);
    }
    /* min_low_pfn */
    if (csymbol_exists("min_low_pfn")){
        try_get_symbol_data(TO_CONST_STRING("min_low_pfn"), sizeof(ulong), &min_low_pfn);
    }
    /* PAGE_EXT_OWNER{,_ALLOCATED} */
    enumerator_value(TO_CONST_STRING("PAGE_EXT_OWNER"), &PAGE_EXT_OWNER);
    enumerator_value(TO_CONST_STRING("PAGE_EXT_OWNER_ALLOCATED"), &PAGE_EXT_OWNER_ALLOCATED); /* 5.4 and later */
    // fprintf(fp, "min_low_pfn:%ld\n", min_low_pfn);
    // fprintf(fp, "max_pfn:%ld\n", max_pfn);
    for (size_t pfn = min_low_pfn; pfn < max_pfn; pfn++){
        ulong page = pfn_to_page(pfn);
        if (!is_kvaddr(page))
            continue;
        ulong page_ext = lookup_page_ext(page);
        if (!is_kvaddr(page_ext))
            continue;
        ulong flags = read_ulong(page_ext + field_offset(page_ext, flags), "page_ext_flags");
        if (!((flags & (1UL << PAGE_EXT_OWNER)) != 0))
            continue;
        if (!((flags & (1UL << PAGE_EXT_OWNER_ALLOCATED)) != 0))
            continue;
        ulong page_owner_addr = get_page_owner(page_ext);
        ulong page_start = page_owner_addr & page_mask;
        page_owner_page_list.insert(page_start);
        std::shared_ptr<page_owner> owner_ptr = parser_page_owner(page_owner_addr);
        if (debug){
            fprintf(fp, "pfn:%zu page_ext:%lx page_owner:%lx handle:%ld free_handle:%ld\n",
                pfn,page_ext,page_owner_addr,(ulong)owner_ptr->handle,(ulong)owner_ptr->free_handle);
        }
        if(owner_ptr == nullptr)continue;
        if (!IS_ALIGNED(pfn, 1 << owner_ptr->order))
            continue;
        owner_ptr->pfn = pfn;
        owner_map[pfn] = owner_ptr;
    }
}

ulong Pageowner::get_page_owner(ulong page_ext){
    return page_ext + ops_offset;
}

ulong Pageowner::lookup_page_ext(ulong page) {
    ulong pfn = page_to_pfn(page);
    ulong page_ext = 0;
    if(get_config_val("CONFIG_PAGE_EXTENSION") != "y"){
        return 0;
    }
    if(get_config_val("CONFIG_SPARSEMEM") == "y"){
        ulong section = 0;
        ulong section_nr = pfn_to_section_nr(pfn);
        if (!(section = valid_section_nr(section_nr)))
            return 0;
        if (!is_kvaddr(section))return 0;
        // fprintf(fp, "section:%lx\n", section);
        page_ext = read_pointer(section + field_offset(mem_section,page_ext),"mem_section_page_ext");
        if (page_ext_invalid(page_ext))return 0;
        return get_entry(page_ext, pfn);
    }else{
        int nid = page_to_nid(page);
        struct node_table *nt = &vt->node_table[nid];
        page_ext = read_pointer(nt->pgdat + field_offset(pglist_data,node_page_ext),"pglist_data_node_page_ext");
        ulong index = pfn - phy_to_pfn(nt->start_paddr);
        return get_entry(page_ext, pfn);
    }
}

ulong Pageowner::get_entry(ulong base, ulong pfn) {
    // fprintf(fp, "page_ext:%lx pfn:%lx\n", base,pfn);
#ifdef ARM64
    return base + page_ext_size * pfn;
#else
    ulong pfn_index = pfn - phy_to_pfn(machdep->machspec->phys_base);
    return base + page_ext_size * pfn_index;
#endif
}

bool Pageowner::page_ext_invalid(ulong page_ext){
    return !is_kvaddr(page_ext) || (((unsigned long)page_ext & PAGE_EXT_INVALID) == PAGE_EXT_INVALID);
}

#pragma GCC diagnostic pop
