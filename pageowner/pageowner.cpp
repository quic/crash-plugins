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

#include "pageowner.h"
#include <chrono>

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wpointer-arith"

#ifndef BUILD_TARGET_TOGETHER
DEFINE_PLUGIN_COMMAND(Pageowner)
#endif

/**
 * cmd_main - Main entry point for the pageowner command
 *
 * This function processes command-line arguments and dispatches to the appropriate
 * handler based on the options provided. It supports various operations like
 * displaying allocated/freed pages, searching by address, and memory statistics.
 */
void Pageowner::cmd_main(void) {
    // Check if sufficient arguments are provided
    if (argcnt < 2) {
        LOGD("Insufficient arguments: argcnt=%d", argcnt);
        cmd_usage(pc->curcmd, SYNOPSIS);
        return;
    }

    // Verify page_owner is enabled in the kernel
    if (!is_enable_pageowner()) {
        LOGE("Page owner is not enabled in kernel");
        return;
    }

    // Parse all page owner information if not already done (lazy initialization)
    if (owner_map.empty()) {
        LOGD("Owner map is empty, parsing all page owners...");
        parser_all_pageowners();
        LOGD("Parsed %zu page owner entries", owner_map.size());
    } else {
        LOGD("Using cached owner_map with %zu entries", owner_map.size());
    }

    int c;
    int argerrs = 0;

    // Process command-line options
    while ((c = getopt(argcnt, args, "afs:tmp:")) != EOF) {
        switch(c) {
            case 'a': // Display all allocated page_owner info
                print_all_allocated_pages();
                break;
            case 'f': // Display all freed page_owner info
                print_all_freed_pages();
                break;
            case 's': // Search page_owner info by address (auto-detect type)
                print_page_owner_auto(std::string(optarg));
                break;
            case 't': // Sort and display page_owner info by total allocation count
                print_sorted_allocation_summary();
                break;
            case 'm': // Display overall memory information
                print_memory_info();
                break;
            default:
                LOGE("Unknown option: %c", c);
                argerrs++;
                break;
        }
    }

    // Display usage if there were argument errors
    if (argerrs) {
        cmd_usage(pc->curcmd, SYNOPSIS);
    }
}

/**
 * print_page_owner_auto - Automatically detect address type and print page owner info
 * @addr_str: Address string in hexadecimal format
 *
 * This function automatically detects whether the provided address is a PFN,
 * physical address, page structure address, or virtual address, then displays
 * the corresponding page owner information.
 */
void Pageowner::print_page_owner_auto(const std::string& addr_str) {
    // Validate input string
    if (addr_str.empty()) {
        LOGE("Empty address string provided");
        return;
    }
    // Parse hexadecimal address string
    ulonglong addr;
    try {
        addr = std::stoull(addr_str, nullptr, 16);
    } catch (const std::exception& e) {
        LOGE("Failed to parse address: %s", addr_str.c_str());
        return;
    }
    // Reject null address
    if (addr == 0) {
        LOGE("Null address provided");
        return;
    }
    // Detect address type and dispatch to appropriate handler
    AddressType addr_type = detect_address_type(addr);
    LOGD("Detected address type: %d", addr_type);
    switch (addr_type) {
        case ADDR_PFN:
            LOGD("Address 0x%llx identified as PFN", addr);
            print_page_owner(addr_str, INPUT_PFN);
            break;
        case ADDR_PHYSICAL:
            LOGD("Address 0x%llx identified as Physical Address", addr);
            print_page_owner(addr_str, INPUT_PYHS);
            break;
        case ADDR_PAGE:
            LOGD("Address 0x%llx identified as Page Structure Address", addr);
            print_page_owner(addr_str, INPUT_PAGE);
            break;
        case ADDR_VIRTUAL:
            LOGD("Address 0x%llx identified as Virtual Address", addr);
            print_page_owner(addr_str, INPUT_VADDR);
            break;
        case ADDR_UNKNOWN:
        default:
            LOGE("Cannot determine address type for 0x%llx", addr);
            break;
    }
}

/**
 * detect_address_type - Determine the type of a given address
 * @addr: Address to analyze
 *
 * This function uses various heuristics to determine whether an address is:
 * - A Page Frame Number (PFN)
 * - A physical memory address
 * - A kernel page structure address
 * - A virtual address (kernel or user space)
 *
 * Returns: AddressType enum value indicating the detected type
 */
Pageowner::AddressType Pageowner::detect_address_type(ulonglong addr) {
    // Check if address is in valid PFN range
    // PFNs are typically small numbers representing page frame indices
    if (addr >= min_low_pfn && addr <= max_pfn) {
        ulong page = pfn_to_page(addr);
        if (is_kvaddr(page)) {
            LOGD("Address in PFN range [0x%lx, 0x%lx]", min_low_pfn, max_pfn);
            return ADDR_PFN;
        }
    }

    // Check if it's a kernel virtual address
    if (is_kvaddr(addr)) {
        // Distinguish between page structure address and other kernel addresses
        if (is_page_address(addr)) {
            LOGD("Address is a page address");
            return ADDR_PAGE;
        }
        LOGD("Address is a generic kernel virtual address");
        return ADDR_VIRTUAL;
    }

    // Check if it's a physical address
    if (is_physical_address(addr)) {
        LOGD("Address is a physical address");
        return ADDR_PHYSICAL;
    }

    // Try to translate as user virtual address from current task
    physaddr_t paddr = 0;
    if (CURRENT_TASK() && uvtop(CURRENT_CONTEXT(), addr, &paddr, 0)) {
        LOGD("Address translates in current task context to phys: 0x%llx", (ulonglong)paddr);
        return ADDR_VIRTUAL;
    }

    // Search through all tasks to find if this is a user virtual address
    struct task_context *tc;
    for (ulong i = 0; i < RUNNING_TASKS(); i++) {
        tc = FIRST_CONTEXT() + i;
        if (tc->task && uvtop(tc, addr, &paddr, 0)) {
            LOGD("Address found in task PID:%ld [%s], phys: 0x%llx", task_to_pid(tc->task), tc->comm, (ulonglong)paddr);
            return ADDR_VIRTUAL;
        }
    }

    // Unable to determine address type
    LOGD("Unable to determine address type");
    return ADDR_UNKNOWN;
}

bool Pageowner::is_page_address(ulonglong addr) {
    try {
        ulong pfn = page_to_pfn(addr);
        if (pfn >= min_low_pfn && pfn <= max_pfn) {
            ulong back_page = pfn_to_page(pfn);
            return (back_page == addr);
        }
    } catch (...) {
    }
    return false;
}

bool Pageowner::is_physical_address(ulonglong addr) {
    ulong pfn = phy_to_pfn(addr);
    return (pfn >= min_low_pfn && pfn <= max_pfn);
}

void Pageowner::print_all_allocated_pages() {
    size_t allocated_count = 0;
    size_t total_pages = 0;
    size_t total_size = 0;
    for (const auto& pair : owner_map) {
        const auto& owner_ptr = pair.second;
        if (is_page_allocated(owner_ptr)) {
            allocated_count++;
            ulong page_count = 1UL << owner_ptr->order;
            total_pages += page_count;
            total_size += page_count * page_size;
        }
    }
    PRINT("═══════════════════════════════════════════════════════════════\n");
    PRINT("                    ALLOCATED PAGES SUMMARY\n");
    PRINT("═══════════════════════════════════════════════════════════════\n");
    PRINT("Total allocated entries: %zu\n", allocated_count);
    PRINT("Total allocated pages:   %zu\n", total_pages);
    PRINT("Total allocated memory:  %s\n", csize(total_size).c_str());
    PRINT("═══════════════════════════════════════════════════════════════\n");
    size_t entry_num = 0;
    for (const auto& pair : owner_map) {
        const auto& owner_ptr = pair.second;
        if (is_page_allocated(owner_ptr)) {
            entry_num++;
            print_page_owner_entry(owner_ptr, false, entry_num, allocated_count);
        }
    }
    PRINT("═══════════════════════════════════════════════════════════════\n");
    PRINT("Displayed %zu allocated page entries\n", allocated_count);
    PRINT("═══════════════════════════════════════════════════════════════\n");
}

void Pageowner::print_all_freed_pages() {
    size_t freed_count = 0;
    size_t total_pages = 0;
    size_t total_size = 0;
    for (const auto& pair : owner_map) {
        const auto& owner_ptr = pair.second;
        if (!is_page_allocated(owner_ptr) && owner_ptr->free_handle > 0) {
            freed_count++;
            ulong page_count = 1UL << owner_ptr->order;
            total_pages += page_count;
            total_size += page_count * page_size;
        }
    }
    PRINT("═══════════════════════════════════════════════════════════════\n");
    PRINT("                      FREED PAGES SUMMARY\n");
    PRINT("═══════════════════════════════════════════════════════════════\n");
    PRINT("Total freed entries: %zu\n", freed_count);
    PRINT("Total freed pages:   %zu\n", total_pages);
    PRINT("Total freed memory:  %s\n", csize(total_size).c_str());
    PRINT("═══════════════════════════════════════════════════════════════\n");
    size_t entry_num = 0;
    for (const auto& pair : owner_map) {
        const auto& owner_ptr = pair.second;
        if (!is_page_allocated(owner_ptr) && owner_ptr->free_handle > 0) {
            entry_num++;
            print_page_owner_entry(owner_ptr, true, entry_num, freed_count);
        }
    }
    PRINT("═══════════════════════════════════════════════════════════════\n");
    PRINT("Displayed %zu freed page entries\n", freed_count);
    PRINT("═══════════════════════════════════════════════════════════════\n");
}

void Pageowner::print_page_owner_entry(std::shared_ptr<page_owner> owner_ptr, bool is_free,
                                       size_t entry_num, size_t total_entries) {
    const ulong end_pfn = owner_ptr->pfn + (1UL << owner_ptr->order);
    const ulong page = pfn_to_page(owner_ptr->pfn);
    const unsigned int handle = is_free ? owner_ptr->free_handle : owner_ptr->handle;
    const ulong timestamp = is_free ? owner_ptr->free_ts_nsec : owner_ptr->ts_nsec;
    const char* action = is_free ? "FREE" : "ALLOC";
    ulong page_count = 1UL << owner_ptr->order;
    ulong total_size = page_count * page_size;
    std::string comm = owner_ptr->comm;
    if (comm.empty()) {
        struct task_context *tc = pid_to_context(owner_ptr->pid);
        if (tc) {
            comm = std::string(tc->comm);
        } else {
            comm = "unknown";
        }
    }
    std::string time_str = formatTimestamp(timestamp);
    std::shared_ptr<stack_record_t> record_ptr = get_stack_record(handle);
    if (record_ptr != nullptr) {
        PRINT("[%zu/%zu] %s: PFN:0x%lx~0x%lx (%lu page%s, %s) Page:0x%lx PID:%zu [%s] %s\n",
            entry_num, total_entries, action, owner_ptr->pfn, end_pfn, page_count,
            (page_count > 1) ? "s" : "", csize(total_size).c_str(),
            page, owner_ptr->pid, comm.c_str(), time_str.c_str());

        std::string stack = get_call_stack(record_ptr);
        PRINT("%s \n", stack.c_str());
    }
}

bool Pageowner::is_enable_pageowner(){
    if(get_config_val("CONFIG_PAGE_OWNER") != "y"){
        LOGE("page_owner is disabled\n");
        return false;
    }
    if (!csymbol_exists("page_owner_inited")){
        LOGE("page_owner is disabled\n");
        return false;
    }
    int inited;
    // see set_page_owner in page_owner.h
    try_get_symbol_data(TO_CONST_STRING("page_owner_inited"), sizeof(int), &inited);
    if (inited != 1){
        LOGE("page_owner is disabled, pls check the page_owner=on in cmdline\n");
        return false;
    }
    return true;
}

void Pageowner::init_offset(void) {
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
    field_init(mem_section,page_ext);
    field_init(pglist_data,node_page_ext);
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
}

void Pageowner::init_command(void) {
    cmd_name = "pageowner";
    help_str_list={
        "pageowner",                            /* command name */
        "dump page owner information",        /* short description */
        "-a \n"
            "  pageowner -f \n"
            "  pageowner -t \n"
            "  pageowner -s <address>\n"
            "  pageowner -m \n"
            "  This command dumps the pageowner info.",
        "\n",
        "EXAMPLES",
        "  Display alloc stack for every page:",
        "    %s> pageowner -a",
        "    [1/387729] ALLOC: PFN:0xbffff~0xc0000 (1 page, 4KB) Page:0xfffffffe01ffffc0 PID:68 [kswapd0] 00:09:46.363353298 (uptime)",
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
        "    [1/944] FREE: PFN:0x99073~0x99074 (1 page, 4KB) Page:0xfffffffe01641cc0 PID:504 [lmkd] 00:00:12.745040350 (uptime)",
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
        "  Display the alloc and free stack for specific virtual address:",
        "    %s> pageowner -s 0x7fff12345000",
        "    Virtual address translation: 0x7fff12345000 -> PFN:0x4000e",
        "    ═══════════════════════════════════════════════════════════════",
        "           PAGE OWNER INFO FOR VIRTUAL ADDRESS 0x7fff12345000",
        "    ═══════════════════════════════════════════════════════════════",
        "    PFN Range:       0x4000e - 0x4000e",
        "    Page Address:    0xfffffffe00000380",
        "    Order:           0 (1 page, 4KB)",
        "    Current Status:  ALLOCATED",
        "    ═══════════════════════════════════════════════════════════════",
        "",
        "    ALLOCATION HISTORY:",
        "    Action:          ALLOC",
        "    PID:             1 [init]",
        "    Timestamp:       1d 00:53:20.156",
        "    GFP Mask:        0x400dc0",
        "",
        "    [<ffffffde2edb039c>] post_alloc_hook+0x20c",
        "    [<ffffffde2edb3064>] prep_new_page+0x28",
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
}

Pageowner::Pageowner(){}

void Pageowner::print_page_owner(const std::string& addr, int flags) {
    if (addr.empty()) return;

    ulonglong number;
    try {
        number = std::stoull(addr, nullptr, 16);
    } catch (const std::exception&) {
        LOGE("Invalid address format\n");
        return;
    }

    if (number == 0) return;

    ulong pfn = 0;
    switch (flags) {
        case INPUT_PFN:
            pfn = number;
            break;
        case INPUT_PYHS:
            pfn = phy_to_pfn(number);
            break;
        case INPUT_PAGE:
            pfn = page_to_pfn(number);
            break;
        case INPUT_VADDR:
            pfn = vaddr_to_pfn(number);
            if (pfn == 0) {
                LOGE("Cannot translate virtual address 0x%llx to pfn\n", number);
                return;
            }
            LOGD( "Virtual address translation: 0x%llx -> PFN:0x%lx\n", number, pfn);
            break;
        default:
            LOGE("Invalid input type\n");
            return;
    }

    if (pfn < min_low_pfn || pfn > max_pfn) {
        LOGE("Invalid pfn: 0x%lx (valid range: 0x%lx - 0x%lx)\n", pfn, min_low_pfn, max_pfn);
        return;
    }

    ulong page = pfn_to_page(pfn);
    if (!is_kvaddr(page)) {
        LOGE("Invalid page address: 0x%lx\n", page);
        return;
    }

    ulong page_ext = lookup_page_ext(page);
    if (!is_kvaddr(page_ext)) {
        LOGE("Cannot find page_ext for PFN:0x%lx\n", pfn);
        return;
    }
    ulong page_ext_flags = read_ulong(page_ext + field_offset(page_ext, flags), "page_ext_flags");
    if (!(page_ext_flags & (1UL << PAGE_EXT_OWNER))) {
        LOGE("Page owner not enabled for PFN:0x%lx\n", pfn);
        return;
    }
    if (!(page_ext_flags & (1UL << PAGE_EXT_OWNER_ALLOCATED))) {
        LOGE("Page owner not allocated for PFN:0x%lx\n", pfn);
        return;
    }
    ulong page_owner_addr = get_page_owner(page_ext);
    std::shared_ptr<page_owner> owner_ptr = parser_page_owner(page_owner_addr);
    if (!owner_ptr) {
        LOGE("Cannot parse page owner for PFN:0x%lx\n", pfn);
        return;
    }
    owner_ptr->pfn = pfn;
    bool currently_allocated = is_page_allocated(owner_ptr);
    PRINT("═══════════════════════════════════════════════════════════════\n");
    if (flags == INPUT_VADDR) {
        PRINT("           PAGE OWNER INFO FOR VIRTUAL ADDRESS 0x%llx\n", number);
    } else {
        PRINT("                    PAGE OWNER INFO FOR PFN:0x%lx\n", pfn);
    }
    PRINT("═══════════════════════════════════════════════════════════════\n");

    ulong page_count = 1UL << owner_ptr->order;
    ulong total_size = page_count * page_size;
    PRINT("PFN Range      :   0x%lx - 0x%lx\n", pfn, pfn + page_count - 1);
    PRINT("Page Address   :   0x%lx\n", page);
    PRINT("Order          :   %d (%lu page%s, %s)\n", owner_ptr->order, page_count,
            (page_count > 1) ? "s" : "", csize(total_size).c_str());
    PRINT("Current Status :   %s\n",
            currently_allocated ? "ALLOCATED" : "FREED");
    PRINT("═══════════════════════════════════════════════════════════════\n");
    if (owner_ptr->handle > 0) {
        PRINT("ALLOCATION HISTORY:\n");
        print_page_owner_detailed(owner_ptr, false);
    }
    if (owner_ptr->free_handle > 0) {
        PRINT("FREE HISTORY:\n");
        print_page_owner_detailed(owner_ptr, true);
    }
    PRINT("═══════════════════════════════════════════════════════════════\n");
}

ulong Pageowner::vaddr_to_pfn(ulong vaddr) {
    physaddr_t paddr = 0;
    if (kvtop(NULL, vaddr, &paddr, 0)) {
        return phy_to_pfn(paddr);
    }
    if (CURRENT_TASK() && uvtop(CURRENT_CONTEXT(), vaddr, &paddr, 0)) {
        return phy_to_pfn(paddr);
    }
    struct task_context *tc;
    for (ulong i = 0; i < RUNNING_TASKS(); i++) {
        tc = FIRST_CONTEXT() + i;
        if (tc->task && uvtop(tc, vaddr, &paddr, 0)) {
            LOGD("Found virtual address in task PID:%ld [%s]\n",
                    task_to_pid(tc->task), tc->comm);
            return phy_to_pfn(paddr);
        }
    }
    return 0;
}

void Pageowner::print_page_owner_detailed(std::shared_ptr<page_owner> owner_ptr, bool is_free) {
    const unsigned int handle = is_free ? owner_ptr->free_handle : owner_ptr->handle;
    const ulong timestamp = is_free ? owner_ptr->free_ts_nsec : owner_ptr->ts_nsec;
    const char* action = is_free ? "FREE" : "ALLOC";
    std::string comm = owner_ptr->comm;
    if (comm.empty()) {
        struct task_context *tc = pid_to_context(owner_ptr->pid);
        if (tc) {
            comm = std::string(tc->comm);
        } else {
            comm = "unknown";
        }
    }

    std::string time_str = formatTimestamp(timestamp);
    std::shared_ptr<stack_record_t> record_ptr = get_stack_record(handle);
    if (record_ptr != nullptr) {
        PRINT( "Status     :   %s\n", action);
        PRINT( "PID        :   %zu [%s]\n", owner_ptr->pid, comm.c_str());
        PRINT( "Timestamp  :   %s\n", time_str.c_str());
        PRINT( "GFP Mask   :   0x%x\n", owner_ptr->gfp_mask);
        if (owner_ptr->last_migrate_reason >= 0) {
            PRINT( "Migrate Reason:  %d\n", owner_ptr->last_migrate_reason);
        }
        std::string stack = get_call_stack(record_ptr);
        PRINT( "%s \n", stack.c_str());
    }
}

bool Pageowner::is_page_allocated(std::shared_ptr<page_owner> owner_ptr) {
    if (owner_ptr->ts_nsec > 0 && owner_ptr->free_ts_nsec > 0) {
        return owner_ptr->ts_nsec > owner_ptr->free_ts_nsec;
    }
    ulong page = pfn_to_page(owner_ptr->pfn);
    if (is_kvaddr(page)) {
        ulong page_ext = lookup_page_ext(page);
        if (is_kvaddr(page_ext)) {
            ulong flags = read_ulong(page_ext + field_offset(page_ext, flags), "page_ext_flags");
            return (flags & (1UL << PAGE_EXT_OWNER_ALLOCATED)) != 0;
        }
    }
    if (owner_ptr->handle > 0 && owner_ptr->free_handle <= 0) {
        return true;
    }
    if (owner_ptr->free_handle > 0 && owner_ptr->handle <= 0) {
        return false;
    }
    return true;
}

void Pageowner::print_memory_info(){
    std::ostringstream oss;
    oss << std::left << std::setw(8) << "PID" << " "
        << std::left << std::setw(20) << "Comm" << " "
        << std::left << std::setw(10) << "Times" << " "
        << std::left << std::setw(10) << "Size";
    PRINT( "%s \n", oss.str().c_str());

    const ulong page_owner_size = page_owner_page_list.size() * page_size;
    oss.str("");
    oss << std::left << std::setw(8) << "" << " "
        << std::left << std::setw(20) << "page_owner" << " "
        << std::left << std::setw(10) << "" << " "
        << std::left << std::setw(10) << csize(page_owner_size);
    PRINT( "%s \n", oss.str().c_str());

    const ulong stack_record_size = stack_record_page_list.size() * page_size;
    oss.str("");
    oss << std::left << std::setw(8) << "" << " "
        << std::left << std::setw(20) << "stack_record" << " "
        << std::left << std::setw(10) << "" << " "
        << std::left << std::setw(10) << csize(stack_record_size);
    PRINT( "%s \n", oss.str().c_str());

    std::unordered_map<size_t, std::shared_ptr<process_info>> process_map;
    process_map.reserve(owner_map.size() / 4); // Reserve space to reduce reallocations

    for (const auto& pair : owner_map) {
        const auto& owner_ptr = pair.second;
        if (owner_ptr->handle <= 0 || owner_ptr->pid <= 0) continue;

        const ulong page_size_for_order = power(2, owner_ptr->order) * page_size;
        auto result = process_map.emplace(owner_ptr->pid, nullptr);
        auto it = result.first;
        bool inserted = result.second;

        if (inserted) {
            it->second = std::make_shared<process_info>();
            it->second->total_cnt = 1;
            it->second->total_size = page_size_for_order;
        } else {
            it->second->total_cnt += 1;
            it->second->total_size += page_size_for_order;
        }
    }

    // Sort by total count
    std::vector<std::pair<size_t, std::shared_ptr<process_info>>> process_vec;
    process_vec.reserve(process_map.size());
    for (auto& pair : process_map) {
        auto& pid = pair.first;
        auto& proc_ptr = pair.second;
        process_vec.emplace_back(pid, std::move(proc_ptr));
    }

    std::sort(process_vec.begin(), process_vec.end(),
              [](const auto& a, const auto& b) {
                  return a.second->total_cnt > b.second->total_cnt;
              });

    constexpr size_t print_cnt = 50;
    const size_t max_print = std::min(process_vec.size(), print_cnt);

    for (size_t i = 0; i < max_print; ++i) {
        const auto& pair = process_vec[i];
        const auto& pid = pair.first;
        const auto& proc_ptr = pair.second;

        std::string name = "unknow";
        if (struct task_context* tc = pid_to_context(pid)) {
            name = tc->comm;
        }

        oss.str("");
        oss << std::left << std::setw(8) << pid << " "
            << std::left << std::setw(20) << name << " "
            << std::left << std::setw(10) << proc_ptr->total_cnt << " "
            << std::left << std::setw(10) << csize(proc_ptr->total_size);
        PRINT( "%s \n", oss.str().c_str());
    }
}

void Pageowner::print_sorted_allocation_summary(){
    if (handle_map.empty()){
        handle_map.reserve(owner_map.size() / 4); // Reserve space to reduce reallocations

        for (const auto& pair : owner_map) {
            const ulong pfn = pair.first;
            const auto& owner_ptr = pair.second;
            if(owner_ptr->handle <= 0) continue;

            const ulong page_size_for_order = power(2, owner_ptr->order) * page_size;
            auto result = handle_map.emplace(owner_ptr->handle, nullptr);
            auto it = result.first;
            bool inserted = result.second;

            if (inserted) {
                it->second = std::make_shared<stack_info>();
                it->second->total_cnt = 1;
                it->second->total_size = page_size_for_order;
                it->second->handle = owner_ptr->handle;
                it->second->owner_list.reserve(64); // Reserve space for owner_list
            } else {
                it->second->total_cnt += 1;
                it->second->total_size += page_size_for_order;
            }
            it->second->owner_list[pfn] = owner_ptr;
        }
    }

    // Sort by total count
    std::vector<std::pair<unsigned int, std::shared_ptr<stack_info>>> handle_vec;
    handle_vec.reserve(handle_map.size());
    for (auto& pair : handle_map) {
        handle_vec.emplace_back(pair.first, std::move(pair.second));
    }

    std::sort(handle_vec.begin(), handle_vec.end(),
              [](const auto& a, const auto& b) {
                  return a.second->total_cnt > b.second->total_cnt;
              });

    for (const auto& pair : handle_vec) {
        const unsigned int handle = pair.first;
        const auto& stack_ptr = pair.second;
        PRINT( "Allocated %ld times, Total memory: %s\n", stack_ptr->total_cnt, csize(stack_ptr->total_size).c_str());
        std::shared_ptr<stack_record_t> record_ptr = get_stack_record(handle);
        if (record_ptr != nullptr){
            std::string stack = get_call_stack(record_ptr);
            PRINT( "%s",stack.c_str());
        }
        print_process_memory_summary(stack_ptr->owner_list);
        PRINT( "\n");
    }
}

void Pageowner::print_process_memory_summary(std::unordered_map<size_t, std::shared_ptr<page_owner>> owner_list){
    std::unordered_map<size_t, std::shared_ptr<process_info>> process_map; //<pid,process_info>
    for (const auto& pair : owner_list) {
        std::shared_ptr<page_owner> owner_ptr = pair.second;
        if(owner_ptr->pid <= 0) continue;
        LOGD("pid:%zu, handle:%ld order:%d\n",owner_ptr->pid,(ulong)owner_ptr->handle,owner_ptr->order);
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
    PRINT( "-------------------------------------------------\n");
    std::ostringstream oss;
    oss << std::left << std::setw(8) << "PID" << " "
        << std::left << std::setw(20) << "Comm" << " "
        << std::left << std::setw(10) << "Times" << " "
        << std::left << std::setw(10) << "Size";
    PRINT( "%s \n", oss.str().c_str());
    size_t print_cnt = 20; //only print top 20
    for (size_t i = 0; i < process_vec.size() && i < print_cnt; i++){
        size_t pid = process_vec[i].first;
        std::string name = "unknow";
        struct task_context *tc = pid_to_context(pid);
        if (tc){
            name = std::string(tc->comm);
        }
        std::shared_ptr<process_info> proc_ptr = process_vec[i].second;
        oss.str("");
        oss << std::left << std::setw(8) << pid << " "
            << std::left << std::setw(20) << name << " "
            << std::left << std::setw(10) << proc_ptr->total_cnt << " "
            << std::left << std::setw(10) << csize(proc_ptr->total_size);
        PRINT( "%s \n", oss.str().c_str());
    }
}

std::shared_ptr<page_owner> Pageowner::parser_page_owner(ulong addr){
    if (!is_kvaddr(addr)) return nullptr;

    void *page_owner_buf = read_struct(addr, "page_owner");
    if (page_owner_buf == nullptr) return nullptr;

    auto owner_ptr = std::make_shared<page_owner>();
    owner_ptr->addr = addr;

    // Read all fields in one go to minimize pointer arithmetic
    const char* buf_base = static_cast<const char*>(page_owner_buf);
    owner_ptr->order = SHORT(buf_base + field_offset(page_owner, order));
    owner_ptr->handle = UINT(buf_base + field_offset(page_owner, handle));
    owner_ptr->free_handle = UINT(buf_base + field_offset(page_owner, free_handle));
    owner_ptr->last_migrate_reason = SHORT(buf_base + field_offset(page_owner, last_migrate_reason));
    owner_ptr->ts_nsec = ULONG(buf_base + field_offset(page_owner, ts_nsec));
    owner_ptr->free_ts_nsec = ULONG(buf_base + field_offset(page_owner, free_ts_nsec));
    owner_ptr->gfp_mask = INT(buf_base + field_offset(page_owner, gfp_mask));
    owner_ptr->pid = INT(buf_base + field_offset(page_owner, pid));

    // Handle optional fields
    const auto comm_offset = field_offset(page_owner, comm);
    if (comm_offset > 0) {
        owner_ptr->comm = read_cstring(addr + comm_offset, 64, "page_owner_comm");
    }

    const auto tgid_offset = field_offset(page_owner, tgid);
    if (tgid_offset > 0) {
        owner_ptr->tgid = INT(buf_base + tgid_offset);
    } else {
        struct task_context *tc = pid_to_context(owner_ptr->pid);
        if (tc) {
            owner_ptr->tgid = task_tgid(tc->task);
            if (comm_offset <= 0) {
                owner_ptr->comm = std::string(tc->comm);
            }
        }
    }

    FREEBUF(page_owner_buf);
    return owner_ptr;
}

/**
 * parser_all_pageowners - Parse all page owner information from crash dump
 *
 * This function iterates through all physical page frames in the system and
 * extracts page owner information for pages that have tracking enabled.
 * It builds the owner_map which maps PFN to page_owner structures.
 *
 * This is a performance-critical function that may take significant time
 * for systems with large amounts of memory.
 */
void Pageowner::parser_all_pageowners(){
    // Verify page_owner is enabled before proceeding
    if (!is_enable_pageowner()){
        LOGE("Page owner is not enabled, cannot parse");
        return;
    }
    // Determine page_ext_size based on kernel version
    // Kernel 5.4+ uses page_ext_size symbol directly
    if (csymbol_exists("page_ext_size")) {
        try_get_symbol_data(TO_CONST_STRING("page_ext_size"), sizeof(ulong), &page_ext_size);
        LOGD("Found page_ext_size symbol: %d", page_ext_size);
    } else if (csymbol_exists("extra_mem") && struct_size(page_ext)) {
        // Older kernels: calculate from struct size + extra_mem
        ulong extra_mem;
        if (try_get_symbol_data(TO_CONST_STRING("extra_mem"), sizeof(ulong), &extra_mem)){
            page_ext_size = struct_size(page_ext) + extra_mem;
            LOGD("Calculated page_ext_size from extra_mem: %d", page_ext_size);
        }
    }
    if (page_ext_size <= 0){
        LOGE("Cannot determine page_ext_size value");
        return;
    }
    LOGD("page_ext_size: %d bytes", page_ext_size);
    // Get the offset of page_owner within page_ext structure
    if (csymbol_exists("page_owner_ops")){
        ulong ops_addr = csymbol_value("page_owner_ops");
        ops_offset = read_ulong(ops_addr + field_offset(page_ext_operations,offset),"page_owner_ops.offset");
        LOGD("ops_offset: %zu", ops_offset);
    }
    if (ops_offset < 0){
        LOGE("Cannot determine ops_offset value");
        return;
    }
    // Verify stack_slabs is available for stack trace lookup
    if (!stack_slabs){
        LOGE("stack_slabs not available");
        return;
    }
    // Read page extension flag bit positions
    PAGE_EXT_OWNER = read_enum_val("PAGE_EXT_OWNER");
    PAGE_EXT_OWNER_ALLOCATED = read_enum_val("PAGE_EXT_OWNER_ALLOCATED");
    LOGD("Starting to parse page owners from PFN range: 0x%lx - 0x%lx", min_low_pfn, max_pfn);
    size_t total_pfns = max_pfn - min_low_pfn;
    size_t processed = 0;
    size_t valid_owners = 0;
    size_t progress_interval = total_pfns / 10; // Log progress every 10%
    // Iterate through all page frame numbers in the system
    for (size_t pfn = min_low_pfn; pfn < max_pfn; pfn++){
        processed++;
        // Log progress periodically for large memory systems
        if (progress_interval > 0 && processed % progress_interval == 0) {
            LOGD("Parsing progress: %zu/%zu PFNs (%.1f%%)",
                     processed, total_pfns, (processed * 100.0) / total_pfns);
        }

        // Convert PFN to page structure address
        ulong page = pfn_to_page(pfn);
        if (!is_kvaddr(page)) {
            LOGE("PFN 0x%zx: invalid page address 0x%lx", pfn, page);
            continue;
        }

        // Lookup the page_ext structure for this page
        ulong page_ext = lookup_page_ext(page);
        if (!is_kvaddr(page_ext)) {
            LOGE("PFN 0x%zx: invalid page_ext address", pfn);
            continue;
        }

        // Check if page owner tracking is enabled for this page
        ulong flags = read_ulong(page_ext + field_offset(page_ext, flags), "page_ext_flags");
        if (!((flags & (1UL << PAGE_EXT_OWNER)) != 0)) {
            LOGE("PFN 0x%zx: PAGE_EXT_OWNER not set", pfn);
            continue;
        }
        if (!((flags & (1UL << PAGE_EXT_OWNER_ALLOCATED)) != 0)) {
            LOGE("PFN 0x%zx: PAGE_EXT_OWNER_ALLOCATED not set", pfn);
            continue;
        }

        // Get page_owner structure address and parse it
        ulong page_owner_addr = get_page_owner(page_ext);
        page_owner_page_list.insert(page_owner_addr & page_mask);

        std::shared_ptr<page_owner> owner_ptr = parser_page_owner(page_owner_addr);
        LOGD( "pfn:%zu page_ext:%lx page_owner:%lx handle:%ld free_handle:%ld\n",
                pfn,page_ext,page_owner_addr,(ulong)owner_ptr->handle,(ulong)owner_ptr->free_handle);

        if(owner_ptr == nullptr) {
            LOGE("PFN 0x%zx: failed to parse page_owner", pfn);
            continue;
        }

        // Verify PFN alignment with allocation order
        // Pages are allocated in power-of-2 blocks, so PFN must be aligned
        if (!IS_ALIGNED(pfn, 1 << owner_ptr->order)) {
            LOGE("PFN 0x%zx: not aligned to order %d", pfn, owner_ptr->order);
            continue;
        }
        owner_ptr->pfn = pfn;

        // Retrieve and cache stack trace records for both allocation and free
        std::shared_ptr<stack_record_t> record_ptr;
        if(owner_ptr->free_handle > 0){
            record_ptr = get_stack_record(owner_ptr->free_handle);
            if (record_ptr) {
                stack_record_page_list.insert(record_ptr->record_addr & page_mask);
            }
        }
        if(owner_ptr->handle > 0){
            record_ptr = get_stack_record(owner_ptr->handle);
            if (record_ptr) {
                stack_record_page_list.insert(record_ptr->record_addr & page_mask);
            }
        }
        // Store in the owner map for later retrieval
        owner_map[pfn] = owner_ptr;
        valid_owners++;
    }
    LOGD("Parsing complete: processed %zu PFNs, found %zu valid page owners", processed, valid_owners);
    LOGD("page_owner structures use %zu pages (%s)", page_owner_page_list.size(), csize(page_owner_page_list.size() * page_size).c_str());
    LOGD("stack_record structures use %zu pages (%s)", stack_record_page_list.size(),csize(stack_record_page_list.size() * page_size).c_str());
}

ulong Pageowner::get_page_owner(ulong page_ext){
    return page_ext + ops_offset;
}

ulong Pageowner::lookup_page_ext(ulong page) {
    if(get_config_val("CONFIG_PAGE_EXTENSION") != "y"){
        LOGD("Not enable CONFIG_PAGE_EXTENSION \n");
        return 0;
    }
    const ulong pfn = page_to_pfn(page);
    ulong page_ext = 0;

    if(get_config_val("CONFIG_SPARSEMEM") == "y"){
        const ulong section_nr = pfn_to_section_nr(pfn);
        const ulong section = valid_section_nr(section_nr);
        if (!section || !is_kvaddr(section)){
            LOGD("invaild section %#lx \n",section);
            return 0;
        }
        page_ext = read_pointer(section + field_offset(mem_section,page_ext),"mem_section_page_ext");
        if (page_ext_invalid(page_ext)){
            LOGD("invaild page_ext %#lx \n",page_ext);
            return 0;
        }
    } else {
        const int nid = page_to_nid(page);
        const struct node_table *nt = &vt->node_table[nid];
        page_ext = read_pointer(nt->pgdat + field_offset(pglist_data,node_page_ext),"pglist_data_node_page_ext");
    }
    return get_entry(page_ext, pfn);
}

ulong Pageowner::get_entry(ulong base, ulong pfn) {
    LOGD("page_ext:%lx pfn:%lx\n", base,pfn);
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
