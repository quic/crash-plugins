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

#ifndef PAGE_OWNER_DEFS_H_
#define PAGE_OWNER_DEFS_H_

#include "plugin.h"

/* Page extension invalid flag from mm/page_ext.c */
#define PAGE_EXT_INVALID    (0x1)

/**
 * struct page_owner - Represents page ownership information
 *
 * This structure contains allocation/deallocation tracking information
 * for a physical page in the kernel memory management system.
 */
struct page_owner {
    ulong addr;                      // Virtual address of page_owner structure
    ulong pfn;                       // Page Frame Number
    unsigned short order;            // Allocation order (2^order pages)
    short last_migrate_reason;       // Last page migration reason code
    unsigned int gfp_mask;           // GFP (Get Free Pages) allocation flags
    unsigned int handle;             // Stack trace handle for allocation
    unsigned int free_handle;        // Stack trace handle for deallocation
    unsigned long long ts_nsec;      // Allocation timestamp in nanoseconds
    unsigned long long free_ts_nsec; // Deallocation timestamp in nanoseconds
    size_t pid;                      // Process ID that allocated the page
    size_t tgid;                     // Thread Group ID (process group)
    std::string comm;                // Process command name
};

/**
 * struct process_info - Aggregated memory statistics per process
 */
struct process_info {
    ulong total_cnt;   // Total number of allocations
    ulong total_size;  // Total memory size in bytes
};

/**
 * struct stack_info - Aggregated allocation statistics per stack trace
 */
struct stack_info {
    unsigned int handle;             // Stack trace handle identifier
    ulong total_cnt;                 // Total allocation count for this stack
    ulong total_size;                // Total memory size for this stack
    std::unordered_map<size_t, std::shared_ptr<page_owner>> owner_list; // Map of PFN to page_owner
};

/**
 * class Pageowner - Plugin for analyzing kernel page owner information
 *
 * This plugin provides functionality to analyze page allocation and deallocation
 * tracking in Linux kernel crash dumps. It can display allocation stacks,
 * memory usage statistics, and track page ownership across the system.
 */
class Pageowner : public ParserPlugin {
private:
    /**
     * enum AddressType - Types of memory addresses that can be analyzed
     */
    enum AddressType {
        ADDR_PFN,       // Page Frame Number
        ADDR_PHYSICAL,  // Physical memory address
        ADDR_PAGE,      // Kernel page structure address
        ADDR_VIRTUAL,   // Virtual memory address
        ADDR_UNKNOWN    // Unknown or invalid address type
    };

    // Input type flags for address interpretation
    static const int INPUT_PFN = 0x0001;    // Input is a Page Frame Number
    static const int INPUT_PYHS = 0x0002;   // Input is a Physical address
    static const int INPUT_PAGE = 0x0004;   // Input is a Page structure address
    static const int INPUT_VADDR = 0x0008;  // Input is a Virtual address

    // Kernel data structure sizes and offsets
    int page_ext_size;                      // Size of page_ext structure
    size_t ops_offset;                      // Offset to page_owner in page_ext
    long PAGE_EXT_OWNER;                    // Page owner extension flag bit
    long PAGE_EXT_OWNER_ALLOCATED;          // Page allocated flag bit

    // Data caches for parsed information
    std::unordered_map<size_t, std::shared_ptr<page_owner>> owner_map;        // PFN -> page_owner mapping
    std::unordered_map<unsigned int, std::shared_ptr<stack_info>> handle_map; // Stack handle -> stack_info mapping
    std::set<ulong> page_owner_page_list;   // Set of pages used by page_owner structures
    std::set<ulong> stack_record_page_list; // Set of pages used by stack_record structures

    // Core functionality methods
    bool is_enable_pageowner();             // Check if page_owner is enabled in kernel
    void parser_all_pageowners();           // Parse all page owner information from crash dump
    std::shared_ptr<page_owner> parser_page_owner(ulong addr); // Parse single page_owner structure

    // Page extension lookup methods
    ulong get_entry(ulong base, ulong pfn); // Calculate page_ext entry address
    bool page_ext_invalid(ulong page_ext);  // Check if page_ext pointer is valid
    ulong lookup_page_ext(ulong page);      // Lookup page_ext for a given page
    ulong get_page_owner(ulong page_ext);   // Get page_owner from page_ext

    // Display and output methods
    void print_page_owner(const std::string& addr, int flags); // Print page owner info for address
    void print_sorted_allocation_summary(); // Print allocations sorted by frequency
    void print_process_memory_summary(std::unordered_map<size_t, std::shared_ptr<page_owner>> owner_list); // Print per-process summary
    void print_memory_info();               // Print overall memory usage statistics
    void print_all_allocated_pages();       // Print all currently allocated pages
    void print_all_freed_pages();           // Print all freed pages
    void print_page_owner_entry(std::shared_ptr<page_owner> owner_ptr, bool is_free,
                               size_t entry_num, size_t total_entries); // Print single page owner entry
    void print_page_owner_detailed(std::shared_ptr<page_owner> owner_ptr, bool is_free); // Print detailed page owner info
    void print_page_owner_auto(const std::string& addr_str); // Auto-detect address type and print

    // Address analysis methods
    AddressType detect_address_type(ulonglong addr); // Detect what type of address is provided
    bool is_page_address(ulonglong addr);   // Check if address is a page structure
    bool is_physical_address(ulonglong addr); // Check if address is physical
    bool is_user_virtual_address(ulonglong addr); // Check if address is user virtual
    ulong vaddr_to_pfn(ulong vaddr);        // Convert virtual address to PFN

    // Page state methods
    bool is_page_allocated(std::shared_ptr<page_owner> owner_ptr); // Check if page is currently allocated

public:
    Pageowner();
    void cmd_main(void) override;
    void init_offset(void) override;
    void init_command(void) override;
    DEFINE_PLUGIN_INSTANCE(Pageowner)
};

#endif // PAGE_OWNER_DEFS_H_
