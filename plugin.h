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

#ifndef PARSER_DEFS_H_
#define PARSER_DEFS_H_

#include <iostream>
#include <string>
#include <vector>
#include <linux/types.h>
#include <unistd.h>
#include <getopt.h>
#include <unordered_map>
#include <memory>
#include <functional>
#include <algorithm>
#include <bitset>
#include <set>
#include <regex.h>
#include <execinfo.h>
#include <stdio.h>
#include <stdlib.h>
#include <iomanip>
#include <arpa/inet.h>
#include <inttypes.h>
#include "struct_info.h"
#include <sstream>
#include <gelf.h>
#include <map>

#define field_init(type,field_name) type_init(TO_STD_STRING(type),TO_STD_STRING(field_name))
#define field_size(type,field_name) type_size(TO_STD_STRING(type),TO_STD_STRING(field_name))
#define field_offset(type,field_name) type_offset(TO_STD_STRING(type),TO_STD_STRING(field_name))

#define struct_init(type) type_init(TO_STD_STRING(type))
#define struct_size(type) type_size(TO_STD_STRING(type))
#define IS_ALIGNED(x, a)    (((x) & ((typeof(x))(a) - 1)) == 0)

typedef struct {
    long long counter;
} atomic64_t;

typedef struct {
    int counter;
} atomic_t;

typedef struct {
    int counter;
} atomic_long_t;

typedef struct {
    uint32_t type;
    uint32_t val;
} Elf32_Auxv_t;

typedef struct {
    uint64_t type;
    uint64_t val;
} Elf64_Auxv_t;

#define VM_NONE             0x00000000
#define VM_READ             0x00000001    /* currently active flags */
#define VM_WRITE            0x00000002
#define VM_EXEC             0x00000004
#define VM_SHARED           0x00000008
#define VM_MAYREAD          0x00000010    /* limits for mprotect() etc */
#define VM_MAYWRITE         0x00000020
#define VM_MAYEXEC          0x00000040
#define VM_MAYSHARE         0x00000080
#define VM_GROWSDOWN        0x00000100    /* general info on the segment */
#define VM_UFFD_MISSING     0x00000200    /* missing pages tracking */
#define VM_PFNMAP           0x00000400    /* Page-ranges managed without "struct page", just pure PFN */
#define VM_DENYWRITE        0x00000800    /* ETXTBSY on write attempts.. */
#define VM_UFFD_WP          0x00001000    /* wrprotect pages tracking */
#define VM_LOCKED           0x00002000
#define VM_IO               0x00004000    /* Memory mapped I/O or similar */
#define VM_HUGETLB          0x00400000
#define VM_DONTDUMP         0x04000000

#define GENMASK_ULL(h, l) (((1ULL<<(h+1))-1)&(~((1ULL<<l)-1)))

class ParserPlugin {
private:
#if defined(ARM)
    ulong* pmd_page_addr(ulong pmd);
#endif

protected:
    std::unordered_map<std::string, std::unique_ptr<Typeinfo>> typetable;
    static constexpr double KB = 1024.0;
    static constexpr double MB = 1024.0 * 1024.0;
    static constexpr double GB = 1024.0 * 1024.0 * 1024.0;

public:
    ParserPlugin();
    const size_t page_size = PAGESIZE();
    const size_t page_shift = PAGESHIFT();
    const size_t page_mask = ~(page_size - 1);
    ulong vaddr_mask = 0;
    std::string cmd_name;
    std::vector<std::string> help_str_list;
    char** cmd_help;

    virtual void cmd_main(void)=0;
    void initialize(void);
    std::string csize(uint64_t size);
    std::string csize(uint64_t size, int unit, int precision);
    void print_table();
    void type_init(const std::string& type);
    void type_init(const std::string& type,const std::string& field);
    int type_offset(const std::string& type,const std::string& field);
    int type_size(const std::string& type,const std::string& field);
    int type_size(const std::string& type);

    std::vector<ulong> for_each_rbtree(ulong rb_root,int offset);
    std::vector<ulong> for_each_list(ulong list_head,int offset);
    std::vector<ulong> for_each_hlist(ulong hlist_head,int offset);
    std::vector<ulong> for_each_xarray(ulong xarray_addr);
    std::vector<ulong> for_each_mptree(ulong maptree_addr);
    std::vector<ulong> for_each_radix(ulong root_rnode);

    std::vector<ulong> for_each_process();
    std::vector<ulong> for_each_threads();
    std::vector<ulong> for_each_vma(ulong& task_addr);
    std::vector<ulong> for_each_bus();
    std::vector<ulong> for_each_class();
    ulong get_bus_subsys_private(std::string bus_name);
    ulong get_class_subsys_private(std::string class_name);
    std::vector<ulong> for_each_device_for_bus(std::string bus_name);
    std::vector<ulong> for_each_device_for_class(std::string class_name);
    std::vector<ulong> for_each_device_for_driver(ulong driver_addr);
    std::vector<ulong> for_each_driver(std::string bus_name);
    ulonglong read_structure_field(ulong addr, const std::string &type, const std::string &field, bool virt = true);
    std::string read_cstring(ulong addr,int len, const std::string& note,bool virt=true);
    void* read_struct(ulong addr,const std::string& type,bool virt=true);
    bool read_struct(ulong addr,void* buf, int len, const std::string& type,bool virt=true);
    void* read_memory(ulong addr,int len, const std::string& note,bool virt=true);
    ulong read_pointer(ulong addr, const std::string& note,bool virt=true);
    short read_short(ulong addr,const std::string& note,bool virt=true);
    ushort read_ushort(ulong addr,const std::string& note,bool virt=true);
    ulonglong read_ulonglong(ulong addr,const std::string& note,bool virt=true);
    ulong read_ulong(ulong addr,const std::string& note,bool virt=true);
    long read_long(ulong addr,const std::string& note,bool virt=true);
    uint read_uint(ulong addr,const std::string& note,bool virt=true);
    int read_int(ulong addr,const std::string& note,bool virt=true);
    bool read_bool(ulong addr,const std::string& note,bool virt=true);
    unsigned char read_byte(ulong addr, const std::string& note,bool virt=true);
    int csymbol_exists(const std::string& note);
    ulong csymbol_value(const std::string& note);
    bool is_kvaddr(ulong addr);
    bool is_uvaddr(ulong addr, struct task_context *);
    int page_to_nid(ulong page);
    ulong virt_to_phy(ulong paddr);
    ulong phy_to_virt(ulong vaddr);
    ulong page_to_pfn(ulong page);
    ulong pfn_to_page(ulong pfn);
    ulong phy_to_page(ulong paddr);
    physaddr_t page_to_phy(ulong page);
    physaddr_t pfn_to_phy(ulong pfn);
    ulong phy_to_pfn(ulong paddr);
    std::string get_config_val(const std::string& conf_name);
    void cfill_pgd(ulonglong pgd, int type, ulong size);
    void cfill_pmd(ulonglong pmd, int type, ulong size);
    void cfill_ptbl(ulonglong ptbl, int type, ulong size);
    void print_backtrace();

    bool is_binary_stripped(std::string& filename);
    bool add_symbol_file(std::string& filename);
    void verify_userspace_symbol(std::string& symbol_name);
    bool isNumber(const std::string& str);
    std::string extract_string(const char *input);
    int is_bigendian(void);
    std::vector<std::string> get_enumerator_list(const std::string &enum_name);
    long read_enum_val(const std::string &enum_name);
    std::map<std::string, ulong> read_enum_list(const std::string& enum_list_name);
    char get_printable(uint8_t d);
    std::string print_line(uint64_t addr, const std::vector<uint8_t>& data);
    std::string hexdump(uint64_t addr, const char* buf, size_t length, bool little_endian = true);
#if defined(ARM)
    ulong get_arm_pte(ulong task_addr, ulong page_vaddr);
#endif
    bool load_symbols(std::string& path, std::string name);
    std::unordered_map<ulong, ulong> parser_auvx_list(ulong mm_struct_addr, bool is_compat);
    void uwind_irq_back_trace(int cpu, ulong x30);
    void uwind_task_back_trace(int pid, ulong x30);
};

#define DEFINE_PLUGIN_INSTANCE(class_name)                                                                      \
    static std::shared_ptr<class_name> instance;                                                                \
    static void wrapper_func() {                                                                                \
        if (instance) {                                                                                         \
            instance->cmd_main();                                                                               \
        }                                                                                                       \
    }

#ifndef BUILD_TARGET_TOGETHER
#define DEFINE_PLUGIN_COMMAND(class_name)                                                                       \
    extern "C" void class_name##_init(void);                                                                    \
    extern "C" void class_name##_fini(void);                                                                    \
    std::shared_ptr<class_name> class_name::instance = std::make_shared<class_name>();                          \
    static struct command_table_entry command_table[] = {                                                       \
        { &class_name::instance->cmd_name[0], &class_name::wrapper_func, class_name::instance->cmd_help, 0 },   \
        { NULL }                                                                                                \
    };                                                                                                          \
    extern "C" void __attribute__((constructor)) class_name##_init(void) {                                      \
        register_extension(command_table);                                                                      \
    }                                                                                                           \
    extern "C" void __attribute__((destructor)) class_name##_fini(void) {                                       \
        class_name::instance.reset();                                                                           \
    }
#endif // BUILD_TARGET_TOGETHER

#endif // PARSER_DEFS_H_
