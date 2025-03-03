// Copyright (c) 2024-2025 Qualcomm Innovation Center, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause-Clear

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
#include "logger/log.h"
#include <sstream>

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

class PaserPlugin {
protected:
    std::unordered_map<std::string, std::unique_ptr<Typeinfo>> typetable;
    static constexpr double KB = 1024.0;
    static constexpr double MB = 1024.0 * 1024.0;
    static constexpr double GB = 1024.0 * 1024.0 * 1024.0;

public:
    PaserPlugin();
    const size_t page_size = PAGESIZE();
    const size_t page_shift = PAGESHIFT();
    const ulong page_mask = ~((ulong)(page_size - 1));
    std::string cmd_name;
    std::vector<std::string> help_str_list;
    char** cmd_help;

    virtual void cmd_main(void)=0;
    void initialize(void);
    std::string csize(size_t size);
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

    std::string read_start_args(ulong& task_addr);
    ulonglong read_structure_field(ulong kvaddr,const std::string& type,const std::string& field);
    std::string read_cstring(ulong kvaddr,int len, const std::string& note);
    void* read_struct(ulong kvaddr,const std::string& type);
    bool read_struct(ulong kvaddr,void* buf, int len, const std::string& type);
    void* read_memory(ulong kvaddr,int len, const std::string& note);
    void* read_phys_memory(ulong paddr, int len, const std::string& note);
    ulong read_pointer(ulong kvaddr, const std::string& note);
    short read_short(ulong kvaddr,const std::string& note);
    ushort read_ushort(ulong kvaddr,const std::string& note);
    ulonglong read_ulonglong(ulong kvaddr,const std::string& note);
    ulong read_ulong(ulong kvaddr,const std::string& note);
    long read_long(ulong kvaddr,const std::string& note);
    uint read_uint(ulong kvaddr,const std::string& note);
    int read_int(ulong kvaddr,const std::string& note);
    bool read_bool(ulong kvaddr,const std::string& note);
    unsigned char read_byte(ulong kvaddr, const std::string& note);
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
    long read_enum_val(const std::string& enum_name);
    char get_printable(uint8_t d);
    std::string print_line(uint64_t addr, const std::vector<uint8_t>& data);
    std::string hexdump(uint64_t addr, const char* buf, size_t length, bool little_endian = true);
};

#define DEFINE_PLUGIN_INSTANCE(class_name)                                                                      \
    static std::unique_ptr<class_name> instance;                                                                \
    static void wrapper_func() {                                                                                \
        if (instance) {                                                                                         \
            instance->cmd_main();                                                                               \
        }                                                                                                       \
    }

#ifndef BUILD_TARGET_TOGETHER
#define DEFINE_PLUGIN_COMMAND(class_name)                                                                       \
    extern "C" void class_name##_init(void);                                                                    \
    extern "C" void class_name##_fini(void);                                                                    \
    std::unique_ptr<class_name> class_name::instance = std::make_unique<class_name>();                          \
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
