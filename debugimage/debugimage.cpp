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

#include "debugimage.h"

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wpointer-arith"

#ifndef BUILD_TARGET_TOGETHER
DEFINE_PLUGIN_COMMAND(DebugImage)
#endif

void DebugImage::cmd_main(void) {
    int c;
    std::string cppString;
    if (argcnt < 2) cmd_usage(pc->curcmd, SYNOPSIS);
    if (image_list.size() == 0){
        parser_memdump();
    }
    while ((c = getopt(argcnt, args, "acs")) != EOF) {
        switch(c) {
            case 'a':
                print_memdump();
                break;
            case 'c':
                parse_cpu_ctx();
                break;
            case 's':
                print_cpu_stack();
                break;
            default:
                argerrs++;
                break;
        }
    }
    if (argerrs)
        cmd_usage(pc->curcmd, SYNOPSIS);
}

DebugImage::DebugImage(){
    cmd_name = "dbi";
    help_str_list={
        "dbi",                            /* command name */
        "dump debug image region information",        /* short description */
        "-a \n"
            "  dbi -i <entry addr>\n"
            "  This command dumps the debug image info.",
        "\n",
        "EXAMPLES",
        "  Display all debug image info:",
        "    %s> dbi -a",
        "     DumpTable base:bc700000",
        "     Id   Dump_entry       version magic            DataAddr         DataLen    Name",
        "     0    bc707e10         20      42445953         bc707e50         2048       c0_context",
        "     1    bc708650         20      42445953         bc708690         2048       c1_context",
        "     2    bc708e90         20      42445953         bc708ed0         2048       c2_context",
        "     3    bc7096d0         20      42445953         bc709710         2048       c3_context",
        "\n",
        "  Parser specified debug image:",
        "    %s> dbi -i bc707e10",
        "\n",
    };
    initialize();
}

void DebugImage::print_memdump(){
    std::ostringstream oss_hd;
    oss_hd  << std::left << std::setw(4)            << "Id" << " "
            << std::left << std::setw(16)           << "Dump_entry" << " "
            << std::left << std::setw(8)            << "version" << " "
            << std::left << std::setw(VADDR_PRLEN)  << "magic" << " "
            << std::left << std::setw(VADDR_PRLEN)  << "DataAddr" << " "
            << std::left << std::setw(10)           << "DataLen" << " "
            << std::left << "Name";
    fprintf(fp, "%s \n",oss_hd.str().c_str());
    for (const auto& entry_ptr : image_list) {
        std::ostringstream oss;
        oss << std::left << std::setw(4)            << std::dec << entry_ptr->id << " "
            << std::left << std::setw(16)           << std::hex << entry_ptr->addr << " "
            << std::left << std::setw(8)            << std::dec << entry_ptr->version << " "
            << std::left << std::setw(VADDR_PRLEN)  << std::hex << entry_ptr->magic << " "
            << std::left << std::setw(VADDR_PRLEN)  << std::hex << entry_ptr->data_addr << " "
            << std::left << std::setw(10)           << std::dec << entry_ptr->data_len << " "
            << std::left  << entry_ptr->data_name;
        fprintf(fp, "%s \n",oss.str().c_str());
    }
}

void DebugImage::parser_memdump(){
    if (!csymbol_exists("memdump")){
        fprintf(fp, "memdump doesn't exist in this kernel!\n");
        return;
    }
    ulong dump_addr = csymbol_value("memdump");
    if (!is_kvaddr(dump_addr)) {
        fprintf(fp, "memdump address is invalid!\n");
        return;
    }
    field_init(msm_memory_dump,table_phys);
    field_init(msm_dump_table,version);
    field_init(msm_dump_table,num_entries);
    field_init(msm_dump_table,entries);
    field_init(msm_dump_entry,id);
    field_init(msm_dump_entry,name);
    field_init(msm_dump_entry,type);
    field_init(msm_dump_entry,addr);
    field_init(msm_dump_data,version);
    field_init(msm_dump_data,magic);
    field_init(msm_dump_data,name);
    field_init(msm_dump_data,addr);
    field_init(msm_dump_data,len);
    field_init(msm_dump_data,reserved);
    struct_init(msm_dump_table);
    struct_init(msm_dump_entry);
    struct_init(msm_dump_data);
    uint64_t table_phys = read_ulonglong(dump_addr + field_offset(msm_memory_dump,table_phys),"table_phys");
    // fprintf(fp, "DumpTable base:%" PRIx64 "\n", table_phys);
    parser_dump_table(table_phys);
}

void DebugImage::print_cpu_stack(){
    for (const auto& entry_ptr : image_list) {
        if (entry_ptr->id >= DATA_CPU_CTX && entry_ptr->id < DATA_L1_INST_TLB){
            parse_cpu_stack(entry_ptr);
        }
    }
}

void DebugImage::parse_cpu_ctx(){
    for (const auto& entry_ptr : image_list) {
        if (entry_ptr->id >= DATA_CPU_CTX && entry_ptr->id < DATA_L1_INST_TLB){
            parse_cpu_ctx(entry_ptr);
        }
    }
}

void DebugImage::parse_cpu_stack(std::shared_ptr<Dump_entry> entry_ptr){
    int core = entry_ptr->id - DATA_CPU_CTX;
    int major = entry_ptr->version >> 4;
    int minor = entry_ptr->version & 0xF;
    fprintf(fp, "%s  core:%d  version:%d.%d\n",entry_ptr->data_name.c_str(), core,major,minor);
    if (major == 2 && minor == 0){ //v2.0
        parser_ptr = std::make_shared<Cpu64_Context_V20>();
    }else{
        if (BITS64()){
            if (major == 1 && minor == 3){ //v1.3
                parser_ptr = std::make_shared<Cpu64_Context_V13>();
            }else if (major == 1 && minor == 4){ //v1.4
                parser_ptr = std::make_shared<Cpu64_Context_V14>();
            }
        }else{
            parser_ptr = std::make_shared<Cpu32_Context>();
        }
    }
    parser_ptr->print_stack(entry_ptr);
}

void DebugImage::parse_cpu_ctx(std::shared_ptr<Dump_entry> entry_ptr){
    int core = entry_ptr->id - DATA_CPU_CTX;
    int major = entry_ptr->version >> 4;
    int minor = entry_ptr->version & 0xF;
    fprintf(fp, "%s  core:%d  version:%d.%d\n",entry_ptr->data_name.c_str(), core,major,minor);
    if (major == 2 && minor == 0){ //v2.0
        parser_ptr = std::make_shared<Cpu64_Context_V20>();
    }else{
        if (BITS64()){
            if (major == 1 && minor == 3){ //v1.3
                parser_ptr = std::make_shared<Cpu64_Context_V13>();
            }else if (major == 1 && minor == 4){ //v1.4
                parser_ptr = std::make_shared<Cpu64_Context_V14>();
            }
        }else{
            parser_ptr = std::make_shared<Cpu32_Context>();
        }
    }
    parser_ptr->generate_cmm(entry_ptr);
}

void DebugImage::parser_dump_data(std::shared_ptr<Dump_entry> entry_ptr){
    entry_ptr->version = read_uint(entry_ptr->addr + field_offset(msm_dump_data,version),"version",false);
    entry_ptr->magic = read_uint(entry_ptr->addr + field_offset(msm_dump_data,magic),"magic",false);
    if (entry_ptr->magic != MAGIC_NUMBER && entry_ptr->magic != HYP_MAGIC_NUMBER){
        return;
    }
    if (entry_ptr->id > DATA_MAX){
        return;
    }
    entry_ptr->data_name= read_cstring(entry_ptr->addr + field_offset(msm_dump_data,name),32, "name",false);
    entry_ptr->data_addr = read_ulonglong(entry_ptr->addr + field_offset(msm_dump_data,addr),"addr",false);
    entry_ptr->data_len = read_ulonglong(entry_ptr->addr + field_offset(msm_dump_data,len),"len",false);
    image_list.push_back(entry_ptr);
}

void DebugImage::parser_dump_table(uint64_t paddr){
    uint32_t version = read_uint(paddr + field_offset(msm_dump_table,version),"version",false);
    uint32_t num_entries = read_uint(paddr + field_offset(msm_dump_table,num_entries),"num_entries",false);
    if (num_entries == 0 || num_entries > 100){
        return;
    }
    uint64_t entries = paddr + field_offset(msm_dump_table,entries);
    for (size_t i = 0; i < num_entries; i++){
        uint64_t entry_addr = entries + struct_size(msm_dump_entry) * i;
        std::shared_ptr<Dump_entry> entry_ptr = std::make_shared<Dump_entry>();
        entry_ptr->id = read_uint(entry_addr + field_offset(msm_dump_entry,id),"id",false);
        int type = read_uint(entry_addr + field_offset(msm_dump_entry,type),"type",false);
        entry_ptr->addr = read_ulonglong(entry_addr + field_offset(msm_dump_entry,addr),"addr",false);
        // entry_ptr->name = read_cstring(entry_addr + field_offset(msm_dump_entry,name),32, "name",false);
        if (type == Entry_type::ENTRY_TYPE_DATA){
            parser_dump_data(entry_ptr);
        }else if (type == Entry_type::ENTRY_TYPE_TABLE){
            parser_dump_table(entry_ptr->addr);
        }
    }
}

#pragma GCC diagnostic pop
