// Copyright (c) 2024-2025 Qualcomm Innovation Center, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause-Clear

#include "reserved.h"

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wpointer-arith"

#ifndef BUILD_TARGET_TOGETHER
DEFINE_PLUGIN_COMMAND(Reserved)
#endif

void Reserved::cmd_main(void) {
    int c;
    if (argcnt < 2) cmd_usage(pc->curcmd, SYNOPSIS);
    while ((c = getopt(argcnt, args, "a")) != EOF) {
        switch(c) {
            case 'a':
                print_reserved_mem();
                break;
            default:
                argerrs++;
                break;
        }
    }
    if (argerrs)
        cmd_usage(pc->curcmd, SYNOPSIS);
}

Reserved::Reserved(){
    dts = std::make_shared<Devicetree>();
    field_init(reserved_mem,name);
    field_init(reserved_mem,base);
    field_init(reserved_mem,size);
    struct_init(reserved_mem);
    cmd_name = "reserved";
    help_str_list={
        "reserved",                            /* command name */
        "dump reserved memory information",        /* short description */
        "-a \n"
            "\n",
        "EXAMPLES",
        "  Display reserved memory info",
        "    %s> reserved -a",
        "    ==============================================================================================================",
        "    [0] oda_region@45700000        reserved_mem:0xffffffde316b16e0 range:[0x45700000~0x45a00000] size:3.00Mb     [no-map]",
        "    [1] deepsleep_region@45A00000  reserved_mem:0xffffffde316b1718 range:[0x45a00000~0x45b00000] size:1.00Mb     [no-map]",
        "    [2] splash_region@5c000000     reserved_mem:0xffffffde316b19b8 range:[0x5c000000~0x5cf00000] size:15.00Mb    [unknow]",
        "    [3] linux,cma                  reserved_mem:0xffffffde316b1600 range:[0xbc000000~0xbe000000] size:32.00Mb    [reusable]",
        "    [4] adsp_region                reserved_mem:0xffffffde316b15c8 range:[0xbe000000~0xbe800000] size:8.00Mb     [reusable]",
        "    ==============================================================================================================",
        "    Total:448.20Mb nomap:168.20Mb reuse:264.00Mb other:16.00Mb",
        "\n",
    };
    initialize();
    parser_reserved_mem();
}

// struct reserved_mem {
//     const char *name;
//     unsigned long fdt_node;
//     unsigned long phandle;
//     const struct reserved_mem_ops *ops;
//     phys_addr_t base;
//     phys_addr_t size;
//     void *priv;
// }
void Reserved::parser_reserved_mem(){
    if (!csymbol_exists("reserved_mem")){
        LOGE("reserved_mem doesn't exist in this kernel!\n");
        return;
    }
    ulong reserved_mem_addr = csymbol_value("reserved_mem");
    if (!reserved_mem_addr) return;
    ulong reserved_mem_count = read_pointer(csymbol_value("reserved_mem_count"),"reserved_mem_count");
    for (int i = 0; i < reserved_mem_count; ++i) {
        ulong reserved_addr = reserved_mem_addr + i * struct_size(reserved_mem);
        void *reserved_mem_buf = read_struct(reserved_addr,"reserved_mem");
        if(reserved_mem_buf == nullptr) return;
        std::shared_ptr<reserved_mem> mem_ptr = std::make_shared<reserved_mem>();
        std::string name = read_cstring(ULONG(reserved_mem_buf + field_offset(reserved_mem,name)),64, "reserved_mem_name");
        mem_ptr->addr = reserved_addr;
        mem_ptr->name = name;
        std::vector<std::shared_ptr<device_node>> nodes = dts->find_node_by_name(name);
        if (nodes.size() == 0){
            continue;
        }
        mem_ptr->type = Type::UNKNOW;
        std::shared_ptr<Property> prop = dts->getprop(nodes[0]->addr,"no-map");
        if (prop.get() != nullptr){
            mem_ptr->type = Type::NO_MAP;
        }
        prop = dts->getprop(nodes[0]->addr,"reusable");
        if (prop.get() != nullptr){
            mem_ptr->type = Type::REUSABLE;
        }
        if(get_config_val("CONFIG_PHYS_ADDR_T_64BIT") == "y"){
            mem_ptr->base = ULONGLONG(reserved_mem_buf + field_offset(reserved_mem,base));
            mem_ptr->size = ULONGLONG(reserved_mem_buf + field_offset(reserved_mem,size));
        }else{
            mem_ptr->base = ULONG(reserved_mem_buf + field_offset(reserved_mem,base));
            mem_ptr->size = ULONG(reserved_mem_buf + field_offset(reserved_mem,size));
        }
        FREEBUF(reserved_mem_buf);
        mem_list.push_back(mem_ptr);
    }
}

void Reserved::print_reserved_mem(){
    ulong total_size = 0;
    ulong nomap_size = 0;
    ulong reusable_size = 0;
    ulong other_size = 0;
    char buf_index[BUFSIZE];
    char buf_name[BUFSIZE];
    char buf_addr[BUFSIZE];
    char buf_range[BUFSIZE];
    char buf_size[BUFSIZE];
    char buf_flag[BUFSIZE];
    int index = 0;
    fprintf(fp, "==============================================================================================================\n");
    std::sort(mem_list.begin(), mem_list.end(),[&](const std::shared_ptr<reserved_mem>& a, const std::shared_ptr<reserved_mem>& b){
        return a->base < b->base;
    });
    size_t max_name_len = 0;
    for (const auto& mem : mem_list) {
        max_name_len = std::max(max_name_len,mem->name.size());
    }
    for (const auto& mem : mem_list) {
        total_size += mem->size;
        sprintf(buf_index, "[%d]",index);
        sprintf(buf_addr, "reserved_mem:0x%lx",mem->addr);
        sprintf(buf_range, "range:[0x%llx~0x%llx]",mem->base,(mem->base + mem->size));
        convert_size(mem->size,buf_size);
        if (mem->type == Type::NO_MAP){
            sprintf(buf_flag, "[%s]", "no-map");
            nomap_size += mem->size;
        }else if (mem->type == Type::REUSABLE){
            sprintf(buf_flag, "[%s]", "reusable");
            reusable_size += mem->size;
        }else{
            sprintf(buf_flag, "[%s]", "unknow");
            other_size += mem->size;
        }
        fprintf(fp, "%s%s %s %s %s %s\n",
            mkstring(buf_index, 4, LJUST,buf_index),
            mkstring(buf_name, max_name_len + 1, LJUST, mem->name.c_str()),
            mkstring(buf_addr, 20, LJUST, buf_addr),
            mkstring(buf_range,20, LJUST, buf_range),
            mkstring(buf_flag, 10, LJUST, buf_flag),
            mkstring(buf_size, 10, LJUST, buf_size));

        index += 1;
    }
    fprintf(fp, "==============================================================================================================\n");
    convert_size(total_size,buf_size);
    fprintf(fp, "Total:%s ",buf_size);
    convert_size(nomap_size,buf_size);
    fprintf(fp, "nomap:%s ",buf_size);
    convert_size(reusable_size,buf_size);
    fprintf(fp, "reuse:%s ",buf_size);
    convert_size(other_size,buf_size);
    fprintf(fp, "other:%s\n",buf_size);
}

#pragma GCC diagnostic pop
