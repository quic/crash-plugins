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

#include "dts.h"

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wpointer-arith"

#ifndef BUILD_TARGET_TOGETHER
DEFINE_PLUGIN_COMMAND(Dts)
#endif // !BUILD_TARGET_TOGETHER

void Dts::cmd_main(void) {
    int c;
    int flags;
    std::string cppString;
    if (argcnt < 2) cmd_usage(pc->curcmd, SYNOPSIS);
    if (root_node == nullptr){
        root_node = read_node("", root_addr);
    }
    while ((c = getopt(argcnt, args, "afb:n:m")) != EOF) {
        switch(c) {
            case 'a': //print dts info
            {
                flags = DTS_SHOW;
                print_node(root_node,0,flags);
                break;
            }
            case 'f': //print dts info with address
            {
                flags = DTS_SHOW | DTS_ADDR;
                print_node(root_node,0,flags);
                break;
            }
            case 'b': //store dts info to devicetree.dtb
                cppString.assign(optarg);
                read_dtb(cppString);
                break;
            case 'n': //print a specified node info by name or path
            {
                flags = DTS_SHOW | DTS_ADDR;
                cppString.assign(optarg);
                if (isNumber(cppString)){
                    unsigned long addr = std::stoul(cppString, nullptr, 16);
                    if(is_kvaddr(addr)){
                        std::shared_ptr<device_node> node_ptr = find_node_by_addr(addr);
                        print_node(node_ptr,flags);
                    }else{
                        fprintf(fp, "invalid address %lx\n",addr);
                    }
                }else{
                    std::vector<std::shared_ptr<device_node>> node_list = find_node_by_name(cppString);
                    for (const auto& node_ptr : node_list) {
                        print_node(node_ptr,flags);
                    }
                }
                break;
            }
            case 'm': //print memory size
                print_ddr_info();
                break;
            default:
                argerrs++;
                break;
        }
    }
    if (argerrs)
        cmd_usage(pc->curcmd, SYNOPSIS);
}

Dts::Dts(){
    cmd_name = "dts";
    help_str_list={
        "dts",                            /* command name */
        "dump dts info",        /* short description */
        "-a \n"
            "  dts -f\n"
            "  dts -b\n"
            "  dts -n <name>\n"
            "  dts -m\n"
            "  This command dumps the dts info.",
        "\n",
        "EXAMPLES",
        "  Display whole dts info:",
        "    %s> dts -a",
        "       memory{",
        "           ddr_device_hbb_ch0_rank0=< d >;",
        "           ddr_device_rank_ch0=< 1 >;",
        "           ddr_device_type=< 7 >;",
        "           device_type=<memory>;",
		"       };",
        "\n",
        "  Display whole dts info with address:",
        "    %s> dts -f",
        "       ffffff806f28a458:memory{",
        "           ffffff806f28a5b8:ddr_device_hbb_ch0_rank0=< d >;",
        "           ffffff806f28a618:ddr_device_rank_ch0=< 1 >;",
        "           ffffff806f28a678:ddr_device_type=< 7 >;",
        "           ffffff806f28a7f8:device_type=<memory>;",
		"       };",
        "\n",
        "  Display one node info by node name or node path",
        "    %s> dts -n memory",
        "       memory{",
        "           ddr_device_type=< 0x7 >;",
        "           device_type=<memory>;",
        "           reg=< 0x0 0x40000000 0x0 0x3ee00000 0x0 0x80000000 0x0 0x40000000 >;",
        "       };",
        "\n",
        "  Display physic memory total size:",
        "    %s> dts -m",
        "       =========================================",
        "         0x40000000~0x7ee00000  size:0x3ee00000 ",
        "         0x80000000~0xc0000000  size:0x40000000 ",
        "       =========================================",
        "          Total size:    2030M ",
        "\n",
        "  Read out the whole dtb memory:",
        "    %s> dts -b ./dts.dtb",
        "       save dtb to ./dts.dtb",
        "\n",
        "       please use below command to generate dts file:",
        "           dtc -I dtb -O dts -o ./xx.dts ./dts.dtb",
        "\n",
    };
    initialize();
}

void Dts::print_ddr_info(){
    ulong total_size = 0;
    std::vector<DdrRange> ranges = get_ddr_size();
    fprintf(fp, "DDR memory ranges:\n");
    fprintf(fp, "===================================================\n");
    int index = 1;
    for (auto it = ranges.begin(); it != ranges.end(); ++it) {
        DdrRange item = *it;
        std::ostringstream oss;
        oss << "[" << std::setw(2) << std::setfill('0') << index << "]"
            << "<" << std::left << std::hex  << std::setfill(' ') << std::setw(10) << item.address
            << "~" << std::right << std::hex  << std::setfill(' ') << std::setw(10) << (item.address + item.size) << "> "
            << ": " << std::left << csize(item.size);
        fprintf(fp, "%s \n",oss.str().c_str());
        total_size += item.size;
        index++;
    }
    fprintf(fp, "===================================================\n");
    fprintf(fp, "Total size:%s\n",csize(total_size).c_str());
}

void Dts::print_node(std::shared_ptr<device_node> node_ptr,int flag){
    fprintf(fp, "%s\n",node_ptr->node_path.c_str());
    if (flag & DTS_ADDR){
        fprintf(fp, "%#lx:%s{\n",node_ptr->addr, node_ptr->full_name.c_str());
    }else{
        fprintf(fp, "%s{\n",node_ptr->full_name.c_str());
    }
    bool is_symbol_node = false;
    if (node_ptr->full_name.find("symbols") != std::string::npos || node_ptr->full_name.find("aliases") != std::string::npos) {
        is_symbol_node = true;
    }
    if (node_ptr->props.size() > 0){
        print_properties(node_ptr->props,0,is_symbol_node,flag);
    }
    if (node_ptr->child != nullptr){
        fprintf(fp, "\n");
        print_node(node_ptr->child,1,flag);
    }
    fprintf(fp, "};\n\n");
}

void Dts::read_dtb(std::string& path){
    if (!csymbol_exists("initial_boot_params")){
       fprintf(fp, "initial_boot_params doesn't exist in this kernel!\n");
       return;
    }
    ulong initial_boot_params_addr = csymbol_value("initial_boot_params");
    if (!is_kvaddr(initial_boot_params_addr)) {
       fprintf(fp,"initial_boot_params address is invalid !\n");
       return;
    }
    ulong initial_boot_params = read_pointer(initial_boot_params_addr,"initial_boot_params");
    void* header = read_memory(initial_boot_params,20,"dtb header");
    if (!header) {
       fprintf(fp,"Failed to read dtb header at address %lx\n", initial_boot_params);
       return;
    }
    ulong magic = UINT(header);
    if (magic != 0xEDFE0DD0){
        fprintf(fp, "magic:%lx is not correct !\n",magic);
        FREEBUF(header);
        return;
    }
    ulong db_size = ULONG(header + 4);
    db_size=((db_size & 0xFF)<<24)|((db_size & 0xFF00)<<8)|((db_size & 0xFF0000)>>8)|((db_size & 0xFF000000)>>24);
    if(db_size > DTB_MAX_SIZE) {
        fprintf(fp, "too large dtb size %ld\n",db_size);
        FREEBUF(header);
        return;
    }
    // fprintf(fp, "magic:%x\n",magic);
    fprintf(fp, "dtb addr:%#lx, size:%ld\n",initial_boot_params,db_size);
    FREEBUF(header);
    FILE *file = fopen(path.c_str(), "wb");
    if (file == nullptr) {
        fprintf(fp, "Failed to open file");
        return;
    }
    void *dtb_buf = read_memory(initial_boot_params,db_size,"read dtb");
    fwrite(dtb_buf, db_size, 1, file);
    fprintf(fp, "save dtb to %s",path.c_str());
    fclose(file);
    FREEBUF(dtb_buf);
}

void Dts::print_node(std::shared_ptr<device_node> node_ptr,int level,int flag){
    if (flag & DTS_SHOW){
        for (int i = 0; i < level; i++) {
            fprintf(fp, "\t");
        }
        if (flag & DTS_ADDR){
            fprintf(fp, "%#lx:%s{\n",node_ptr->addr, node_ptr->full_name.c_str());
        }else{
            fprintf(fp, "%s{\n",node_ptr->full_name.c_str());
        }
    }
    bool is_symbol_node = false;
    if (node_ptr->full_name.find("symbols") != std::string::npos || node_ptr->full_name.find("aliases") != std::string::npos) {
        is_symbol_node = true;
    }
    if ((flag & DTS_SHOW) && node_ptr->props.size() > 0){
        print_properties(node_ptr->props,level,is_symbol_node,flag);
    }
    int sibl_level = level;
    int chil_level = level;
    if (node_ptr->child != nullptr){
        if (flag & DTS_SHOW){
            fprintf(fp, "\n");
        }
        chil_level += 1;
        print_node(node_ptr->child,chil_level,flag);
    }
    if (flag & DTS_SHOW){
        for (int i = 0; i < level; i++) {
            fprintf(fp, "\t");
        }
        fprintf(fp, "};\n\n");
    }
    if (node_ptr->sibling != nullptr){
        print_node(node_ptr->sibling,sibl_level,flag);
    }
}

void Dts::print_properties(std::vector<std::shared_ptr<Property>> props,int level,bool is_symbol,int flag){
    int prop_level = level + 1;
    for (auto it = props.begin(); it != props.end(); ++it) {
        std::shared_ptr<Property> ptr = *it;
        std::string prop_name = ptr->name;
        void* prop_val = ptr->value;
        ulong prop_addr = ptr->addr;
        int prop_length = ptr->length;
        for (int i = 0; i < prop_level; i++) {
            fprintf(fp, "\t");
        }
        if (prop_length == 0){
            if (flag & DTS_ADDR){
                fprintf(fp, "%#lx:%s;\n",prop_addr,prop_name.c_str());
            }else{
                fprintf(fp, "%s;\n",prop_name.c_str());
            }
        }else{
            if (is_symbol || is_str_prop(prop_name)){
                if (flag & DTS_ADDR){
                    fprintf(fp, "%#lx:%s=<%s>;\n",prop_addr,prop_name.c_str(),(char*)prop_val);
                }else{
                    fprintf(fp, "%s=<%s>;\n",prop_name.c_str(),(char*)prop_val);
                }
            }else if (is_int_prop(prop_name) || ((prop_length % 4) == 0)){
                if (flag & DTS_ADDR){
                    fprintf(fp, "%#lx:%s=<",prop_addr,prop_name.c_str());
                }else{
                    fprintf(fp, "%s=<",prop_name.c_str());
                }
                for (int i = 0; i < (prop_length / 4); ++i) {
                    int val = UINT(prop_val + i * sizeof(int));
                    if (i == (prop_length / 4)-1){
                        fprintf(fp, "%#x",ntohl(val));
                    }else{
                        fprintf(fp, "%#x ",ntohl(val));
                    }
                }
                fprintf(fp, ">;\n");
            }else{
                if (flag & DTS_ADDR){
                    fprintf(fp, "%#lx:%s=<%s>;\n",prop_addr,prop_name.c_str(),(char*)prop_val);
                }else{
                    fprintf(fp, "%s=<%s>;\n",prop_name.c_str(),(char*)prop_val);
                }
            }
        }
    }
}

#pragma GCC diagnostic pop
