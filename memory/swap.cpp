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

#include "swap.h"

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wpointer-arith"

#ifndef BUILD_TARGET_TOGETHER
DEFINE_PLUGIN_COMMAND(Swap)
#endif

void Swap::cmd_main(void) {
    int c;
    std::string cppString;
    if (argcnt < 2) cmd_usage(pc->curcmd, SYNOPSIS);
    while ((c = getopt(argcnt, args, "ap:d")) != EOF) {
        switch(c) {
            case 'a':
                print_swaps();
                break;
            case 'p':
                cppString.assign(optarg);
                print_page_memory(cppString);
                break;
            default:
                argerrs++;
                break;
        }
    }
    if (argerrs)
        cmd_usage(pc->curcmd, SYNOPSIS);
}

Swap::Swap(std::shared_ptr<Zraminfo> zram) : Swapinfo(zram){}

Swap::Swap() : Swapinfo(std::make_shared<Zraminfo>()) {}

void Swap::init_offset(void) {}

void Swap::init_command(void){
    cmd_name = "swapinfo";
    help_str_list={
        "swapinfo",                            /* command name */
        "dump swap information",        /* short description */
        "-a \n"
            "  swapinfo -p <vaddr>\n"
            "  swapinfo -d\n"
            "  This command dumps the swap info.",
        "\n",
        "EXAMPLES",
        "  Display swap info:",
        "    %s> swapinfo -a",
        "       swap_info_struct   size       used       address_space      file",
        "       ========================================================================",
        "       ffffff804d3d1800   1.50Gb     292.25Mb   ffffff8026a40000   /dev/block/zram0",
        "       ========================================================================",
        "\n",
        "  Display a page data with specified virt address:",
        "    %s> swapinfo -p 12c000e0",
        "       12c00000: 153F 7F98 0000 0000 7051 4C80 0000 0000 .?......pQL.....",
        "       12c00010: 0000 0000 0000 0000 0000 0000 12C0 0020 ...............",
        "       12c00020: 7098 2630 0000 0000 706C 18B8 0000 0000 p.&0....pl......",
        "       12c00030: 0000 0000 706C 3798 0000 0000 12C0 0020 ....pl7........",
        "       12c00040: 13B5 2680 12D4 01D8 0000 0000 0000 0000 ..&.............",
        "\n",
        "  Enable debug log:",
        "    %s> swapinfo -d",
        "\n",
    };
}

void Swap::print_page_memory(std::string addr){
    struct task_context *tc = CURRENT_CONTEXT();
    if (!tc){
        fprintf(fp, "please set current task context by command set <pid>\n");
        return;
    }
    ulong uaddr = std::stoul(addr, nullptr, 16);
    std::vector<char> page_data = uread_memory(tc->task,uaddr, page_size, "read page");
    if(page_data.size() == 0){
        fprintf(fp, "not mapped page\n");
        return;
    }else{
        fprintf(fp, "\nprint_page_memory:\n%s \n", hexdump(uaddr, page_data.data(), page_size).c_str());
    }
}

void Swap::print_swaps(){
    nr_swap = read_int(csymbol_value("nr_swapfiles"),"nr_swapfiles");
    if (swap_list.size() == 0 && nr_swap > 0){
        parser_swap_info();
    }
    std::ostringstream oss;
    fprintf(fp, "========================================================================\n");
    oss << std::left << std::setw(VADDR_PRLEN + 2) << "swap_info_struct" << " "
        << std::left << std::setw(10) << "size" << " "
        << std::left << std::setw(10) << "used" << " "
        << std::left << std::setw(VADDR_PRLEN + 2) << "address_space" << " "
        << "file" << "\n";

    for (const auto& swap_ptr : swap_list) {
        oss << std::left << std::setw(VADDR_PRLEN + 2) << std::hex << swap_ptr->addr << " "
            << std::left << std::setw(10) << csize(swap_ptr->pages * page_size) << " "
            << std::left << std::setw(10) << csize(swap_ptr->inuse_pages * page_size) << " "
            << std::left << std::setw(VADDR_PRLEN + 2) << std::hex << swap_ptr->swap_space << " "
            << swap_ptr->swap_file;
    }
    fprintf(fp, "%s \n", oss.str().c_str());
    fprintf(fp, "========================================================================\n");
}
#pragma GCC diagnostic pop
