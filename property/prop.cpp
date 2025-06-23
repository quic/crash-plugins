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

#include "prop.h"

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wpointer-arith"

#ifndef BUILD_TARGET_TOGETHER
DEFINE_PLUGIN_COMMAND(Prop)
#endif

void Prop::cmd_main(void) {
    int c;
    std::string cppString;
    if (argcnt < 2) cmd_usage(pc->curcmd, SYNOPSIS);
    while ((c = getopt(argcnt, args, "s:ap:")) != EOF) {
        switch(c) {
            case 's':
            {
                try {
                    cppString.assign(optarg);
                    if (cppString.empty()){
                        fprintf(fp, "invaild symbol path: %s\n",optarg);
                        return;
                    }
                    for (auto& symbol : symbol_list) {
                        std::string symbol_path = cppString;
                        if (load_symbols(symbol_path, symbol.name)){
                            symbol.path = symbol_path;
                            // fprintf(fp, "%s : %s\n",symbol.name.c_str(),symbol.path.c_str());
                        }
                    }
                } catch (...) {
                    fprintf(fp, "invaild arg %s\n",optarg);
                }
            }
            break;
            case 'a':
            {
                if (prop_map.size() == 0){
                    parser_propertys();
                    parser_prop_by_init();
                    if(task_ptr != nullptr){
                        task_ptr.reset();
                    }
                }
                print_propertys();
            }
            break;
            case 'p':
            {
                try {
                    cppString.assign(optarg);
                    if (cppString.empty()){
                        fprintf(fp, "invaild prop name: %s\n",optarg);
                        return;
                    }
                    fprintf(fp, "%s \n",get_prop(cppString).c_str());
                } catch (...) {
                    fprintf(fp, "invaild arg %s\n",optarg);
                }
            }
            break;
            default:
                argerrs++;
                break;
        }
    }
    if (argerrs)
        cmd_usage(pc->curcmd, SYNOPSIS);
}

Prop::Prop(std::shared_ptr<Swapinfo> swap) : PropInfo(swap){
    init_command();
}

Prop::Prop() : PropInfo(std::make_shared<Swapinfo>()) {
    init_command();
}

void Prop::init_command(){
    cmd_name = "getprop";
    help_str_list={
        "getprop",                            /* command name */
        "dump android property information",        /* short description */
        "-s <symbol directory path>\n"
            "  getprop -a\n"
            "  getprop -p <prop name>\n"
            "  This command dumps the property info.",
        "\n",
        "EXAMPLES",
        "  Load symbol for property:",
        "    %s> getprop -s <libc.so symbol path>",
        "    crash> getprop -s xx/symbols",
        "    add symbol table from file xx/symbols/libc.so",
        "    Reading symbols from xx/symbols/libc.so...",
        "    Add symbol:xx/symbols/libc.so succ",
        "\n",
        "  Display all propertys:",
        "    %s> getprop -a",
        "    [0001]wifi.aware.interface                                                   wifi-aware0",
        "    [0002]ro.crypto.state                                                        encrypted",
        "    [0003]ro.crypto.type                                                         file",
        "\n",
        "  Display specified property's value:",
        "    %s> getprop -p ro.crypto.state",
        "    encrypted",
        "\n",
    };
    initialize();
}

void Prop::print_propertys(){
    size_t max_len = 0;
    for (const auto& pair : prop_map) {
        max_len = std::max(max_len,pair.first.size());
    }
    size_t index = 1;
    for (const auto& pair : prop_map) {
        std::ostringstream oss;
        oss << "[" << std::setw(4) << std::setfill('0') << index << "]"
            << std::left << std::setw(max_len) << std::setfill(' ') << pair.first << " "
            << std::left << pair.second;
        fprintf(fp, "%s \n",oss.str().c_str());
        index++;
    }
}
#pragma GCC diagnostic pop
