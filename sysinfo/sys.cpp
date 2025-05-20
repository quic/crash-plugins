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

#include "sys.h"

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wpointer-arith"

#ifndef BUILD_TARGET_TOGETHER
DEFINE_PLUGIN_COMMAND(SysInfo)
#endif

void SysInfo::cmd_main(void) {
    int c;
    std::string cppString;
    if (argcnt < 2) cmd_usage(pc->curcmd, SYNOPSIS);
    while ((c = getopt(argcnt, args, "cs")) != EOF) {
        switch(c) {
            case 'c': //print command line
                print_command_line();
                break;
            case 's': //print soc info
                print_soc_info();
                break;
            default:
                argerrs++;
                break;
        }
    }
    if (argerrs)
        cmd_usage(pc->curcmd, SYNOPSIS);
}

SysInfo::SysInfo(){
    cmd_name = "env";
    help_str_list={
        "env",                            /* command name */
        "dump system information",        /* short description */
        "-c \n"
            "  This command dumps the config info.",
        "\n",
        "EXAMPLES",
        "  Display kernel command line:",
        "    %s> env -c",
        "    resume                         : /dev/mmcblk0p76",
        "    init                           : /init",
        "    kernel.panic_on_rcu_stall      : 1",
        "    console                        : ttyMSM0,115200n8",
        "    kasan.stacktrace               : off",
        "\n",
    };
    initialize();
}

void SysInfo::print_soc_info(){
    if (THIS_KERNEL_VERSION > LINUX(5,4,0)){
        print_soc_info5();
    }else{
        fprintf(fp,  "Not support for < kernel5.4 !\n");
    }
}

void SysInfo::print_soc_info5(){
    field_init(socinfo,fmt);
    field_init(socinfo,id);
    field_init(socinfo,ver);
    field_init(socinfo,raw_id);
    field_init(socinfo,hw_plat);
    field_init(socinfo,plat_ver);
    field_init(socinfo,pmic_model);
    field_init(socinfo,serial_num);
    field_init(socinfo,num_pmics);
    field_init(socinfo,chip_family);
    field_init(socinfo,nproduct_id);
    field_init(socinfo,chip_id);
    field_init(socinfo,nmodem_supported);
    struct_init(socinfo);
    if (!csymbol_exists("socinfo")){
        fprintf(fp,  "socinfo doesn't exist in this kernel!\n");
        return;
    }
    ulong soc_addr = read_pointer(csymbol_value("socinfo"),"socinfo");
    if (!is_kvaddr(soc_addr)) {
        fprintf(fp, "socinfo address is invalid!\n");
        return;
    }
    void *buf = read_struct(soc_addr,"socinfo");
    if (!buf) {
        return;
    }
    socinfo_format = UINT(buf + field_offset(socinfo,fmt));
    read_pmic_models();
    read_hw_platforms();
    read_soc_ids();
    uint32_t ver = UINT(buf + field_offset(socinfo,ver));
    uint32_t chip_ver_major = (ver & 0xFFFF0000) >> 16;
    uint32_t chip_ver_minor = (ver & 0x0000FFFF);
    std::string chip_id = read_cstring(soc_addr + field_offset(socinfo,chip_id),32,"chip_id");
    uint soc_id = UINT(buf + field_offset(socinfo,id));
    uint32_t pmic_id = UINT(buf + field_offset(socinfo,pmic_model));
    uint32_t hw_id = UINT(buf + field_offset(socinfo,hw_plat));
    std::string pmic_name = "";
    if (pmic_id < pmic_models.size()){
        pmic_name = pmic_models[pmic_id];
    }
    std::string hw_name = "";
    if (hw_id < hw_platforms.size()){
        hw_name = hw_platforms[hw_id];
    }
    std::ostringstream oss;
    oss << std::left << std::setw(12) << "Chip Version      : " << chip_ver_major << "." << chip_ver_minor << "\n"
        << std::left << std::setw(12) << "Chip Family       : " << UINT(buf + field_offset(socinfo,chip_family)) << "\n"
        << std::left << std::setw(12) << "Serial Number     : " << UINT(buf + field_offset(socinfo,serial_num)) << "\n"
        << std::left << std::setw(12) << "Soc ID            : " << soc_id << "\n"
        << std::left << std::setw(12) << "Soc Name          : " << soc_ids[soc_id] << "\n"
        << std::left << std::setw(12) << "HARDWARE          : " << hw_name  << "\n"
        << std::left << std::setw(12) << "PMIC              : " << pmic_name  << "\n";
    fprintf(fp, "%s \n",oss.str().c_str());
    FREEBUF(buf);
}

void SysInfo::read_pmic_models(){
    size_t len = get_array_length(TO_CONST_STRING("pmic_models"), NULL, 0);
    for (size_t i = 0; i < len; i++){
        ulong name_addr = read_pointer(csymbol_value("pmic_models") + i * sizeof(void*),"addr");
        if (!is_kvaddr(name_addr)) {
            continue;
        }
        std::string name = read_cstring(name_addr,64,"name");
        pmic_models.push_back(name);
    }
}

void SysInfo::read_hw_platforms(){
    size_t len = get_array_length(TO_CONST_STRING("hw_platform"), NULL, 0);
    for (size_t i = 0; i < len; i++){
        ulong name_addr = read_pointer(csymbol_value("hw_platform") + i * sizeof(void*),"addr");
        if (!is_kvaddr(name_addr)) {
            hw_platforms.push_back("");
            continue;
        }
        std::string name = read_cstring(name_addr,64,"name");
        hw_platforms.push_back(name);
    }
}

void SysInfo::read_soc_ids(){
    field_init(soc_id,id);
    field_init(soc_id,name);
    struct_init(soc_id);
    size_t len = get_array_length(TO_CONST_STRING("soc_id"), NULL, 0);
    for (size_t i = 0; i < len; i++){
        ulong addr = csymbol_value("soc_id") + i * struct_size(soc_id);
        uint id = read_uint(addr + field_offset(soc_id,id),"id");
        ulong name_addr = read_pointer(addr + field_offset(soc_id,name),"name addr");
        if (!is_kvaddr(name_addr)) {
            continue;
        }
        std::string name = read_cstring(name_addr,64,"name");
        soc_ids[id] = name;
    }
}

void SysInfo::print_command_line(){
    if (!csymbol_exists("saved_command_line")){
        fprintf(fp,  "saved_command_line doesn't exist in this kernel!\n");
        return;
    }
    ulong cmd_addr = read_pointer(csymbol_value("saved_command_line"),"saved_command_line");
    if (!is_kvaddr(cmd_addr)) {
        fprintf(fp, "saved_command_line address is invalid!\n");
        return;
    }
    std::string cmd_line = read_cstring(cmd_addr,2048,"saved_command_line");
    size_t pos = 0;
    while ((pos = cmd_line.find('\0')) != std::string::npos) {
        cmd_line.replace(pos, 1, " ");
    }
    // fprintf(fp, "%s \n\n",cmd_line.c_str());
    std::unordered_map<std::string, std::string> kconfigs;
    std::istringstream cmdarg(cmd_line);
    std::string config;
    std::string mapKey;
    size_t max_len = 0;
    while (cmdarg >> config) {
        size_t pos = config.find('=');
        if (pos != std::string::npos) {
            mapKey = config.substr(0, pos);
            max_len = std::max(max_len,mapKey.size());
            kconfigs[mapKey] = config.substr(pos + 1);
        } else {
            mapKey = config;
            max_len = std::max(max_len,mapKey.size());
            kconfigs[mapKey] = "";
        }
    }
    for (const auto& pair : kconfigs) {
        std::ostringstream oss;
        oss << std::left << std::setw(max_len + 1) << pair.first
            << ": " << pair.second;
        fprintf(fp, "%s \n",oss.str().c_str());
    }
}

#pragma GCC diagnostic pop
