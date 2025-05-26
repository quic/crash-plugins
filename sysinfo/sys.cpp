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
            "  env -s \n"
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
        "  Display soc info:",
        "    %s> env -s",
        "\n",
    };
    initialize();
}

void SysInfo::print_socinfo(){
    field_init(socinfo,id);
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
    field_init(socinfo,num_subset_parts);
    field_init(socinfo,nsubset_parts_array_offset);
    struct_init(socinfo);
    ulong soc_addr = read_pointer(csymbol_value("socinfo"),"socinfo");
    if (!is_kvaddr(soc_addr)) {
        fprintf(fp, "socinfo address is invalid!\n");
        return;
    }
    void *buf = read_struct(soc_addr,"socinfo");
    uint soc_id = UINT(buf + field_offset(socinfo,id));
    std::string chip_id = read_cstring(soc_addr + field_offset(socinfo,chip_id),32,"chip_id");
    uint32_t hw_id = UINT(buf + field_offset(socinfo,hw_plat));
    std::string hw_name = "";
    if (hw_id < hw_platforms.size()){
        hw_name = hw_platforms[hw_id];
    }
    uint32_t num_parts = UINT(buf + field_offset(socinfo,num_subset_parts));
    uint32_t offset = UINT(buf + field_offset(socinfo,nsubset_parts_array_offset));
    ulong part_addr = soc_addr + offset;
    std::vector<std::string> subset_parts = get_enumerator_list("subset_part_type");
    std::unordered_map<uint32_t, std::string> parts_map;
    for (const auto& part : subset_parts){
        parts_map[read_enum_val(part)] = part;
    }
    std::ostringstream oss;
    oss << std::left << std::setw(20) << "Chip"             << ": " << chip_id << "\n"
        << std::left << std::setw(20) << "Machine"          << ": " << soc_ids[soc_id] << "\n"
        << std::left << std::setw(20) << "Soc ID"           << ": " << soc_id << "\n"
        << std::left << std::setw(20) << "Serial Number"    << ": " << UINT(buf + field_offset(socinfo,serial_num)) << "\n"
        << std::left << std::setw(20) << "HARDWARE"         << ": " << hw_name  << "\n"
        << std::left << std::setw(20) << "Product ID"       << ": " << UINT(buf + field_offset(socinfo,nproduct_id))  << "\n";
    if (num_parts > subset_parts.size()){
        num_parts = subset_parts.size() - 1;
    }
    if (num_parts > 0){
        for (uint32_t i = 1; i < num_parts; i++){
            ulong addr =  part_addr + i * sizeof(uint32_t);
            uint32_t part_entry = read_uint(addr,"part");
            if (part_entry & 1){
                oss << std::left << std::setw(20) << parts_map[i] << ": "  << "Enable" << "\n";
            }else{
                oss << std::left << std::setw(20) << parts_map[i] << ": "  << "Disable" << "\n";
            }
        }
    }
    fprintf(fp, "%s \n",oss.str().c_str());
    FREEBUF(buf);
}

void SysInfo::print_qsocinfo(){
    field_init(device,kobj);
    field_init(kobject,name);
    field_init(device,driver_data);
    field_init(qcom_socinfo,attr);
    field_init(qcom_socinfo,info);

    field_init(soc_device_attribute,machine);
    field_init(soc_device_attribute,family);
    field_init(soc_device_attribute,revision);
    field_init(soc_device_attribute,serial_number);
    field_init(soc_device_attribute,soc_id);

    field_init(socinfo_params,raw_device_family);
    field_init(socinfo_params,hw_plat_subtype);
    field_init(socinfo_params,raw_ver);
    field_init(socinfo_params,hw_plat);
    field_init(socinfo_params,fmt);
    field_init(socinfo_params,nproduct_id);
    struct_init(socinfo_params);
    for (const auto& dev_addr : for_each_device_for_bus("platform")) {
        std::string device_name;
        size_t name_addr = read_pointer(dev_addr + field_offset(device,kobj) + field_offset(kobject,name),"device name addr");
        if (is_kvaddr(name_addr)){
            device_name = read_cstring(name_addr,100, "device name");
        }
        if (device_name.empty() || device_name != "qcom-socinfo"){
            continue;
        }
        ulong socinfo_addr = read_pointer(dev_addr + field_offset(device,driver_data) ,"driver_data");
        if (!is_kvaddr(socinfo_addr)){
            continue;
        }
        fprintf(fp, "addr: %#lx \n",socinfo_addr);
        ulong attr_addr = socinfo_addr + field_offset(qcom_socinfo,attr);
        std::string machine;
        name_addr = read_pointer(attr_addr + field_offset(soc_device_attribute,machine),"machine addr");
        if (is_kvaddr(name_addr)){
            machine = read_cstring(name_addr,100, "machine");
        }
        std::string family;
        name_addr = read_pointer(attr_addr + field_offset(soc_device_attribute,family),"family addr");
        if (is_kvaddr(name_addr)){
            family = read_cstring(name_addr,100, "family");
        }
        std::string serial_number;
        name_addr = read_pointer(attr_addr + field_offset(soc_device_attribute,serial_number),"serial_number addr");
        if (is_kvaddr(name_addr)){
            serial_number = read_cstring(name_addr,100, "serial_number");
        }
        std::string soc_id;
        name_addr = read_pointer(attr_addr + field_offset(soc_device_attribute,soc_id),"soc_id addr");
        if (is_kvaddr(name_addr)){
            soc_id = read_cstring(name_addr,100, "soc_id");
        }
        ulong param_addr = socinfo_addr + field_offset(qcom_socinfo,info);
        void *param_buf = read_struct(param_addr,"socinfo_params");
        uint32_t hw_id = UINT(param_buf + field_offset(socinfo_params,hw_plat));
        std::string hw_name = "";
        if (hw_id < hw_platforms.size()){
            hw_name = hw_platforms[hw_id];
        }
        std::ostringstream oss;
        oss << std::left << std::setw(12) << "Chip Family       : " << family << "\n"
            << std::left << std::setw(12) << "Machine           : " << machine << "\n"
            << std::left << std::setw(12) << "Soc ID            : " << soc_id << "\n"
            << std::left << std::setw(12) << "Serial Number     : " << serial_number << "\n"
            << std::left << std::setw(12) << "HARDWARE          : " << hw_name  << "\n"
            << std::left << std::setw(12) << "Product ID        : " << UINT(param_buf + field_offset(socinfo_params,nproduct_id))  << "\n";
        fprintf(fp, "%s \n",oss.str().c_str());
        FREEBUF(param_buf);
    }
}

void SysInfo::print_soc_info(){
    if (THIS_KERNEL_VERSION <= LINUX(5,4,0)){
        fprintf(fp,  "Not support for < kernel5.4 !\n");
        return;
    }
    // read_pmic_models();
    read_hw_platforms();
    read_soc_ids();
    if (!csymbol_exists("socinfo")){
        print_qsocinfo();
    }else{
        print_socinfo();
    }
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
