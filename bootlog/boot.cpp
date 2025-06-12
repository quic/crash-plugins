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

#include "boot.h"

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wpointer-arith"

#ifndef BUILD_TARGET_TOGETHER
DEFINE_PLUGIN_COMMAND(BootInfo)
#endif

void BootInfo::cmd_main(void) {
    int c;
    std::string cppString;
    if (argcnt < 2) cmd_usage(pc->curcmd, SYNOPSIS);
    while ((c = getopt(argcnt, args, "pb")) != EOF) {
        switch(c) {
            case 'p':
                print_pmic_info();
                break;
            default:
                argerrs++;
                break;
        }
    }
    if (argerrs)
        cmd_usage(pc->curcmd, SYNOPSIS);
}

BootInfo::BootInfo(){
    field_init(kobject,name);
    field_init(device,kobj);
    field_init(device,driver_data);
    cmd_name = "boot";
    help_str_list={
        "boot",                          /* command name */
        "dump pmic and boot log",        /* short description */
        "-p \n"
            "  boot -b\n"
            "  This command dumps the boot info.",
        "\n",
        "EXAMPLES",
        "  Display pmic log:",
        "    %s> boot -p",
        "    Reset Trigger: PS_HOLD",
        "    Reset Type: WARM_RESET",
        "    Waiting on PS_HOLD",
        "    Warm Reset Count: 2",
        "    Waiting on PS_HOLD",
        "    Warm Reset Count: 2",
        "    PON Successful",
        "\n",
    };
    initialize();
}

void BootInfo::read_pmic_pon_trigger_maps(){
    field_init(pmic_pon_trigger_mapping,code);
    field_init(pmic_pon_trigger_mapping,label);
    struct_init(pmic_pon_trigger_mapping);
    size_t len = get_array_length(TO_CONST_STRING("pmic_pon_pon_trigger_map"), NULL, 0);
    for (size_t i = 0; i < len; i++){
        ulong addr = csymbol_value("pmic_pon_pon_trigger_map") + i * struct_size(pmic_pon_trigger_mapping);
        uint id = read_ushort(addr + field_offset(pmic_pon_trigger_mapping,code),"code");
        ulong name_addr = read_pointer(addr + field_offset(pmic_pon_trigger_mapping,label),"label addr");
        if (!is_kvaddr(name_addr)) {
            continue;
        }
        std::string name = read_cstring(name_addr,64,"name");
        pmic_pon_trigger_map[id] = name;
        // fprintf(fp, fp, "%d : %s \n",id,name.c_str());
    }

    len = get_array_length(TO_CONST_STRING("pmic_pon_reset_trigger_map"), NULL, 0);
    for (size_t i = 0; i < len; i++){
        ulong addr = csymbol_value("pmic_pon_reset_trigger_map") + i * struct_size(pmic_pon_trigger_mapping);
        uint id = read_ushort(addr + field_offset(pmic_pon_trigger_mapping,code),"code");
        ulong name_addr = read_pointer(addr + field_offset(pmic_pon_trigger_mapping,label),"label addr");
        if (!is_kvaddr(name_addr)) {
            continue;
        }
        std::string name = read_cstring(name_addr,64,"name");
        pmic_pon_reset_trigger_map[id] = name;
        // fprintf(fp, "%d : %s \n",id,name.c_str());
    }

    len = get_array_length(TO_CONST_STRING("pmic_pon_fault_reason1"), NULL, 0);
    for (size_t i = 0; i < len; i++){
        ulong addr = read_pointer(csymbol_value("pmic_pon_fault_reason1") + i * sizeof(void *),"fault_reason1");
        if (!is_kvaddr(addr)) {
            pmic_pon_fault_reason1.push_back("");
            continue;
        }
        std::string name = read_cstring(addr,64,"name");
        // fprintf(fp, "%s \n",name.c_str());
        pmic_pon_fault_reason1.push_back(name);
    }

    len = get_array_length(TO_CONST_STRING("pmic_pon_fault_reason2"), NULL, 0);
    for (size_t i = 0; i < len; i++){
        ulong addr = read_pointer(csymbol_value("pmic_pon_fault_reason2") + i * sizeof(void *),"fault_reason2");
        if (!is_kvaddr(addr)) {
            pmic_pon_fault_reason2.push_back("");
            continue;
        }
        std::string name = read_cstring(addr,64,"name");
        // fprintf(fp, "%s \n",name.c_str());
        pmic_pon_fault_reason2.push_back(name);
    }

    len = get_array_length(TO_CONST_STRING("pmic_pon_fault_reason3"), NULL, 0);
    for (size_t i = 0; i < len; i++){
        ulong addr = read_pointer(csymbol_value("pmic_pon_fault_reason3") + i * sizeof(void *),"fault_reason3");
        if (!is_kvaddr(addr)) {
            pmic_pon_fault_reason3.push_back("");
            continue;
        }
        std::string name = read_cstring(addr,64,"name");
        // fprintf(fp, "%s \n",name.c_str());
        pmic_pon_fault_reason3.push_back(name);
    }

    len = get_array_length(TO_CONST_STRING("pmic_pon_s3_reset_reason"), NULL, 0);
    for (size_t i = 0; i < len; i++){
        ulong addr = read_pointer(csymbol_value("pmic_pon_s3_reset_reason") + i * sizeof(void *),"s3_reset");
        if (!is_kvaddr(addr)) {
            pmic_pon_s3_reset_reason.push_back("");
            continue;
        }
        std::string name = read_cstring(addr,64,"name");
        // fprintf(fp, "%s \n",name.c_str());
        pmic_pon_s3_reset_reason.push_back(name);
    }

    len = get_array_length(TO_CONST_STRING("pmic_pon_pon_pbl_status"), NULL, 0);
    for (size_t i = 0; i < len; i++){
        ulong addr = read_pointer(csymbol_value("pmic_pon_pon_pbl_status") + i * sizeof(void *),"pon_pbl");
        if (!is_kvaddr(addr)) {
            pmic_pon_pon_pbl_status.push_back("");
            continue;
        }
        std::string name = read_cstring(addr,64,"name");
        // fprintf(fp, "%s \n",name.c_str());
        pmic_pon_pon_pbl_status.push_back(name);
    }

    len = get_array_length(TO_CONST_STRING("pmic_pon_reset_type_label"), NULL, 0);
    for (size_t i = 0; i < len; i++){
        ulong addr = read_pointer(csymbol_value("pmic_pon_reset_type_label") + i * sizeof(void *),"label");
        if (!is_kvaddr(addr)) {
            pmic_pon_reset_type_label.push_back("");
            continue;
        }
        std::string name = read_cstring(addr,64,"name");
        pmic_pon_reset_type_label.push_back(name);
    }
}

void BootInfo::pmic_pon_log_print_reason(uint8_t data, std::vector<std::string> reasons){
    if (data == 0) {
        fprintf(fp, "None \n");
    }else{
        bool first = true;
        for (int i = 0; i < 8; i++) {
            if (data & (1U << i)) {
                fprintf(fp, "%s%s \n",(first ? "" : ", "), reasons[i].c_str());
                first = false;
            }
        }
    }
}

void BootInfo::parser_pmic_pon_log_dev(ulong addr){
    bool is_important;
    field_init(pmic_pon_log_dev,log);
    field_init(pmic_pon_log_dev,log_len);
    struct_init(pmic_pon_log_dev);
    if(field_offset(pmic_pon_log_dev,log) == -1 || struct_size(pmic_pon_log_dev) == -1){
        fprintf(fp, "pls load pmic_pon_log.ko at first !\n");
        return;
    }
    read_pmic_pon_trigger_maps();
    ulong entry_addr = read_pointer(addr + field_offset(pmic_pon_log_dev,log),"log_entry");
    size_t log_len = read_int(addr + field_offset(pmic_pon_log_dev,log_len),"log_len");
    for (size_t i = 0; i < log_len; i++){
        struct pmic_event_t entry;
        ulong addr = entry_addr + i * sizeof(pmic_event_t);
        if(read_struct(addr,&entry,sizeof(entry),"pmic_event_t")){
            uint16_t data = (entry.data1 << 8) | entry.data0;
            switch (entry.event) {
                case PMIC_PON_EVENT_PON_TRIGGER_RECEIVED:
                    if (pmic_pon_trigger_map.find(data) != pmic_pon_trigger_map.end()) {
                        fprintf(fp, "%s \n",pmic_pon_trigger_map[data].c_str());
                    }else{
                        fprintf(fp, "SID=0x%X, PID=0x%02X, IRQ=0x%X \n",entry.data1 >> 4, (data >> 4) & 0xFF,
                        entry.data0 & 0x7);
                    }
                    break;
                case PMIC_PON_EVENT_OTP_COPY_COMPLETE:
                    fprintf(fp, "OTP Copy Complete: last addr written=0x%04X \n", data);
                    break;
                case PMIC_PON_EVENT_TRIM_COMPLETE:
                    fprintf(fp, "Trim Complete: %u bytes written \n", data);
                    break;
                case PMIC_PON_EVENT_XVLO_CHECK_COMPLETE:
                    fprintf(fp, "XVLO Check Complete \n");
                    break;
                case PMIC_PON_EVENT_PMIC_CHECK_COMPLETE:
                    fprintf(fp, "PMICs Detected: SID Mask=0x%04X \n", data);
                    break;
                case PMIC_PON_EVENT_RESET_TRIGGER_RECEIVED:
                    if (pmic_pon_reset_trigger_map.find(data) != pmic_pon_reset_trigger_map.end()) {
                        fprintf(fp, "Reset Trigger: %s \n",pmic_pon_reset_trigger_map[data].c_str());
                    }else{
                        fprintf(fp, "SID=0x%X, PID=0x%02X, IRQ=0x%X \n",entry.data1 >> 4, (data >> 4) & 0xFF,
                        entry.data0 & 0x7);
                    }
                    break;
                case PMIC_PON_EVENT_RESET_TYPE:
                    if (entry.data0 < pmic_pon_reset_type_label.size() && !pmic_pon_reset_type_label[entry.data0].empty()){
                        fprintf(fp, "Reset Type: %s \n",pmic_pon_reset_type_label[entry.data0].c_str());
                    }else{
                        fprintf(fp, "Reset Type: UNKNOWN (%u) \n",entry.data0);
                    }
                    break;
                case PMIC_PON_EVENT_WARM_RESET_COUNT:
                    fprintf(fp, "Warm Reset Count: %u \n",data);
                    break;
                case PMIC_PON_EVENT_FAULT_REASON_1_2:
                    if (!entry.data0 && !entry.data1){
                        is_important = false;
                    }
                    if (entry.data0 || !is_important) {
                        fprintf(fp, "FAULT_REASON1=");
                        pmic_pon_log_print_reason(entry.data0,pmic_pon_fault_reason1);
                    }
                    if (entry.data1 || !is_important) {
                        fprintf(fp, "%sFAULT_REASON2=",(entry.data0 || !is_important) ? "; " : "");
                        pmic_pon_log_print_reason(entry.data1,pmic_pon_fault_reason2);
                    }
                    break;
                case PMIC_PON_EVENT_FAULT_REASON_3:
                    if (!entry.data0){
                        is_important = false;
                    }
                    fprintf(fp, "FAULT_REASON3=");
                    pmic_pon_log_print_reason(entry.data0,pmic_pon_fault_reason3);
                    break;
                case PMIC_PON_EVENT_PBS_PC_DURING_FAULT:
                    fprintf(fp, "PBS PC at Fault: 0x%04X \n", data);
                    break;
                case PMIC_PON_EVENT_FUNDAMENTAL_RESET:
                    if (!entry.data0 && !entry.data1){
                        is_important = false;
                    }
                    fprintf(fp, "Fundamental Reset: ");
                    if (entry.data1 || !is_important) {
                        fprintf(fp, "PON_PBL_STATUS=");
                        pmic_pon_log_print_reason(entry.data1,pmic_pon_pon_pbl_status);
                    }
                    if (entry.data0 || !is_important) {
                        fprintf(fp, "%sS3_RESET_REASON=",(entry.data1 || !is_important) ? "; " : "");
                        pmic_pon_log_print_reason(entry.data0,pmic_pon_s3_reset_reason);
                    }
                    break;
                case PMIC_PON_EVENT_PON_SEQ_START:
                    fprintf(fp, "Begin PON Sequence \n");
                    break;
                case PMIC_PON_EVENT_PON_SUCCESS:
                    fprintf(fp, "PON Successful \n");
                    break;
                case PMIC_PON_EVENT_WAITING_ON_PSHOLD:
                    fprintf(fp, "Waiting on PS_HOLD \n");
                    break;
                case PMIC_PON_EVENT_PMIC_SID1_FAULT ... PMIC_PON_EVENT_PMIC_SID13_FAULT:
                    if (!entry.data0 && !entry.data1){
                        is_important = false;
                    }
                    fprintf(fp, "PMIC SID%u ", entry.event - PMIC_PON_EVENT_PMIC_SID1_FAULT + 1);
                    if (entry.data0 || !is_important) {
                        fprintf(fp, "FAULT_REASON1=");
                        pmic_pon_log_print_reason(entry.data0,pmic_pon_fault_reason1);
                    }
                    if (entry.data1 || !is_important) {
                        fprintf(fp, "%sFAULT_REASON2=",(entry.data0 || !is_important) ? "; " : "");
                        pmic_pon_log_print_reason(entry.data1,pmic_pon_fault_reason2);
                    }
                    break;
                case PMIC_PON_EVENT_PMIC_VREG_READY_CHECK:
                    if (!data){
                        is_important = false;
                    }
                    fprintf(fp, "VREG Check: %sVREG_FAULT detected \n", data ? "" : "No ");
                    break;
                default:
                    fprintf(fp, "Unknown Event (0x%02X): data=0x%04X \n",entry.event, data);
                    break;
            }
        }
    }
}

void BootInfo::print_pmic_info(){
    ulong device_addr = 0;
    for (const auto& dev_addr : for_each_device_for_bus("platform")) {
        std::string device_name;
        size_t name_addr = read_pointer(dev_addr + field_offset(device,kobj) + field_offset(kobject,name),"device name addr");
        if (is_kvaddr(name_addr)){
            device_name = read_cstring(name_addr,100, "device name");
        }
        if (device_name.empty() || device_name.find("pmic-pon-log") == std::string::npos){
            continue;
        }
        ulong addr = read_pointer(dev_addr + field_offset(device,driver_data) ,"driver_data");
        if (!is_kvaddr(addr)){
            continue;
        }
        device_addr = addr;
    }
    if(is_kvaddr(device_addr)){
        parser_pmic_pon_log_dev(device_addr);
    }else{
        fprintf(fp, "No device found ! \n");
    }
}
#pragma GCC diagnostic pop
