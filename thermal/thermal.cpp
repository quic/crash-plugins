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

#include "thermal.h"

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wpointer-arith"

#ifndef BUILD_TARGET_TOGETHER
DEFINE_PLUGIN_COMMAND(Thermal)
#endif

void Thermal::cmd_main(void) {
    int c;
    std::string cppString;
    if (argcnt < 2) cmd_usage(pc->curcmd, SYNOPSIS);
    if (zone_list.size() == 0){
        parser_thrermal_zone();
    }
    while ((c = getopt(argcnt, args, "dD:")) != EOF) {
        switch(c) {
            case 'd':
                print_zone_device();
                break;
            case 'D':
                cppString.assign(optarg);
                print_zone_device(cppString);
                break;
            default:
                argerrs++;
                break;
        }
    }
    if (argerrs)
        cmd_usage(pc->curcmd, SYNOPSIS);
}

Thermal::Thermal(){
    field_init(thermal_zone_device, node);
    field_init(thermal_zone_device, id);
    field_init(thermal_zone_device, type);
    field_init(thermal_zone_device, temperature);
    field_init(thermal_zone_device, last_temperature);
    field_init(thermal_zone_device, num_trips);
    field_init(thermal_zone_device, trips);
    field_init(thermal_zone_device, devdata);
    field_init(thermal_zone_device, thermal_instances);
    field_init(thermal_zone_device, governor);
    struct_init(thermal_zone_device);
    field_init(__thermal_zone, ntrips);
    field_init(__thermal_zone, trips);
    struct_init(__thermal_zone);
    field_init(thermal_trip, temperature);
    struct_init(thermal_trip);
    field_init(thermal_instance, tz_node);
    field_init(thermal_instance, cdev_node);
    field_init(thermal_instance, trip);
    field_init(thermal_instance, cdev);
    field_init(thermal_governor, name);
    struct_init(thermal_instance);
    field_init(thermal_cooling_device, id);
    field_init(thermal_cooling_device, type);
    cmd_name = "tm";
    help_str_list={
        "tm",                            /* command name */
        "dump thermal information",        /* short description */
        "-d \n"
            "  tm -D <thermal zone name>\n"
            "  This command dumps the thermal info.",
        "\n",
        "EXAMPLES",
        "  Display all thermal zone info:",
        "    %s> tm -d",
        "    11    e9ae1c00   gpu-step           step_wise    38700      33600",
        "    12    e9ae1000   cpuss-0-step       step_wise    34300      34600",
        "    13    e9ae4c00   cpuss-1-step       step_wise    34600      35300",
        "\n",
        "  Display the temperature gear and cooling action of specified thermal zone:",
        "    %s> tm -D cpuss-0-step",
        "    cpuss-0-step:",
        "        temperature:100000",
        "            [4]thermal_cooling_device:0xe574c000 --> cpu-isolate0",
        "            [6]thermal_cooling_device:0xe574a800 --> cpu-isolate2",
        "\n",
    };
    initialize();
}

void Thermal::print_zone_device(std::string dev_name){
    for (auto& zone_ptr : zone_list) {
        if (zone_ptr->name == dev_name){
            fprintf(fp, "%s: \n",zone_ptr->name.c_str());
            for (auto& trip_ptr : zone_ptr->trip_list) {
                fprintf(fp, "   temperature:%d \n",trip_ptr->temp);
                for (auto& cdev_ptr : trip_ptr->cool_list) {
                    fprintf(fp, "      [%d]thermal_cooling_device:%#lx --> %s \n",cdev_ptr->id,cdev_ptr->addr,cdev_ptr->name.c_str());
                }
            }
        }
    }
}

void Thermal::print_zone_device(){
    size_t name_max_len = 10;
    size_t governor_name_max_len = 10;
    for (auto& zone_ptr : zone_list) {
        name_max_len = std::max(name_max_len,zone_ptr->name.size());
        governor_name_max_len = std::max(governor_name_max_len,zone_ptr->governor.size());
    }
    std::ostringstream oss_hd;
    oss_hd << std::left << std::setw(5) << "ID" << " "
        << std::left << std::setw(VADDR_PRLEN + 2) << "ADDR" << " "
        << std::left << std::setw(name_max_len) << "Name" << " "
        << std::left << std::setw(governor_name_max_len + 2) << "governor" << " "
        << std::left << std::setw(10) << "cur_temp" << " "
        << std::left << std::setw(10) << "last_temp" << " ";
    fprintf(fp, "%s \n",oss_hd.str().c_str());
    for (auto& zone_ptr : zone_list) {
        std::ostringstream oss;
        oss << std::left << std::hex << std::setw(5) << std::dec << zone_ptr->id << " "
            << std::left << std::setw(VADDR_PRLEN + 2) << std::hex << zone_ptr->addr << " "
            << std::left << std::setw(name_max_len) << zone_ptr->name << " "
            << std::left << std::setw(governor_name_max_len + 2) << zone_ptr->governor << " "
            << std::left << std::setw(10) << std::dec << zone_ptr->cur_temp << " "
            << std::left << std::setw(10) << std::dec << zone_ptr->last_temp << " ";
        fprintf(fp, "%s \n",oss.str().c_str());
    }
}

void Thermal::parser_thrermal_zone(){
    if (!csymbol_exists("thermal_tz_list")){
        fprintf(fp, "thermal_tz_list doesn't exist in this kernel!\n");
        return;
    }
    ulong list_head = csymbol_value("thermal_tz_list");
    if (!is_kvaddr(list_head)) {
        fprintf(fp, "thermal_tz_list address is invalid!\n");
        return;
    }
    int offset = field_offset(thermal_zone_device, node);
    for (const auto& addr : for_each_list(list_head,offset)) {
        void *dev_buf = read_struct(addr,"thermal_zone_device");
        std::shared_ptr<zone_dev> zone_ptr = std::make_shared<zone_dev>();
        zone_ptr->addr = addr;
        zone_ptr->id = INT(dev_buf + field_offset(thermal_zone_device,id));
        zone_ptr->cur_temp = INT(dev_buf + field_offset(thermal_zone_device,temperature));
        zone_ptr->last_temp = INT(dev_buf + field_offset(thermal_zone_device,last_temperature));
        zone_ptr->name = read_cstring(addr + field_offset(thermal_zone_device,type),20, "type");
        ulong governor_addr = ULONG(dev_buf + field_offset(thermal_zone_device,governor));
        if (field_size(thermal_governor,name) > sizeof(void*)){
            zone_ptr->governor = read_cstring(governor_addr,20, "governor name");
        }else{
            ulong name_addr = read_pointer(governor_addr + field_offset(thermal_governor,name),"name addr");
            if (is_kvaddr(name_addr)) {
                zone_ptr->governor = read_cstring(name_addr,64, "governor name");
            }
        }
        int trip_cnt = 0;
        ulong trip_addr = 0;
        if (field_offset(thermal_zone_device,trips) != -1){
            trip_cnt = INT(dev_buf + field_offset(thermal_zone_device,num_trips));
            trip_addr = ULONG(dev_buf + field_offset(thermal_zone_device,trips));
        }else{
            ulong tz_addr = ULONG(dev_buf + field_offset(thermal_zone_device,devdata));
            void *tz_buf = read_struct(tz_addr,"__thermal_zone");
            trip_cnt = INT(tz_buf + field_offset(__thermal_zone,ntrips));
            trip_addr = ULONG(tz_buf + field_offset(__thermal_zone,trips));
            FREEBUF(tz_buf);
        }
        // fprintf(fp, "trip base addr:%#lx trip_cnt:%d\n",trip_addr,trip_cnt);
        if (is_kvaddr(trip_addr)) {
            for (size_t i = 0; i < trip_cnt; i++){
                ulong tt_addr = trip_addr + i * struct_size(thermal_trip);
                std::shared_ptr<trip> trip_ptr = std::make_shared<trip>();
                trip_ptr->addr = tt_addr;
                trip_ptr->temp = read_int(tt_addr + field_offset(thermal_trip,temperature),"temperature");
                // fprintf(fp, "trip addr:%#lx temp:%d\n",trip_ptr->addr,trip_ptr->temp);
                zone_ptr->trip_list.push_back(trip_ptr);
            }
        }
        if (zone_ptr->trip_list.size() > 0){
            int node_offset = field_offset(thermal_instance, tz_node);
            ulong head_addr = addr + field_offset(thermal_zone_device,thermal_instances);
            for (const auto& ins_addr : for_each_list(head_addr,node_offset)) {
                void *ins_buf = read_struct(ins_addr,"thermal_instance");
                int trip = INT(ins_buf + field_offset(thermal_instance,trip));
                if (trip > zone_ptr->trip_list.size()) {
                    continue;
                }
                ulong cdev = ULONG(ins_buf + field_offset(thermal_instance,cdev));
                FREEBUF(ins_buf);
                if (!is_kvaddr(cdev)) {
                    continue;
                }
                std::shared_ptr<cool_dev> cdev_ptr = std::make_shared<cool_dev>();
                cdev_ptr->addr = cdev;
                ulong type_addr = read_pointer(cdev + field_offset(thermal_cooling_device,type),"type addr");
                if (is_kvaddr(type_addr)){
                    cdev_ptr->name = read_cstring(type_addr,64, "type");
                }else{
                    cdev_ptr->name = "";
                }
                cdev_ptr->id = read_int(cdev + field_offset(thermal_cooling_device,id), "id");
                // fprintf(fp, "trip:%d cdev name:%s\n",trip,cdev_ptr->name.c_str());
                zone_ptr->trip_list[trip]->cool_list.push_back(cdev_ptr);
            }
        }
        FREEBUF(dev_buf);
        zone_list.push_back(zone_ptr);
    }
}

#pragma GCC diagnostic pop
