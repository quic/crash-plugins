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

#include "regulator.h"

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wpointer-arith"

#ifndef BUILD_TARGET_TOGETHER
DEFINE_PLUGIN_COMMAND(Regulator)
#endif

void Regulator::cmd_main(void) {
    int c;
    std::string cppString;
    if (argcnt < 2) cmd_usage(pc->curcmd, SYNOPSIS);
    if (regulator_list.size() == 0){
        parser_regulator_dev();
    }
    while ((c = getopt(argcnt, args, "arc:")) != EOF) {
        switch(c) {
            case 'a':
                print_regulator_info();
                break;
            case 'r':
                print_regulator_dev();
                break;
            case 'c':
                cppString.assign(optarg);
                print_regulator_consumer(cppString);
                break;
            default:
                argerrs++;
                break;
        }
    }
    if (argerrs)
        cmd_usage(pc->curcmd, SYNOPSIS);
}

Regulator::Regulator(){
    field_init(class,p);
    field_init(subsys_private,klist_devices);
    field_init(klist,k_list);
    field_init(klist_node, n_node);
    field_init(device_private,knode_class);
    field_init(device_private,device);
    field_init(regulator_dev,dev);
    field_init(regulator_dev,constraints);
    field_init(regulator_dev,desc);
    field_init(regulator_dev,use_count);
    field_init(regulator_dev,open_count);
    field_init(regulator_dev,bypass_count);
    field_init(regulator_dev,consumer_list);
    field_init(regulation_constraints,name);
    field_init(regulation_constraints,min_uV);
    field_init(regulation_constraints,max_uV);
    field_init(regulation_constraints,input_uV);
    field_init(regulator_desc,name);
    field_init(regulator,list);
    field_init(regulator,uA_load);
    field_init(regulator,enable_count);
    field_init(regulator,voltage);
    field_init(regulator,supply_name);
    field_init(regulator,voltage);
    field_init(regulator_voltage,min_uV);
    field_init(regulator_voltage,max_uV);
    struct_init(regulator_voltage);
    cmd_name = "reg";
    help_str_list={
        "reg",                            /* command name */
        "dump regulator information",        /* short description */
        "-a \n"
            "  reg -r \n"
            "  reg -c <name>\n"
            "  This command dumps the regulator info.",
        "\n",
        "EXAMPLES",
        "  Display all regulator and consumer info:",
        "    %s> reg -a",
        "    regulator_dev:ffffff8006994800 regulator-dummy open_count:4 use_count:3 bypass_count:0 min_uV:0 max_uV:0 input_uV:0",
        "       regulator:ffffff801e51c000 enable:0 load:0uA 5e94000,mdss_dsi0_ctrl-refgen",
        "       regulator:ffffff801e51c0c0 enable:0 load:0uA 5e94400,mdss_dsi_phy0-gdsc",
        "       regulator:ffffff801ad6cc00 enable:1 load:0uA soc:usb_nop_phy-vcc",
        "       regulator:ffffff800a036780 enable:1 load:0uA regulator.21-SUPPLY",
        "\n",
        "  Display all regulator info:",
        "    %s> reg -r",
        "    regulator_dev    open use bypass regulator_desc   constraints      min_uV   max_uV   input_uV Name",
        "    ffffff8006994800 4    3   0      ffffffeee20a0020 ffffff80067f8d00 0        0        0        regulator-dummy",
        "    ffffff8007811800 17   0   0      ffffff8003999048 ffffff80033ebb00 0        0        0        gcc_camss_top_gdsc",
        "    ffffff8007813000 1    1   0      ffffff8003999448 ffffff80033eb700 0        0        0        gcc_usb20_prim_gdsc",
        "    ffffff8007815000 3    0   0      ffffff800a39bc48 ffffff8007a39e00 0        0        0        gpu_cx_gdsc",
        "    ffffff8007814000 1    0   0      ffffff800a398048 ffffff8007a39c00 0        0        0        gpu_gx_gdsc",
        "    ffffff8007bac800 0    0   0      ffffff8002114400 ffffff8012ee5200 1816000  1904000  1904000  pm5100_s4",
        "    ffffff8002158000 0    0   0      ffffff8002114600 ffffff8012ee5900 1000000  1000000  1000000  pm5100_l11",
        "\n",
        "  Display all consumer info of regulator:",
        "    %s> reg -c pm5100_l12",
        "    Consumers:",
        "       regulator        load       enable Name",
        "       ffffff802a899a80 0uA        0      5c54000,csiphy1-mipi-csi-vdd1",
        "       ffffff802a883780 0uA        0      5c52000,csiphy0-mipi-csi-vdd1",
        "       ffffff801e51ca80 0uA        0      5e94400,mdss_dsi_phy0-vdda-0p9 voltage:[904000uV~904000uV,]",
        "       ffffff801ad6ce40 30000uA    1      1613000.hsphy-vdd voltage:[904000uV~904000uV,]",
        "       ffffff8002204f00 0uA        1      regulator.59-SUPPLY",
        "\n",
    };
    initialize();
}

void Regulator::print_regulator_consumer(std::string reg_name){
    for (const auto& dev_ptr : regulator_list) {
        if (dev_ptr->name != reg_name){
            continue;
        }
        fprintf(fp, "Consumers: \n");
        std::ostringstream oss_hd;
        oss_hd  << std::left << std::setw(16)   << "regulator" << " "
                << std::left << std::setw(10)    << "load" << " "
                << std::left << std::setw(6)    << "enable" << " "
                << std::left << "Name";
        fprintf(fp, "   %s \n",oss_hd.str().c_str());
        for (const auto& c_ptr : dev_ptr->consumers) {
            std::ostringstream oss;
            oss << std::left << std::setw(16) << std::hex << c_ptr->addr << " "
                << std::left << std::setw(10)  << std::dec << std::to_string(c_ptr->load) + "uA" << " "
                << std::left << std::setw(6)  << std::dec << c_ptr->enable_count << " "
                << std::left << c_ptr->name;
            if (c_ptr->voltages.size() > 0){
                oss << std::left << " voltage:[";
                for (const auto& vol : c_ptr->voltages) {
                    oss << std::left << std::to_string(vol->min_uV) << "uV~" << std::to_string(vol->max_uV) << "uV,";
                }
                oss << std::left << "]";
            }
            fprintf(fp, "   %s \n",oss.str().c_str());
        }
    }
}

void Regulator::print_regulator_info(){
    if(regulator_list.size() == 0) return;
    for (const auto& dev_ptr : regulator_list) {
        std::ostringstream oss;
        oss << std::left << "regulator_dev:" << std::hex << dev_ptr->addr << " " << std::left << dev_ptr->name << " "
            << std::left << "open_count:" << std::dec << dev_ptr->open_count << " "
            << std::left << "use_count:" << std::dec << dev_ptr->use_count << " "
            << std::left << "bypass_count:" << std::dec << dev_ptr->bypass_count << " "
            << std::left << "min_uV:"  << std::dec << dev_ptr->min_uV << " "
            << std::left << "max_uV:"  << std::dec << dev_ptr->max_uV << " "
            << std::left << "input_uV:" << std::dec << dev_ptr->input_uV;
        fprintf(fp, "%s \n",oss.str().c_str());
        for (const auto& c_ptr : dev_ptr->consumers) {
            std::ostringstream oss;
            oss << std::left << "regulator:" << std::hex << c_ptr->addr << " "
                << std::left << "enable:"  << std::dec << c_ptr->enable_count << " "
                << std::left << "load:"  << std::dec << std::to_string(c_ptr->load) + "uA" << " ";
            if (c_ptr->voltages.size() > 0){
                oss << std::left << " voltage:[";
                for (const auto& vol : c_ptr->voltages) {
                    oss << std::left << std::to_string(vol->min_uV) << "uV~" << std::to_string(vol->max_uV) << "uV,";
                }
                oss << std::left << "] ";
            }
            oss << std::left << c_ptr->name;
            fprintf(fp, "   %s \n",oss.str().c_str());
        }
        fprintf(fp, "\n");
    }
}

void Regulator::print_regulator_dev(){
    if(regulator_list.size() == 0) return;
    std::ostringstream oss_hd;
    oss_hd  << std::left << std::setw(16)   << "regulator_dev" << " "
            << std::left << std::setw(4)    << "open" << " "
            << std::left << std::setw(3)    << "use" << " "
            << std::left << std::setw(6)    << "bypass" << " "
            << std::left << std::setw(16)   << "regulator_desc" << " "
            << std::left << std::setw(16)   << "constraints" << " "
            << std::left << std::setw(8)    << "min_uV" << " "
            << std::left << std::setw(8)    << "max_uV" << " "
            << std::left << std::setw(8)    << "input_uV" << " "
            << std::left << "Name";
    fprintf(fp, "%s \n",oss_hd.str().c_str());
    for (const auto& dev_ptr : regulator_list) {
        std::ostringstream oss;
        oss << std::left << std::setw(16)   << std::hex << dev_ptr->addr << " "
            << std::left << std::setw(4)    << std::dec << dev_ptr->open_count << " "
            << std::left << std::setw(3)    << std::dec << dev_ptr->use_count << " "
            << std::left << std::setw(6)    << std::dec << dev_ptr->bypass_count << " "
            << std::left << std::setw(16)   << std::hex << dev_ptr->desc << " "
            << std::left << std::setw(16)   << std::hex << dev_ptr->constraint << " "
            << std::left << std::setw(8)    << std::dec << dev_ptr->min_uV << " "
            << std::left << std::setw(8)    << std::dec << dev_ptr->max_uV << " "
            << std::left << std::setw(8)    << std::dec << dev_ptr->input_uV << " "
            << std::left << dev_ptr->name;
        fprintf(fp, "%s \n",oss.str().c_str());
    }
}

void Regulator::parser_regulator_dev(){
    for (auto& addr : for_each_device_for_class("regulator")) {
        addr = addr - field_offset(regulator_dev,dev);
        std::shared_ptr<regulator_dev> dev_ptr = std::make_shared<regulator_dev>();
        dev_ptr->addr = addr;
        dev_ptr->constraint = read_pointer(addr + field_offset(regulator_dev,constraints),"regulation_constraints");
        ulong name_addr = 0;
        if (is_kvaddr(dev_ptr->constraint)){
            name_addr = read_pointer(dev_ptr->constraint + field_offset(regulation_constraints,name),"name");
            if (is_kvaddr(name_addr)){
                dev_ptr->name = read_cstring(name_addr,64, "regulator name");
            }
            dev_ptr->min_uV = read_int(dev_ptr->constraint + field_offset(regulation_constraints,min_uV),"min_uV");
            dev_ptr->max_uV = read_int(dev_ptr->constraint + field_offset(regulation_constraints,max_uV),"max_uV");
            dev_ptr->input_uV = read_int(dev_ptr->constraint + field_offset(regulation_constraints,input_uV),"input_uV");
        }
        dev_ptr->desc = read_pointer(addr + field_offset(regulator_dev,desc),"regulator_desc");
        if(dev_ptr->name.empty()){
            if (is_kvaddr(dev_ptr->desc)){
                name_addr = read_pointer(dev_ptr->desc + field_offset(regulator_desc,name),"name");
                if (is_kvaddr(name_addr)){
                    dev_ptr->name = read_cstring(name_addr,64, "regulator name");
                }
            }
        }
        if(dev_ptr->name.empty()){
            dev_ptr->name = "UnKnow";
        }
        dev_ptr->use_count = read_uint(addr + field_offset(regulator_dev,use_count),"use_count");
        dev_ptr->open_count = read_uint(addr + field_offset(regulator_dev,open_count),"open_count");
        dev_ptr->bypass_count = read_uint(addr + field_offset(regulator_dev,bypass_count),"bypass_count");
        ulong consumer_list = addr + field_offset(regulator_dev,consumer_list);
        int offset = field_offset(regulator, list);
        for (const auto& reg : for_each_list(consumer_list,offset)) {
            std::shared_ptr<regulator> reg_ptr = std::make_shared<regulator>();
            reg_ptr->addr = reg;
            reg_ptr->load = read_int(reg + field_offset(regulator,uA_load),"uA_load");
            reg_ptr->enable_count = read_uint(reg + field_offset(regulator,enable_count),"enable_count");
            ulong name_addr = read_pointer(reg + field_offset(regulator,supply_name),"name");
            if (is_kvaddr(name_addr)){
                reg_ptr->name = read_cstring(name_addr,64, "supply_name");
            }
            size_t cnt = field_size(regulator,voltage)/struct_size(regulator_voltage);
            for(size_t i=0; i < cnt; i++){
                ulong vol_addr = reg + field_offset(regulator,voltage) + i * struct_size(regulator_voltage);
                int min_uV = read_int(vol_addr + field_offset(regulator_voltage,min_uV),"min_uV");
                int max_uV = read_int(vol_addr + field_offset(regulator_voltage,max_uV),"max_uV");
                if(min_uV != 0 || max_uV != 0){
                    std::shared_ptr<voltage> vol_ptr = std::make_shared<voltage>();
                    vol_ptr->min_uV = min_uV;
                    vol_ptr->max_uV = max_uV;
                    reg_ptr->voltages.push_back(vol_ptr);
                }
            }
            dev_ptr->consumers.push_back(reg_ptr);
        }
        regulator_list.push_back(dev_ptr);
    }
}

#pragma GCC diagnostic pop
