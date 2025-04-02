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

#include "dd.h"

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wpointer-arith"

#ifndef BUILD_TARGET_TOGETHER
DEFINE_PLUGIN_COMMAND(DDriver)
#endif

void DDriver::cmd_main(void) {
    int c;
    std::string cppString;
    if (argcnt < 2) cmd_usage(pc->curcmd, SYNOPSIS);
    if (bus_list.size() == 0){
        parser_bus_info();
        for (auto& bus_ptr : bus_list) {
            bus_ptr->device_list = parser_device_list(bus_ptr->subsys_private,field_offset(device_private,knode_bus));
            bus_ptr->driver_list = parser_driver_list(bus_ptr->subsys_private,field_offset(driver_private,knode_bus));
        }
    }
    if (class_list.size() == 0){
        parser_class_info();
        for (auto& class_ptr : class_list) {
            class_ptr->device_list = parser_device_list(class_ptr->subsys_private,field_offset(device_private,knode_class));
        }
    }
    while ((c = getopt(argcnt, args, "bB:cC:dDs:")) != EOF) {
        switch(c) {
            case 'b': //list all bus
                print_bus_info();
                break;
            case 'B'://list all device under specified bus
                cppString.assign(optarg);
                print_device_driver_for_bus(cppString);
                break;
            case 'c': //list all class
                print_class_info();
                break;
            case 'C'://list all device under specified bus
                cppString.assign(optarg);
                print_device_driver_for_class(cppString);
                break;
            case 'd'://list all device
                print_device_list();
                break;
            case 'D'://list all driver
                print_driver_list();
                break;
            case 's'://list all device under specified driver
                cppString.assign(optarg);
                print_device_list_for_driver(cppString);
                break;
            default:
                argerrs++;
                break;
        }
    }
    if (argerrs)
        cmd_usage(pc->curcmd, SYNOPSIS);
}

DDriver::DDriver(){
    field_init(kset,list);
    field_init(kset,kobj);
    field_init(kobject, entry);
    field_init(subsys_private,subsys);
    field_init(subsys_private,bus);
    field_init(subsys_private,class);
    field_init(bus_type,name);
    field_init(bus_type,probe);
    field_init(bus_type,p);
    field_init(class,name);
    field_init(class,p);
    field_init(subsys_private,klist_devices);
    field_init(subsys_private,klist_drivers);
    field_init(klist,k_list);
    field_init(klist_node, n_node);
    field_init(device_private,knode_bus);
    field_init(device_private,knode_class);
    field_init(device_private,device);
    field_init(device_private,knode_driver);
    field_init(driver_private,driver);
    field_init(driver_private,knode_bus);
    field_init(driver_private,klist_devices);
    field_init(device,kobj);
    field_init(device,driver);
    field_init(kobject,name);
    field_init(device_driver,name);
    field_init(device_driver,mod_name);
    field_init(device_driver,probe);
    field_init(device_driver,of_match_table);
    field_init(of_device_id,compatible);
    cmd_name = "dd";
    help_str_list={
        "dd",                            /* command name */
        "dump device driver information",        /* short description */
        "-b \n"
            "  dd -B <bus name> \n"
            "  dd -c \n"
            "  dd -C <class name> \n"
            "  dd -d \n"
            "  dd -D \n"
            "  dd -s <driver name> \n"
            "  This command dumps the device driver info.",
        "\n",
        "EXAMPLES",
        "  Display all bus info:",
        "    %s> dd -b",
        "    bus_type   name         subsys_private   probe func",
        "    c209bf98   platform     f6d5a000",
        "    c209c060   cpu          f6d5b000",
        "    c205f608   pci          f645b200         pci_device_probe+0",
        "\n",
        "  Display all device and driver info for specified bus:",
        "    %s> dd -B platform",
        "    ============================================================================",
        "                                      All devices",
        "    ============================================================================",
        "    device     name                                                              driver     driver_name",
        "    f6410810   reg-dummy                                                         c2074488   reg-dummy",
        "    f64a3410   f120000.timer",
        "    f64a1010   soc:cpu-pmu                                                       c2018658   armv7-pmu",
        "",
        "    ============================================================================",
        "                                      All drivers",
        "    ============================================================================",
        "    device_driver    name                            compatible                      probe func",
        "    c20b7aa0         syscon-reboot                   syscon-reboot                   platform_drv_probe+0",
        "    c208c360         iommu-debug                     iommu-debug-test                platform_drv_probe+0",
        "\n",
        "  Display all class info:",
        "    %s> dd -c",
        "    class      name                 subsys_private",
        "    c20741b0   regulator            f6ffe400",
        "    f643a180   bdi                  f645a800",
        "    c205f010   gpio                 f645b600",
        "\n",
        "  Display all device and driver info for specified class:",
        "    %s> dd -C rpmsg",
        "    ============================================================================",
        "                                      All devices",
        "    ============================================================================",
        "    device     name                                                              driver     driver_name",
        "    f67db068   rpmsg_ctrl0",
        "    f20b5068   rpmsg_ctrl1",
        "    efaa4c68   rpmsg_ctrl2",
        "\n",
        "  Display all device info:",
        "    %s> dd -d",
        "    device     name                                                              Bus             driver     driver_name",
        "    f6410810   reg-dummy                                                         platform        c2074488   reg-dummy",
        "    f64a0410   soc                                                               platform",
        "    f64a2410   soc:psci                                                          platform",
        "    f64a2010   soc:timer                                                         platform",
        "\n",
        "  Display all driver info:",
        "    %s> dd -D",
        "    device_driver    name                                 Bus                 compatible                 probe func",
        "    c2071e88         dcc                                  platform            dcc-v2                     platform_drv_probe+0",
        "    c2072b68         watchdog                             platform            watchdog                   platform_drv_probe+0",
        "\n",
        "  Display all device for specified driver:",
        "    %s> dd -s rpm-smd-regulator-resource",
        "    device     name",
        "    f60b8810   rpm-smd:rpm-regulator-smpa1",
        "    f60ba810   rpm-smd:rpm-regulator-smpa3",
        "    f60bac10   rpm-smd:rpm-regulator-smpa4",
        "    f60b8410   rpm-smd:rpm-regulator-smpa5",
        "\n",
    };
    initialize();
}

void DDriver::print_class_info(){
    size_t name_max_len = 20;
    for (auto& class_ptr : class_list) {
        name_max_len = std::max(name_max_len,class_ptr->name.size());
    }
    std::ostringstream oss_hd;
    oss_hd  << std::left << std::setw(VADDR_PRLEN + 2)  << "class" << " "
            << std::left << std::setw(name_max_len)     << "name"  << " "
            << std::left                                << "subsys_private";
    fprintf(fp, "%s \n",oss_hd.str().c_str());
    for (auto& class_ptr : class_list) {
        std::ostringstream oss;
        oss << std::left << std::hex << std::setw(VADDR_PRLEN + 2)  << class_ptr->addr << " "
            << std::left << std::setw(name_max_len)                 << class_ptr->name << " "
            << std::left << std::hex                                << class_ptr->subsys_private;
        fprintf(fp, "%s \n",oss.str().c_str());
    }
}

void DDriver::print_bus_info(){
    size_t name_max_len = 10;
    for (auto& bus_ptr : bus_list) {
        name_max_len = std::max(name_max_len,bus_ptr->name.size());
    }
    std::ostringstream oss_hd;
    oss_hd  << std::left << std::setw(VADDR_PRLEN + 2)  << "bus_type" << " "
            << std::left << std::setw(name_max_len)     << "name" << " "
            << std::left << std::setw(16)               << "subsys_private" << " "
            << std::left                                << "probe func";
    fprintf(fp, "%s \n",oss_hd.str().c_str());
    for (auto& bus_ptr : bus_list) {
        std::ostringstream oss;
        oss << std::left << std::hex << std::setw(VADDR_PRLEN + 2)  << bus_ptr->addr << " "
            << std::left << std::setw(name_max_len)                 << bus_ptr->name << " "
            << std::left << std::hex << std::setw(16)               << bus_ptr->subsys_private << " "
            << std::left                                            << bus_ptr->probe;
        fprintf(fp, "%s \n",oss.str().c_str());
    }
}

void DDriver::print_device_list(){
    size_t name_max_len = 10;
    for (auto& bus_ptr : bus_list) {
        for (auto& dev_ptr : bus_ptr->device_list) {
            name_max_len = std::max(name_max_len,dev_ptr->name.size());
        }
    }
    std::ostringstream oss_hd;
    oss_hd  << std::left << std::setw(VADDR_PRLEN + 2)  << "device" << " "
            << std::left << std::setw(name_max_len)     << "name" << " "
            << std::left << std::setw(15)               << "Bus" << " "
            << std::left << std::setw(VADDR_PRLEN + 2)  << "driver" << " "
            << std::left                                << "driver_name";
    fprintf(fp, "%s \n",oss_hd.str().c_str());
    for (auto& bus_ptr : bus_list) {
        for (auto& dev_ptr : bus_ptr->device_list) {
            std::ostringstream oss;
            oss << std::left << std::hex << std::setw(VADDR_PRLEN + 2)  << dev_ptr->addr << " "
                << std::left << std::setw(name_max_len)                 << dev_ptr->name << " "
                << std::left << std::setw(15)                           << bus_ptr->name << " ";
            if (dev_ptr->driv != nullptr){
                oss << std::left << std::hex << std::setw(VADDR_PRLEN + 2) << dev_ptr->driv->addr << " "
                    << std::left << dev_ptr->driv->name;
            }
            fprintf(fp, "%s \n",oss.str().c_str());
        }
    }
}

void DDriver::print_device_driver_for_bus(std::string bus_name){
    std::vector<std::shared_ptr<device>> device_list;
    std::vector<std::shared_ptr<driver>> driver_list;
    for (auto& bus_ptr : bus_list) {
        if (bus_ptr->name == bus_name){
            device_list = bus_ptr->device_list;
            driver_list = bus_ptr->driver_list;
            break;
        }
    }
    fprintf(fp, "============================================================================\n");
    fprintf(fp, "                                All devices                                 \n");
    fprintf(fp, "============================================================================\n");
    if (device_list.size() > 0){
        size_t name_max_len = 10;
        for (auto& dev_ptr : device_list) {
            name_max_len = std::max(name_max_len,dev_ptr->name.size());
        }
        std::ostringstream oss_hd;
        oss_hd  << std::left << std::setw(VADDR_PRLEN + 2)  << "device" << " "
                << std::left << std::setw(name_max_len)     << "name"   << " "
                << std::left << std::setw(VADDR_PRLEN + 2)  << "driver" << " "
                << std::left                                << "driver_name";
        fprintf(fp, "%s \n",oss_hd.str().c_str());
        for (auto& dev_ptr : device_list) {
            std::ostringstream oss;
            oss << std::left << std::hex << std::setw(VADDR_PRLEN + 2) << dev_ptr->addr << " "
                << std::left << std::setw(name_max_len) << dev_ptr->name << " ";
            if (dev_ptr->driv != nullptr){
                oss << std::left << std::hex << std::setw(VADDR_PRLEN + 2) << dev_ptr->driv->addr << " "
                    << std::left << dev_ptr->driv->name;
            }
            fprintf(fp, "%s \n",oss.str().c_str());
        }
    }
    fprintf(fp, "\n\n\n");
    fprintf(fp, "============================================================================\n");
    fprintf(fp, "                                All drivers                                 \n");
    fprintf(fp, "============================================================================\n");
    if (driver_list.size() > 0){
        size_t name_max_len = 10;
        size_t compat_max_len = 10;
        for (auto& driv_ptr : driver_list) {
            name_max_len = std::max(name_max_len,driv_ptr->name.size());
            compat_max_len = std::max(compat_max_len,driv_ptr->compatible.size());
        }
        std::ostringstream oss_hd;
        oss_hd  << std::left << std::setw(16)               << "device_driver" << " "
                << std::left << std::setw(name_max_len)     << "name" << " "
                << std::left << std::setw(compat_max_len)   << "compatible" << " "
                << std::left                                << "probe func";
        fprintf(fp, "%s \n",oss_hd.str().c_str());
        for (auto& driv_ptr : driver_list) {
            std::ostringstream oss;
            oss << std::left << std::hex << std::setw(16)   << driv_ptr->addr << " "
                << std::left << std::setw(name_max_len)     << driv_ptr->name << " "
                << std::left << std::setw(compat_max_len)   << driv_ptr->compatible << " "
                << std::left << driv_ptr->probe;
            fprintf(fp, "%s \n",oss.str().c_str());
        }
    }
}

void DDriver::print_device_driver_for_class(std::string class_name){
    std::vector<std::shared_ptr<device>> device_list;
    for (auto& class_ptr : class_list) {
        if (class_ptr->name == class_name){
            device_list = class_ptr->device_list;
            break;
        }
    }
    fprintf(fp, "============================================================================\n");
    fprintf(fp, "                                All devices                                 \n");
    fprintf(fp, "============================================================================\n");
    if (device_list.size() > 0){
        size_t name_max_len = 10;
        for (auto& dev_ptr : device_list) {
            name_max_len = std::max(name_max_len,dev_ptr->name.size());
        }
        std::ostringstream oss_hd;
        oss_hd  << std::left << std::setw(VADDR_PRLEN + 2)   << "device" << " "
                << std::left << std::setw(name_max_len)      << "name"   << " "
                << std::left << std::setw(VADDR_PRLEN + 2)   << "driver" << " "
                << std::left                                 << "driver_name";
        fprintf(fp, "%s \n",oss_hd.str().c_str());
        for (auto& dev_ptr : device_list) {
            std::ostringstream oss;
            oss << std::left << std::hex << std::setw(VADDR_PRLEN + 2) << dev_ptr->addr << " "
                << std::left << std::setw(name_max_len) << dev_ptr->name << " ";
            if (dev_ptr->driv != nullptr){
                oss << std::left << std::hex << std::setw(VADDR_PRLEN + 2) << dev_ptr->driv->addr << " "
                    << std::left << dev_ptr->driv->name;
            }
            fprintf(fp, "%s \n",oss.str().c_str());
        }
    }
}

void DDriver::print_device_list_for_driver(std::string driver_name){
    std::vector<std::shared_ptr<device>> device_list;
    bool found = false;
    for (auto& bus_ptr : bus_list) {
        for (auto& drv_ptr : bus_ptr->driver_list) {
            if (drv_ptr->name == driver_name){
                device_list = drv_ptr->device_list;
                found = true;
                break;
            }
        }
        if (found){
            break;
        }
    }
    if (device_list.empty()){
        return;
    }
    size_t name_max_len = 10;
    for (auto& dev_ptr : device_list) {
        name_max_len = std::max(name_max_len,dev_ptr->name.size());
    }
    std::ostringstream oss_hd;
    oss_hd << std::left << "   " << std::setw(VADDR_PRLEN + 2) << "device" << " "
        << std::left << std::setw(name_max_len) << "name";
    fprintf(fp, "%s \n",oss_hd.str().c_str());
    for (auto& dev_ptr : device_list) {
        std::ostringstream oss;
        oss << std::left << "   " << std::hex << std::setw(VADDR_PRLEN + 2) << dev_ptr->addr << " "
            << std::left << std::setw(name_max_len) << dev_ptr->name << " ";
        fprintf(fp, "%s \n",oss.str().c_str());
    }
}

void DDriver::print_driver_list(){
    size_t name_max_len = 10;
    size_t compat_max_len = 10;
    for (auto& bus_ptr : bus_list) {
        for (auto& driv_ptr : bus_ptr->driver_list) {
            name_max_len = std::max(name_max_len,driv_ptr->name.size());
            compat_max_len = std::max(compat_max_len,driv_ptr->compatible.size());
        }
    }
    std::ostringstream oss_hd;
    oss_hd  << std::left << std::setw(16)               << "device_driver" << " "
            << std::left << std::setw(name_max_len)     << "name" << " "
            << std::left << std::setw(15)               << "Bus" << " "
            << std::left << std::setw(compat_max_len)   << "compatible" << " "
            << std::left                                << "probe func";
    fprintf(fp, "%s \n",oss_hd.str().c_str());
    for (auto& bus_ptr : bus_list) {
        for (auto& driv_ptr : bus_ptr->driver_list) {
            std::ostringstream oss;
            oss << std::left << std::hex << std::setw(16) << driv_ptr->addr << " "
                << std::left << std::setw(name_max_len) << driv_ptr->name << " "
                << std::left << std::setw(15) << bus_ptr->name << " "
                << std::left << std::setw(compat_max_len) << driv_ptr->compatible << " "
                << std::left << driv_ptr->probe;
            fprintf(fp, "%s \n",oss.str().c_str());
        }
    }
}

void DDriver::parser_class_info(){
    if (!csymbol_exists("class_kset")){
        fprintf(fp, "class_kset doesn't exist in this kernel!\n");
        return;
    }
    size_t class_kset_addr = read_pointer(csymbol_value("class_kset"),"class_kset");
    if (!is_kvaddr(class_kset_addr)) {
        fprintf(fp, "class_kset address is invalid!\n");
        return;
    }
    size_t list_head = class_kset_addr + field_offset(kset,list);
    int offset = field_offset(kobject, entry);
    for (const auto& kobject_addr : for_each_list(list_head,offset)) {
        size_t kset_addr = kobject_addr - field_offset(kset,kobj);
        if (!is_kvaddr(kset_addr)) continue;
        size_t subsys_addr = kset_addr - field_offset(subsys_private,subsys);
        if (!is_kvaddr(subsys_addr)) continue;
        size_t class_addr = read_pointer(subsys_addr + field_offset(subsys_private,class),"class");
        if (!is_kvaddr(class_addr)) continue;
        std::shared_ptr<class_type> class_ptr = std::make_shared<class_type>();
        class_ptr->addr = class_addr;
        // fprintf(fp, "class_addr: %zx\n",class_addr);
        size_t name_addr = read_pointer(class_addr + field_offset(class,name),"name addr");
        if (is_kvaddr(name_addr)){
            class_ptr->name = read_cstring(name_addr,16, "class name");
        }else{
            class_ptr->name = "";
        }
        if (!class_ptr->name.empty() && *class_ptr->name.rbegin() == '\n') {
            class_ptr->name.pop_back();
        }
        if (field_offset(class,p) != -1){
            class_ptr->subsys_private = read_pointer(class_addr + field_offset(class,p),"subsys_private");
        }else{
            class_ptr->subsys_private = subsys_addr;
        }
        class_list.push_back(class_ptr);
    }
}

void DDriver::parser_bus_info(){
    if (!csymbol_exists("bus_kset")){
        fprintf(fp, "bus_kset doesn't exist in this kernel!\n");
        return;
    }
    size_t bus_kset_addr = read_pointer(csymbol_value("bus_kset"),"bus_kset");
    if (!is_kvaddr(bus_kset_addr)) {
        fprintf(fp, "bus_kset address is invalid!\n");
        return;
    }
    size_t list_head = bus_kset_addr + field_offset(kset,list);
    int offset = field_offset(kobject, entry);
    for (const auto& kobject_addr : for_each_list(list_head,offset)) {
        size_t kset_addr = kobject_addr - field_offset(kset,kobj);
        if (!is_kvaddr(kset_addr)) continue;
        size_t subsys_addr = kset_addr - field_offset(subsys_private,subsys);
        if (!is_kvaddr(subsys_addr)) continue;
        size_t bus_addr = read_pointer(subsys_addr + field_offset(subsys_private,bus),"bus_type");
        if (!is_kvaddr(bus_addr)) continue;
        std::shared_ptr<bus_type> bus_ptr = std::make_shared<bus_type>();
        bus_ptr->addr = bus_addr;
        size_t name_addr = read_pointer(bus_addr + field_offset(bus_type,name),"name addr");
        if (is_kvaddr(name_addr)){
            bus_ptr->name = read_cstring(name_addr,16, "bus name");
        }else{
            bus_ptr->name = "";
        }
        size_t probe_addr = read_pointer(bus_addr + field_offset(bus_type,probe),"probe addr");
        std::ostringstream oss;
        if (is_kvaddr(probe_addr)){
            ulong offset;
            struct syment *sp = value_search(probe_addr, &offset);
            if (sp) {
                oss << sp->name << "+" << offset;
            } else {
                oss << std::hex << probe_addr;
            }
            bus_ptr->probe = oss.str();
            oss.str("");
        }else{
            bus_ptr->probe = "";
        }
        if (field_offset(bus_type,p) != -1){
            bus_ptr->subsys_private = read_pointer(bus_addr + field_offset(bus_type,p),"subsys_private");
        }else{
            bus_ptr->subsys_private = subsys_addr;
        }
        bus_list.push_back(bus_ptr);
    }
}

std::vector<std::shared_ptr<device>> DDriver::parser_device_list(size_t subsys_addr,int off){
    std::vector<std::shared_ptr<device>> device_list;
    if (!is_kvaddr(subsys_addr)){
        return device_list;
    }
    size_t list_head = subsys_addr + field_offset(subsys_private,klist_devices) + field_offset(klist,k_list);
    int offset = field_offset(klist_node, n_node);
    for (const auto& node : for_each_list(list_head,offset)) {
        if (!is_kvaddr(node)) continue;
        size_t private_addr = node - off;
        if (!is_kvaddr(private_addr)) continue;
        size_t device_addr = read_pointer(private_addr + field_offset(device_private,device),"device_private");
        if (!is_kvaddr(device_addr)) continue;
        // fprintf(fp, "device_addr:%#zx \n",device_addr);
        std::shared_ptr<device> dev_ptr = parser_device(device_addr);
        if (dev_ptr == nullptr) continue;
        device_list.push_back(dev_ptr);
    }
    return device_list;
}

std::vector<std::shared_ptr<driver>> DDriver::parser_driver_list(size_t subsys_addr,int off){
    std::vector<std::shared_ptr<driver>> driver_list;
    if (!is_kvaddr(subsys_addr)){
        return driver_list;
    }
    size_t list_head = subsys_addr + field_offset(subsys_private,klist_drivers) + field_offset(klist,k_list);
    int offset = field_offset(klist_node, n_node);
    for (const auto& node : for_each_list(list_head,offset)) {
        if (!is_kvaddr(node)) continue;
        size_t driver_private_addr = node - off;
        if (!is_kvaddr(driver_private_addr)) continue;
        size_t driver_addr = read_pointer(driver_private_addr + field_offset(driver_private,driver),"driver_private");
        if (!is_kvaddr(driver_addr)) continue;
        // fprintf(fp, "driver_addr:%#zx \n",driver_addr);
        std::shared_ptr<driver> driv_ptr = parser_driver(driver_addr);
        if (driv_ptr == nullptr) continue;

        size_t dev_list_head = driver_private_addr + field_offset(driver_private,klist_devices) + field_offset(klist,k_list);
        for (const auto& kobject_addr : for_each_list(dev_list_head,offset)) {
            size_t device_private_addr = kobject_addr - field_offset(device_private,knode_driver);
            if (!is_kvaddr(device_private_addr)) continue;
            size_t device_addr = read_pointer(device_private_addr + field_offset(device_private,device),"device_private");
            if (!is_kvaddr(device_addr)) continue;
            // fprintf(fp, "device_addr:%#zx \n",device_addr);
            std::shared_ptr<device> dev_ptr = parser_device(device_addr);
            if (dev_ptr == nullptr) continue;
            driv_ptr->device_list.push_back(dev_ptr);
        }
        driver_list.push_back(driv_ptr);
    }
    return driver_list;
}

std::shared_ptr<device> DDriver::parser_device(size_t addr){
    if (!is_kvaddr(addr)) return nullptr;
    std::shared_ptr<device> dev_ptr = std::make_shared<device>();
    dev_ptr->addr = addr;
    size_t name_addr = read_pointer(addr + field_offset(device,kobj) + field_offset(kobject,name),"device name addr");
    if (is_kvaddr(name_addr)){
        dev_ptr->name = read_cstring(name_addr,100, "device name");
    }else{
        dev_ptr->name = "";
    }
    size_t driver_addr = read_pointer(addr + field_offset(device,driver) ,"driver addr");
    if (is_kvaddr(driver_addr)){
        dev_ptr->driv = parser_driver(driver_addr);
    }
    return dev_ptr;
}

std::shared_ptr<driver> DDriver::parser_driver(size_t addr){
    if (!is_kvaddr(addr)) return nullptr;
    std::shared_ptr<driver> driv_ptr = std::make_shared<driver>();
    driv_ptr->addr = addr;
    size_t name_addr = read_pointer(addr + field_offset(device_driver,name),"driver name addr");
    if (is_kvaddr(name_addr)){
        driv_ptr->name = read_cstring(name_addr,100, "driver name");
    }else{
        driv_ptr->name = "";
    }
    size_t probe_addr = read_pointer(addr + field_offset(device_driver,probe),"probe addr");
    std::ostringstream oss;
    if (is_kvaddr(probe_addr)){
        ulong offset;
        struct syment *sp = value_search(probe_addr, &offset);
        if (sp) {
            oss << sp->name << "+" << offset;
        } else {
            oss << std::hex << probe_addr;
        }
        driv_ptr->probe = oss.str();
        oss.str("");
    }else{
        driv_ptr->probe = "";
    }
    size_t match_table = read_pointer(addr + field_offset(device_driver,of_match_table),"match_table addr");
    if (is_kvaddr(match_table)){
        driv_ptr->compatible = read_cstring(match_table + field_offset(of_device_id,compatible),128, "compatible");
    }else{
        driv_ptr->compatible = "";
    }
    return driv_ptr;
}

#pragma GCC diagnostic pop
