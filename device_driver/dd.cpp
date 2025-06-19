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
            bus_ptr->device_list = parser_bus_device_list(bus_ptr->name);
            bus_ptr->driver_list = parser_driver_list(bus_ptr->name);
        }
    }
    if (class_list.size() == 0){
        parser_class_info();
        for (auto& class_ptr : class_list) {
            class_ptr->device_list = parser_class_device_list(class_ptr->name);
        }
    }
    while ((c = getopt(argcnt, args, "bB:cC:lLs:amDdp:")) != EOF) {
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
            case 'l'://list all device
                print_device_list();
                break;
            case 'L'://list all driver
                print_driver_list();
                break;
            case 's'://list all device under specified driver
                cppString.assign(optarg);
                print_device_list_for_driver(cppString);
                break;
            case 'a'://list all char_device_struct
                print_char_device();
                break;
            case 'm'://list all misc device
                print_misc_device();
                break;
            case 'D'://list all block device
                print_block_device();
                break;
            case 'd'://list all disk
                print_gendisk();
                break;
            case 'p'://list all partition under specified disk
                cppString.assign(optarg);
                print_partition(cppString);
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
    field_init(bus_type,probe);
    field_init(device,kobj);
    field_init(device,driver);
    field_init(kobject,name);
    field_init(device_driver,name);
    field_init(device_driver,mod_name);
    field_init(device_driver,probe);
    field_init(device_driver,of_match_table);
    field_init(of_device_id,compatible);
    field_init(char_device_struct,major);
    field_init(char_device_struct,baseminor);
    field_init(char_device_struct,minorct);
    field_init(char_device_struct, cdev);
    field_init(char_device_struct, name);
    field_init(miscdevice,minor);
    field_init(miscdevice,name);
    field_init(miscdevice,fops);
    struct_init(gendisk);
    field_init(gendisk,major);
    field_init(gendisk,minors);
    field_init(gendisk,disk_name);
    field_init(gendisk,part_tbl);
    field_init(disk_part_tbl,len);
    field_init(disk_part_tbl,part);
    struct_init(block_device);
    field_init(block_device,bd_start_sect);
    field_init(block_device,bd_nr_sectors);
    field_init(block_device,bd_disk);
    field_init(block_device,bd_mapping);
    field_init(block_device,bd_meta_info);
    field_init(block_device,bd_super);
    field_init(block_device,bd_part);
    field_init(block_device,bd_block_size);
    field_init(block_device,bd_partno);
    field_init(super_block,s_blocksize);
    field_init(super_block,s_type);
    field_init(super_block, s_list);
    field_init(super_block,s_bdev);
    field_init(file_system_type,name);
    field_init(file_system_type,fs_flags);
    struct_init(hd_struct);
    field_init(hd_struct,info);
    field_init(hd_struct,__dev);
    field_init(hd_struct,start_sect);
    field_init(hd_struct,nr_sects);
    field_init(hd_struct,partno);
    field_init(partition_meta_info,uuid);
    field_init(partition_meta_info,volname);
    cmd_name = "dd";
    help_str_list={
        "dd",                            /* command name */
        "dump device driver information",        /* short description */
        "-b \n"
            "  dd -B <bus name> \n"
            "  dd -c \n"
            "  dd -C <class name> \n"
            "  dd -l \n"
            "  dd -L \n"
            "  dd -s <driver name> \n"
            "  dd -a \n"
            "  dd -m \n"
            "  dd -D \n"
            "  dd -d \n"
            "  dd -p <disk name> \n"
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
        "    %s> dd -l",
        "    device     name                                                              Bus             driver     driver_name",
        "    f6410810   reg-dummy                                                         platform        c2074488   reg-dummy",
        "    f64a0410   soc                                                               platform",
        "    f64a2410   soc:psci                                                          platform",
        "    f64a2010   soc:timer                                                         platform",
        "\n",
        "  Display all driver info:",
        "    %s> dd -L",
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
        "  Display all char device:",
        "    %s> dd -a ",
        "    char_device_struct   major      minorct    cdev               name",
        "    ffffff80095b5b00     1          256        ffffff800a3aac00   mem",
        "    ffffff80095b5800     5          1          0                  /dev/tty",
        "    ffffff80095bbe80     5          1          0                  /dev/console",
        "    ffffff80099b7f80     10         256        ffffff800a39ec00   misc",
        "\n",
        "  Display all misc device:",
        "    %s> dd -m ",
        "    miscdevice           minor      ops                            name",
        "    ffffffd0d7f763f0     124        gh_dev_fops                    gunyah",
        "    ffffffd0dd022060     125        cpu_latency_qos_fops           cpu_dma_latency",
        "    ffffffd0dd193370     127        ashmem_fops                    ashmem",
        "\n",
        "  Display all block device:",
        "    %s> dd -D ",
        "    block_device      super_block       type  bsize devname         volname              UUID",
        "    ffffff8809154280  ffffff885d8d4000  ext4  4096  mmcblk0p1       xbl_a                0c768d03-3a3c-a990-0600-daf94674e882",
        "    ffffff8809156a40  ffffff885d32c000  ext4  4096  loop13          xbl_b                fcb4ebd9-7f11-c81c-ef48-43b90e410a24",
        "    ffffff8818e60d80  ffffff885d32c000  ext4  4096  mmcblk0p5       shrm_a               4717f043-65f9-3aa8-0e23-877e2c76ca7f",
        "\n",
        "  Display all disk:",
        "    %s> dd -d ",
        "    gendisk            minor major partitions name",
        "    ffffff8802ffa000   1     1     1          ram1",
        "    ffffff8802ffb800   1     1     1          ram2",
        "    ffffff8802ffe800   1     1     1          ram0",
        "\n",
        "  Display all partition for specified disk:",
        "    %s> dd -p mmcblk0",
        "    block_device      partno start_sect sectors    size       bsize  type   devname              volname              UUID",
        "    ffffff8818e9a800  0      21364736   471040     230MB      0             mmcblk0p69           vm-persist           05bdafd5-4ec6-238c-7366-42ba33c98fb2",
        "    ffffff8818ea1ac0  0      30670848   512        256KB      0             mmcblk0p82           apdp                 dafea201-493e-7f88-ae4b-590a34946832",
        "    ffffff8818ea5d00  0      30539776   8          4KB        0             mmcblk0p81           devinfo              2e547183-c9aa-f37a-0bbc-84d081cc4394",
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

void DDriver::print_char_device(){
    std::ostringstream oss_hd;
    oss_hd  << std::left << std::setw(20)           << "char_device_struct" << " "
            << std::left << std::setw(10)           << "major"              << " "
            << std::left << std::setw(10)           << "minorct"            << " "
            << std::left << std::setw(VADDR_PRLEN  + 2)  << "cdev"          << " "
            << std::left << "name";
    fprintf(fp, "%s \n",oss_hd.str().c_str());
    for (auto& addr : for_each_char_device()) {
        uint32_t major = read_uint(addr + field_offset(char_device_struct,major),"major");
        // uint32_t baseminor = read_uint(addr + field_offset(char_device_struct,baseminor),"baseminor");
        uint32_t minorct = read_uint(addr + field_offset(char_device_struct,minorct),"minorct");
        ulong cdev_addr = read_pointer(addr + field_offset(char_device_struct, cdev),"cdev");
        std::string name = read_cstring(addr + field_offset(char_device_struct, name),64, "name");
        std::ostringstream oss;
        oss << std::left << std::setw(20)           << std::hex   << addr         << " "
            << std::left << std::setw(10)           << std::dec   << major        << " "
            << std::left << std::setw(10)           << std::dec   << minorct      << " "
            << std::left << std::setw(VADDR_PRLEN + 2)  << std::hex   << cdev_addr<< " "
            << std::left << name;
        fprintf(fp, "%s \n",oss.str().c_str());
    }
}

void DDriver::print_gendisk(){
    int major = 0;
    int minor = 0;
    int partition_cnt = 0;
    std::string name = "";
    std::ostringstream oss_hd;
    oss_hd  << std::left << std::setw(VADDR_PRLEN + 2)   << "gendisk"    << " "
            << std::left << std::setw(5)    << "minor"      << " "
            << std::left << std::setw(5)    << "major"      << " "
            << std::left << std::setw(10)    << "partitions" << " "
            << std::left << "name";
    fprintf(fp, "%s \n",oss_hd.str().c_str());
    std::set<ulong> disk_list;
    for (auto& addr : for_each_disk()) {
        disk_list.insert(addr);
    }
    for (auto& addr : disk_list) {
        major = read_uint(addr + field_offset(gendisk,major),"major");
        minor = read_uint(addr + field_offset(gendisk,minors),"minors");
        name = read_cstring(addr + field_offset(gendisk,disk_name),32, "name");
        ulong tbl_addr = 0;
        if (field_size(gendisk,part_tbl) == sizeof(void *)){
            tbl_addr = read_pointer(addr + field_offset(gendisk,part_tbl),"part_tbl");
            if (is_kvaddr(tbl_addr)){
                partition_cnt = read_uint(tbl_addr + field_offset(disk_part_tbl,len),"len");
            }
        }else{
            tbl_addr = addr + field_offset(gendisk,part_tbl);
            std::vector<ulong> ptbl = for_each_xarray(tbl_addr);
            partition_cnt = ptbl.size();
        }
        std::ostringstream oss;
        oss  << std::left << std::setw(VADDR_PRLEN + 2)  << std::hex << addr             << " "
            << std::left << std::setw(5)    << std::dec << minor            << " "
            << std::left << std::setw(5)    << std::dec << major            << " "
            << std::left << std::setw(10)   << std::dec << partition_cnt    << " "
            << std::left << name;
        fprintf(fp, "%s \n",oss.str().c_str());
    }
}

void DDriver::print_partition(std::string disk_name){
    std::vector<ulong> ptbl;
    for (auto& addr : for_each_disk()) {
        std::string name = read_cstring(addr + field_offset(gendisk,disk_name),32, "name");
        if (name != disk_name){
            continue;
        }
        ulong tbl_addr = 0;
        if (field_size(gendisk,part_tbl) == sizeof(void *)){
            tbl_addr = read_pointer(addr + field_offset(gendisk,part_tbl),"part_tbl");
            if (!is_kvaddr(tbl_addr)){
                break;
            }
            size_t len = read_uint(tbl_addr + field_offset(disk_part_tbl,len),"len");
            ulong ptb_addr = tbl_addr + field_offset(disk_part_tbl,part);
            for (size_t i = 0; i < len; i++){
                ulong hd_addr = read_pointer(ptb_addr + (i * sizeof(void *)),"part");
                if (!is_kvaddr(hd_addr)){
                    continue;
                }
                ptbl.push_back(hd_addr);
            }
        }else{
            tbl_addr = addr + field_offset(gendisk,part_tbl);
            if (!is_kvaddr(tbl_addr)){
                break;
            }
            ptbl = for_each_xarray(tbl_addr);
        }
    }
    if (ptbl.size() == 0){
        return;
    }
    std::vector<std::shared_ptr<partition>> part_list;
    for (auto& addr : ptbl) {
        std::shared_ptr<partition> part_ptr;
        if (struct_size(hd_struct) != -1){
            part_ptr = parser_hd_struct(addr);
        }else{
            part_ptr = parser_block_device(addr);
        }
        if (part_ptr == nullptr){
            continue;
        }
        part_list.push_back(part_ptr);
    }
    std::sort(part_list.begin(), part_list.end(),[&](std::shared_ptr<partition> a, std::shared_ptr<partition> b){
        return a->partno < b->partno;
    });
    if (struct_size(hd_struct) == -1 && field_offset(block_device,bd_nr_sectors) == -1){
        for (size_t i = 1; i < part_list.size() - 1; i++){
            part_list[i]->nr_sectors = part_list[i + 1]->start_sect - part_list[i]->start_sect;
        }
    }
    std::ostringstream oss_hd;
    if (struct_size(hd_struct) != -1){
        oss_hd  << std::left << std::setw(17)   << "hd_struct"  << " "
            << std::left << std::setw(6)        << "partno"     << " "
            << std::left << std::setw(10)       << "start_sect" << " "
            << std::left << std::setw(10)       << "sectors"    << " "
            << std::left << std::setw(10)       << "size"       << " "
            << std::left << std::setw(6)        << "bsize"      << " "
            << std::left << std::setw(6)        << "type"    << " "
            << std::left << std::setw(20)       << "devname"    << " "
            << std::left << std::setw(20)       << "volname"    << " "
            << std::left << "UUID";
    }else{
        oss_hd  << std::left << std::setw(17)   << "block_device"   << " "
            << std::left << std::setw(6)        << "partno"         << " "
            << std::left << std::setw(10)       << "start_sect"     << " "
            << std::left << std::setw(10)       << "sectors"        << " "
            << std::left << std::setw(10)       << "size"           << " "
            << std::left << std::setw(6)        << "bsize"          << " "
            << std::left << std::setw(6)        << "type"        << " "
            << std::left << std::setw(20)       << "devname"        << " "
            << std::left << std::setw(20)       << "volname"        << " "
            << std::left << "UUID";
    }
    fprintf(fp, "%s \n",oss_hd.str().c_str());
    for (auto& part_ptr : part_list) {
        std::ostringstream oss;
        oss  << std::left << std::setw(17)  << std::hex << part_ptr->addr         << " "
            << std::left << std::setw(6)    << std::dec << part_ptr->partno       << " "
            << std::left << std::setw(10)   << std::dec << part_ptr->start_sect   << " "
            << std::left << std::setw(10)   << std::dec << part_ptr->nr_sectors     << " "
            << std::left << std::setw(10)   << std::dec << csize(part_ptr->nr_sectors*512)  << " "
            << std::left << std::setw(6)    << std::dec << part_ptr->block_size     << " "
            << std::left << std::setw(6)    << std::dec << part_ptr->fs_type        << " "
            << std::left << std::setw(20)   << part_ptr->devname  << " "
            << std::left << std::setw(20)   << part_ptr->volname  << " "
            << std::left << part_ptr->uuid;
        fprintf(fp, "%s \n",oss.str().c_str());
    }
}

std::shared_ptr<partition> DDriver::parser_hd_struct(ulong addr){
    std::shared_ptr<partition> part_ptr = std::make_shared<partition>();
    part_ptr->addr = addr;
    if (field_offset(hd_struct,start_sect) != -1){
        part_ptr->start_sect = read_ulonglong(addr + field_offset(hd_struct,start_sect),"start_sect");
    }
    if (field_offset(hd_struct,nr_sects) != -1){
        part_ptr->nr_sectors = read_ulonglong(addr + field_offset(hd_struct,nr_sects),"nr_sects");
    }
    if (field_offset(hd_struct,partno) != -1){
        part_ptr->partno = read_uint(addr + field_offset(hd_struct,partno),"partno");
    }
    if (field_offset(hd_struct,info) != -1){
        ulong meta_info_addr = read_pointer(addr + field_offset(hd_struct,info),"info");
        if (is_kvaddr(meta_info_addr)){
            part_ptr->uuid = read_cstring(meta_info_addr + field_offset(partition_meta_info,uuid),37, "uuid");
            part_ptr->volname = read_cstring(meta_info_addr + field_offset(partition_meta_info,volname),64, "volname");
        }
    }
    if (field_offset(hd_struct,__dev) != -1){
        size_t name_addr = read_pointer(addr + field_offset(hd_struct,__dev) + field_offset(device,kobj) + field_offset(kobject,name),"device name addr");
        if (is_kvaddr(name_addr)){
            part_ptr->devname = read_cstring(name_addr,100, "device name");
        }
    }
    //find the block_device for this hd_struct
    for (auto& bd_addr : for_each_block_device()) {
        ulong bd_part_addr = read_pointer(bd_addr + field_offset(block_device,bd_part),"bd_part");
        if (bd_part_addr != addr){
            continue;
        }
        ulong bd_super = 0;
        if (field_offset(block_device,bd_super) != -1){
            bd_super = read_pointer(bd_addr + field_offset(block_device,bd_super),"bd_super");
        }
        if (is_kvaddr(bd_super)){
            if (field_offset(super_block,s_blocksize) != -1){
                part_ptr->block_size = read_ulong(bd_super + field_offset(super_block,s_blocksize),"s_blocksize");
            }
            if (field_offset(super_block,s_type) != -1){
                ulong fst_addr = read_pointer(bd_super + field_offset(super_block,s_type),"s_type");
                if (is_kvaddr(fst_addr)){
                    size_t name_addr = read_pointer(fst_addr + field_offset(file_system_type,name),"name addr");
                    if (is_kvaddr(name_addr)){
                        part_ptr->fs_type = read_cstring(name_addr,64, "name");
                    }
                }
            }
        }
    }
    return part_ptr;
}

std::shared_ptr<partition> DDriver::parser_block_device(ulong addr){
    void *buf = read_struct(addr,"block_device");
    if (!buf) {
        return nullptr;
    }
    std::shared_ptr<partition> part_ptr = std::make_shared<partition>();
    part_ptr->addr = addr;
    if (field_offset(block_device,bd_start_sect) != -1){
        part_ptr->start_sect = ULONGLONG(buf + field_offset(block_device,bd_start_sect));
    }
    if (field_offset(block_device,bd_nr_sectors) != -1){
        part_ptr->nr_sectors = ULONGLONG(buf + field_offset(block_device,bd_nr_sectors));
    }
    if (field_offset(block_device,bd_meta_info) != -1){
        ulong meta_info = ULONG(buf + field_offset(block_device,bd_meta_info));
        if (is_kvaddr(meta_info)){
            part_ptr->uuid = read_cstring(meta_info + field_offset(partition_meta_info,uuid),37, "uuid");
            part_ptr->volname = read_cstring(meta_info + field_offset(partition_meta_info,volname),64, "volname");
        }
    }
    if (field_offset(block_device,bd_block_size) != -1){
        part_ptr->block_size = UINT(buf + field_offset(block_device,bd_block_size));
    }
    if (field_offset(block_device,bd_partno) != -1){
        part_ptr->partno = USHORT(buf + field_offset(block_device,bd_partno));
    }
    if (field_offset(block_device,bd_device) != -1){
        size_t name_addr = read_pointer(addr + field_offset(block_device,bd_device) + field_offset(device,kobj) + field_offset(kobject,name),"device name addr");
        if (is_kvaddr(name_addr)){
            part_ptr->devname = read_cstring(name_addr,64, "device name");
        }
    }
    if (field_offset(block_device,bd_super) != -1){
        ulong bd_super = ULONG(buf + field_offset(block_device,bd_super));
        if (is_kvaddr(bd_super)){
            if (field_offset(super_block,s_blocksize) != -1){
                part_ptr->block_size = read_ulong(bd_super + field_offset(super_block,s_blocksize),"s_blocksize");
            }
            if (field_offset(super_block,s_type) != -1){
                ulong fst_addr = read_pointer(bd_super + field_offset(super_block,s_type),"s_type");
                if (is_kvaddr(fst_addr)){
                    size_t name_addr = read_pointer(fst_addr + field_offset(file_system_type,name),"name addr");
                    if (is_kvaddr(name_addr)){
                        part_ptr->fs_type = read_cstring(name_addr,64, "name");
                    }
                }
            }
        }
    }else{
        //find the super_block for this block_device
        ulong list_head = csymbol_value("super_blocks");
        for (const auto& bd_super : for_each_list(list_head, field_offset(super_block, s_list))) {
            ulong bd_addr = read_pointer(bd_super + field_offset(super_block,s_bdev),"s_bdev");
            if (bd_addr != part_ptr->addr){
                continue;
            }
            if (field_offset(super_block,s_blocksize) != -1){
                part_ptr->block_size = read_ulong(bd_super + field_offset(super_block,s_blocksize),"s_blocksize");
            }
            if (field_offset(super_block,s_type) != -1){
                ulong fst_addr = read_pointer(bd_super + field_offset(super_block,s_type),"s_type");
                if (is_kvaddr(fst_addr)){
                    size_t name_addr = read_pointer(fst_addr + field_offset(file_system_type,name),"name addr");
                    if (is_kvaddr(name_addr)){
                        part_ptr->fs_type = read_cstring(name_addr,64, "name");
                    }
                }
            }
        }
    }
    FREEBUF(buf);
    return part_ptr;
}

void DDriver::print_block_device(){
    uint64_t bd_block_size = 0;
    ulong bd_meta_info = 0;
    ulong bd_super = 0;
    std::string fs_type = "";
    std::string uuid = "";
    std::string volname = "";
    std::string devname = "";
    std::ostringstream oss_hd;
    std::set<ulong> bd_list;
    for (auto& addr : for_each_block_device()) {
        bd_list.insert(addr);
    }
    if (bd_list.size() == 0){
        return;
    }
    oss_hd  << std::left << std::setw(17)   << "block_device"   << " "
            << std::left << std::setw(17)   << "super_block"    << " "
            << std::left << std::setw(5)    << "type"           << " "
            << std::left << std::setw(5)    << "bsize"          << " "
            << std::left << std::setw(15)   << "devname"        << " "
            << std::left << std::setw(20)   << "volname"        << " "
            << std::left << "UUID";
    fprintf(fp, "%s \n",oss_hd.str().c_str());
    for (auto& addr : bd_list) {
        void *buf = read_struct(addr,"block_device");
        if (!buf) {
            continue;
        }
        if (field_offset(block_device,bd_meta_info) != -1){
            bd_meta_info = ULONG(buf + field_offset(block_device,bd_meta_info));
            if (is_kvaddr(bd_meta_info)){
                uuid = read_cstring(bd_meta_info + field_offset(partition_meta_info,uuid),37, "uuid");
                volname = read_cstring(bd_meta_info + field_offset(partition_meta_info,volname),64, "volname");
            }
        }
        if (field_offset(block_device,bd_super) != -1){
            bd_super = ULONG(buf + field_offset(block_device,bd_super));
            if (is_kvaddr(bd_super)){
                if (field_offset(super_block,s_blocksize) != -1){
                    bd_block_size = read_ulong(bd_super + field_offset(super_block,s_blocksize),"s_blocksize");
                }
                if (field_offset(super_block,s_type) != -1){
                    ulong fst_addr = read_pointer(bd_super + field_offset(super_block,s_type),"s_type");
                    if (is_kvaddr(fst_addr)){
                        size_t name_addr = read_pointer(fst_addr + field_offset(file_system_type,name),"name addr");
                        if (is_kvaddr(name_addr)){
                            fs_type = read_cstring(name_addr,64, "name");
                        }
                    }
                }
            }
        }else{
            //find the super_block for this block_device
            ulong list_head = csymbol_value("super_blocks");
            for (const auto& sb_addr : for_each_list(list_head, field_offset(super_block, s_list))) {
                ulong bd_addr = read_pointer(sb_addr + field_offset(super_block,s_bdev),"s_bdev");
                if (bd_addr != addr){
                    continue;
                }
                bd_super = sb_addr;
                if (field_offset(super_block,s_blocksize) != -1){
                    bd_block_size = read_ulong(sb_addr + field_offset(super_block,s_blocksize),"s_blocksize");
                }
                if (field_offset(super_block,s_type) != -1){
                    ulong fst_addr = read_pointer(sb_addr + field_offset(super_block,s_type),"s_type");
                    if (is_kvaddr(fst_addr)){
                        size_t name_addr = read_pointer(fst_addr + field_offset(file_system_type,name),"name addr");
                        if (is_kvaddr(name_addr)){
                            fs_type = read_cstring(name_addr,64, "name");
                        }
                    }
                }
            }
        }
        if (field_offset(block_device,bd_part) != -1){
            ulong bd_part = ULONGLONG(buf + field_offset(block_device,bd_part));
            if (is_kvaddr(bd_part)){
                if (field_offset(hd_struct,info) != -1){
                    ulong meta_info_addr = read_pointer(bd_part + field_offset(hd_struct,info),"info");
                    if (is_kvaddr(meta_info_addr)){
                        uuid = read_cstring(meta_info_addr + field_offset(partition_meta_info,uuid),37, "uuid");
                        volname = read_cstring(meta_info_addr + field_offset(partition_meta_info,volname),64, "volname");
                    }
                }
                if (field_offset(hd_struct,__dev) != -1){
                    size_t name_addr = read_pointer(bd_part + field_offset(hd_struct,__dev) + field_offset(device,kobj) + field_offset(kobject,name),"device name addr");
                    if (is_kvaddr(name_addr)){
                        devname = read_cstring(name_addr,100, "device name");
                    }
                }
            }
        }
        if (field_offset(block_device,bd_block_size) != -1){
            bd_block_size = UINT(buf + field_offset(block_device,bd_block_size));
        }
        if (field_offset(block_device,bd_device) != -1){
            size_t name_addr = read_pointer(addr + field_offset(block_device,bd_device) + field_offset(device,kobj) + field_offset(kobject,name),"device name addr");
            if (is_kvaddr(name_addr)){
                devname = read_cstring(name_addr,100, "device name");
            }
        }
        FREEBUF(buf);
        std::ostringstream oss;
        oss  << std::left << std::setw(17)  << std::hex     << addr         << " "
            << std::left << std::setw(17)   << std::hex     << bd_super     << " "
            << std::left << std::setw(5)    << fs_type                      << " "
            << std::left << std::setw(5)    << std::dec     << bd_block_size<< " "
            << std::left << std::setw(15)   << devname                      << " "
            << std::left << std::setw(20)   << volname                      << " "
            << std::left << uuid;
        fprintf(fp, "%s \n",oss.str().c_str());
    }
}

void DDriver::print_misc_device(){
    std::ostringstream oss_hd;
    oss_hd  << std::left << std::setw(20)           << "miscdevice" << " "
            << std::left << std::setw(10)           << "minor"      << " "
            << std::left << std::setw(30)           << "ops"        << " "
            << std::left << "name";
    fprintf(fp, "%s \n",oss_hd.str().c_str());
    for (auto& addr : for_each_misc_device()) {
        uint32_t minor = read_uint(addr + field_offset(miscdevice,minor),"minor");
        std::string name = "";
        size_t name_addr = read_pointer(addr + field_offset(miscdevice,name),"name addr");
        if (is_kvaddr(name_addr)){
            name = read_cstring(name_addr,64, "name");
        }
        std::string ops_name = "";
        size_t ops_addr = read_pointer(addr + field_offset(miscdevice,fops),"fops addr");
        if (is_kvaddr(ops_addr)){
            ulong offset;
            struct syment *sp = value_search(ops_addr, &offset);
            if (sp) {
                ops_name = sp->name;
            }
        }
        std::ostringstream oss;
        oss << std::left << std::setw(20)   << std::hex   << addr   << " "
            << std::left << std::setw(10)   << std::dec   << minor  << " "
            << std::left << std::setw(30)   << ops_name             << " "
            << std::left << name;
        fprintf(fp, "%s \n",oss.str().c_str());
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
    for (const auto& class_addr : for_each_class()) {
        std::shared_ptr<class_type> class_ptr = std::make_shared<class_type>();
        class_ptr->addr = class_addr;
        // fprintf(fp, "class_addr: %zx\n",class_addr);
        size_t name_addr = read_pointer(class_addr + field_offset(class,name),"name addr");
        if (is_kvaddr(name_addr)){
            class_ptr->name = read_cstring(name_addr,64, "class name");
        }
        if (class_ptr->name.empty()){
            continue;
        }
        if (!class_ptr->name.empty() && *class_ptr->name.rbegin() == '\n') {
            class_ptr->name.pop_back();
        }
        class_ptr->subsys_private = get_class_subsys_private(class_ptr->name);
        class_list.push_back(class_ptr);
    }
}

void DDriver::parser_bus_info(){
    for (const auto& bus_addr : for_each_bus()) {
        std::shared_ptr<bus_type> bus_ptr = std::make_shared<bus_type>();
        bus_ptr->addr = bus_addr;
        size_t name_addr = read_pointer(bus_addr + field_offset(bus_type,name),"name addr");
        if (is_kvaddr(name_addr)){
            bus_ptr->name = read_cstring(name_addr,64, "bus name");
        }
        if (bus_ptr->name.empty()){
            continue;
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
        bus_ptr->subsys_private = get_bus_subsys_private(bus_ptr->name);
        bus_list.push_back(bus_ptr);
    }
}

std::vector<std::shared_ptr<device>> DDriver::parser_class_device_list(std::string class_name){
    std::vector<std::shared_ptr<device>> device_list;
    for (const auto& device_addr : for_each_device_for_class(class_name)) {
        // fprintf(fp, "device_addr:%#zx \n",device_addr);
        std::shared_ptr<device> dev_ptr = parser_device(device_addr);
        if (dev_ptr == nullptr) continue;
        device_list.push_back(dev_ptr);
    }
    return device_list;
}

std::vector<std::shared_ptr<device>> DDriver::parser_bus_device_list(std::string bus_name){
    std::vector<std::shared_ptr<device>> device_list;
    for (const auto& device_addr : for_each_device_for_bus(bus_name)) {
        // fprintf(fp, "device_addr:%#zx \n",device_addr);
        std::shared_ptr<device> dev_ptr = parser_device(device_addr);
        if (dev_ptr == nullptr) continue;
        device_list.push_back(dev_ptr);
    }
    return device_list;
}

std::vector<std::shared_ptr<driver>> DDriver::parser_driver_list(std::string bus_name){
    std::vector<std::shared_ptr<driver>> driver_list;
    for (const auto& driver_addr : for_each_driver(bus_name)) {
        // fprintf(fp, "driver_addr:%#zx \n",driver_addr);
        std::shared_ptr<driver> driv_ptr = parser_driver(driver_addr);
        if (driv_ptr == nullptr) continue;
        for (const auto& device_addr : for_each_device_for_driver(driver_addr)) {
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
