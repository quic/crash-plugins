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

#include "dd.h"

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wpointer-arith"

#ifndef BUILD_TARGET_TOGETHER
DEFINE_PLUGIN_COMMAND(DDriver)
#endif

/**
 * Initialize field offsets for kernel structures
 */
void DDriver::init_offset(void) {
    // ========================================================================
    // Bus and Device Core Structures
    // ========================================================================
    // bus_type: Represents a bus type (platform, pci, usb, etc.)
    field_init(bus_type, probe);

    // device: Core device structure
    field_init(device, kobj);           // Embedded kobject for sysfs
    field_init(device, driver);         // Pointer to bound driver

    // kobject: Kernel object for sysfs representation
    field_init(kobject, name);          // Device name

    // ========================================================================
    // Device Driver Structures
    // ========================================================================
    field_init(device_driver, name);            // Driver name
    field_init(device_driver, mod_name);        // Module name
    field_init(device_driver, probe);           // Probe function pointer
    field_init(device_driver, of_match_table);  // Device tree match table

    // of_device_id: Device tree matching structure
    field_init(of_device_id, compatible);       // Compatible string

    // ========================================================================
    // Character Device Structures
    // ========================================================================
    field_init(char_device_struct, major);      // Major number
    field_init(char_device_struct, baseminor);  // Base minor number
    field_init(char_device_struct, minorct);    // Minor count
    field_init(char_device_struct, cdev);       // Character device structure
    field_init(char_device_struct, name);       // Device name

    // miscdevice: Miscellaneous character device (major 10)
    field_init(miscdevice, minor);              // Minor number
    field_init(miscdevice, name);               // Device name
    field_init(miscdevice, fops);               // File operations

    // ========================================================================
    // Block Device and Disk Structures
    // ========================================================================
    struct_init(gendisk);                       // Initialize structure size
    field_init(gendisk, major);                 // Major number
    field_init(gendisk, minors);                // Number of minors
    field_init(gendisk, disk_name);             // Disk name (e.g., "sda")
    field_init(gendisk, part_tbl);              // Partition table

    // disk_part_tbl: Disk partition table (legacy)
    field_init(disk_part_tbl, len);             // Number of partitions
    field_init(disk_part_tbl, part);            // Partition array

    // block_device: Block device structure
    struct_init(block_device);                  // Initialize structure size
    field_init(block_device, bd_start_sect);    // Start sector
    field_init(block_device, bd_nr_sectors);    // Number of sectors
    field_init(block_device, bd_disk);          // Associated gendisk
    field_init(block_device, bd_mapping);       // Address space mapping
    field_init(block_device, bd_meta_info);     // Partition metadata
    field_init(block_device, bd_super);         // Superblock pointer
    field_init(block_device, bd_part);          // Partition (hd_struct)
    field_init(block_device, bd_block_size);    // Block size
    field_init(block_device, bd_partno);        // Partition number

    // ========================================================================
    // Filesystem and Superblock Structures
    // ========================================================================
    // super_block: Filesystem superblock
    field_init(super_block, s_blocksize);       // Block size
    field_init(super_block, s_type);            // Filesystem type
    field_init(super_block, s_list);            // List of superblocks
    field_init(super_block, s_bdev);            // Block device

    // file_system_type: Filesystem type descriptor
    field_init(file_system_type, name);         // Filesystem name (e.g., "ext4")
    field_init(file_system_type, fs_flags);     // Filesystem flags

    // ========================================================================
    // Partition Structures (Legacy and Modern)
    // ========================================================================
    // hd_struct: Legacy partition structure (pre-5.11 kernels)
    struct_init(hd_struct);                     // Initialize structure size
    field_init(hd_struct, info);                // Partition metadata
    field_init(hd_struct, __dev);               // Device structure
    field_init(hd_struct, start_sect);          // Start sector
    field_init(hd_struct, nr_sects);            // Number of sectors
    field_init(hd_struct, partno);              // Partition number

    // partition_meta_info: Partition metadata (UUID, volume name)
    field_init(partition_meta_info, uuid);      // Partition UUID
    field_init(partition_meta_info, volname);   // Volume name
}

/**
 * Main command entry point
 * Parses command line arguments and dispatches to appropriate handler functions
 */
void DDriver::cmd_main(void) {
    int c;
    std::string cppString;
    // Check if at least one argument is provided
    if (argcnt < 2) {
        LOGE("Insufficient arguments provided (count: %d)\n", argcnt);
        cmd_usage(pc->curcmd, SYNOPSIS);
        return;
    }

    // Initialize field offsets if not already done
    if (bus_list.empty() || class_list.empty()){
        init_offset();
    } else {
        LOGD("Using cached data: %zu buses, %zu classes\n",
             bus_list.size(), class_list.size());
    }
    // Parse bus information if not cached
    if (bus_list.empty()){
        parser_bus_info();
        // Parse devices and drivers for each bus
        for (auto& bus_ptr : bus_list) {
            bus_ptr->device_list = parser_bus_device_list(bus_ptr->name);
            bus_ptr->driver_list = parser_driver_list(bus_ptr->name);
            LOGD("Bus '%s': %zu devices, %zu drivers\n",
                    bus_ptr->name.c_str(),
                    bus_ptr->device_list.size(),
                    bus_ptr->driver_list.size());
        }
    }

    // Parse class information if not cached
    if (class_list.empty()){
        parser_class_info();
        // Parse devices for each class
        for (auto& class_ptr : class_list) {
            LOGD("Processing class: '%s' (addr: 0x%lx)\n", class_ptr->name.c_str(), class_ptr->addr);
            class_ptr->device_list = parser_class_device_list(class_ptr->name);
            LOGD("Class '%s': %zu devices\n",
                    class_ptr->name.c_str(),
                    class_ptr->device_list.size());
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
            case 'C'://list all device under specified class
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
                LOGE("Unknown option: %c\n", c);
                argerrs++;
                break;
        }
    }
    if (argerrs) {
        LOGE("Command parsing failed with %d errors\n", argerrs);
        cmd_usage(pc->curcmd, SYNOPSIS);
    }
}

void DDriver::init_command(void) {
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
}

DDriver::DDriver(){
    do_init_offset = false;
}

/**
 * Print all device class information in formatted table
 *
 * Displays a formatted table containing all device classes found in the system.
 * The table includes class address, name, and subsys_private pointer.
 *
 * Output format:
 *   class      name                 subsys_private
 *   <addr>     <class_name>         <subsys_private_addr>
 *
 */
void DDriver::print_class_info(){
    size_t name_max_len = 20;
    for (auto& class_ptr : class_list) {
        name_max_len = std::max(name_max_len,class_ptr->name.size());
    }
    std::ostringstream oss;
    oss  << std::left << std::setw(VADDR_PRLEN + 2)  << "class" << " "
            << std::left << std::setw(name_max_len)     << "name"  << " "
            << std::left                                << "subsys_private"
            << "\n";
    for (auto& class_ptr : class_list) {
        oss << std::left << std::hex << std::setw(VADDR_PRLEN + 2)  << class_ptr->addr << " "
            << std::left << std::setw(name_max_len)                 << class_ptr->name << " "
            << std::left << std::hex                                << class_ptr->subsys_private
            << "\n";
    }
    PRINT("%s \n",oss.str().c_str());
}

/**
 * Print all bus type information in formatted table
 *
 * Displays a formatted table containing all bus types found in the system.
 * The table includes bus_type address, name, subsys_private pointer, and probe function.
 *
 * Output format:
 *   bus_type   name         subsys_private   probe func
 *   <addr>     <bus_name>   <subsys_addr>    <probe_func>
 *
 */
void DDriver::print_bus_info(){
    size_t name_max_len = 10;
    for (auto& bus_ptr : bus_list) {
        name_max_len = std::max(name_max_len,bus_ptr->name.size());
    }
    std::ostringstream oss;
    oss  << std::left << std::setw(VADDR_PRLEN + 2)  << "bus_type" << " "
            << std::left << std::setw(name_max_len)     << "name" << " "
            << std::left << std::setw(16)               << "subsys_private" << " "
            << std::left                                << "probe func"
            << "\n";
    for (auto& bus_ptr : bus_list) {
        oss << std::left << std::hex << std::setw(VADDR_PRLEN + 2)  << bus_ptr->addr << " "
            << std::left << std::setw(name_max_len)                 << bus_ptr->name << " "
            << std::left << std::hex << std::setw(16)               << bus_ptr->subsys_private << " "
            << std::left                                            << bus_ptr->probe
            << "\n";
    }
    PRINT("%s \n",oss.str().c_str());
}

/**
 * Print all devices across all buses in formatted table
 *
 * Displays a comprehensive table of all devices found on all buses in the system.
 * For each device, shows its address, name, associated bus, and bound driver (if any).
 *
 * Output format:
 *   device     name                 Bus             driver     driver_name
 *   <addr>     <device_name>        <bus_name>      <drv_addr> <driver_name>
 *
 */
void DDriver::print_device_list(){
    size_t name_max_len = 10;
    for (auto& bus_ptr : bus_list) {
        for (auto& dev_ptr : bus_ptr->device_list) {
            name_max_len = std::max(name_max_len,dev_ptr->name.size());
        }
    }
    std::ostringstream oss;
    oss  << std::left << std::setw(VADDR_PRLEN + 2)  << "device" << " "
            << std::left << std::setw(name_max_len)     << "name" << " "
            << std::left << std::setw(15)               << "Bus" << " "
            << std::left << std::setw(VADDR_PRLEN + 2)  << "driver" << " "
            << std::left                                << "driver_name"
            << "\n";
    for (auto& bus_ptr : bus_list) {
        for (auto& dev_ptr : bus_ptr->device_list) {
            oss << std::left << std::hex << std::setw(VADDR_PRLEN + 2)  << dev_ptr->addr << " "
                << std::left << std::setw(name_max_len)                 << dev_ptr->name << " "
                << std::left << std::setw(15)                           << bus_ptr->name << " "
                << "\n";
            if (dev_ptr->driv != nullptr){
                oss << std::left << std::hex << std::setw(VADDR_PRLEN + 2) << dev_ptr->driv->addr << " "
                    << std::left << dev_ptr->driv->name
                    << "\n";
            }
        }
    }
    PRINT("%s \n",oss.str().c_str());
}

/**
 * Print all devices and drivers for a specific bus
 *
 * Displays two formatted tables:
 * 1. All devices on the specified bus with their bound drivers
 * 2. All drivers registered on the specified bus with their properties
 *
 * Device table format:
 *   device     name                 driver     driver_name
 *   <addr>     <device_name>        <drv_addr> <driver_name>
 *
 * Driver table format:
 *   device_driver    name            compatible          probe func
 *   <addr>           <driver_name>   <compatible_str>    <probe_func>
 *
 * @param bus_name Name of the bus to query (e.g., "platform", "pci", "usb")
 */
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
    PRINT("============================================================================\n");
    PRINT("                                All devices                                 \n");
    PRINT("============================================================================\n");
    std::ostringstream oss;
    if (device_list.size() > 0){
        size_t name_max_len = 10;
        for (auto& dev_ptr : device_list) {
            name_max_len = std::max(name_max_len,dev_ptr->name.size());
        }
        oss  << std::left << std::setw(VADDR_PRLEN + 2)  << "device" << " "
                << std::left << std::setw(name_max_len)     << "name"   << " "
                << std::left << std::setw(VADDR_PRLEN + 2)  << "driver" << " "
                << std::left                                << "driver_name"
                << "\n";
        for (auto& dev_ptr : device_list) {
            oss << std::left << std::hex << std::setw(VADDR_PRLEN + 2) << dev_ptr->addr << " "
                << std::left << std::setw(name_max_len) << dev_ptr->name << " "
                << "\n";
            if (dev_ptr->driv != nullptr){
                oss << std::left << std::hex << std::setw(VADDR_PRLEN + 2) << dev_ptr->driv->addr << " "
                    << std::left << dev_ptr->driv->name
                    << "\n";
            }
        }
    }
    oss << "\n\n\n";
    oss << "============================================================================\n";
    oss << "                                All drivers                                 \n";
    oss << "============================================================================\n";
    if (driver_list.size() > 0){
        size_t name_max_len = 10;
        size_t compat_max_len = 10;
        for (auto& driv_ptr : driver_list) {
            name_max_len = std::max(name_max_len,driv_ptr->name.size());
            compat_max_len = std::max(compat_max_len,driv_ptr->compatible.size());
        }
        oss  << std::left << std::setw(16)               << "device_driver" << " "
                << std::left << std::setw(name_max_len)     << "name" << " "
                << std::left << std::setw(compat_max_len)   << "compatible" << " "
                << std::left                                << "probe func"
                << "\n";
        for (auto& driv_ptr : driver_list) {
            oss << std::left << std::hex << std::setw(16)   << driv_ptr->addr << " "
                << std::left << std::setw(name_max_len)     << driv_ptr->name << " "
                << std::left << std::setw(compat_max_len)   << driv_ptr->compatible << " "
                << std::left << driv_ptr->probe << "\n";
        }
    }
    PRINT("%s \n",oss.str().c_str());
}

/**
 * Print all devices for a specific device class
 *
 * Displays a formatted table of all devices belonging to the specified device class.
 * Shows device address, name, and bound driver information (if any).
 *
 * Output format:
 *   device     name                 driver     driver_name
 *   <addr>     <device_name>        <drv_addr> <driver_name>
 *
 * @param class_name Name of the device class to query (e.g., "block", "net", "input")
 */
void DDriver::print_device_driver_for_class(std::string class_name){
    std::vector<std::shared_ptr<device>> device_list;
    for (auto& class_ptr : class_list) {
        if (class_ptr->name == class_name){
            device_list = class_ptr->device_list;
            break;
        }
    }
    PRINT("============================================================================\n");
    PRINT("                                All devices                                 \n");
    PRINT("============================================================================\n");
    if (device_list.size() > 0){
        size_t name_max_len = 10;
        for (auto& dev_ptr : device_list) {
            name_max_len = std::max(name_max_len,dev_ptr->name.size());
        }
        std::ostringstream oss;
        oss  << std::left << std::setw(VADDR_PRLEN + 2)   << "device" << " "
                << std::left << std::setw(name_max_len)      << "name"   << " "
                << std::left << std::setw(VADDR_PRLEN + 2)   << "driver" << " "
                << std::left                                 << "driver_name" << "\n";
        for (auto& dev_ptr : device_list) {
            oss << std::left << std::hex << std::setw(VADDR_PRLEN + 2) << dev_ptr->addr << " "
                << std::left << std::setw(name_max_len) << dev_ptr->name << " " << "\n";
            if (dev_ptr->driv != nullptr){
                oss << std::left << std::hex << std::setw(VADDR_PRLEN + 2) << dev_ptr->driv->addr << " "
                    << std::left << dev_ptr->driv->name << "\n";
            }
        }
        PRINT("%s \n",oss.str().c_str());
    }
}

/**
 * Print all character device structures in formatted table
 *
 * Displays information about all character devices registered in the system.
 * Shows major number, minor count, cdev pointer, and device name.
 *
 * Output format:
 *   char_device_struct   major      minorct    cdev               name
 *   <addr>               <major>    <count>    <cdev_addr>        <dev_name>
 */
void DDriver::print_char_device(){
    std::ostringstream oss;
    oss  << std::left << std::setw(20)           << "char_device_struct" << " "
            << std::left << std::setw(10)           << "major"              << " "
            << std::left << std::setw(10)           << "minorct"            << " "
            << std::left << std::setw(VADDR_PRLEN  + 2)  << "cdev"          << " "
            << std::left << "name" << "\n";
    for (auto& addr : for_each_char_device()) {
        uint32_t major = read_uint(addr + field_offset(char_device_struct,major),"major");
        // uint32_t baseminor = read_uint(addr + field_offset(char_device_struct,baseminor),"baseminor");
        uint32_t minorct = read_uint(addr + field_offset(char_device_struct,minorct),"minorct");
        ulong cdev_addr = read_pointer(addr + field_offset(char_device_struct, cdev),"cdev");
        std::string name = read_cstring(addr + field_offset(char_device_struct, name),64, "name");
        oss << std::left << std::setw(20)           << std::hex   << addr         << " "
            << std::left << std::setw(10)           << std::dec   << major        << " "
            << std::left << std::setw(10)           << std::dec   << minorct      << " "
            << std::left << std::setw(VADDR_PRLEN + 2)  << std::hex   << cdev_addr<< " "
            << std::left << name << "\n";
    }
    PRINT("%s \n",oss.str().c_str());
}

/**
 * Print all generic disk (gendisk) structures in formatted table
 *
 * Displays information about all block devices (disks) in the system.
 * Shows disk address, minor number, major number, partition count, and disk name.
 *
 * Output format:
 *   gendisk            minor major partitions name
 *   <addr>             <min> <maj> <count>     <disk_name>
 *
 */
void DDriver::print_gendisk(){
    int major = 0;
    int minor = 0;
    int partition_cnt = 0;
    std::string name = "";
    std::ostringstream oss;
    oss  << std::left << std::setw(VADDR_PRLEN + 2)   << "gendisk"    << " "
            << std::left << std::setw(5)    << "minor"      << " "
            << std::left << std::setw(5)    << "major"      << " "
            << std::left << std::setw(10)    << "partitions" << " "
            << std::left << "name" << "\n";
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
        oss  << std::left << std::setw(VADDR_PRLEN + 2)  << std::hex << addr             << " "
            << std::left << std::setw(5)    << std::dec << minor            << " "
            << std::left << std::setw(5)    << std::dec << major            << " "
            << std::left << std::setw(10)   << std::dec << partition_cnt    << " "
            << std::left << name << "\n";
    }
    PRINT("%s \n",oss.str().c_str());
}

/**
 * Print all partitions for a specific disk in formatted table
 *
 * Displays detailed information about all partitions on the specified disk.
 * Shows partition number, start sector, size, filesystem type, device name, volume name, and UUID.
 *
 * Output format (for hd_struct):
 *   hd_struct      partno start_sect sectors    size       bsize  type   devname    volname    UUID
 *   <addr>         <num>  <start>    <sectors>  <size_str> <bsz>  <fs>   <devname>  <volname>  <uuid>
 *
 * Output format (for block_device):
 *   block_device   partno start_sect sectors    size       bsize  type   devname    volname    UUID
 *   <addr>         <num>  <start>    <sectors>  <size_str> <bsz>  <fs>   <devname>  <volname>  <uuid>
 *
 * @param disk_name Name of the disk to query (e.g., "sda", "mmcblk0", "nvme0n1")
 */
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
    std::ostringstream oss;
    if (struct_size(hd_struct) != -1){
        oss  << std::left << std::setw(17)   << "hd_struct"  << " "
            << std::left << std::setw(6)        << "partno"     << " "
            << std::left << std::setw(10)       << "start_sect" << " "
            << std::left << std::setw(10)       << "sectors"    << " "
            << std::left << std::setw(10)       << "size"       << " "
            << std::left << std::setw(6)        << "bsize"      << " "
            << std::left << std::setw(6)        << "type"    << " "
            << std::left << std::setw(20)       << "devname"    << " "
            << std::left << std::setw(20)       << "volname"    << " "
            << std::left << "UUID" << "\n";
    }else{
        oss  << std::left << std::setw(17)   << "block_device"   << " "
            << std::left << std::setw(6)        << "partno"         << " "
            << std::left << std::setw(10)       << "start_sect"     << " "
            << std::left << std::setw(10)       << "sectors"        << " "
            << std::left << std::setw(10)       << "size"           << " "
            << std::left << std::setw(6)        << "bsize"          << " "
            << std::left << std::setw(6)        << "type"        << " "
            << std::left << std::setw(20)       << "devname"        << " "
            << std::left << std::setw(20)       << "volname"        << " "
            << std::left << "UUID" << "\n";
    }
    for (auto& part_ptr : part_list) {
        oss  << std::left << std::setw(17)  << std::hex << part_ptr->addr         << " "
            << std::left << std::setw(6)    << std::dec << part_ptr->partno       << " "
            << std::left << std::setw(10)   << std::dec << part_ptr->start_sect   << " "
            << std::left << std::setw(10)   << std::dec << part_ptr->nr_sectors     << " "
            << std::left << std::setw(10)   << std::dec << csize(part_ptr->nr_sectors*512)  << " "
            << std::left << std::setw(6)    << std::dec << part_ptr->block_size     << " "
            << std::left << std::setw(6)    << std::dec << part_ptr->fs_type        << " "
            << std::left << std::setw(20)   << part_ptr->devname  << " "
            << std::left << std::setw(20)   << part_ptr->volname  << " "
            << std::left << part_ptr->uuid  << "\n";
    }
    PRINT("%s \n",oss.str().c_str());
}

/**
 * Parse legacy hd_struct (hard disk structure) from kernel memory
 *
 * Extracts partition information from the legacy hd_struct kernel structure.
 * This structure was used in older kernel versions to represent disk partitions.
 *
 * Extracted information includes:
 * - Partition number (partno)
 * - Start sector (start_sect)
 * - Number of sectors (nr_sects)
 * - Partition metadata (UUID, volume name)
 * - Device name
 * - Filesystem type and block size (by finding associated block_device)
 *
 * @param addr Kernel virtual address of the hd_struct structure
 * @return Shared pointer to partition object containing parsed data, or nullptr on failure
 */
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
    for (auto& bd_addr : for_each_bdev()) {
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
    LOGD("=== parser_hd_struct(0x%lx) - Complete ===\n", addr);
    return part_ptr;
}

/**
 * Parse block_device structure from kernel memory
 *
 * Extracts partition information from the modern block_device kernel structure.
 * This structure is used in newer kernel versions to represent disk partitions.
 *
 * Extracted information includes:
 * - Partition number (bd_partno)
 * - Start sector (bd_start_sect)
 * - Number of sectors (bd_nr_sectors)
 * - Block size (bd_block_size)
 * - Partition metadata (UUID, volume name from bd_meta_info)
 * - Device name
 * - Filesystem type (from associated super_block)
 *
 * @param addr Kernel virtual address of the block_device structure
 * @return Shared pointer to partition object containing parsed data, or nullptr on failure
 */
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

/**
 * Print all block devices in formatted table
 *
 * Displays comprehensive information about all block devices in the system.
 * Shows block device address, associated super_block, filesystem type, block size,
 * device name, volume name, and UUID.
 *
 * Output format:
 *   block_device      super_block       type  bsize devname         volname              UUID
 *   <bd_addr>         <sb_addr>         <fs>  <bsz> <devname>       <volname>            <uuid>
 */
void DDriver::print_block_device(){
    uint64_t bd_block_size = 0;
    ulong bd_meta_info = 0;
    ulong bd_super = 0;
    std::string fs_type = "";
    std::string uuid = "";
    std::string volname = "";
    std::string devname = "";
    std::ostringstream oss;
    std::set<ulong> bd_list;
    for (auto& addr : for_each_bdev()) {
        bd_list.insert(addr);
    }
    if (bd_list.size() == 0){
        return;
    }
    oss  << std::left << std::setw(17)   << "block_device"   << " "
            << std::left << std::setw(17)   << "super_block"    << " "
            << std::left << std::setw(5)    << "type"           << " "
            << std::left << std::setw(5)    << "bsize"          << " "
            << std::left << std::setw(15)   << "devname"        << " "
            << std::left << std::setw(20)   << "volname"        << " "
            << std::left << "UUID" << "\n";
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
        oss  << std::left << std::setw(17)  << std::hex     << addr         << " "
            << std::left << std::setw(17)   << std::hex     << bd_super     << " "
            << std::left << std::setw(5)    << fs_type                      << " "
            << std::left << std::setw(5)    << std::dec     << bd_block_size<< " "
            << std::left << std::setw(15)   << devname                      << " "
            << std::left << std::setw(20)   << volname                      << " "
            << std::left << uuid << "\n";
    }
    PRINT("%s \n",oss.str().c_str());
}

/**
 * Print all miscellaneous devices in formatted table
 *
 * Displays information about all miscellaneous character devices registered in the system.
 * Miscellaneous devices are character devices that share major number 10.
 * Shows device address, minor number, file operations structure name, and device name.
 *
 * Output format:
 *   miscdevice           minor      ops                            name
 *   <addr>               <minor>    <fops_symbol_name>             <dev_name>
 *
 */
void DDriver::print_misc_device(){
    std::ostringstream oss;
    oss  << std::left << std::setw(20)           << "miscdevice" << " "
            << std::left << std::setw(10)           << "minor"      << " "
            << std::left << std::setw(30)           << "ops"        << " "
            << std::left << "name" << "\n";
    for (auto& addr : for_each_misc_dev()) {
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
        oss << std::left << std::setw(20)   << std::hex   << addr   << " "
            << std::left << std::setw(10)   << std::dec   << minor  << " "
            << std::left << std::setw(30)   << ops_name             << " "
            << std::left << name << "\n";
    }
    PRINT("%s \n",oss.str().c_str());
}

/**
 * Print all devices bound to a specific driver
 *
 * Displays a formatted table of all devices that are currently bound to the specified driver.
 * Shows device address and device name for each bound device.
 *
 * Output format:
 *      device     name
 *      <addr>     <device_name>
 *
 * @param driver_name Name of the driver to query (e.g., "ahci", "e1000e", "usbhid")
 */
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
    std::ostringstream oss;
    oss << std::left << "   " << std::setw(VADDR_PRLEN + 2) << "device" << " "
        << std::left << std::setw(name_max_len) << "name" << "\n";
    for (auto& dev_ptr : device_list) {
        oss << std::left << "   " << std::hex << std::setw(VADDR_PRLEN + 2) << dev_ptr->addr << " "
            << std::left << std::setw(name_max_len) << dev_ptr->name << " " << "\n";
    }
    PRINT("%s \n",oss.str().c_str());
}

/**
 * Print all drivers across all buses in formatted table
 *
 * Displays a comprehensive table of all device drivers registered on all buses in the system.
 * Shows driver address, name, associated bus, device tree compatible string, and probe function.
 *
 * Output format:
 *   device_driver    name                 Bus         compatible          probe func
 *   <addr>           <driver_name>        <bus_name>  <compatible_str>    <probe_func>
 *
 */
void DDriver::print_driver_list(){
    size_t name_max_len = 10;
    size_t compat_max_len = 10;
    for (auto& bus_ptr : bus_list) {
        for (auto& driv_ptr : bus_ptr->driver_list) {
            name_max_len = std::max(name_max_len,driv_ptr->name.size());
            compat_max_len = std::max(compat_max_len,driv_ptr->compatible.size());
        }
    }
    std::ostringstream oss;
    oss  << std::left << std::setw(16)               << "device_driver" << " "
            << std::left << std::setw(name_max_len)     << "name" << " "
            << std::left << std::setw(15)               << "Bus" << " "
            << std::left << std::setw(compat_max_len)   << "compatible" << " "
            << std::left                                << "probe func"
            << "\n";
    for (auto& bus_ptr : bus_list) {
        for (auto& driv_ptr : bus_ptr->driver_list) {
            oss << std::left << std::hex << std::setw(16) << driv_ptr->addr << " "
                << std::left << std::setw(name_max_len) << driv_ptr->name << " "
                << std::left << std::setw(15) << bus_ptr->name << " "
                << std::left << std::setw(compat_max_len) << driv_ptr->compatible << " "
                << std::left << driv_ptr->probe
                << "\n";
        }
    }
    PRINT("%s \n",oss.str().c_str());
}

/**
 * Parse all device class information from kernel memory
 * Iterates through all device classes and extracts their properties
 */
void DDriver::parser_class_info(){
    int class_count = 0;
    for (const auto& class_addr : for_each_class()) {
        LOGD("Processing class #%d at address: 0x%lx\n", class_count + 1, class_addr);
        if (!is_kvaddr(class_addr)) {
            LOGE("Invalid class address 0x%lx, skipping\n", class_addr);
            continue;
        }
        std::shared_ptr<class_type> class_ptr = std::make_shared<class_type>();
        class_ptr->addr = class_addr;
        // Read the class name from kernel memory
        size_t name_addr = read_pointer(class_addr + field_offset(class,name),"name addr");
        if (!is_kvaddr(name_addr)){
            LOGE("Invalid name address 0x%lx for class at 0x%lx, skipping\n",
                 name_addr, class_addr);
            continue;
        }
        class_ptr->name = read_cstring(name_addr, 64, "class name");
        // Skip if name is empty
        if (class_ptr->name.empty()){
            LOGE("Empty class name at address 0x%lx, skipping\n", class_addr);
            continue;
        }
        // Remove trailing newline if present
        if (*class_ptr->name.rbegin() == '\n') {
            class_ptr->name.pop_back();
        }
        LOGD("Class name: '%s' subsys_private: 0x%lx \n", class_ptr->name.c_str(),class_ptr->subsys_private);
        // Get the subsys_private pointer for this class
        class_ptr->subsys_private = get_class_subsys_private(class_ptr->name);
        class_list.push_back(class_ptr);
        class_count++;
    }
}

/**
 * Parse all bus type information from kernel memory
 * Iterates through all bus types and extracts their properties including probe functions
 */
void DDriver::parser_bus_info(){
    std::ostringstream oss;
    int bus_count = 0;
    for (const auto& bus_addr : for_each_bus()) {
        LOGD("Processing bus #%d at address: 0x%lx\n", bus_count + 1, bus_addr);
        if (!is_kvaddr(bus_addr)) {
            LOGE("Invalid bus address 0x%lx, skipping\n", bus_addr);
            continue;
        }
        std::shared_ptr<bus_type> bus_ptr = std::make_shared<bus_type>();
        bus_ptr->addr = bus_addr;
        // Read the bus name from kernel memory
        size_t name_addr = read_pointer(bus_addr + field_offset(bus_type,name),"name addr");
        if (!is_kvaddr(name_addr)){
            LOGE("Invalid name address 0x%lx for bus at 0x%lx, skipping\n",
                 name_addr, bus_addr);
            continue;
        }
        bus_ptr->name = read_cstring(name_addr, 128, "bus name");
        // Skip if name is empty
        if (bus_ptr->name.empty()){
            LOGE("Empty bus name at address 0x%lx, skipping\n", bus_addr);
            continue;
        }
        // Read and resolve the probe function address
        size_t probe_addr = read_pointer(bus_addr + field_offset(bus_type,probe),"probe addr");
        if (is_kvaddr(probe_addr)){
            ulong offset;
            struct syment *sp = value_search(probe_addr, &offset);
            oss.str("");
            oss.clear();
            if (sp) {
                // Found symbol, format as "symbol+offset"
                oss << sp->name << "+" << offset;
            } else {
                // Symbol not found, use raw address
                oss << std::hex << probe_addr;
            }
            bus_ptr->probe = oss.str();
        }else{
            bus_ptr->probe = "";
        }

        // Get the subsys_private pointer for this bus
        bus_ptr->subsys_private = get_bus_subsys_private(bus_ptr->name);
        LOGD("Bus name:%s subsys_private:0x%lx\n", bus_ptr->name.c_str(), bus_ptr->subsys_private);
        bus_list.push_back(bus_ptr);
        bus_count++;
    }
    LOGD("Successfully parsed: %d bus types\n", bus_count);
}

/**
 * Parse all devices belonging to a specific device class
 * @param class_name The name of the device class
 * @return Vector of device pointers belonging to the class
 */
std::vector<std::shared_ptr<device>> DDriver::parser_class_device_list(std::string class_name){
    std::vector<std::shared_ptr<device>> device_list;
    int device_count = 0;
    for (const auto& device_addr : for_each_device_for_class(class_name)) {
        LOGD("Parsing device #%d at address: 0x%lx\n", device_count + 1, device_addr);
        std::shared_ptr<device> dev_ptr = parser_device(device_addr);
        if (dev_ptr == nullptr) {
            LOGE("Failed to parse device at 0x%lx\n", device_addr);
            continue;
        }
        LOGD("Successfully parsed device: '%s'\n", dev_ptr->name.c_str());
        device_list.push_back(dev_ptr);
        device_count++;
    }
    return device_list;
}

/**
 * Parse all devices belonging to a specific bus
 * @param bus_name The name of the bus
 * @return Vector of device pointers on the bus
 */
std::vector<std::shared_ptr<device>> DDriver::parser_bus_device_list(std::string bus_name){
    std::vector<std::shared_ptr<device>> device_list;
    int device_count = 0;
    for (const auto& device_addr : for_each_device_for_bus(bus_name)) {
        LOGD("Parsing device #%d at address: 0x%lx for bus %s\n", device_count + 1, device_addr, bus_name.c_str());
        std::shared_ptr<device> dev_ptr = parser_device(device_addr);
        if (dev_ptr == nullptr) {
            LOGE("Failed to parse device at 0x%lx\n", device_addr);
            continue;
        }
        LOGD("Successfully parsed device: '%s'\n", dev_ptr->name.c_str());
        device_list.push_back(dev_ptr);
        device_count++;
    }
    return device_list;
}

/**
 * Parse all drivers registered on a specific bus
 * Also parses all devices bound to each driver
 * @param bus_name The name of the bus
 * @return Vector of driver pointers on the bus
 */
std::vector<std::shared_ptr<driver>> DDriver::parser_driver_list(std::string bus_name){
    std::vector<std::shared_ptr<driver>> driver_list;
    int driver_count = 0;
    int failed_driver_count = 0;
    for (const auto& driver_addr : for_each_driver(bus_name)) {
        LOGD("Parsing driver #%d at address: 0x%lx\n", driver_count + 1, driver_addr);
        std::shared_ptr<driver> driv_ptr = parser_driver(driver_addr);
        if (driv_ptr == nullptr) {
            LOGE("Failed to parse driver at 0x%lx\n", driver_addr);
            failed_driver_count++;
            continue;
        }
        // Parse all devices bound to this driver
        int bound_device_count = 0;
        for (const auto& device_addr : for_each_device_for_driver(driver_addr)) {
            std::shared_ptr<device> dev_ptr = parser_device(device_addr);
            if (dev_ptr == nullptr) {
                LOGE("Failed to parse bound device at 0x%lx\n", device_addr);
                continue;
            }
            driv_ptr->device_list.push_back(dev_ptr);
            bound_device_count++;
        }
        LOGD("Driver '%s': bound %d devices \n",driv_ptr->name.c_str(), bound_device_count);
        driver_list.push_back(driv_ptr);
        driver_count++;
    }
    return driver_list;
}

/**
 * Parse a single device structure from kernel memory
 * Extracts device name and associated driver information
 *
 * This function reads the device structure from kernel memory and extracts:
 * - Device name (through kobject->name pointer chain)
 * - Associated driver information (if device is bound to a driver)
 *
 * @param addr Kernel virtual address of the device structure
 * @return Shared pointer to parsed device, or nullptr if invalid address
 */
std::shared_ptr<device> DDriver::parser_device(size_t addr){
    // Validate the address is a kernel virtual address
    if (!is_kvaddr(addr)) {
        LOGE("Invalid device address 0x%lx\n", addr);
        return nullptr;
    }
    LOGD("Parsing device at address 0x%lx\n", addr);
    // Create new device object to store parsed information
    std::shared_ptr<device> dev_ptr = std::make_shared<device>();
    dev_ptr->addr = addr;
    // Read device name through kobject->name pointer chain
    // Path: device->kobj->name
    size_t kobj_offset = field_offset(device, kobj);
    size_t name_offset = field_offset(kobject, name);
    size_t name_addr = read_pointer(addr + kobj_offset + name_offset, "device name addr");
    if (is_kvaddr(name_addr)){
        // Read the device name string from kernel memory
        dev_ptr->name = read_cstring(name_addr, 100, "device name");
    }else{
        // Invalid name address, set empty string
        dev_ptr->name = "";
        LOGE("Invalid device name address 0x%lx, using empty string\n", name_addr);
    }
    // Read associated driver if device is bound to one
    // Path: device->driver
    size_t driver_offset = field_offset(device, driver);
    size_t driver_addr = read_pointer(addr + driver_offset, "driver addr");
    if (is_kvaddr(driver_addr)){
        // Device is bound to a driver, parse the driver information
        LOGD("Device bound to driver at 0x%lx\n", driver_addr);
        dev_ptr->driv = parser_driver(driver_addr);
    } else {
        // Device is not bound to any driver
        LOGD("Device '%s' is not bound to any driver\n", dev_ptr->name.c_str());
        dev_ptr->driv = nullptr;
    }
    return dev_ptr;
}

/**
 * Parse a single driver structure from kernel memory
 * Extracts driver name, probe function, and device tree compatible string
 * @param addr Kernel virtual address of the device_driver structure
 * @return Shared pointer to parsed driver, or nullptr if invalid
 */
std::shared_ptr<driver> DDriver::parser_driver(size_t addr){
    // Validate the address is a kernel virtual address
    if (!is_kvaddr(addr)) {
        LOGE("Invalid driver address 0x%lx\n", addr);
        return nullptr;
    }
    LOGD("Parsing driver at address 0x%lx\n", addr);
    std::shared_ptr<driver> driv_ptr = std::make_shared<driver>();
    driv_ptr->addr = addr;
    // Read driver name
    size_t name_offset = field_offset(device_driver, name);
    size_t name_addr = read_pointer(addr + name_offset, "driver name addr");
    if (is_kvaddr(name_addr)){
        driv_ptr->name = read_cstring(name_addr, 100, "driver name");
    }else{
        driv_ptr->name = "";
        LOGE("Invalid driver name address 0x%lx\n", name_addr);
    }
    // Read and resolve probe function address
    size_t probe_offset = field_offset(device_driver, probe);
    size_t probe_addr = read_pointer(addr + probe_offset, "probe addr");
    std::ostringstream oss;
    if (is_kvaddr(probe_addr)){
        ulong offset;
        struct syment *sp = value_search(probe_addr, &offset);
        if (sp) {
            // Found symbol, format as "symbol+offset"
            oss << sp->name << "+" << offset;
        } else {
            // Symbol not found, use raw address
            oss << std::hex << probe_addr;
        }
        driv_ptr->probe = oss.str();
        oss.str("");
    }else{
        driv_ptr->probe = "";
    }
    // Read device tree compatible string if present
    size_t match_table_offset = field_offset(device_driver, of_match_table);
    size_t match_table = read_pointer(addr + match_table_offset, "match_table addr");
    if (is_kvaddr(match_table)){
        driv_ptr->compatible = read_cstring(match_table + field_offset(of_device_id,compatible), 128, "compatible");
    }else{
        driv_ptr->compatible = "";
    }
    return driv_ptr;
}

#pragma GCC diagnostic pop
