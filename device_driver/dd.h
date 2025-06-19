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

#ifndef DEVICE_DRIVER_DEFS_H_
#define DEVICE_DRIVER_DEFS_H_

#include "plugin.h"

struct device;

struct driver {
    size_t addr;
    std::string name;
    std::string probe;
    std::string compatible;
    std::vector<std::shared_ptr<device>> device_list;
};

struct device {
    size_t addr;
    std::string name;
    std::shared_ptr<driver> driv;
};

struct bus_type {
    size_t addr;
    std::string name;
    std::string probe;
    size_t subsys_private;
    std::vector<std::shared_ptr<device>> device_list;
    std::vector<std::shared_ptr<driver>> driver_list;
};

struct class_type {
    size_t addr;
    std::string name;
    size_t subsys_private;
    std::vector<std::shared_ptr<device>> device_list;
    std::vector<std::shared_ptr<driver>> driver_list;
};

struct partition {
    ulong addr;
    int partno = 0;
    int block_size = 0;
    uint64_t start_sect = 0;
    uint64_t nr_sectors = 0;
    std::string uuid = "";
    std::string volname = "";
    std::string devname = "";
    std::string fs_type = "";
};

class DDriver : public ParserPlugin {
public:
    std::vector<std::shared_ptr<bus_type>> bus_list;
    std::vector<std::shared_ptr<class_type>> class_list;
    DDriver();

    void print_class_info();
    void cmd_main(void) override;
    void print_bus_info();
    void print_device_list();
    void print_device_driver_for_bus(std::string bus_name);
    void print_device_driver_for_class(std::string class_name);
    void print_char_device();
    void print_gendisk();
    void print_partition(std::string disk_name);
    std::shared_ptr<partition> parser_hd_struct(ulong addr);
    std::shared_ptr<partition> parser_block_device(ulong addr);
    void print_block_device();
    void print_misc_device();
    void print_device_list_for_driver(std::string driver_name);
    void print_driver_list();
    void parser_bus_info();
    std::vector<std::shared_ptr<device>> parser_bus_device_list(std::string bus_name);
    std::vector<std::shared_ptr<device>> parser_class_device_list(std::string class_name);
    void parser_class_info();
    std::shared_ptr<driver> parser_driver(size_t addr);
    std::vector<std::shared_ptr<driver>> parser_driver_list(std::string bus_name);
    std::shared_ptr<device> parser_device(size_t addr);
    DEFINE_PLUGIN_INSTANCE(DDriver)
};

#endif // DEVICE_DRIVER_DEFS_H_
