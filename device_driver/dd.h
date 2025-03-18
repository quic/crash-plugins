// Copyright (c) 2024-2025 Qualcomm Innovation Center, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause-Clear

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

class DDriver : public PaserPlugin {
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
    void print_device_list_for_driver(std::string driver_name);
    void print_driver_list();
    void parser_bus_info();
    std::vector<std::shared_ptr<device>> parser_device_list(size_t subsys_addr, int off);
    std::vector<std::shared_ptr<driver>> parser_driver_list(size_t subsys_addr, int off);
    void parser_class_info();
    std::shared_ptr<driver> parser_driver(size_t addr);
    std::shared_ptr<device> parser_device(size_t addr);
    DEFINE_PLUGIN_INSTANCE(DDriver)
};

#endif // DEVICE_DRIVER_DEFS_H_
