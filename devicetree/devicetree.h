// Copyright (c) 2024-2025 Qualcomm Innovation Center, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause-Clear

#ifndef DEVICE_TREE_DEFS_H_
#define DEVICE_TREE_DEFS_H_

#include "plugin.h"
#include <arpa/inet.h>
#include <algorithm>

struct DdrRange {
    size_t address;
    size_t size;
};

struct Property {
    ulong addr;
    int length;
    std::string name;
    void *value;
};

struct device_node {
    ulong addr;
    std::string name;
    std::string full_name;
    std::string node_path;
    std::vector<std::shared_ptr<Property>> props;
    std::shared_ptr<device_node> child;
    std::shared_ptr<device_node> sibling;
};

class Devicetree : public PaserPlugin {
private:
    std::vector<std::string> str_props={
        "model",
        "compatible",
        "bootargs",
        "name",
        "function",
        "label",
        "fsmgr_flags",
        "pins",
        "parts",
        "serial",
        "hsuart",
        "names",
    };

    std::vector<std::string> int_props={
        "phandle",
        "reg",
        "size",
        "cells",
        "addr",
        "offset",
        "id",
        "strength",
    };

public:
    Devicetree();
    ulong root_addr;
    std::shared_ptr<device_node> root_node;
    std::unordered_map<ulong, std::shared_ptr<device_node>> node_addr_maps;
    std::unordered_map<std::string, std::shared_ptr<device_node>> node_path_maps;

    void cmd_main(void) override;
    std::shared_ptr<Property> getprop(ulong node_addr,const std::string& name);
    std::vector<DdrRange> get_ddr_size();
    std::vector<std::shared_ptr<device_node>> find_node_by_name(const std::string& name);
    std::shared_ptr<device_node> find_node_by_addr(ulong addr);
    bool is_str_prop(const std::string& name);
    bool is_int_prop(const std::string& name);
    std::vector<DdrRange> parse_memory_regs(std::shared_ptr<Property> prop);
    std::vector<std::shared_ptr<Property>> read_propertys(ulong addr);
    std::shared_ptr<device_node> read_node(const std::string& path, ulong node_addr);
};

#endif // DEVICE_TREE_DEFS_H_
