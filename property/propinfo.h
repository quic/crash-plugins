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

#ifndef PROP_INFO_DEFS_H_
#define PROP_INFO_DEFS_H_

#include "plugin.h"
#include "memory/swapinfo.h"
#include "../utils/utask.h"

struct prop_area{
    uint32_t bytes_used_;
    unsigned int serial_;
    uint32_t magic_;
    uint32_t version_;
    uint32_t reserved_[28];
    char data_[0];
};

struct prop_bt{
    uint32_t namelen;
    unsigned int prop;
    unsigned int left;
    unsigned int right;
    unsigned int children;
    char name[0];
};

struct prop_info {
    unsigned int serial;
    union {
        char value[92];
        struct {
            char error_message[56];
            uint32_t offset;
        } long_property;
    };
    char name[0];
};

struct symbol {
    std::string name;
    std::string path;
};

struct offset_list {
    int SystemProperties_contexts_;
    int ContextsSerialized_context_nodes_;
    int ContextsSerialized_num_context_nodes_;
    int ContextsSerialized_serial_prop_area_;
    int ContextNode_pa_;
    int ContextNode_filename_;
    int ContextNode_context_;
    int prop_bt_prop;
    int prop_area_data_;
    int prop_info_name;
};

struct size_list {
    int ContextNode;
};

class PropInfo : public ParserPlugin {
private:
    bool debug = false;
    struct task_context *tc_init;
    bool is_compat;
    size_t pa_size;
    size_t pa_data_size;
    struct offset_list g_offset;
    struct size_list g_size;

    std::string get_symbol_file(std::string name);
    void print_propertys();
    bool parser_prop_area(size_t vaddr);
    void parser_prop_bt(size_t root, size_t prop_bt_addr);
    void parser_prop_info(size_t prop_info_addr);
    bool for_each_prop(uint32_t prop_bt_off, size_t vma_len, char *vma_data);
    std::string cleanString(const std::string &str);

protected:
    std::shared_ptr<Swapinfo> swap_ptr;
    std::shared_ptr<UTask> task_ptr;
    std::unordered_map<std::string, std::string> prop_map; //<name, val>

public:
    std::vector<symbol> symbol_list = {
        {"libc.so", ""},
    };

    std::string get_prop(std::string name);
    void parser_prop_by_init();
    bool parser_propertys();
    PropInfo(std::shared_ptr<Swapinfo> swap);
    ~PropInfo();
    void cmd_main(void) override;
    void init_offset(void) override;
    void init_command(void) override;

};

#endif // PROP_INFO_DEFS_H_
