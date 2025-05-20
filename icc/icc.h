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

#ifndef ICC_DEFS_H_
#define ICC_DEFS_H_

#include "plugin.h"

struct icc_req {
    ulong addr;
    bool enabled;
    uint32_t tag;
    uint32_t avg_bw;
    uint32_t peak_bw;
    std::string name;
};

struct icc_node {
    ulong addr;
    int id;
    uint32_t avg_bw;
    uint32_t peak_bw;
    ulong data;
    std::string name;
    std::vector<std::shared_ptr<icc_req>> req_list;
};

struct icc_provider {
    ulong addr;
    int users;
    std::string name;
    std::vector<std::shared_ptr<icc_node>> node_list;
};

class ICC : public ParserPlugin {
private:
    std::vector<std::shared_ptr<icc_provider>> provider_list;

public:
    ICC();
    void print_icc_request(std::string node_name);
    void print_icc_nodes(std::string provider_name);
    void print_icc_info();
    void print_icc_provider();
    void cmd_main(void) override;
    void parser_icc_provider();
    void parser_icc_node(std::shared_ptr<icc_provider> provider_ptr, ulong head);
    void parser_icc_req(std::shared_ptr<icc_node> node_ptr, ulong head);
    DEFINE_PLUGIN_INSTANCE(ICC)
};

#endif // ICC_DEFS_H_
