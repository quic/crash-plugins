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

#ifndef CMA_DEFS_H_
#define CMA_DEFS_H_

#include "plugin.h"

struct cma_mem {
    ulong addr;
    ulong base_pfn;
    ulong count;
    ulong bitmap;
    int order_per_bit;
    std::string name;
    ulong allocated_size;
};

class Cma : public PaserPlugin {
public:
    std::vector<std::shared_ptr<cma_mem>> mem_list;
    Cma();

    void cmd_main(void) override;
    void parser_cma_areas();
    int get_cma_used_size(std::shared_ptr<cma_mem> cma);
    void print_cma_areas();
    void print_cma_page_status(std::string name,bool alloc);
    ulong cma_bitmap_maxno(std::shared_ptr<cma_mem> cma);
    DEFINE_PLUGIN_INSTANCE(Cma)
};

#endif // CMA_DEFS_H_
