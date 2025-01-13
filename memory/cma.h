// Copyright (c) 2024-2025 Qualcomm Innovation Center, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause-Clear

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
