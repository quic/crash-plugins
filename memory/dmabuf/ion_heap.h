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

#ifndef ION_HEAP_DEFS_H_
#define ION_HEAP_DEFS_H_

#include "heap.h"
#include "dmabuf.h"

enum ion_heap_type {
    ION_HEAP_TYPE_SYSTEM = 0,
    ION_HEAP_TYPE_DMA = 2,
    ION_HEAP_TYPE_CUSTOM = 16,
    ION_HEAP_TYPE_MAX = 31,
};

struct ion_heap {
    ulong addr;
    enum ion_heap_type type;
    std::string ops;
    unsigned long flags;
    unsigned int id;
    std::string name;
    uint64_t buf_cnt;
    uint64_t total_allocated;
    std::vector<std::shared_ptr<dma_buf>> bufs;
};

class IonHeap : public Heap {
private:
    std::unordered_map<int, std::string> heap_type;
    std::vector<std::shared_ptr<ion_heap>> ion_heaps;

    std::vector<ulong> get_ion_heaps_by_internal_dev();
    std::vector<ulong> get_ion_heaps_by_heaps();
    std::vector<ulong> get_heaps() override;
    void parser_heaps() override;
    void print_heaps() override;
    void print_system_heap_pool() override;
    void parser_ion_system_heap(ulong addr);
    void parser_ion_msm_system_heap(ulong addr);
    void parser_page_pool(ulong addr);
    void parser_ion_page_pool(ulong addr);
    void parser_ion_msm_page_pool(ulong addr);
    void print_heap(std::string name);

public:
    IonHeap(std::shared_ptr<Dmabuf> dmabuf);
};

#endif // ION_HEAP_DEFS_H_
