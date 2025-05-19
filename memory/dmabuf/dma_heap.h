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

#ifndef DMA_HEAP_DEFS_H_
#define DMA_HEAP_DEFS_H_

#include "heap.h"
#include "dmabuf.h"

struct dma_heap {
    ulong addr;
    std::string ops;
    ulong priv_addr;
    int refcount;
    std::string name;
    uint64_t buf_cnt;
    uint64_t total_allocated;
    std::vector<std::shared_ptr<dma_buf>> bufs;
};

class DmaHeap : public Heap {
public:
    std::vector<std::shared_ptr<dma_heap>> dma_heaps;
    DmaHeap(std::shared_ptr<Dmabuf> dmabuf);
    std::vector<ulong> get_heaps() override;
    void parser_heaps() override;
    void print_heaps() override;
    void print_system_heap_pool() override;
    void parser_ion_system_heap(std::shared_ptr<dma_heap> heap_ptr);
    void parser_dynamic_page_pool(ulong addr);
    void print_heap(std::string name);
};

#endif // DMA_HEAP_DEFS_H_
