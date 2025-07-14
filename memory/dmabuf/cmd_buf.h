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

#ifndef DMA_ION_DEFS_H_
#define DMA_ION_DEFS_H_

#include "plugin.h"
#include "dmabuf.h"
#include "heap.h"
#include "dma_heap.h"
#include "ion_heap.h"

class DmaIon : public ParserPlugin {
private:
    std::shared_ptr<Dmabuf> dmabuf_ptr;
    std::shared_ptr<Heap> heap_ptr;

public:
    DmaIon();
    void cmd_main(void) override;
    void init_offset(void) override;
    void init_command(void) override;
    DEFINE_PLUGIN_INSTANCE(DmaIon)
};

#endif // DMA_ION_DEFS_H_
