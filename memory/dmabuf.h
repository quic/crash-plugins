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

#ifndef DMABUF_DEFS_H_
#define DMABUF_DEFS_H_

#include "plugin.h"

enum dma_data_direction {
  DMA_BIDIRECTIONAL = 0,
  DMA_TO_DEVICE = 1,
  DMA_FROM_DEVICE = 2,
  DMA_NONE = 3,
};

struct dma_buf_map {
    union {
        void *vaddr_iomem;
        void *vaddr;
    };
    bool is_iomem;
};

struct dma_buf_attachment {
    ulong addr;
    ulong sg_table;
    enum dma_data_direction dir;
    ulong importer_priv;
    ulong priv;
    ulong dma_map_attrs;
    std::string device_name;
    std::string driver_name;
};

struct dma_buf {
    ulong addr;
    size_t size;
    ulong file;
    ulong f_count;
    std::vector<std::shared_ptr<dma_buf_attachment>> attachments;
    unsigned int vmapping_counter;
    struct dma_buf_map vmap_ptr;
    std::string ops_name;
    std::string exp_name;
    std::string name;
    ulong priv;
};

class Dmabuf : public PaserPlugin {
public:
    static const int SHOW_DMA_BUF = 0x0001;
    static const int SHOW_ATTACH = 0x0002;
    std::vector<std::string> directions = { "DMA_BIDIRECTIONAL", "DMA_TO_DEVICE", "DMA_FROM_DEVICE", "DMA_NONE" };
    std::vector<std::shared_ptr<dma_buf>> buf_list;
    Dmabuf();

    void cmd_main(void) override;
    void parser_dma_bufs();
    std::vector<std::shared_ptr<dma_buf_attachment>> parser_dma_buf_attachment(ulong list_head);
    void print_dma_buf_list(int flag);
    void print_dma_buf(std::string addr);
    DEFINE_PLUGIN_INSTANCE(Dmabuf)
};

#endif // DMABUF_DEFS_H_
