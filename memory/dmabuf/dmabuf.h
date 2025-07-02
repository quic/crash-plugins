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

struct attachment {
    ulong addr;
    ulong sg_table;
    enum dma_data_direction dir;
    ulong importer_priv;
    ulong priv;
    ulong dma_map_attrs;
    std::string device_name;
    std::string driver_name;
};

struct proc_info {
    struct task_context *tc;
    std::unordered_map<ulong, int> fd_map;
};

struct scatterlist {
    ulong addr;
    ulong page_link;
    unsigned int offset;
    unsigned int length;
    size_t dma_address;
    unsigned int dma_length;
};

struct dma_buf {
    ulong addr;
    ulong heap;
    ulong sg_table;
    std::vector<std::shared_ptr<scatterlist>> sgl_list;
    size_t size;
    std::string file;
    ulong f_count;
    std::vector<std::shared_ptr<attachment>> attachments;
    std::string ops_name;
    std::string exp_name;
    std::string name;
    ulong priv;
    std::vector<std::shared_ptr<proc_info>> procs;
};

class Dmabuf : public ParserPlugin {
private:
    std::vector<std::string> directions = { "DMA_BIDIRECTIONAL", "DMA_TO_DEVICE", "DMA_FROM_DEVICE", "DMA_NONE" };

public:
    std::vector<std::shared_ptr<proc_info>> proc_list;
    std::vector<std::shared_ptr<dma_buf>> buf_list;
    Dmabuf();
    void cmd_main(void) override;
    void parser_dma_bufs();
    std::shared_ptr<dma_buf> parser_dma_buf(ulong addr);
    void parser_buffer(std::shared_ptr<dma_buf> buf_ptr);
    bool sg_is_chain(ulong page_link);
    bool sg_is_last(ulong page_link);
    ulong sg_chain_ptr(ulong page_link);
    ulong sg_next(ulong sgl_addr, ulong page_link);
    void parser_sg_table(std::shared_ptr<dma_buf> buf_ptr);
    void get_dmabuf_from_proc();
    void get_proc_info(std::shared_ptr<dma_buf> buf_ptr);
    std::vector<std::shared_ptr<attachment>> parser_attachments(ulong list_head);
    void print_dma_buf_list();
    void print_attachment(std::shared_ptr<dma_buf> buf_ptr);
    void print_dma_buf(std::shared_ptr<dma_buf> buf_ptr);
    void print_proc_info(std::shared_ptr<dma_buf> buf_ptr);
    void print_sg_table(std::shared_ptr<dma_buf> buf_ptr);
    void print_dma_buf(std::string addr);
    void save_dma_buf(std::string addr);
    void print_procs();
    void print_proc(ulong pid);
};

#endif // DMABUF_DEFS_H_
