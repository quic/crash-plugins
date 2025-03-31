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

#include "dma_heap.h"

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wpointer-arith"

DmaHeap::DmaHeap(std::shared_ptr<Dmabuf> dmabuf) : Heap(dmabuf){
    field_init(plist_node,node_list);
    field_init(dma_heap,name);
    field_init(dma_heap,refcount);
    field_init(dma_heap,priv);
    field_init(dma_heap,list);
    field_init(dma_heap,ops);
    struct_init(dma_heap);
    parser_heaps();
}

void DmaHeap::print_heaps(){
    size_t name_max_len = 10;
    size_t ops_max_len = 10;
    for (auto& heap_ptr : dma_heaps) {
        name_max_len = std::max(name_max_len,heap_ptr->name.size());
        ops_max_len = std::max(ops_max_len,heap_ptr->ops.size());
    }
    std::ostringstream oss_hd;
    oss_hd << std::left << std::setw(VADDR_PRLEN + 2) << "dma_heap" << " "
        << std::left << std::setw(name_max_len + 2) << "Name" << " "
        << std::left << std::setw(4) << "ref" << " "
        << std::left << std::setw(ops_max_len + 2) << "ops" << " "
        << std::left << std::setw(VADDR_PRLEN + 2) << "priv" << " "
        << std::left << std::setw(7) << "buf_cnt" << " "
        << std::left << "total_size";
    fprintf(fp, "%s \n",oss_hd.str().c_str());
    for (const auto& heap_ptr : dma_heaps) {
        size_t total_size = 0;
        for (const auto& dma_buf : heap_ptr->bufs) {
            total_size += dma_buf->size;
        }
        std::ostringstream oss;
        oss << std::left << std::hex << std::setw(VADDR_PRLEN + 2) << heap_ptr->addr << " "
            << std::left << std::setw(name_max_len + 2) << heap_ptr->name << " "
            << std::left << std::dec << std::setw(4) << heap_ptr->refcount << " "
            << std::left << std::setw(ops_max_len + 2) << heap_ptr->ops << " "
            << std::left << std::hex << std::setw(VADDR_PRLEN + 2) << heap_ptr->priv_addr << " "
            << std::left << std::dec << std::setw(7) << heap_ptr->bufs.size() << " "
            << std::left << csize(total_size);
        fprintf(fp, "%s \n",oss.str().c_str());
    }
}

void DmaHeap::print_heap(std::string name){
    for (const auto& heap_ptr : dma_heaps) {
        if (heap_ptr->name == name){
            for (const auto& buf_ptr : heap_ptr->bufs) {
                dmabuf_ptr->print_dma_buf(buf_ptr);
            }
        }
    }
}

std::vector<ulong> DmaHeap::get_heaps(){
    std::vector<ulong> heap_list;
    if (!csymbol_exists("heap_list")){
        return heap_list;
    }
    ulong list_head = csymbol_value("heap_list");
    if (!is_kvaddr(list_head))return heap_list;
    int offset = field_offset(dma_heap,list);
    heap_list = for_each_list(list_head,offset);
    return heap_list;
}

void DmaHeap::parser_heaps(){
    std::vector<ulong> heaps = get_heaps();
    for (const auto& addr : heaps) {
        void *heap_buf = read_struct(addr,"dma_heap");
        if (!heap_buf) {
            continue;
        }
        std::shared_ptr<dma_heap> heap_ptr = std::make_shared<dma_heap>();
        heap_ptr->addr = addr;
        ulong name_addr = ULONG(heap_buf + field_offset(dma_heap,name));
        if (is_kvaddr(name_addr)){
            heap_ptr->name = read_cstring(name_addr,64, "dma_heap_name");
        }
        heap_ptr->refcount = INT(heap_buf + field_offset(dma_heap,refcount));
        heap_ptr->priv_addr = ULONG(heap_buf + field_offset(dma_heap,priv));
        heap_ptr->ops = "";
        ulong ops_addr = ULONG(heap_buf + field_offset(dma_heap,ops));
        if (is_kvaddr(ops_addr)){
            ulong offset;
            struct syment *sp = value_search(ops_addr, &offset);
            if (sp) {
                heap_ptr->ops = sp->name;
            }
        }
        for (const auto& dmabuf_ptr : dmabuf_ptr->buf_list) {
            if (dmabuf_ptr->heap == addr){
                heap_ptr->bufs.push_back(dmabuf_ptr);
            }
        }
        FREEBUF(heap_buf);
        dma_heaps.push_back(heap_ptr);
    }
}

#pragma GCC diagnostic pop
