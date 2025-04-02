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

void DmaHeap::print_system_heap_pool(){
    for (const auto& heap_ptr : dma_heaps) {
        if (heap_ptr->ops == "system_heap_ops"){
            parser_ion_system_heap(heap_ptr);
        }
    }
}

void DmaHeap::parser_ion_system_heap(std::shared_ptr<dma_heap> heap_ptr){
    if (!is_kvaddr(heap_ptr->priv_addr)){
        return;
    }
    struct_init(qcom_system_heap);
    field_init(qcom_system_heap,uncached);
    field_init(qcom_system_heap,pool_list);
    ulong pools_addr = read_pointer(heap_ptr->priv_addr + field_offset(qcom_system_heap,pool_list),"pools");
    if (!is_kvaddr(pools_addr)){
        return;
    }
    fprintf(fp, "%s: \n",heap_ptr->name.c_str());
    std::ostringstream oss_hd;
    oss_hd  << std::left  << std::setw(VADDR_PRLEN + 2) << "page_pool" << " "
        << std::left << std::setw(5) << "order" << " "
        << std::left << std::setw(10) << "high" << " "
        << std::left << std::setw(10) << "low" << " "
        << std::left << std::setw(10) << "total";
    fprintf(fp, "   %s \n",oss_hd.str().c_str());
    for (size_t i = 0; i < 3; i++){
        ulong pool_addr = read_pointer(pools_addr + i * sizeof(void *),"pool");
        if (!is_kvaddr(pool_addr)){
            continue;
        }
        parser_dynamic_page_pool(pool_addr);
    }
    fprintf(fp, "\n");
}

void DmaHeap::parser_dynamic_page_pool(ulong addr){
    struct_init(dynamic_page_pool);
    field_init(dynamic_page_pool,high_count);
    field_init(dynamic_page_pool,low_count);
    field_init(dynamic_page_pool,count);
    field_init(dynamic_page_pool,order);
    field_init(dynamic_page_pool,high_items);
    field_init(dynamic_page_pool,low_items);
    void *pool_buf = read_struct(addr,"dynamic_page_pool");
    if (!pool_buf) {
        return;
    }
    uInt order = UINT(pool_buf + field_offset(dynamic_page_pool,order));
    int buf_size = power(2, order) * page_size;
    int high_count = INT(pool_buf + field_offset(dynamic_page_pool,high_count));
    if (high_count < 0){
        high_count = 0;
    }
    high_count = high_count * buf_size;

    int low_count = INT(pool_buf + field_offset(dynamic_page_pool,low_count));
    if (low_count < 0){
        low_count = 0;
    }
    low_count = low_count * buf_size;

    int count = INT(pool_buf + field_offset(dynamic_page_pool,count));
    if (count < 0){
        count = 0;
    }
    count = count * buf_size;
    // int offset = field_offset(page,lru);
    // ulong high_items_head = addr + field_offset(dynamic_page_pool,high_items);
    // std::vector<ulong> high_page_list = for_each_list(high_items_head,offset);

    // ulong low_items_head = addr + field_offset(dynamic_page_pool,low_items);
    // std::vector<ulong> low_page_list = for_each_list(low_items_head,offset);
    std::ostringstream oss;
    oss << std::left  << std::hex << std::setw(VADDR_PRLEN + 2) << addr << " "
        << std::left  << std::setw(5)  << order << " "
        << std::left  << std::setw(10) << csize(high_count) << " "
        << std::left  << std::setw(10) << csize(low_count) << " "
        << std::left  << std::setw(10) << csize(count);
    fprintf(fp, "   %s \n",oss.str().c_str());
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
