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

#include "ion_heap.h"

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wpointer-arith"

IonHeap::IonHeap(std::shared_ptr<Dmabuf> dmabuf) : Heap(dmabuf){
    field_init(ion_device,heaps);
    field_init(ion_heap,node);
    field_init(plist_node,node_list);
    field_init(ion_heap,name);
    field_init(ion_heap,id);
    field_init(ion_heap,flags);
    field_init(ion_heap,ops);
    field_init(ion_heap,num_of_buffers);
    field_init(ion_heap,num_of_alloc_bytes);
    field_init(ion_heap,type);
    struct_init(ion_heap);
    field_init(page, lru);
    heap_type[read_enum_val("ION_HEAP_TYPE_SYSTEM")] = "ION_HEAP_TYPE_SYSTEM";
    heap_type[read_enum_val("ION_HEAP_TYPE_DMA")] = "ION_HEAP_TYPE_DMA";
    heap_type[read_enum_val("ION_HEAP_TYPE_CUSTOM")] = "ION_HEAP_TYPE_CUSTOM";
    heap_type[read_enum_val("ION_HEAP_TYPE_MAX")] = "ION_HEAP_TYPE_MAX";
    parser_heaps();
    // print_table();
}

void IonHeap::print_heaps(){
    size_t name_max_len = 10;
    size_t ops_max_len = 10;
    for (auto& heap_ptr : ion_heaps) {
        name_max_len = std::max(name_max_len,heap_ptr->name.size());
        ops_max_len = std::max(ops_max_len,heap_ptr->ops.size());
    }
    std::ostringstream oss;
    oss << std::left << std::setw(3) << "Id" << " "
        << std::left << std::setw(VADDR_PRLEN + 2) << "ion_heap" << " "
        << std::left << std::setw(22) << "type" << " "
        << std::left << std::setw(name_max_len + 2) << "Name" << " "
        << std::left << std::setw(6) << "flags" << " "
        << std::left << std::setw(ops_max_len + 2) << "ops" << " "
        << std::left << std::setw(7) << "buf_cnt" << " "
        << std::left << "total_size"
        << "\n";
    for (const auto& heap_ptr : ion_heaps) {
        oss << std::left << std::dec << std::setw(3) << heap_ptr->id << " "
            << std::left << std::hex << std::setw(VADDR_PRLEN + 2) << heap_ptr->addr << " "
            << std::left << std::setw(22) << heap_type[heap_ptr->type] << " "
            << std::left << std::setw(name_max_len + 2) << heap_ptr->name << " "
            << std::left << std::dec << std::setw(6) << heap_ptr->flags << " "
            << std::left << std::setw(ops_max_len + 2) << heap_ptr->ops << " "
            << std::left << std::dec << std::setw(7) << heap_ptr->buf_cnt << " "
            << std::left << csize(heap_ptr->total_allocated)
            << "\n";
    }
    fprintf(fp, "%s \n", oss.str().c_str());
}

void IonHeap::print_system_heap_pool(){
    struct_init(ion_system_heap);
    struct_init(ion_msm_system_heap);
    for (const auto& heap_ptr : ion_heaps) {
        if (heap_ptr->ops == "system_heap_ops"){
            if (struct_size(ion_system_heap) != -1){
                parser_ion_system_heap(heap_ptr->addr);
            }else if (struct_size(ion_msm_system_heap) != -1){
                parser_ion_msm_system_heap(heap_ptr->addr);
            }
        }
    }
}

void IonHeap::parser_ion_system_heap(ulong addr){
    field_init(ion_system_heap,heap);
    field_init(ion_system_heap,pools);
    ulong heap_addr = addr - field_offset(ion_system_heap,heap);
    fprintf(fp, "pools: \n");
    std::ostringstream oss;
    oss  << std::left  << std::setw(VADDR_PRLEN + 2) << "page_pool" << " "
        << std::left << std::setw(5) << "order" << " "
        << std::left << std::setw(10) << "high" << " "
        << std::left << std::setw(10) << "low" << " "
        << std::left << std::setw(10) << "total";
    fprintf(fp, "   %s \n", oss.str().c_str());
    size_t pools_cnt = field_size(ion_system_heap,pools)/sizeof(void *);
    ulong pools_addr = heap_addr + field_offset(ion_system_heap,pools);
    for (size_t i = 0; i < pools_cnt; i++){
        ulong pool_addr = read_pointer(pools_addr + i * sizeof(void *),"pool");
        if (!is_kvaddr(pool_addr)){
            continue;
        }
        parser_ion_page_pool(pool_addr);
    }
}

void IonHeap::parser_ion_msm_system_heap(ulong addr){
    field_init(ion_msm_system_heap,heap);
    field_init(ion_msm_system_heap,uncached_pools);
    field_init(ion_msm_system_heap,cached_pools);
    field_init(ion_msm_system_heap,secure_pools);
    field_init(msm_ion_heap,ion_heap);
    ulong heap_addr = addr - field_offset(msm_ion_heap,ion_heap) - field_offset(ion_msm_system_heap,heap);
    fprintf(fp, "uncached_pools: \n");
    std::ostringstream oss;
    oss  << std::left  << std::setw(VADDR_PRLEN + 2) << "page_pool" << " "
        << std::left << std::setw(5) << "order" << " "
        << std::left << std::setw(10) << "high" << " "
        << std::left << std::setw(10) << "low" << " "
        << std::left << std::setw(10) << "total" << " "
        << std::left << "cached"
        << "\n";
    size_t uncached_pools_cnt = field_size(ion_msm_system_heap,uncached_pools)/sizeof(void *);
    ulong uncached_pools_addr = heap_addr + field_offset(ion_msm_system_heap,uncached_pools);
    for (size_t i = 0; i < uncached_pools_cnt; i++){
        ulong pools_addr = read_pointer(uncached_pools_addr + i * sizeof(void *),"uncached_pool");
        if (!is_kvaddr(pools_addr)){
            continue;
        }
        parser_ion_msm_page_pool(pools_addr);
    }

    oss << "\n\ncached_pools: \n";
    oss  << std::left  << std::setw(VADDR_PRLEN + 2) << "page_pool" << " "
        << std::left << std::setw(5) << "order" << " "
        << std::left << std::setw(10) << "high" << " "
        << std::left << std::setw(10) << "low" << " "
        << std::left << std::setw(10) << "total" << " "
        << std::left << "cached"
        << "\n";
    size_t cached_pools_cnt = field_size(ion_msm_system_heap,cached_pools)/sizeof(void *);
    ulong cached_pools_addr = heap_addr + field_offset(ion_msm_system_heap,cached_pools);
    for (size_t i = 0; i < uncached_pools_cnt; i++){
        ulong pools_addr = read_pointer(cached_pools_addr + i * sizeof(void *),"cached_pools");
        if (!is_kvaddr(pools_addr)){
            continue;
        }
        parser_ion_msm_page_pool(pools_addr);
    }

    oss << "\n\nsecure_pools: \n";
    oss  << std::left  << std::setw(VADDR_PRLEN + 2) << "page_pool" << " "
        << std::left << std::setw(5) << "order" << " "
        << std::left << std::setw(10) << "high" << " "
        << std::left << std::setw(10) << "low" << " "
        << std::left << std::setw(10) << "total" << " "
        << std::left << "cached"
        << "\n";
    fprintf(fp, "   %s \n", oss.str().c_str());
    size_t secure_pools_cnt = field_size(ion_msm_system_heap,secure_pools)/sizeof(void *)/cached_pools_cnt;
    ulong secure_pools_addr = heap_addr + field_offset(ion_msm_system_heap,secure_pools);
    for (size_t i = 0; i < secure_pools_cnt; i++){
        for (size_t j = 0; j < cached_pools_cnt; j++){
            ulong pools_addr = read_pointer(secure_pools_addr + i * j * sizeof(void *),"secure_pools");
            if (!is_kvaddr(pools_addr)){
                continue;
            }
            parser_ion_msm_page_pool(pools_addr);
        }
    }
}

void IonHeap::parser_ion_page_pool(ulong addr){
    struct_init(ion_page_pool);
    field_init(ion_page_pool,high_count);
    field_init(ion_page_pool,low_count);
    field_init(ion_page_pool,order);
    field_init(ion_page_pool,high_items);
    field_init(ion_page_pool,low_items);
    void *pool_buf = read_struct(addr,"ion_page_pool");
    if (!pool_buf) {
        return;
    }
    uInt order = UINT(pool_buf + field_offset(ion_page_pool,order));
    size_t buf_size = power(2, order) * page_size;
    size_t high_count = INT(pool_buf + field_offset(ion_page_pool,high_count));
    if (high_count < 0){
        high_count = 0;
    }
    high_count = high_count * buf_size;

    size_t low_count = INT(pool_buf + field_offset(ion_page_pool,low_count));
    if (low_count < 0){
        low_count = 0;
    }
    low_count = low_count * buf_size;

    // int offset = field_offset(page,lru);
    // ulong high_items_head = addr + field_offset(ion_page_pool,high_items);
    // std::vector<ulong> high_page_list = for_each_list(high_items_head,offset);

    // ulong low_items_head = addr + field_offset(ion_page_pool,low_items);
    // std::vector<ulong> low_page_list = for_each_list(low_items_head,offset);
    std::ostringstream oss;
    oss << std::left  << std::hex << std::setw(VADDR_PRLEN + 2) << addr << " "
        << std::left << std::setw(5)  << order << " "
        << std::left << std::setw(10) << csize(high_count) << " "
        << std::left << std::setw(10) << csize(low_count) << " "
        << std::left << std::setw(10) << csize(high_count + low_count);
    fprintf(fp, "   %s \n",oss.str().c_str());
}

void IonHeap::parser_ion_msm_page_pool(ulong addr){
    struct_init(ion_msm_page_pool);
    field_init(ion_msm_page_pool,high_count);
    field_init(ion_msm_page_pool,low_count);
    field_init(ion_msm_page_pool,count);
    field_init(ion_msm_page_pool,cached);
    field_init(ion_msm_page_pool,order);
    field_init(ion_msm_page_pool,high_items);
    field_init(ion_msm_page_pool,low_items);
    void *pool_buf = read_struct(addr,"ion_msm_page_pool");
    if (!pool_buf) {
        return;
    }
    uInt order = UINT(pool_buf + field_offset(ion_msm_page_pool,order));
    int buf_size = power(2, order) * page_size;
    int high_count = INT(pool_buf + field_offset(ion_msm_page_pool,high_count));
    if (high_count < 0){
        high_count = 0;
    }
    high_count = high_count * buf_size;

    int low_count = INT(pool_buf + field_offset(ion_msm_page_pool,low_count));
    if (low_count < 0){
        low_count = 0;
    }
    low_count = low_count * buf_size;

    int count = INT(pool_buf + field_offset(ion_msm_page_pool,count));
    if (count < 0){
        count = 0;
    }
    count = count * buf_size;
    bool cached = UINT(pool_buf + field_offset(ion_msm_page_pool,cached));

    // int offset = field_offset(page,lru);
    // ulong high_items_head = addr + field_offset(ion_msm_page_pool,high_items);
    // std::vector<ulong> high_page_list = for_each_list(high_items_head,offset);

    // ulong low_items_head = addr + field_offset(ion_msm_page_pool,low_items);
    // std::vector<ulong> low_page_list = for_each_list(low_items_head,offset);
    std::ostringstream oss;
    oss << std::left  << std::hex << std::setw(VADDR_PRLEN + 2) << addr << " "
        << std::left << std::setw(5)  << order << " "
        << std::left << std::setw(10) << csize(high_count) << " "
        << std::left << std::setw(10) << csize(low_count) << " "
        << std::left << std::setw(10) << csize(count) << " "
        << std::left << (cached ? "True" : "False");
    fprintf(fp, "   %s \n",oss.str().c_str());
}

void IonHeap::print_heap(std::string name){
    for (const auto& heap_ptr : ion_heaps) {
        if (heap_ptr->name == name){
            for (const auto& buf_ptr : heap_ptr->bufs) {
                dmabuf_ptr->print_dma_buf(buf_ptr);
            }
        }
    }
}

void IonHeap::parser_heaps(){
    std::vector<ulong> heaps = get_heaps();
    for (const auto& addr : heaps) {
        void *heap_buf = read_struct(addr,"ion_heap");
        if (!heap_buf) {
            return;
        }
        std::shared_ptr<ion_heap> heap_ptr = std::make_shared<ion_heap>();
        heap_ptr->addr = addr;
        ulong name_addr = ULONG(heap_buf + field_offset(ion_heap,name));
        heap_ptr->type = (enum ion_heap_type)INT(heap_buf + field_offset(ion_heap,type));
        if (is_kvaddr(name_addr)){
            heap_ptr->name = read_cstring(name_addr,64, "ion_heap_name");
        }
        heap_ptr->id = UINT(heap_buf + field_offset(ion_heap,id));
        heap_ptr->flags = ULONG(heap_buf + field_offset(ion_heap,flags));
        heap_ptr->ops = "";
        ulong ops_addr = ULONG(heap_buf + field_offset(ion_heap,ops));
        if (is_kvaddr(ops_addr)){
            ulong offset;
            struct syment *sp = value_search(ops_addr, &offset);
            if (sp) {
                heap_ptr->ops = sp->name;
            }
        }
        if(field_offset(ion_heap,num_of_buffers) != -1){
            heap_ptr->buf_cnt = ULONG(heap_buf + field_offset(ion_heap,num_of_buffers));
        }
        heap_ptr->total_allocated = ULONG(heap_buf + field_offset(ion_heap,num_of_alloc_bytes));
        FREEBUF(heap_buf);
        for (const auto& dmabuf_ptr : dmabuf_ptr->buf_list) {
            if (dmabuf_ptr->heap == addr){
                heap_ptr->bufs.push_back(dmabuf_ptr);
            }
        }
        ion_heaps.push_back(heap_ptr);
    }
}

std::vector<ulong> IonHeap::get_heaps(){
    if(csymbol_exists("heaps")){
        return get_ion_heaps_by_heaps();
    }else{
        return get_ion_heaps_by_internal_dev();
    }
}

std::vector<ulong> IonHeap::get_ion_heaps_by_internal_dev(){
    std::vector<ulong> heap_list;
    if (!csymbol_exists("internal_dev")){
        return heap_list;
    }
    ulong internal_dev_addr = read_pointer(csymbol_value("internal_dev"),"internal_dev");
    // int heap_cnt = read_int(internal_dev_addr + field_offset(ion_device,heap_cnt),"heap_cnt");
    ulong list_head = internal_dev_addr + field_offset(ion_device,heaps);
    if (!is_kvaddr(list_head))return heap_list;
    int offset = field_offset(ion_heap,node) + field_offset(plist_node,node_list);
    heap_list = for_each_list(list_head,offset);
    return heap_list;
}

std::vector<ulong> IonHeap::get_ion_heaps_by_heaps(){
    std::vector<ulong> heap_list;
    if (!csymbol_exists("heaps")){
        return heap_list;
    }
    size_t num_heaps = read_int(csymbol_value("num_heaps"),"num_heaps");
    ulong heaps = read_pointer(csymbol_value("heaps"),"heaps");
    if (!is_kvaddr(heaps))return heap_list;
    for(size_t i = 0; i < num_heaps; i++){
        ulong heap_addr = read_pointer(heaps + (i * sizeof(void *)),"heap");
        if (!is_kvaddr(heap_addr))continue;
        heap_list.push_back(heap_addr);
    }
    return heap_list;
}

#pragma GCC diagnostic pop
