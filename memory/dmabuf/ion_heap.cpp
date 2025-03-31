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
    std::ostringstream oss_hd;
    oss_hd << std::left << std::setw(3) << "Id" << " "
        << std::left << std::setw(VADDR_PRLEN + 2) << "ion_heap" << " "
        << std::left << std::setw(22) << "type" << " "
        << std::left << std::setw(name_max_len + 2) << "Name" << " "
        << std::left << std::setw(6) << "flags" << " "
        << std::left << std::setw(ops_max_len + 2) << "ops" << " "
        << std::left << std::setw(7) << "buf_cnt" << " "
        << std::left << "total_size";
    fprintf(fp, "%s \n",oss_hd.str().c_str());
    for (const auto& heap_ptr : ion_heaps) {
        std::ostringstream oss;
        oss << std::left << std::dec << std::setw(3) << heap_ptr->id << " "
            << std::left << std::hex << std::setw(VADDR_PRLEN + 2) << heap_ptr->addr << " "
            << std::left << std::setw(22) << heap_type[heap_ptr->type] << " "
            << std::left << std::setw(name_max_len + 2) << heap_ptr->name << " "
            << std::left << std::dec << std::setw(6) << heap_ptr->flags << " "
            << std::left << std::setw(ops_max_len + 2) << heap_ptr->ops << " "
            << std::left << std::dec << std::setw(7) << heap_ptr->buf_cnt << " "
            << std::left << csize(heap_ptr->total_allocated);
        fprintf(fp, "%s \n",oss.str().c_str());
    }
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
    int num_heaps = read_int(csymbol_value("num_heaps"),"num_heaps");
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
