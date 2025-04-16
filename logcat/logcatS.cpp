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

#include "logcatS.h"

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wpointer-arith"

LogcatS::LogcatS(std::shared_ptr<Swapinfo> swap) : Logcat(swap){
    init_datatype_info();
}

void LogcatS::init_datatype_info(){
    field_init(SerializedLogBuffer, logs_);
    field_init(SerializedLogBuffer, sequence_);
    field_init(SerializedLogChunk, contents_);
    field_init(SerializedLogChunk, write_offset_);
    field_init(SerializedLogChunk, writer_active_);
    field_init(SerializedLogChunk, compressed_log_);
    field_init(SerializedData, size_);
    field_init(SerializedData, data_);
    struct_init(SerializedData);
    struct_init(SerializedLogChunk);
    if (field_offset(SerializedLogBuffer, logs_) == -1){
        g_offset.SerializedLogBuffer_logs_ = BITS64() ? (is_compat ? 48 : 96) : 48;
        g_offset.SerializedLogBuffer_sequence_ = BITS64() ? (is_compat ? 144 : 288) : 144;
        g_offset.SerializedLogChunk_contents_ = BITS64() ? (is_compat ? 0 : 0) : 0;
        g_offset.SerializedLogChunk_write_offset_ = BITS64() ? (is_compat ? 8 : 16) : 8;
        g_offset.SerializedLogChunk_writer_active_ = BITS64() ? (is_compat ? 16 : 24) : 16;
        g_offset.SerializedLogChunk_compressed_log_ = BITS64() ? (is_compat ? 32 : 40) : 32;
        g_offset.SerializedData_size_ = BITS64() ? (is_compat ? 4 : 8) : 4;
        g_offset.SerializedData_data_ = BITS64() ? (is_compat ? 0 : 0) : 0;
        g_size.SerializedData = BITS64() ? (is_compat ? 8 : 16) : 8;
        g_size.SerializedLogChunk = BITS64() ? (is_compat ? 56 : 80) : 56;
        g_size.SerializedLogBuffer_logs_ = BITS64() ? (is_compat ? 96 : 192) : 96;
        g_size.stdlist_node_size = (g_offset.SerializedLogBuffer_sequence_ - g_offset.SerializedLogBuffer_logs_) / 8;
    }else{
        g_offset.SerializedLogBuffer_logs_ = field_offset(SerializedLogBuffer, logs_);
        g_offset.SerializedLogBuffer_sequence_ = field_offset(SerializedLogBuffer, sequence_);
        g_offset.SerializedLogChunk_contents_ = field_offset(SerializedLogChunk, contents_);
        g_offset.SerializedLogChunk_write_offset_ = field_offset(SerializedLogChunk, write_offset_);
        g_offset.SerializedLogChunk_writer_active_ = field_offset(SerializedLogChunk, writer_active_);
        g_offset.SerializedLogChunk_compressed_log_ = field_offset(SerializedLogChunk, compressed_log_);
        g_offset.SerializedData_size_ = field_offset(SerializedData, size_);
        g_offset.SerializedData_data_ = field_offset(SerializedData, data_);
        g_size.SerializedData = struct_size(SerializedData);
        g_size.SerializedLogChunk = struct_size(SerializedLogChunk);
        g_size.SerializedLogBuffer_logs_ = field_size(SerializedLogBuffer, logs_);
        g_size.stdlist_node_size = (g_offset.SerializedLogBuffer_sequence_ - g_offset.SerializedLogBuffer_logs_) / 8;
    }
}

ulong LogcatS::parser_logbuf_addr(){
    size_t logbuf_addr;
    get_rw_vma_list();
    logbuf_addr = get_logbuf_addr_from_bss();
    if (is_uvaddr(logbuf_addr, tc_logd) &&
        logbuf_addr > min_rw_vma_addr &&
        logbuf_addr < max_rw_vma_addr){
        return logbuf_addr + g_offset.SerializedLogBuffer_logs_;
    }
    logbuf_addr = get_logbuf_addr_from_vma();
    if (is_uvaddr(logbuf_addr, tc_logd) &&
        logbuf_addr > min_rw_vma_addr &&
        logbuf_addr < max_rw_vma_addr){
        return logbuf_addr;
    }
    return 0;
}

size_t LogcatS::get_logbuf_addr_from_vma(){
    int index = 0;
    for (const auto& vma_ptr : rw_vma_list) {
        if (debug){
            std::cout << "check vma:[" << std::dec << index << "]"
                << "[" << std::hex << vma_ptr->vm_start
                << "~" << std::hex << vma_ptr->vm_end << "]"
                << std::endl;
        }
        long stdlist_addr = check_ChunkList_in_vma(vma_ptr,vma_ptr->vm_start);
        if (debug){
            if (stdlist_addr == -1) {
                std::cout << "Result: " << stdlist_addr << "\n" << std::endl;
            } else {
                std::cout << "Result: " << std::showbase << std::hex << stdlist_addr << "\n" << std::endl;
            }
        }
        index++;
        if (stdlist_addr == -1){
            continue;
        }
        bool is_match = true;
        for (size_t i = 1; i < ALL; i++){
            long check_addr = stdlist_addr + g_size.stdlist_node_size * i;
            if (debug){
                std::cout << "check Log[" << std::dec << i << "] from " << std::hex << check_addr << std::endl;
            }
            long list_addr = check_ChunkList_in_vma(vma_ptr,check_addr);
            if (debug){
                if (list_addr == -1) {
                    std::cout << "Result: " << list_addr << "\n" << std::endl;
                } else {
                    std::cout << "Result: " << std::showbase << std::hex << list_addr << "\n" << std::endl;
                }
            }
            if (list_addr == -1 || list_addr != check_addr){
                is_match = false;
                break;
            }
        }
        if (is_match){
            return static_cast<size_t>(stdlist_addr);
        }
    }
    return 0;
}

void LogcatS::get_rw_vma_list(){
    for (auto &vma_addr : for_each_vma(tc_logd->task)){
        void *vma_buf = read_struct(vma_addr, "vm_area_struct");
        if (!vma_buf) {
            continue;
        }
        ulong vm_file = ULONG(vma_buf + field_offset(vm_area_struct, vm_file));
        if(is_kvaddr(vm_file)){
            FREEBUF(vma_buf);
            continue;
        }
        ulong vm_flags = ULONG(vma_buf + field_offset(vm_area_struct, vm_flags));
        if (!(vm_flags & VM_READ) || !(vm_flags & VM_WRITE)) {
            FREEBUF(vma_buf);
            continue;
        }
        ulong vm_start = ULONG(vma_buf + field_offset(vm_area_struct, vm_start));
        ulong vm_end = ULONG(vma_buf + field_offset(vm_area_struct, vm_end));
        FREEBUF(vma_buf);
        min_rw_vma_addr = std::min(min_rw_vma_addr,vm_start);
        max_rw_vma_addr = std::max(max_rw_vma_addr,vm_end);

        std::shared_ptr<rw_vma> vma_ptr = std::make_shared<rw_vma>();
        vma_ptr->vm_start = vm_start;
        vma_ptr->vm_end = vm_end;
        rw_vma_list.push_back(vma_ptr);
    }
    if (debug){
        fprintf(fp, "min_rw_vma_addr:%#lx \n",min_rw_vma_addr);
        fprintf(fp, "max_rw_vma_addr:%#lx \n",max_rw_vma_addr);
    }
}

long LogcatS::check_ChunkList_in_vma(std::shared_ptr<rw_vma> vma_ptr,ulong list_addr){
    int pointer_size = BITS64() ? (is_compat ? 4 : sizeof(long)) : sizeof(long);
    char node_buf[3 * pointer_size];
    for (size_t stdlist_addr = list_addr; stdlist_addr < vma_ptr->vm_end; stdlist_addr += pointer_size){
        size_t tail_node, next_node, list_size;
        BZERO(node_buf, 3 * pointer_size);
        if(!swap_ptr->uread_buffer(tc_logd->task,stdlist_addr,node_buf,3 * pointer_size, "stdlist Node")){
            continue;
        }
        if (is_compat) {
            tail_node = UINT(node_buf + 0 * sizeof(uint32_t));
            next_node = UINT(node_buf + 1 * sizeof(uint32_t));
            list_size = UINT(node_buf + 2 * sizeof(uint32_t));
        } else {
            tail_node = ULONG(node_buf + 0 * sizeof(ulong));
            next_node = ULONG(node_buf + 1 * sizeof(ulong));
            list_size = ULONG(node_buf + 2 * sizeof(ulong));
        }
        tail_node = tail_node & vaddr_mask;
        next_node = next_node & vaddr_mask;
        if (!is_valid_node_addr(tail_node) || !is_valid_node_addr(next_node)){
            continue;
        }
        if (debug){
            std::cout << "addr:" << std::hex << stdlist_addr
                << " tail_node:" << std::hex << tail_node
                << " next_node:" << std::hex << next_node
                << " list_size:" << std::dec << list_size
                << std::endl;
        }
        if (list_size > 5000){
            continue;
        }
        if (list_size < 2 && next_node == tail_node){
            return stdlist_addr;
        }
        int index = 0;
        size_t prev_node_addr = stdlist_addr;
        size_t next_node_addr = next_node;
        size_t prev_node;
        while (next_node_addr > 0 && index < list_size){
            BZERO(node_buf, 3 * pointer_size);
            if(!swap_ptr->uread_buffer(tc_logd->task,next_node_addr,node_buf,3 * pointer_size, "stdlist Node")){
                break;
            }
            size_t tail_node, next_node, list_size;
            if (is_compat) {
                prev_node = UINT(node_buf + 0 * sizeof(uint32_t));
                next_node = UINT(node_buf + 1 * sizeof(uint32_t));
            } else {
                prev_node = ULONG(node_buf + 0 * sizeof(ulong));
                next_node = ULONG(node_buf + 1 * sizeof(ulong));
            }
            prev_node = prev_node & vaddr_mask;
            next_node = next_node & vaddr_mask;
            if (!is_valid_node_addr(prev_node) || !is_valid_node_addr(next_node)){
                break;
            }
            if (debug){
                std::cout << "   [" << std::dec << index << "]"
                    << "addr:" << std::hex << next_node_addr
                    << " prev_node:" << std::hex << prev_node
                    << " next_node:" << std::hex << next_node
                    << std::endl;
            }
            if (prev_node != prev_node_addr){
                break;
            }
            if (next_node == stdlist_addr){
                return stdlist_addr;
            }
            prev_node_addr = next_node_addr;
            next_node_addr = next_node;
            index += 1;
        }
    }
    return -1;
}

bool LogcatS::is_valid_node_addr(size_t addr) {
    if (addr == 0){
        return false;
    }
    if (addr < min_rw_vma_addr || addr > max_rw_vma_addr){
        return false;
    }
    return true;
}

size_t LogcatS::get_logbuf_addr_from_bss(){
    size_t logbuf_addr = swap_ptr->get_var_addr_by_bss("log_buffer", tc_logd->task, logd_symbol);
    if (!is_uvaddr(logbuf_addr,tc_logd)){
        return 0;
    }
    // static LogBuffer* log_buffer = nullptr
    if (is_compat) {
        logbuf_addr = swap_ptr->uread_uint(tc_logd->task,logbuf_addr,"read logbuf addr");
    }else{
        logbuf_addr = swap_ptr->uread_ulong(tc_logd->task,logbuf_addr,"read logbuf addr");
    }
    return logbuf_addr;
}

void LogcatS::parser_logbuf(ulong buf_addr){
    size_t log_size = g_size.SerializedLogBuffer_logs_ / 8;
    if (debug){
        fprintf(fp, "logs_addr:0x%lx log_size:%zu\n",buf_addr,log_size);
    }
    for (size_t i = 0; i <= KERNEL; i++){
        if (i >= MAIN && i <= KERNEL) {
            ulong log_list_addr = buf_addr + i * log_size;
            for(auto data_node: for_each_stdlist(log_list_addr)){
                parser_SerializedLogChunk(static_cast<LOG_ID>(i), data_node);
            }
        }
    }
}

void LogcatS::parser_SerializedLogChunk(LOG_ID log_id, ulong vaddr){
    if (!is_uvaddr(vaddr,tc_logd)){
        return;
    }
    init_datatype_info();
    ulong contents_data = 0;
    ulong contents_size = 0;
    int write_offset = 0;
    unsigned char writer_active = 0;
    ulong compressed_data = 0;
    ulong compressed_size = 0;
    if (is_compat) {
        contents_data = swap_ptr->uread_uint(tc_logd->task,vaddr
                + g_offset.SerializedLogChunk_contents_ + g_offset.SerializedData_data_,"read contents_data");
        contents_size = swap_ptr->uread_uint(tc_logd->task,vaddr
                + g_offset.SerializedLogChunk_contents_ + g_offset.SerializedData_size_ ,"read contents_size");
        write_offset = swap_ptr->uread_int(tc_logd->task,vaddr
                + g_offset.SerializedLogChunk_write_offset_,"read write_offset");
        writer_active = swap_ptr->uread_byte(tc_logd->task,vaddr
                + g_offset.SerializedLogChunk_writer_active_,"read writer_active");
        compressed_data = swap_ptr->uread_uint(tc_logd->task,vaddr
                + g_offset.SerializedLogChunk_compressed_log_ + g_offset.SerializedData_data_,"read compressed_data");
        compressed_size = swap_ptr->uread_uint(tc_logd->task,vaddr
                + g_offset.SerializedLogChunk_compressed_log_ + g_offset.SerializedData_size_,"read compressed_size");
    }else{
        contents_data = swap_ptr->uread_ulong(tc_logd->task,vaddr
                + g_offset.SerializedLogChunk_contents_ + g_offset.SerializedData_data_,"read contents_data");
        contents_size = swap_ptr->uread_ulong(tc_logd->task,vaddr
                + g_offset.SerializedLogChunk_contents_ + g_offset.SerializedData_size_ ,"read contents_size");
        write_offset = swap_ptr->uread_int(tc_logd->task,vaddr
                + g_offset.SerializedLogChunk_write_offset_,"read write_offset");
        writer_active = swap_ptr->uread_byte(tc_logd->task,vaddr
                + g_offset.SerializedLogChunk_writer_active_,"read writer_active");
        compressed_data = swap_ptr->uread_ulong(tc_logd->task,vaddr
                + g_offset.SerializedLogChunk_compressed_log_ + g_offset.SerializedData_data_,"read compressed_data");
        compressed_size = swap_ptr->uread_ulong(tc_logd->task,vaddr
                + g_offset.SerializedLogChunk_compressed_log_ + g_offset.SerializedData_size_,"read compressed_size");
    }
    if (writer_active == false){
        if (!is_uvaddr(compressed_data,tc_logd) || compressed_size == 0){
            return;
        }
        char compressed_log[compressed_size];
        if(!swap_ptr->uread_buffer(tc_logd->task,compressed_data,compressed_log,compressed_size, "compressed_log")){
            return;
        }
        size_t const rBuffSize = ZSTD_getFrameContentSize(compressed_log, compressed_size);
        if (rBuffSize == ZSTD_CONTENTSIZE_ERROR || rBuffSize == ZSTD_CONTENTSIZE_UNKNOWN) {
            std::cout << "Error determining the content size of the compressed data." << std::endl;
            return;
        }
        std::vector<char> buffer(rBuffSize);
        size_t const dSize = ZSTD_decompress(buffer.data(), buffer.size(), compressed_log, compressed_size);
        if (ZSTD_isError(dSize)) {
            std::cout << "Failed to decompress data: " << ZSTD_getErrorName(dSize) << std::endl;
            return;
        }
        // std::cout << std::string(buffer.begin(), buffer.end()) << std::endl;
        parser_SerializedLogEntry(log_id, buffer.data(),buffer.size());
    }else{
        if (!is_uvaddr(contents_data,tc_logd) || write_offset == 0){
            return;
        }
        uint32_t log_len = write_offset;
        char log_data[log_len];
        if(!swap_ptr->uread_buffer(tc_logd->task,contents_data,log_data,log_len, "contents_log")){
            return;
        }
        parser_SerializedLogEntry(log_id, log_data,log_len);
    }
}

void LogcatS::parser_SerializedLogEntry(LOG_ID log_id, char* log_data, uint32_t data_len){
    if(log_data == nullptr || data_len == 0){
        return;
    }
    // fprintf(fp,  "\n\nlog data: \n");
    // fprintf(fp, "%s", hexdump(0x1000,log_data, data_len).c_str());
    size_t pos = 0;
    char* logbuf = log_data;
    int entry_size = sizeof(SerializedLogEntry);
    size_t cnt = 0;
    while (pos + entry_size <= data_len){
        SerializedLogEntry* entry = (SerializedLogEntry*)logbuf;
        std::shared_ptr<LogEntry> log_ptr = std::make_shared<LogEntry>();
        log_ptr->logid = log_id;
        log_ptr->pid = entry->pid;
        log_ptr->tid = entry->tid;
        log_ptr->uid = entry->uid;
        log_ptr->timestamp = formatTime(entry->realtime.tv_sec,entry->realtime.tv_nsec);
        pos += entry_size;
        logbuf += entry_size;
        if(entry->msg_len <= 0){
            continue;
        }
        char log_msg[entry->msg_len + 1];
        memcpy(log_msg, logbuf, entry->msg_len);
        if (log_id == MAIN || log_id == SYSTEM || log_id == RADIO || log_id == CRASH || log_ptr->logid == KERNEL){
            parser_system_log(log_ptr,log_msg,entry->msg_len);
        }else{
            parser_event_log(log_ptr,log_msg,entry->msg_len);
        }
        pos += entry->msg_len;
        logbuf += entry->msg_len;
        log_list.push_back(log_ptr);
    }
}

#pragma GCC diagnostic pop
