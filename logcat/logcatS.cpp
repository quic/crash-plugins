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

}

void LogcatS::init_datatype_info(){
    field_init(SerializedLogBuffer, logs_);
    if (field_offset(SerializedLogBuffer, logs_) == -1){
        g_offset.SerializedLogBuffer_logs_ = (BITS64() && !task_ptr->is_compat()) ? 96 : 48;
        g_offset.SerializedLogBuffer_sequence_ = (BITS64() && !task_ptr->is_compat()) ? 288 : 144;
        g_offset.SerializedLogChunk_contents_ = (BITS64() && !task_ptr->is_compat()) ? 0 : 0;
        g_offset.SerializedLogChunk_write_offset_ = (BITS64() && !task_ptr->is_compat()) ? 16 : 8;
        g_offset.SerializedLogChunk_writer_active_ = (BITS64() && !task_ptr->is_compat()) ? 24 : 16;
        g_offset.SerializedLogChunk_compressed_log_ = (BITS64() && !task_ptr->is_compat()) ? 40 : 32;
        g_offset.SerializedData_size_ = (BITS64() && !task_ptr->is_compat()) ? 8 : 4;
        g_offset.SerializedData_data_ = (BITS64() && !task_ptr->is_compat()) ? 0 : 0;
        g_size.SerializedData = (BITS64() && !task_ptr->is_compat()) ? 16 : 8;
        g_size.SerializedLogChunk = (BITS64() && !task_ptr->is_compat()) ? 80 : 56;
        g_size.SerializedLogBuffer_logs_ = (BITS64() && !task_ptr->is_compat()) ? 192 : 96;
        g_size.stdlist_node_size = (g_offset.SerializedLogBuffer_sequence_ - g_offset.SerializedLogBuffer_logs_) / 8;
    }else{
        field_init(SerializedLogBuffer, sequence_);
        field_init(SerializedLogChunk, contents_);
        field_init(SerializedLogChunk, write_offset_);
        field_init(SerializedLogChunk, writer_active_);
        field_init(SerializedLogChunk, compressed_log_);
        field_init(SerializedData, size_);
        field_init(SerializedData, data_);
        struct_init(SerializedData);
        struct_init(SerializedLogChunk);
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
    init_datatype_info();
    // 1. find the logbuf addr from bss
    field_init(SerializedLogBuffer, logs_);
    if (field_offset(SerializedLogBuffer, logs_) != -1 && !logd_symbol.empty()){
        fprintf(fp, "Looking for static logbuf \n");
        logbuf_addr = get_logbuf_addr_from_bss();
        if (logbuf_addr != 0){
            logbuf_addr += g_offset.SerializedLogBuffer_logs_;
            if (check_SerializedLogChunk_list_array(logbuf_addr)){
                return logbuf_addr;
            }
        }
    }
    std::chrono::time_point<std::chrono::high_resolution_clock, std::chrono::nanoseconds> start, end;
    std::chrono::duration<double> elapsed;

    // 2. find the logbuf addr from register
    if (BITS64() && !task_ptr->is_compat()) {
        fprintf(fp, "Looking for register\n");
        start = std::chrono::high_resolution_clock::now();
        logbuf_addr = get_logbuf_addr_from_register();
        end = std::chrono::high_resolution_clock::now();
        elapsed = end - start;
        fprintf(fp, "time: %.6f s\n",elapsed.count());
        if (logbuf_addr != 0){
            return logbuf_addr;
        }
    }

    // 3. find the logbuf addr from vma
    /*
    *      Scan VMA         SerializedLogBuffer         Core
    *   --------------    -->  -------------        --------------
    *   |            |    |    |   vtbl    |----    |            |
    *   |------------|test|    |-----------|   |in  |------------|
    *   |  VMA (RW)  |-----    |-----------|   ---> | logd .text |
    *   |------------|  |    --|reader_list|        |------------|
    *   |  VMA (RW)  |---  --| |   tags    |        |            |
    *   |------------|     | --|   stats   |        |------------|
    *   |            |     |   |-----------|   ---> |    stack   |
    *   --------------     |   -------------   |in  --------------
    *                      |--------------------
    * Find logbuf based on the class layout characteristics of SerializedLogBuffer
    */
    fprintf(fp, "Looking for SerializedLogBuffer \n");
    start = std::chrono::high_resolution_clock::now();
    logbuf_addr = get_SerializedLogBuffer_from_vma();
    end = std::chrono::high_resolution_clock::now();
    elapsed = end - start;
    fprintf(fp, "time: %.6f s\n",elapsed.count());
    if (logbuf_addr != 0){
        return logbuf_addr + g_offset.SerializedLogBuffer_logs_;
    }

    // 4. find the logbuf addr from std::list
    fprintf(fp, "Looking for std::list \n");
    start = std::chrono::high_resolution_clock::now();
    auto vma_callback = [&](std::shared_ptr<vma_struct> vma_ptr) -> bool {
        if (!(vma_ptr->vm_flags & VM_READ) || !(vma_ptr->vm_flags & VM_WRITE)) {
            return false;
        }
        if (vma_ptr->name.find("alloc") == std::string::npos &&
            vma_ptr->name.find("scudo:primary") == std::string::npos){
            return false;
        }
        return true;
    };
    // check if this node is LogBufferElement
    auto obj_callback = [&](ulong node_addr) -> bool {
        if (!is_uvaddr(node_addr,tc_logd)){
            return false;
        }
        ulong data_addr = node_addr + 2 * task_ptr->get_pointer_size();
        std::vector<char> chunk_buf = task_ptr->read_data(data_addr,g_size.SerializedLogChunk);
        if (chunk_buf.size() == 0){
            return false;
        }
        ulong contents_data = 0;
        ulong contents_size = 0;
        ulong write_offset = 0;
        bool write_active = 0;
        ulong compressed_data = 0;
        ulong compressed_size = 0;
        if (BITS64() && !task_ptr->is_compat()) {
            contents_data = ULONG(chunk_buf.data() + g_offset.SerializedLogChunk_contents_ + g_offset.SerializedData_data_) & task_ptr->vaddr_mask;
            contents_size = ULONG(chunk_buf.data() + g_offset.SerializedLogChunk_contents_ + g_offset.SerializedData_size_) & task_ptr->vaddr_mask;
            write_offset = UINT(chunk_buf.data() + g_offset.SerializedLogChunk_write_offset_ ) & task_ptr->vaddr_mask;
            write_active = BOOL(chunk_buf.data() + g_offset.SerializedLogChunk_writer_active_ ) & task_ptr->vaddr_mask;
            compressed_data = ULONG(chunk_buf.data() + g_offset.SerializedLogChunk_compressed_log_ + g_offset.SerializedData_data_) & task_ptr->vaddr_mask;
            compressed_size = ULONG(chunk_buf.data() + g_offset.SerializedLogChunk_compressed_log_ + g_offset.SerializedData_size_) & task_ptr->vaddr_mask;
        }else{
            contents_data = UINT(chunk_buf.data() + g_offset.SerializedLogChunk_contents_ + g_offset.SerializedData_data_) & task_ptr->vaddr_mask;
            contents_size = UINT(chunk_buf.data() + g_offset.SerializedLogChunk_contents_ + g_offset.SerializedData_size_) & task_ptr->vaddr_mask;
            write_offset = UINT(chunk_buf.data() + g_offset.SerializedLogChunk_write_offset_ ) & task_ptr->vaddr_mask;
            write_active = BOOL(chunk_buf.data() + g_offset.SerializedLogChunk_writer_active_ ) & task_ptr->vaddr_mask;
            compressed_data = UINT(chunk_buf.data() + g_offset.SerializedLogChunk_compressed_log_ + g_offset.SerializedData_data_) & task_ptr->vaddr_mask;
            compressed_size = UINT(chunk_buf.data() + g_offset.SerializedLogChunk_compressed_log_ + g_offset.SerializedData_size_) & task_ptr->vaddr_mask;
        }
        if (write_active == true && contents_data != 0 && contents_size != 0 &&
            write_offset != 0 && write_offset < contents_size) { // uncompressed chunk
            return true;
        } else if (write_active == false && compressed_data != 0 &&
            compressed_size != 0 && write_offset != 0 &&  compressed_size < write_offset) { // compressed chunk
            return true;
        }
        return false;
    };
    logbuf_addr = get_stdlist(vma_callback, obj_callback);
    end = std::chrono::high_resolution_clock::now();
    elapsed = end - start;
    fprintf(fp, "time: %.6f s\n",elapsed.count());
    if (logbuf_addr != 0){
        return logbuf_addr;
    }
    return 0;
}

/*
Find logbuf based virtual class
*/
size_t LogcatS::get_SerializedLogBuffer_from_vma() {
    auto vma_callback = [&](std::shared_ptr<vma_struct> vma_ptr) -> bool {
        if (!(vma_ptr->vm_flags & VM_WRITE)) {
            return false;
        }
        return true;
    };
    std::string libname = task_ptr->uread_cstring(task_ptr->get_auxv(AT_EXECFN), 64);
    // fprintf(fp, "libname:%s \n", libname);
    if (BITS64() && !task_ptr->is_compat()) {
        auto obj_callback = [&](SerializedLogBuffer64_t* obj) -> bool {
            bool match = true;
            std::shared_ptr<vma_struct> stack_vma_ptr = task_ptr->get_vma(task_ptr->get_auxv(AT_PLATFORM));
            if(stack_vma_ptr){
                match &= task_ptr->is_contains(stack_vma_ptr, obj->reader_list_);
                match &= task_ptr->is_contains(stack_vma_ptr, obj->tags_);
                match &= task_ptr->is_contains(stack_vma_ptr, obj->stats_);
            }
            return match;
        };
        return task_ptr->search_obj<SerializedLogBuffer64_t,uint64_t>(libname, false, vma_callback, obj_callback,10);
    } else {
        auto obj_callback = [&](SerializedLogBuffer32_t* obj) -> bool {
            bool match = true;
            std::shared_ptr<vma_struct> stack_vma_ptr = task_ptr->get_vma(task_ptr->get_auxv(AT_PLATFORM));
            if(stack_vma_ptr){
                match &= task_ptr->is_contains(stack_vma_ptr, obj->reader_list_);
                match &= task_ptr->is_contains(stack_vma_ptr, obj->tags_);
                match &= task_ptr->is_contains(stack_vma_ptr, obj->stats_);
            }
            return match;
        };
        return task_ptr->search_obj<SerializedLogBuffer32_t,uint32_t>(libname, false, vma_callback, obj_callback,10);
    }
}

/*
Find logbuf based on X22 register
*/
size_t LogcatS::get_logbuf_addr_from_register(){
#if defined(ARM64)
    ulong pt_regs_addr = GET_STACKTOP(tc_logd->task) - machdep->machspec->user_eframe_offset;
    uint64_t* regs = (uint64_t*)read_memory(pt_regs_addr, 31 * sizeof(uint64_t), "user_pt_regs");
    if (debug){
        fprintf(fp, "user_pt_regs:%#lx \n", pt_regs_addr);
        for (int i = 0; i < 31; i++){
            fprintf(fp, "regs[%d]:%#lx \n", i,regs[i] & task_ptr->vaddr_mask );
        }
    }
    uint64_t x21 = regs[21] & task_ptr->vaddr_mask;
    if (x21 > 0 && is_uvaddr(x21, tc_logd)){
        x21 += g_offset.SerializedLogBuffer_logs_;
        if (check_SerializedLogChunk_list_array(x21)){
            FREEBUF(regs);
            return x21;
        }
    }
    uint64_t x22 = regs[22] & task_ptr->vaddr_mask;
    if (x22 > 0 && is_uvaddr(x22, tc_logd)){
        x22 += g_offset.SerializedLogBuffer_logs_;
        if (check_SerializedLogChunk_list_array(x22)){
            FREEBUF(regs);
            return x22;
        }
    }
    uint64_t x23 = regs[23] & task_ptr->vaddr_mask;
    if (x23 > 0 && is_uvaddr(x23, tc_logd)){
        x23 += g_offset.SerializedLogBuffer_logs_;
        if (check_SerializedLogChunk_list_array(x23)){
            FREEBUF(regs);
            return x23;
        }
    }
    FREEBUF(regs);
#endif
    return 0;
}

bool LogcatS::check_SerializedLogChunk_list_array(ulong addr){
    bool match = true;
    for (size_t i = 0; i < ALL; i++){
        ulong log_list_addr = addr + g_size.stdlist_node_size * i;
        ulong res_addr = 0;
        // Do not use
        ulong list_size = 0;
        if (BITS64() && !task_ptr->is_compat()) {
            res_addr = task_ptr->check_stdlist<list_node64_t, uint64_t>(log_list_addr, nullptr, list_size);
        } else {
            res_addr = task_ptr->check_stdlist<list_node32_t, uint32_t>(log_list_addr, nullptr, list_size);
        }
        if (debug){
            fprintf(fp, "check Log:[%zu] from %#lx, res:%#lx \n", i, log_list_addr, res_addr);
        }
        if (res_addr > 0 && res_addr == log_list_addr){
            match &= true;
        }else{
            match &= false;
        }
    }
    return match;
}

// Find logbuf based on static address
size_t LogcatS::get_logbuf_addr_from_bss(){
    size_t logbuf_addr = task_ptr->get_var_addr_by_bss(logd_symbol, "log_buffer");
    if (!is_uvaddr(logbuf_addr,tc_logd)){
        return 0;
    }
    // static LogBuffer* log_buffer = nullptr
    logbuf_addr = task_ptr->uread_ulong(logbuf_addr);
    return logbuf_addr;
}

void LogcatS::parser_logbuf(ulong buf_addr){
    size_t log_size = g_size.SerializedLogBuffer_logs_ / 8;
    if (debug){
        fprintf(fp, "logs_addr:%#lx log_size:%zd\n",buf_addr,log_size);
    }
    for (size_t i = 0; i <= KERNEL; i++){
        if (i >= MAIN && i <= KERNEL) {
            ulong log_list_addr = buf_addr + i * log_size;
            for(auto data_node: task_ptr->for_each_stdlist(log_list_addr)){
                parser_SerializedLogChunk(static_cast<LOG_ID>(i), data_node);
            }
        }
    }
}

void LogcatS::parser_SerializedLogChunk(LOG_ID log_id, ulong vaddr){
    if (!is_uvaddr(vaddr,tc_logd)){
        return;
    }
    ulong contents_data = 0;
    int write_offset = 0;
    bool writer_active = false;
    ulong compressed_data = 0;
    ulong compressed_size = 0;
    std::vector<char> chunk_buf = task_ptr->read_data(vaddr,g_size.SerializedLogChunk);
    if (chunk_buf.size() == 0){
        return;
    }
    if (BITS64() && !task_ptr->is_compat()) {
        contents_data = ULONG(chunk_buf.data() + g_offset.SerializedLogChunk_contents_ + g_offset.SerializedData_data_) & task_ptr->vaddr_mask;
        write_offset = UINT(chunk_buf.data() + g_offset.SerializedLogChunk_write_offset_ ) & task_ptr->vaddr_mask;
        writer_active = BOOL(chunk_buf.data() + g_offset.SerializedLogChunk_writer_active_ );
        compressed_data = ULONG(chunk_buf.data() + g_offset.SerializedLogChunk_compressed_log_ + g_offset.SerializedData_data_) & task_ptr->vaddr_mask;
        compressed_size = ULONG(chunk_buf.data() + g_offset.SerializedLogChunk_compressed_log_ + g_offset.SerializedData_size_) & task_ptr->vaddr_mask;
    }else{
        contents_data = UINT(chunk_buf.data() + g_offset.SerializedLogChunk_contents_ + g_offset.SerializedData_data_) & task_ptr->vaddr_mask;
        write_offset = UINT(chunk_buf.data() + g_offset.SerializedLogChunk_write_offset_ ) & task_ptr->vaddr_mask;
        writer_active = BOOL(chunk_buf.data() + g_offset.SerializedLogChunk_writer_active_ );
        compressed_data = UINT(chunk_buf.data() + g_offset.SerializedLogChunk_compressed_log_ + g_offset.SerializedData_data_) & task_ptr->vaddr_mask;
        compressed_size = UINT(chunk_buf.data() + g_offset.SerializedLogChunk_compressed_log_ + g_offset.SerializedData_size_) & task_ptr->vaddr_mask;
    }
    if (writer_active == false){
        if (!is_uvaddr(compressed_data,tc_logd) || compressed_size == 0){
            return;
        }
        std::vector<char> compressed_log = task_ptr->read_data(compressed_data,compressed_size);
        if (compressed_log.size() == 0){
            fprintf(fp, "compressed_log \n");
            return;
        }
        size_t const rBuffSize = ZSTD_getFrameContentSize(compressed_log.data(), compressed_size);
        if (rBuffSize == ZSTD_CONTENTSIZE_ERROR || rBuffSize == ZSTD_CONTENTSIZE_UNKNOWN) {
            if(debug) fprintf(fp, "Error determining the content size: %#lx of the compressed data.\n", compressed_size);
            return;
        }
        std::vector<char> buffer(rBuffSize);
        size_t const dSize = ZSTD_decompress(buffer.data(), buffer.size(), compressed_log.data(), compressed_size);
        if (ZSTD_isError(dSize)) {
            if(debug) fprintf(fp, "Failed to decompress data: %s \n", ZSTD_getErrorName(dSize));
            return;
        }
        // std::cout << std::string(buffer.begin(), buffer.end()) << std::endl;
        parser_SerializedLogEntry(log_id, buffer.data(),buffer.size());
    }else{
        if (!is_uvaddr(contents_data,tc_logd) || write_offset == 0){
            return;
        }
        uint32_t log_len = write_offset;
        std::vector<char> log_data = task_ptr->read_data(contents_data,log_len);
        if (log_data.size() == 0){
            return;
        }
        parser_SerializedLogEntry(log_id, log_data.data(), log_len);
    }
}

void LogcatS::parser_SerializedLogEntry(LOG_ID log_id, char* log_data, uint32_t data_len){
    // fprintf(fp,  "\n\nlog data: \n");
    // fprintf(fp, "%s", hexdump(0x1000, log_data, data_len).c_str());
    size_t pos = 0;
    char* logbuf = log_data;
    int entry_size = sizeof(SerializedLogEntry);
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
        /* memory corruption, drop it */
        const size_t remaining = data_len - pos;
        if(log_ptr->pid == 0 || log_ptr->pid > 100000 || log_ptr->uid > 100000 || log_ptr->tid > 100000 || (entry->msg_len > remaining)){
            fprintf(fp, "pid/uid/tid is abnormal[%d, %d, %d], msg_len:%#x, total_len:%u, will save to raw data\n", log_ptr->pid, log_ptr->uid, log_ptr->tid, entry->msg_len, data_len);
            char filename[256];
            snprintf(filename, sizeof(filename), "%u.bin", data_len);
            FILE *file = fopen(filename, "wb");
            if (!file) break;
            fwrite(log_data, 1, data_len, file);
            fclose(file);
            break;
        }
        if (log_id == MAIN || log_id == SYSTEM || log_id == RADIO || log_id == CRASH || log_id == KERNEL){
            parser_system_log(log_ptr, (char *)logbuf, entry->msg_len);
        }else{
            parser_event_log(log_ptr, (char *)logbuf, entry->msg_len);
        }
        pos += entry->msg_len;
        logbuf += entry->msg_len;
        log_list.push_back(log_ptr);
    }
}

#pragma GCC diagnostic pop
