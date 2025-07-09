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

#include "logcatLE.h"

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wpointer-arith"

LogcatLE::LogcatLE(std::shared_ptr<Swapinfo> swap) : Logcat(swap){

}

ulong LogcatLE::parser_logbuf_addr(){
    size_t logbuf_addr;
    struct_init(LogBufferElement);
    if (struct_size(LogBufferElement) != -1 && !logd_symbol.empty()){
        fprintf(fp, "Looking for static logbuf \n");
        logbuf_addr = get_logbuf_addr_from_bss();
        if (logbuf_addr != 0){
            return logbuf_addr;
        }
    }
    fprintf(fp, "Looking for std::list \n");
    auto start = std::chrono::high_resolution_clock::now();
    auto vma_callback = [&](std::shared_ptr<vma_struct> vma_ptr) -> bool {
        if (!(vma_ptr->vm_flags & VM_READ) || !(vma_ptr->vm_flags & VM_WRITE)) {
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
        data_addr = task_ptr->uread_pointer(data_addr);
        if (!is_uvaddr(data_addr, tc_logd)){
            return false;
        }
        std::vector<char> buf = task_ptr->uread_obj<LogBufferElement_LE>(data_addr);
        if (buf.size() == 0){
            return false;
        }
        LogBufferElement_LE* element = reinterpret_cast<LogBufferElement_LE*>(buf.data());
        // (gdb) ptype /o LogBufferElement
        std::shared_ptr<vma_struct> exec_vma_ptr = task_ptr->get_vma(task_ptr->get_auxv(AT_ENTRY));
        if (exec_vma_ptr && (exec_vma_ptr->vm_start <= element->mVptr && element->mVptr < exec_vma_ptr->vm_end)){
            return false;
        }
        // enum log_id : unsigned int {LOG_ID_MIN, LOG_ID_MAIN = 0, LOG_ID_RADIO, LOG_ID_EVENTS, LOG_ID_SYSTEM, LOG_ID_CRASH, LOG_ID_KERNEL, LOG_ID_MAX}
        if (element->mLogId > 6){
            return false;
        }
        return true;
    };
    logbuf_addr = get_stdlist(vma_callback, obj_callback);
    auto end = std::chrono::high_resolution_clock::now();
    std::chrono::duration<double> elapsed = end - start;
    fprintf(fp, "time: %.6f s\n",elapsed.count());
    if (logbuf_addr != 0){
        return logbuf_addr;
    }
    return 0;
}

size_t LogcatLE::get_logbuf_addr_from_bss(){
    ulong logbuf_addr = task_ptr->get_var_addr_by_bss(logd_symbol, "logBuf");
    if (logbuf_addr == 0){
        return 0;
    }
    // static LogBuffer* logBuf = nullptr
    logbuf_addr = task_ptr->uread_ulong(logbuf_addr);
    return logbuf_addr;
}

void LogcatLE::parser_logbuf(ulong buf_addr){
    ulong LogElements_list_addr = buf_addr;
    fprintf(fp, "LogBuffer:%#lx \n", LogElements_list_addr);
    ulong LogBufferElement_addr = 0;
    for(auto data_node: task_ptr->for_each_stdlist(LogElements_list_addr)){
        LogBufferElement_addr = task_ptr->uread_ulong(data_node);
        parser_LogBufferElement(LogBufferElement_addr);
    }
}

void LogcatLE::parser_LogBufferElement(ulong vaddr){
    if (!is_uvaddr(vaddr,tc_logd)){
        return;
    }
    std::vector<char> buf = task_ptr->uread_obj<LogBufferElement_LE>(vaddr);
    if (buf.size() == 0){
        return;
    }
    LogBufferElement_LE* element = reinterpret_cast<LogBufferElement_LE*>(buf.data());
    if (element->mDropped == 1){
        return;
    }
    if (element->mLogId < MAIN || element->mLogId > KERNEL) {
        return;
    }
    std::shared_ptr<LogEntry> log_ptr = std::make_shared<LogEntry>();
    log_ptr->uid = element->mUid;
    log_ptr->pid = element->mPid;
    log_ptr->tid = element->mTid;
    log_ptr->logid = (LOG_ID)element->mLogId;
    log_ptr->timestamp = formatTime(element->mRealTime.tv_sec,element->mRealTime.tv_nsec);
    if (log_ptr->logid == SYSTEM || log_ptr->logid == MAIN || log_ptr->logid == KERNEL
        || log_ptr->logid == RADIO || log_ptr->logid == CRASH){
        std::vector<char> log_msg = task_ptr->read_data(reinterpret_cast<ulong>(element->mMsg),element->mMsgLen);
        if(log_msg.size() != 0){
            parser_system_log(log_ptr,log_msg.data(),element->mMsgLen);
        }
    }else{
        std::vector<char> log_msg = task_ptr->read_data(reinterpret_cast<ulong>(element->mMsg),element->mMsgLen);
        if(log_msg.size() != 0){
            parser_event_log(log_ptr,log_msg.data(),element->mMsgLen);
        }
    }
    log_list.push_back(log_ptr);
    return;
}

#pragma GCC diagnostic pop
