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

#include "logcatR.h"

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wpointer-arith"

LogcatR::LogcatR(std::shared_ptr<Swapinfo> swap) : Logcat(swap){

}

ulong LogcatR::parser_logbuf_addr(){
    ulong logbuf_addr = swap_ptr->get_var_addr_by_bss("logBuf", tc_logd->task, logd_symbol);
    if (logbuf_addr == 0){
        return 0;
    }
    // static LogBuffer* logBuf = nullptr
    if (is_compat) {
        logbuf_addr = swap_ptr->uread_uint(tc_logd->task,logbuf_addr,"read logbuf addr");
    }else{
        logbuf_addr = swap_ptr->uread_ulong(tc_logd->task,logbuf_addr,"read logbuf addr");
    }
    fprintf(fp, "logbuf_addr:0x%lx \n",logbuf_addr);
    return logbuf_addr;
}

void LogcatR::parser_logbuf(ulong buf_addr){
    ulong LogElements_list_addr = buf_addr;
    fprintf(fp, "LogElements_list_addr:0x%lx \n",LogElements_list_addr);
    ulong LogBufferElement_addr = 0;
    for(auto data_node: for_each_stdlist(LogElements_list_addr)){
        if (is_compat) {
            LogBufferElement_addr = swap_ptr->uread_uint(tc_logd->task,data_node,"read data_node");
        }else{
            LogBufferElement_addr = swap_ptr->uread_ulong(tc_logd->task,data_node,"read data_node");
        }
        parser_LogBufferElement(LogBufferElement_addr);
    }
}

void LogcatR::parser_LogBufferElement(ulong vaddr){
    // fprintf(fp, "LogBufferElement_addr:0x%lx \n",vaddr);
    if (!is_uvaddr(vaddr,tc_logd)){
        return;
    }
    char buf_element[sizeof(LogBufferElement)];
    if(!swap_ptr->uread_buffer(tc_logd->task,vaddr,buf_element,sizeof(LogBufferElement), "LogBufferElement")){
        return;
    }
    LogBufferElement* element = (LogBufferElement*)buf_element;
    if (element->mDropped == 1){
        return;
    }
    if (element->mLogId < MAIN || element->mLogId > KERNEL) {
        return;
    }
    char log_msg[element->mMsgLen];
    std::shared_ptr<LogEntry> log_ptr = std::make_shared<LogEntry>();
    log_ptr->uid = element->mUid;
    log_ptr->pid = element->mPid;
    log_ptr->tid = element->mTid;
    log_ptr->timestamp = formatTime(element->mRealTime.tv_sec,element->mRealTime.tv_nsec);
    if (log_ptr->logid == SYSTEM || log_ptr->logid == MAIN || log_ptr->logid == KERNEL
        || log_ptr->logid == RADIO || log_ptr->logid == CRASH){
        if(swap_ptr->uread_buffer(tc_logd->task,reinterpret_cast<ulong>(element->mMsg),log_msg,element->mMsgLen, "read msg log")){
            parser_system_log(log_ptr,log_msg,element->mMsgLen);
        }
    }else{
        if(swap_ptr->uread_buffer(tc_logd->task,reinterpret_cast<ulong>(element->mMsg),log_msg,element->mMsgLen, "read bin log")){
            parser_event_log(log_ptr,log_msg,element->mMsgLen);
        }
    }
    log_list.push_back(log_ptr);
    return;
}

#pragma GCC diagnostic pop
