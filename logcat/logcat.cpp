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

#include "logcat/logcat.h"
#include <dirent.h> // for directory operations
#include <sys/stat.h> // for file status
#include "logcat.h"

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wpointer-arith"

Logcat::Logcat(std::shared_ptr<Swapinfo> swap) : swap_ptr(swap){
    field_init(vm_area_struct, vm_start);
    field_init(vm_area_struct, vm_end);
    field_init(vm_area_struct, vm_file);
    field_init(vm_area_struct, vm_mm);
    field_init(vm_area_struct, detached);
    field_init(vm_area_struct, vm_flags);
    field_init(file, f_vfsmnt);
    field_init(thread_info, flags);
    for(ulong task_addr: for_each_process()){
        struct task_context *tc = task_to_context(task_addr);
        if (!tc){
            continue;
        }
        std::string name = tc->comm;
        if (name == "logd"){
            tc_logd = tc;
            break;
        }
    }
    if (tc_logd){
        field_init(thread_info,flags);
        fill_thread_info(tc_logd->thread_info);
        if (BITS64() && field_offset(thread_info, flags) != -1){
            ulong thread_info_flags = ULONG(tt->thread_info + field_offset(thread_info, flags));
            if(thread_info_flags & (1 << 22)){
                is_compat = true;
            }
        }
    }else{
        fprintf(fp, "Can't found logd process !");
    }
}

Logcat::~Logcat(){

}

void Logcat::cmd_main(void) {

}

std::string Logcat::getLogLevelChar(LogLevel level) {
    switch (level) {
        case LOG_DEFAULT: return "D";
        case LOG_VERBOSE: return "V";
        case LOG_DEBUG: return "D";
        case LOG_INFO: return "I";
        case LOG_WARN: return "W";
        case LOG_ERROR: return "E";
        case LOG_FATAL: return "F";
        case LOG_SILENT: return "S";
        default: return "";
    }
}

void Logcat::parser_logcat_log(){
    if (logd_symbol.empty()){
        fprintf(fp, "Can't found logd symbol, please load logd symbol first ! \n");
        return;
    }
    if (log_list.size() > 0){
        return;
    }
    ulong logbuf_vaddr = parser_logbuf_addr();
    if (!is_uvaddr(logbuf_vaddr,tc_logd)){
        fprintf(fp, "invaild vaddr:0x%lx \n",logbuf_vaddr);
        return;
    }
    parser_logbuf(logbuf_vaddr);
}

bool Logcat::isWhitespaceOrNewline(const std::string& str) {
    return std::all_of(str.begin(), str.end(), [](unsigned char c) {
        return std::isspace(c);
    });
}

void Logcat::print_logcat_log(LOG_ID id){
    // fprintf(fp, "log_list len:%zu  \n",log_list.size());
    for (auto &log_ptr : log_list){
        if(id != ALL && log_ptr->logid != id){
            // std::cout << log_ptr->msg << std::endl;
            continue;
        }
        if (log_ptr->msg.empty() || isWhitespaceOrNewline(log_ptr->msg)){
            continue;
        }
        while (!log_ptr->msg.empty() && (log_ptr->msg.back() == '\r' || log_ptr->msg.back() == '\n')) {
            log_ptr->msg.pop_back();
        }
        std::ostringstream oss;
        if (log_ptr->logid == MAIN || log_ptr->logid == SYSTEM || log_ptr->logid == RADIO
            || log_ptr->logid == CRASH || log_ptr->logid == KERNEL){
            oss << std::setw(18) << std::left << log_ptr->timestamp << " "
                << std::setw(5) << log_ptr->pid << " "
                << std::setw(5) << log_ptr->tid << " "
                << std::setw(6) << log_ptr->uid << " "
                << getLogLevelChar(log_ptr->priority) << " "
                << log_ptr->tag << " "
                << log_ptr->msg;
        }else{
            oss << std::setw(18) << std::left << log_ptr->timestamp << " "
            << std::setw(5) << log_ptr->pid << " "
            << std::setw(5) << log_ptr->tid << " "
            << std::setw(6) << log_ptr->uid << " "
            << getLogLevelChar(log_ptr->priority) << " "
            << log_ptr->msg;
        }
        fprintf(fp, "%s \n",oss.str().c_str());
    }
}

LogEvent Logcat::get_event(size_t pos, char* data, size_t len) {
    LogEvent event = {-1, "", -1};
    if ((pos + sizeof(int8_t)) >= len) {
        return event;
    }
    int8_t event_type = *reinterpret_cast<int8_t*>(data);
    switch (event_type) {
        case TYPE_INT:{
            if (pos + sizeof(android_event_int_t) > len) {
                return event;
            }
            android_event_int_t event_int = *reinterpret_cast<android_event_int_t*>(data);
            event.len = sizeof(android_event_int_t);
            event.type = event_int.type;
            event.val = std::to_string(event_int.data);
        }
        break;
        case TYPE_LONG:{
            if (pos + sizeof(android_event_long_t) > len) {
                return event;
            }
            android_event_long_t event_long = *reinterpret_cast<android_event_long_t*>(data);
            event.len = sizeof(android_event_long_t);
            event.type = event_long.type;
            event.val = std::to_string(event_long.data);
        }
        break;
        case TYPE_FLOAT:{
            if (pos + sizeof(android_event_float_t) > len) {
                return event;
            }
            android_event_float_t event_float = *reinterpret_cast<android_event_float_t*>(data);
            event.len = sizeof(android_event_float_t);
            event.type = event_float.type;
            event.val = std::to_string(event_float.data);
        }
        break;
        case TYPE_LIST:{
            if (pos + sizeof(android_event_list_t) > len) {
                return event;
            }
            android_event_list_t event_list = *reinterpret_cast<android_event_list_t*>(data);
            event.len = sizeof(android_event_list_t);
            event.type = event_list.type;
            event.val = std::to_string(event_list.element_count);
        }
        break;
        case TYPE_STRING:{
            if (pos + sizeof(android_event_string_t) > len) {
                return event;
            }
            android_event_string_t event_str = *reinterpret_cast<android_event_string_t*>(data);
            if (pos + sizeof(android_event_string_t) + event_str.length > len) {
                return event;
            }
            event.len = sizeof(android_event_string_t) + event_str.length;
            event.type = event_str.type;
            event.val.assign(data + sizeof(android_event_string_t), event_str.length);
        }
        break;
        default:
            break;
    }
    return event;
}

std::string Logcat::formatTime(uint32_t tv_sec, long tv_nsec) {
    std::chrono::seconds sec(tv_sec);
    std::chrono::nanoseconds nsec(tv_nsec);
    auto tp = std::chrono::time_point<std::chrono::system_clock>(sec) + nsec;
    std::time_t rtc_time = std::chrono::system_clock::to_time_t(tp);
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(tp.time_since_epoch()) % 1000;
    std::tm* tm = std::localtime(&rtc_time);
    char buffer[30];
    strftime(buffer, sizeof(buffer), "%m-%d %H:%M:%S", tm);
    std::ostringstream oss;
    oss << buffer << "." << std::setw(6) << std::setfill('0') << ms.count();
    return oss.str();
}

std::vector<size_t> Logcat::for_each_stdlist(ulong& stdlist_addr){
    std::vector<size_t> node_list;
    int data_size = BITS64() ? (is_compat ? 4 : sizeof(long)) : sizeof(long);
    size_t tail_node, next_node, list_size;
    if (is_compat) {
        tail_node = swap_ptr->uread_uint(tc_logd->task, stdlist_addr + 0 * data_size, "read tail_node");
        next_node = swap_ptr->uread_uint(tc_logd->task, stdlist_addr + 1 * data_size, "read next_node");
        list_size = swap_ptr->uread_uint(tc_logd->task, stdlist_addr + 2 * data_size, "read list_size");
    } else {
        tail_node = swap_ptr->uread_ulong(tc_logd->task, stdlist_addr + 0 * data_size, "read tail_node");
        next_node = swap_ptr->uread_ulong(tc_logd->task, stdlist_addr + 1 * data_size, "read next_node");
        list_size = swap_ptr->uread_ulong(tc_logd->task, stdlist_addr + 2 * data_size, "read list_size");
    }
    size_t prev_node = 0;
    size_t current = next_node;
    // fprintf(fp, "addr:0x%lx tail_node:0x%zx next_node:0x%zx list_size:%zu\n",stdlist_addr,tail_node,next_node,list_size);
    for (size_t i = 1; i <= list_size && is_uvaddr(current, tc_logd); ++i) {
        if (is_compat) {
            prev_node = swap_ptr->uread_uint(tc_logd->task, current + 0 * data_size, "read prev_node");
            next_node = swap_ptr->uread_uint(tc_logd->task, current + 1 * data_size, "read next_node");
        } else {
            prev_node = swap_ptr->uread_ulong(tc_logd->task, current + 0 * data_size, "read prev_node");
            next_node = swap_ptr->uread_ulong(tc_logd->task, current + 1 * data_size, "read next_node");
        }
        ulong data_node = current + 2 * data_size;
        // fprintf(fp, "[%zu]addr:0x%zx prev_node:0x%zx next_node:0x%zx data_node:0x%lx\n",i,current,prev_node,next_node,data_node);
        if (next_node == 0 || prev_node == tail_node) {
            break;
        }
        node_list.push_back(data_node);
        current = next_node;
    }
    return node_list;
}

//   --------------------------------------------------------
//   |    priority    |          tag         |   log         |
//   --------------------------------------------------------
void Logcat::parser_system_log(std::shared_ptr<LogEntry> log_ptr,char* logbuf, uint16_t msg_len){
    if (!logbuf) {
        return;
    }
    if (logbuf[0] >= LOG_DEFAULT && logbuf[0] <= LOG_SILENT) {
        log_ptr->priority = priorityMap[logbuf[0]];
    } else {
        log_ptr->priority = LOG_DEFAULT;
    }
    const char* tag_start = logbuf + 1;
    const char* tag_end = static_cast<const char*>(memchr(tag_start, '\0', msg_len - 1));
    if (!tag_end) {
        return;
    }
    log_ptr->tag.assign(tag_start, tag_end - tag_start);
    const char* msg_start = tag_end + 1;
    size_t msg_length = msg_len - (msg_start - logbuf);
    log_ptr->msg = std::string(msg_start, msg_length);
}

//  ==============================================================================================================================
//  |   tagindex   |          EVENT_TYPE_LIST        |   EVENT_TYPE_INT  |   value    | EVENT_TYPE_STRING |    len    |   value  |
//  ==============================================================================================================================
//  			   |sizeof(uint8_t) + sizeof(uint8_t)| sizeof(uint8_t) + sizeof(value)| sizeof(uint8_t) + sizeof(int32_t) + len  |
void Logcat::parser_event_log(std::shared_ptr<LogEntry> log_ptr,char* logbuf, uint16_t msg_len){
    if (!logbuf) {
        return;
    }
    log_ptr->priority = LogLevel::LOG_INFO;
    const size_t header_size = sizeof(android_event_header_t);
    size_t pos = 0;
    char* msg_ptr = logbuf;
    while (pos < msg_len){
        if (pos + header_size > msg_len){
            break;
        }
        android_event_header_t head = *reinterpret_cast<android_event_header_t*>(msg_ptr);
        msg_ptr += header_size;
        pos += header_size;
        // read the tag
        log_ptr->tag = std::to_string(head.tag);
        std::ostringstream oss;
        oss << std::left << ":[";
        LogEvent event = get_event(pos, msg_ptr, msg_len);
        if (event.type == -1) {
            break;
        }
        msg_ptr += event.len;
        pos += event.len;
        if (event.type == TYPE_LIST) {
            std::string list_msg;
            int cnt = std::stoi(event.val);
            for (int i = 0; i < cnt && pos < msg_len; ++i) {
                event = get_event(pos, msg_ptr, msg_len);
                if (!list_msg.empty()) {
                    list_msg += ",";
                }
                list_msg += event.val;
                msg_ptr += event.len;
                pos += event.len;
            }
            oss << list_msg;
        } else {
            oss << event.val;
        }
        oss << "]";
        log_ptr->msg = oss.str();
    }
}
#pragma GCC diagnostic pop
