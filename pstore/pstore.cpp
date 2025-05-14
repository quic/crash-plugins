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

#include "pstore.h"
#include "logcat/logcat.h"

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wpointer-arith"

#ifndef BUILD_TARGET_TOGETHER
DEFINE_PLUGIN_COMMAND(Pstore)
#endif

void Pstore::cmd_main(void) {
    int c;
    std::string cppString;
    if (argcnt < 2) cmd_usage(pc->curcmd, SYNOPSIS);
    while ((c = getopt(argcnt, args, "pcfo")) != EOF) {
        switch(c) {
            case 'p':
                print_pmsg();
                break;
            case 'c':
                print_console_log();
                break;
            case 'f':
                print_ftrace_log();
                break;
            case 'o':
                print_oops_log();
                break;
            default:
                argerrs++;
                break;
        }
    }
    if (argerrs)
        cmd_usage(pc->curcmd, SYNOPSIS);
}

Pstore::Pstore(){
    field_init(ramoops_context,dprzs);
    field_init(ramoops_context,cprz);
    field_init(ramoops_context,fprzs);
    field_init(ramoops_context,mprz);
    field_init(ramoops_context,phys_addr);
    field_init(ramoops_context,size);
    field_init(ramoops_context,memtype);
    field_init(ramoops_context,record_size);
    field_init(ramoops_context,console_size);
    field_init(ramoops_context,ftrace_size);
    field_init(ramoops_context,pmsg_size);
    struct_init(ramoops_context);
    field_init(persistent_ram_zone,paddr);
    field_init(persistent_ram_zone,size);
    field_init(persistent_ram_zone,buffer);
    field_init(persistent_ram_buffer,start);
    field_init(persistent_ram_buffer,size);
    cmd_name = "pstore";
    help_str_list={
        "pstore",                            /* command name */
        "dump pstore log information",        /* short description */
        "-p \n"
            "  pstore -c\n"
            "  pstore -f\n"
            "  pstore -o\n"
            "  This command dumps the pstore log info.",
        "\n",
        "EXAMPLES",
        "  Display pmsg log:",
        "    %s> pstore -p",
        "       25-04-20 19:03:41.000775 1719  2299  1000   I SDM ClstcAlgorithmAdapter::QueryLibraryRequest():711 Get library config 0, rc 0",
        "       25-04-20 19:03:41.000775 7290  7911  1000   I lcomm.qti.axiom Waiting for a blocking GC Alloc",
        "       25-04-20 19:03:41.000836 2683  8844  1000   W BestClock java.time.DateTimeException: No network time available",
        "\n",
        "  Display console log:",
        "    %s> pstore -c",
        "\n",
        "  Display ftrace log:",
        "    %s> pstore -f",
        "\n",
        "  Display Oops dump log:",
        "    %s> pstore -o",
        "\n",
    };
    initialize();
}

void Pstore::print_ftrace_log(){
    if (!csymbol_exists("oops_cxt")){
        fprintf(fp, "oops_cxt doesn't exist in this kernel!\n");
        return;
    }
    ulong cxt_addr = csymbol_value("oops_cxt");
    if (!is_kvaddr(cxt_addr)) {
        fprintf(fp, "oops_cxt address is invalid!\n");
        return;
    }
    size_t ftrace_size = read_ulong(cxt_addr + field_offset(ramoops_context,ftrace_size),"ftrace_size");
    if (ftrace_size == 0){
        fprintf(fp, "ftrace_size is 0!\n");
        return;
    }
    ulong fprzs_addr = read_pointer(cxt_addr + field_offset(ramoops_context,cprz),"fprzs");
    if (!is_kvaddr(fprzs_addr)) {
        fprintf(fp, "fprzs address is invalid!\n");
        return;
    }
    ulong zone_paddr = read_ulong(fprzs_addr + field_offset(persistent_ram_zone,paddr),"paddr");
    // ulong zone_size = read_ulong(fprzs_addr + field_offset(persistent_ram_zone,size),"size");
    ulong buffer_addr = read_pointer(fprzs_addr + field_offset(persistent_ram_zone,buffer),"buffer");
    if (!is_kvaddr(buffer_addr)) {
        fprintf(fp, "buffer address is invalid!\n");
        return;
    }
    fprintf(fp, "log addr:%#lx size:%zu\n",zone_paddr,ftrace_size);
}

void Pstore::print_oops_log(){
    if (!csymbol_exists("oops_cxt")){
        fprintf(fp, "oops_cxt doesn't exist in this kernel!\n");
        return;
    }
    ulong cxt_addr = csymbol_value("oops_cxt");
    if (!is_kvaddr(cxt_addr)) {
        fprintf(fp, "oops_cxt address is invalid!\n");
        return;
    }
    size_t record_size = read_ulong(cxt_addr + field_offset(ramoops_context,record_size),"record_size");
    if (record_size == 0){
        fprintf(fp, "record_size is 0!\n");
        return;
    }
    ulong dprzs_addr = read_pointer(cxt_addr + field_offset(ramoops_context,dprzs),"dprzs");
    if (!is_kvaddr(dprzs_addr)) {
        fprintf(fp, "dprzs address is invalid!\n");
        return;
    }
    ulong zone_paddr = read_ulong(dprzs_addr + field_offset(persistent_ram_zone,paddr),"paddr");
    // ulong zone_size = read_ulong(dprzs_addr + field_offset(persistent_ram_zone,size),"size");
    ulong buffer_addr = read_pointer(dprzs_addr + field_offset(persistent_ram_zone,buffer),"buffer");
    if (!is_kvaddr(buffer_addr)) {
        fprintf(fp, "buffer address is invalid!\n");
        return;
    }
    fprintf(fp, "log addr:%#lx size:%zu\n",zone_paddr,record_size);
}

void Pstore::print_console_log(){
    if (!csymbol_exists("oops_cxt")){
        fprintf(fp, "oops_cxt doesn't exist in this kernel!\n");
        return;
    }
    ulong cxt_addr = csymbol_value("oops_cxt");
    if (!is_kvaddr(cxt_addr)) {
        fprintf(fp, "oops_cxt address is invalid!\n");
        return;
    }
    size_t console_size = read_ulong(cxt_addr + field_offset(ramoops_context,console_size),"console_size");
    if (console_size == 0){
        fprintf(fp, "console_size is 0!\n");
        return;
    }
    ulong cprz_addr = read_pointer(cxt_addr + field_offset(ramoops_context,cprz),"cprz");
    if (!is_kvaddr(cprz_addr)) {
        fprintf(fp, "cprz address is invalid!\n");
        return;
    }
    ulong zone_paddr = read_ulong(cprz_addr + field_offset(persistent_ram_zone,paddr),"paddr");
    // ulong zone_size = read_ulong(cprz_addr + field_offset(persistent_ram_zone,size),"size");
    ulong buffer_addr = read_pointer(cprz_addr + field_offset(persistent_ram_zone,buffer),"buffer");
    if (!is_kvaddr(buffer_addr)) {
        fprintf(fp, "buffer address is invalid!\n");
        return;
    }
    fprintf(fp, "log addr:%#lx size:%zu\n",zone_paddr,console_size);
}

void Pstore::print_pmsg(){
    if (!csymbol_exists("oops_cxt")){
        fprintf(fp, "oops_cxt doesn't exist in this kernel!\n");
        return;
    }
    ulong cxt_addr = csymbol_value("oops_cxt");
    if (!is_kvaddr(cxt_addr)) {
        fprintf(fp, "oops_cxt address is invalid!\n");
        return;
    }
    size_t pmsg_size = read_ulong(cxt_addr + field_offset(ramoops_context,pmsg_size),"pmsg_size");
    if (pmsg_size == 0){
        fprintf(fp, "pmsg_size is 0!\n");
        return;
    }
    ulong mprz_addr = read_pointer(cxt_addr + field_offset(ramoops_context,mprz),"mprz");
    if (!is_kvaddr(mprz_addr)) {
        fprintf(fp, "mprz address is invalid!\n");
        return;
    }
    ulong zone_paddr = read_ulong(mprz_addr + field_offset(persistent_ram_zone,paddr),"paddr");
    // ulong zone_size = read_ulong(mprz_addr + field_offset(persistent_ram_zone,size),"size");
    ulong buffer_addr = read_pointer(mprz_addr + field_offset(persistent_ram_zone,buffer),"buffer");
    if (!is_kvaddr(buffer_addr)) {
        fprintf(fp, "buffer address is invalid!\n");
        return;
    }
    int buf_start = read_int(buffer_addr + field_offset(persistent_ram_buffer,start),"start");
    int buf_size = read_int(buffer_addr + field_offset(persistent_ram_buffer,size),"size");
    std::vector<char> logbuf;
    ulong addr = 0;
    size_t len = 0;
    void *data_buf;
    if (buf_start < buf_size){
        addr = zone_paddr + buf_start;
        len = buf_size - buf_start;
        data_buf = read_memory(addr, len,"data1",false);
        appendBuffer(logbuf,data_buf , len);
        FREEBUF(data_buf);

        addr = zone_paddr;
        len = buf_start;
        data_buf = read_memory(addr, len,"data2",false);
        appendBuffer(logbuf, data_buf, len);
        FREEBUF(data_buf);
    }else{
        addr = zone_paddr;
        len = buf_size;
        data_buf = read_memory(addr, len,"data",false);
        appendBuffer(logbuf, data_buf, len);
        FREEBUF(data_buf);
    }
    // fprintf(fp, "%s", hexdump(0x1000,(char*)logbuf.data(), logbuf.size()).c_str());
    extract_pmsg_logs(logbuf);
}

// write log by LogTags::WritePmsgEventLogTags(uint32_t tag, uid_t uid)
void Pstore::extract_pmsg_logs(std::vector<char>& logbuf){
    char* logptr = logbuf.data();
    long len = logbuf.size();
    long head_len = sizeof(android_pmsg_log_header_t) + sizeof(android_log_header_t) ;
    while (len > head_len){
        //   ----------------------------------------------------------------------------------------
        //   |    android_pmsg_log_header_t    |   android_log_header_t   |    tag     |   msg      |
        //   ----------------------------------------------------------------------------------------
        android_pmsg_log_header_t pmsgHeader = *reinterpret_cast<android_pmsg_log_header_t*>(logptr);
        android_log_header_t header = *reinterpret_cast<android_log_header_t*>(logptr + sizeof(android_pmsg_log_header_t));
        if (pmsgHeader.magic == 'l' && (header.id < 7 && header.id >=0) && pmsgHeader.len > head_len){
            if (len > pmsgHeader.len ){
                android_pmsg_log_header_t pmsgHeader2 = *reinterpret_cast<android_pmsg_log_header_t*>(logptr + pmsgHeader.len);
                if (pmsgHeader2.magic != 'l'){
                    len -= head_len;
                    logptr += head_len;
                    continue;
                }
            }
            std::string timestamp = formatTime(header.realtime.tv_sec,header.realtime.tv_nsec);
            char* msg_ptr = logptr + head_len;
            int msg_len = pmsgHeader.len - head_len;
            if (header.id == MAIN || header.id == SYSTEM || header.id == RADIO || header.id == CRASH || header.id == KERNEL){
                //   --------------------------------------------------------
                //   |    priority    |          tag         |   log         |
                //   --------------------------------------------------------
                parser_system_log(timestamp, pmsgHeader.uid, header.tid, pmsgHeader.pid, msg_ptr, msg_len);
            }else if (header.id == EVENTS){
                parser_event_log(timestamp, pmsgHeader.uid, header.tid, pmsgHeader.pid, msg_ptr, msg_len);
            }
            len -= pmsgHeader.len;
            logptr += pmsgHeader.len;
        }else{
            len -= 1;
            logptr += 1;
        }
    }
}

void Pstore::parser_system_log(std::string timestamp, uint16_t uid, uint16_t tid, uint16_t pid, char* logbuf, uint16_t msg_len){
    if (logbuf[0] < 0 || logbuf[0] >= 9){
        return;
    }
    LogLevel priority = priorityMap[logbuf[0]];
    std::string msg = std::string(logbuf +1, msg_len - 1);
    size_t pos = 0;
    while ((pos = msg.find('\0')) != std::string::npos) {
        msg.replace(pos, 1, " ");
    }
    while ((pos = msg.find('\n')) != std::string::npos) {
        msg.replace(pos, 1, " ");
    }
    std::ostringstream log;
    log << std::setw(18) << std::left << timestamp << " "
        << std::setw(5) << pid << " "
        << std::setw(5) << tid << " "
        << std::setw(6) << uid << " "
        << getLogLevelChar(priority) << " "
        << msg;
    fprintf(fp, "%s \n",log.str().c_str());
}

void Pstore::parser_event_log(std::string timestamp, uint16_t uid, uint16_t tid, uint16_t pid, char* logbuf, uint16_t msg_len){
    const size_t header_size = sizeof(android_event_header_t);
    size_t pos = 0;
    char* msg_ptr = logbuf;
    LogLevel priority = priorityMap[LOG_INFO];
    std::ostringstream log;
    log << std::setw(18) << std::left << timestamp << " "
        << std::setw(5) << pid << " "
        << std::setw(5) << tid << " "
        << std::setw(6) << uid << " "
        << getLogLevelChar(priority) << " ";
    while (pos < msg_len){
        if (pos + header_size > msg_len){
            break;
        }
        android_event_header_t head = *reinterpret_cast<android_event_header_t*>(msg_ptr);
        msg_ptr += header_size;
        pos += header_size;
        // read the tag
        log << head.tag << " :[";
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
            log << list_msg;
        } else {
            log << event.val;
        }
        log << "]";
    }
    fprintf(fp, "%s \n",log.str().c_str());
}

LogEvent Pstore::get_event(size_t pos, char* data, size_t len) {
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

std::string Pstore::getLogLevelChar(LogLevel level) {
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

void Pstore::appendBuffer(std::vector<char>& destBuf, void* sourceBuf, size_t length) {
    size_t currentSize = destBuf.size();
    destBuf.resize(currentSize + length);
    memcpy(destBuf.data() + currentSize, sourceBuf, length);
}

std::string Pstore::formatTime(uint32_t tv_sec, uint32_t tv_nsec) {
    std::chrono::seconds sec(tv_sec);
    std::chrono::nanoseconds nsec(tv_nsec);
    auto tp = std::chrono::time_point<std::chrono::system_clock>(sec) + nsec;
    std::time_t rtc_time = std::chrono::system_clock::to_time_t(tp);
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(tp.time_since_epoch()) % 1000;
    std::tm* tm = std::localtime(&rtc_time);
    char buffer[30];
    strftime(buffer, sizeof(buffer), "%y-%m-%d %H:%M:%S", tm);
    std::ostringstream oss;
    oss << buffer << "." << std::setw(6) << std::setfill('0') << ms.count();
    return oss.str();
}
#pragma GCC diagnostic pop
