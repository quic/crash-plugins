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

#ifndef LOGCAT_DEFS_H_
#define LOGCAT_DEFS_H_

#include "plugin.h"
#include "memory/swapinfo.h"
#include <array>
#include <chrono>

enum LOG_ID {
    MAIN = 0,
    RADIO,
    EVENTS,
    SYSTEM,
    CRASH,
    STATS,
    SECURITY,
    KERNEL,
    ALL,
};

enum LogLevel {
    LOG_UNKNOWN = 0,
    LOG_DEFAULT = 1,
    LOG_VERBOSE = 2,
    LOG_DEBUG = 3,
    LOG_INFO = 4,
    LOG_WARN = 5,
    LOG_ERROR = 6,
    LOG_FATAL = 7,
    LOG_SILENT = 8
};

enum EventType {
    TYPE_INT = 0,    // int32_t
    TYPE_LONG = 1,   // int64_t
    TYPE_STRING = 2,
    TYPE_LIST = 3,
    TYPE_FLOAT = 4
};

struct LogEntry {
    LOG_ID logid;
    uint32_t uid;
    uint32_t pid;
    uint32_t tid;
    std::string timestamp;
    std::string tag;
    LogLevel priority;
    std::string msg;
};

struct LogEvent {
    int type;
    std::string val;
    int len;
};

typedef struct __attribute__((__packed__)){
    int32_t tag;
} android_event_header_t;

typedef struct __attribute__((__packed__)){
    int8_t type;
    int64_t data;
} android_event_long_t;

typedef struct __attribute__((__packed__)){
    int8_t type;
    float data;
} android_event_float_t;

typedef struct __attribute__((__packed__)){
    int8_t type;
    int32_t data;
} android_event_int_t;

typedef struct __attribute__((__packed__)){
    int8_t type;
    int32_t length;
    char data[];
} android_event_string_t;

typedef struct __attribute__((__packed__)){
    int8_t type;
    int8_t element_count;
} android_event_list_t;

struct log_time {
    uint32_t tv_sec;
    uint32_t tv_nsec;
};

struct vma_info {
    ulong vm_start;
    ulong vm_end;
    ulong vm_size;
    ulong vm_file;
    ulong vm_flags;
    std::string vma_name;
    void* vm_data;
};

typedef struct{
    uint32_t prev;
    uint32_t next;
    uint32_t data;
} list_node32_t;

typedef struct{
    uint64_t prev;
    uint64_t next;
    uint64_t data;
} list_node64_t;

class Logcat : public ParserPlugin {
protected:
    const std::array<LogLevel, 9> priorityMap = {{
        LogLevel::LOG_UNKNOWN,
        LogLevel::LOG_DEFAULT,
        LogLevel::LOG_VERBOSE,
        LogLevel::LOG_DEBUG,
        LogLevel::LOG_INFO,
        LogLevel::LOG_WARN,
        LogLevel::LOG_ERROR,
        LogLevel::LOG_FATAL,
        LogLevel::LOG_SILENT
    }};
    uint pointer_size = 0;
    ulong min_rw_vma_addr = ULONG_MAX;
    ulong max_rw_vma_addr = 0;
    std::vector<std::shared_ptr<vma_info>> rw_vma_list;
    void get_rw_vma_list();
    void freeResource();
    std::shared_ptr<vma_info> parser_vma_info(ulong vma_addr);
    bool addrContains(std::shared_ptr<vma_info> vma_ptr, ulong addr);
    char* read_node(ulong addr, uint len);
    ulong check_stdlist64(ulong addr, std::function<bool (ulong)> callback, ulong &list_size);
    ulong check_stdlist32(ulong addr, std::function<bool (ulong)> callback, ulong &list_size);
    template<typename T, typename U>
    ulong check_stdlist(ulong addr,std::function<bool (ulong)> callback, ulong &list_size);
    std::string remove_invalid_chars(const std::string &str);

public:
    static bool is_LE;
    bool debug = false;
    bool is_compat = false;
    Logcat(std::shared_ptr<Swapinfo> swap);
    ~Logcat();
    std::vector<std::shared_ptr<LogEntry>> log_list;
    struct task_context *tc_logd;
    std::string logd_symbol;
    std::shared_ptr<Swapinfo> swap_ptr;

    void cmd_main(void) override;
    void parser_logcat_log();
    void print_logcat_log(LOG_ID id);
    LogEvent get_event(size_t pos, char *data, size_t len);
    std::string formatTime(uint32_t tv_sec, long tv_nsec);
    std::string find_symbol(std::string name);
    void parser_system_log(std::shared_ptr<LogEntry> log_ptr, char *logbuf, uint16_t msg_len);
    void parser_event_log(std::shared_ptr<LogEntry> log_ptr, char *logbuf, uint16_t msg_len);
    std::string getLogLevelChar(LogLevel level);
    std::vector<size_t> for_each_stdlist(ulong& stdlist_addr);

    virtual ulong parser_logbuf_addr()=0;
    virtual void parser_logbuf(ulong buf_addr)=0;
    virtual size_t get_stdlist_addr_from_vma()=0;
    virtual size_t get_logbuf_addr_from_bss()=0;
    virtual bool search_stdlist_in_vma(std::shared_ptr<vma_info> vma_ptr, std::function<bool (ulong)> callback, ulong& start_addr)=0;
};

#endif // LOGCAT_DEFS_H_
