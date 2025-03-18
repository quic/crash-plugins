// Copyright (c) 2024-2025 Qualcomm Innovation Center, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause-Clear

#ifndef LOGCAT_DEFS_H_
#define LOGCAT_DEFS_H_

#include "plugin.h"
#include "memory/swapinfo.h"
#include <array>

#ifdef min
#undef min
#endif
#include <chrono>

enum LOG_ID {
    MAIN,
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

class Logcat : public PaserPlugin {
protected:
    const std::array<LogLevel, 9> priorityMap = {{
        LogLevel::LOG_DEFAULT,
        LogLevel::LOG_DEFAULT,
        LogLevel::LOG_VERBOSE,
        LogLevel::LOG_DEBUG,
        LogLevel::LOG_INFO,
        LogLevel::LOG_WARN,
        LogLevel::LOG_ERROR,
        LogLevel::LOG_FATAL,
        LogLevel::LOG_SILENT
    }};

public:
    bool debug = false;
    bool is_compat;
    Logcat(std::shared_ptr<Swapinfo> swap);
    ~Logcat();
    std::vector<std::shared_ptr<LogEntry>> log_list;
    struct task_context *tc_logd;
    std::string logd_symbol;
    std::shared_ptr<Swapinfo> swap_ptr;

    void cmd_main(void) override;
    void parser_logcat_log();
    bool isWhitespaceOrNewline(const std::string &str);
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
};

#endif // LOGCAT_DEFS_H_
