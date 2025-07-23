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

#ifndef PSTORE_DEFS_H_
#define PSTORE_DEFS_H_

#include "plugin.h"
#include "logcat/logcat.h"
#include <ctime>

typedef struct __attribute__((__packed__)) {
    uint8_t magic;
    uint16_t len;
    uint16_t uid;
    uint16_t pid;
} android_pmsg_log_header_t;

typedef struct __attribute__((__packed__)) {
    uint8_t id;
    uint16_t tid;
    log_time realtime;
} android_log_header_t;

class Pstore : public ParserPlugin {
private:
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

    void print_ftrace_log();
    void print_oops_log();
    void print_console_log();
    void print_pmsg();
    void extract_pmsg_logs(std::vector<char> &logbuf);
    void parser_system_log(std::string timestamp, uint16_t uid, uint16_t tid, uint16_t pid, char *logbuf, uint16_t msg_len);
    void parser_event_log(std::string timestamp, uint16_t uid, uint16_t tid, uint16_t pid, char* logbuf, uint16_t msg_len);
    LogEvent get_event(size_t pos, char* data, size_t len);
    void appendBuffer(std::vector<char> &destBuf, void *sourceBuf, size_t length);
    std::string formatTime(uint32_t tv_sec, uint32_t tv_nsec);
    std::string getLogLevelChar(LogLevel level);

public:
    Pstore();
    void cmd_main(void) override;
    void init_offset(void) override;
    void init_command(void) override;
    DEFINE_PLUGIN_INSTANCE(Pstore)
};

#endif // PSTORE_DEFS_H_
