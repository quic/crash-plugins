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

#ifndef IPC_LOG_DEFS_H_
#define IPC_LOG_DEFS_H_

#include "plugin.h"

struct tsv_header {
    unsigned char type;
    unsigned char size;
};

struct ipc_log {
    ulong addr;
    std::string name;
    uint32_t version;
    ulong first_page;
    ulong last_page;
    ulong write_page;
    ulong read_page;
    ulong nd_read_page;
    std::vector<std::string> logs;
};

#define TSV_TYPE_INVALID        0
#define TSV_TYPE_TIMESTAMP      1
#define TSV_TYPE_POINTER        2
#define TSV_TYPE_INT32          3
#define TSV_TYPE_BYTE_ARRAY     4
#define TSV_TYPE_QTIMER         5
#define IPC_LOG_CONTEXT_MAGIC_NUM   0x25874452
#define IPC_LOGGING_MAGIC_NUM       0x52784425

class IPCLog : public ParserPlugin {
public:
    IPCLog();
    std::vector<std::shared_ptr<ipc_log>> ipc_list;
    void cmd_main(void) override;
    void parser_ipc_log();
    void print_ipc_info();
    void save_ipc_log();
    void print_ipc_log(std::string name);
    void parser_ipc_log_page(std::shared_ptr<ipc_log> log_ptr);
    void appendBuffer(std::vector<char> &destBuf, void *sourceBuf, size_t length);
    DEFINE_PLUGIN_INSTANCE(IPCLog)
};

#endif // IPC_LOG_DEFS_H_
