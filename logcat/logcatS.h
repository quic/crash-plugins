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

#ifndef LOGCAT_S_DEFS_H_
#define LOGCAT_S_DEFS_H_

#include "logcat.h"
#include "zstd.h"

struct logcat_offset_table {
    int SerializedLogBuffer_sequence_;
    int SerializedLogBuffer_logs_;
    int SerializedLogChunk_contents_;
    int SerializedLogChunk_write_offset_;
    int SerializedLogChunk_writer_active_;
    int SerializedLogChunk_compressed_log_;
    int SerializedLogChunk;
    int SerializedData_size_;
    int SerializedData_data_;
};

struct logcat_size_table {
    int SerializedData;
    int SerializedLogChunk;
    int SerializedLogBuffer_logs_; // 96
    int stdlist_node_size; // 24
};

struct SerializedLogEntry {
    uint32_t uid;
    uint32_t pid;
    uint32_t tid;
    uint64_t sequence;
    struct log_time realtime;
    uint16_t msg_len;
}__attribute__((packed));

typedef struct{
    uint32_t vtpr;
    uint32_t reader_list_;
    uint32_t tags_;
    uint32_t stats_;
    uint32_t max_size_[8];
    list_node32_t logs_[8];
} SerializedLogBuffer32_t;

typedef struct{
    uint64_t vtpr;
    uint64_t reader_list_;
    uint64_t tags_;
    uint64_t stats_;
    uint64_t max_size_[8];
    list_node64_t logs_[8];
} SerializedLogBuffer64_t;

class LogcatS : public Logcat {
private:
    /*
     SerializedLogBuffer has 10 virtual functions
    */
    const size_t vtbl_size = 10;
    struct logcat_offset_table g_offset;
    struct logcat_size_table g_size;
    void init_datatype_info();
    ulong parser_logbuf_addr() override;
    size_t get_stdlist_addr_from_vma() override;
    size_t get_logbuf_addr_from_bss() override;
    bool search_stdlist_in_vma(std::shared_ptr<vma_info> vma_ptr, std::function<bool (ulong)> callback, ulong& start_addr) override;

    size_t get_logbuf_addr_from_register();
    bool check_SerializedLogChunk_list_array(ulong addr);
    template<typename T, typename U>
    size_t get_SerializedLogBuffer_from_vma();
    void parser_SerializedLogChunk(LOG_ID log_id, ulong vaddr);
    void parser_SerializedLogEntry(LOG_ID log_id, char *log_data, uint32_t data_len);

public:
    LogcatS(std::shared_ptr<Swapinfo> swap);
    void parser_logbuf(ulong buf_addr) override;
};

#endif // LOGCAT_S_DEFS_H_
