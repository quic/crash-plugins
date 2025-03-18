// Copyright (c) 2024-2025 Qualcomm Innovation Center, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause-Clear

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
    int SerializedLogBuffer_logs_;
    int stdlist_node_size;
};

struct SerializedLogEntry {
    uint32_t uid;
    uint32_t pid;
    uint32_t tid;
    uint64_t sequence;
    struct log_time realtime;
    uint16_t msg_len;
}__attribute__((packed));

struct rw_vma {
    ulong vm_start;
    ulong vm_end;
};

class LogcatS : public Logcat {
private:
    struct logcat_offset_table g_offset;
    struct logcat_size_table g_size;
    ulong min_rw_vma_addr = ULONG_MAX;
    ulong max_rw_vma_addr = 0;
    std::unordered_map<ulong, char*> page_data_list; //<paddr, buf>
    std::vector<std::shared_ptr<rw_vma>> rw_vma_list;

public:
    LogcatS(std::shared_ptr<Swapinfo> swap);
    void init_datatype_info();
    ulong parser_logbuf_addr() override;
    size_t get_logbuf_addr_from_vma();
    void get_rw_vma_list();
    long check_ChunkList_in_vma(std::shared_ptr<rw_vma> vma_ptr,ulong list_addr);
    bool is_valid_node_addr(size_t addr);
    size_t get_logbuf_addr_from_register();
    size_t get_logbuf_addr_from_bss();
    void parser_logbuf(ulong buf_addr) override;
    void parser_SerializedLogChunk(LOG_ID log_id, ulong vaddr);
    void parser_SerializedLogEntry(LOG_ID log_id, char *log_data, uint32_t data_len);
};

#endif // LOGCAT_S_DEFS_H_
