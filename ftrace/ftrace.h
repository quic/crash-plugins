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

#ifndef FTRACE_DEFS_H_
#define FTRACE_DEFS_H_

#include "plugin.h"
#include "trace_event.h"
#include "events.h"

enum {
    TRACECMD_OPTION_DONE,         /* 0 */
    TRACECMD_OPTION_DATE,         /* 1 */
    TRACECMD_OPTION_CPUSTAT,      /* 2 */
    TRACECMD_OPTION_BUFFER,       /* 3 */
    TRACECMD_OPTION_TRACECLOCK,   /* 4 */
    TRACECMD_OPTION_UNAME,        /* 5 */
    TRACECMD_OPTION_HOOK,         /* 6 */
};

struct ring_buffer_per_cpu {
    ulong addr;
    int cpu;
    std::vector<ulong> buffer_pages;
    std::vector<ulong> data_pages;
};

struct trace_array {
    ulong addr;
    int cpus;
    std::string name;
    uint64_t time_start;
    size_t nr_pages;
    size_t offset;
    std::vector<std::shared_ptr<ring_buffer_per_cpu>> cpu_ring_buffers;
};

struct ring_buffer_event {
    uint32_t type_len : 5;
    uint32_t time_delta : 27;
    uint32_t array[];
};

struct saved_cmdlines_buffer {
    ulong map_pid_to_cmdline;
    ulong map_cmdline_to_pid;
    unsigned int cmdline_num;
    int cmdline_idx;
    ulong saved_cmdlines;
};

enum ring_buffer_type {
    RINGBUF_TYPE_DATA_TYPE_LEN_MAX = 28,
    RINGBUF_TYPE_PADDING,
    RINGBUF_TYPE_TIME_EXTEND,
    RINGBUF_TYPE_TIME_STAMP,
};

struct trace_log {
    int cpu;
    ulong timestamp;
    std::string array_name;
    std::string log;
};

class Ftrace : public ParserPlugin {
private:
    bool debug = false;
    const int TRACE_FLAG_IRQS_OFF           = 0x01;
    const int TRACE_FLAG_IRQS_NOSUPPORT     = 0x02;
    const int TRACE_FLAG_NEED_RESCHED       = 0x04;
    const int TRACE_FLAG_HARDIRQ            = 0x08;
    const int TRACE_FLAG_SOFTIRQ            = 0x10;
    const int TRACE_FLAG_PREEMPT_RESCHED    = 0x20;
    const int TRACE_FLAG_NMI                = 0x40;
    const int TRACE_FLAG_BH_OFF             = 0x80;
    int pid_max;
    int nr_cpu_ids = 0;
    std::string trace_path;
    FILE* trace_file;
    std::shared_ptr<trace_array> global_trace;
    std::vector<std::shared_ptr<trace_array>> trace_list;
    std::vector<std::shared_ptr<trace_log>> trace_logs;
    std::shared_ptr<saved_cmdlines_buffer> savedcmd_ptr;
    std::unordered_map<unsigned int, std::shared_ptr<TraceEvent>> event_maps;
    std::unordered_map<std::string, std::shared_ptr<trace_field>> common_field_maps;
    std::unordered_map<int, std::string> comm_pid_dict;
    std::shared_ptr<trace_array> parser_trace_array(ulong addr);
    ulong buffer_page_has_data(ulong addr);
    void parser_trace_buffer(std::shared_ptr<trace_array> ta, ulong addr);
    void parser_ring_buffer_per_cpu(std::shared_ptr<trace_array> ta, ulong addr);
    bool write_trace_data();
    void write_buffer_data();
    void write_trace_array_buffers(std::shared_ptr<trace_array> ta_ptr);
    void write_res_data();
    void write_cmdlines();
    void write_printk_data();
    void write_kallsyms_data();
    void save_proc_kallsyms_mod_v6_4(std::vector<char> &buf, size_t &pos);
    void save_proc_kallsyms_mod_legacy(std::vector<char> &buf, size_t &pos);
    void write_to_buf(std::vector<char> &buffer, size_t &pos, const char *fmt, ...);
    void write_init_data();
    void dump_file();
    void write_header_data();
    void write_events_data();
    void write_events(uint system_id);
    void write_event(std::shared_ptr<TraceEvent> event_ptr);
    void ftrace_show();
    void ftrace_dump();
    void print_trace_log(std::string name);
    void print_trace_log();
    void print_trace_log(int cpu);
    void print_event_format();
    void parser_savedcmd();
    void parser_ftrace_trace_arrays();
    void print_trace_array();
    void parse_buffer_page(std::shared_ptr<trace_array> ta_ptr, std::shared_ptr<ring_buffer_per_cpu> rb_ptr, ulong addr);
    int get_trace_length(ulong event_addr, ring_buffer_event *event, ulong event_end);
    void parse_trace_entry(std::shared_ptr<trace_array> ta_ptr, std::shared_ptr<ring_buffer_per_cpu> rb_ptr, ulong addr, ulong timestamp);
    std::vector<std::string> extractPrefixes(const std::string &input);
    std::string find_cmdline(int pid);
    std::shared_ptr<TraceEvent> parser_trace_event_call(ulong addr);
    void parser_common_trace_fields();
    uint get_event_type_id(ulong addr);
    std::string get_event_type_name(ulong addr);
    std::string get_event_type_system(ulong addr);
    std::string get_event_type_print_fmt(ulong addr);
    std::shared_ptr<trace_field> parser_event_field(ulong addr);
    std::string get_lat_fmt(unsigned char flags, unsigned char preempt_count);
    void parser_ftrace_events_list();

public:
    Ftrace();
    void cmd_main(void) override;
    void init_offset(void) override;
    void init_command(void) override;
    DEFINE_PLUGIN_INSTANCE(Ftrace)
};

#endif // FTRACE_DEFS_H_
