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

#ifndef TRACE_EVENT_DEFS_H_
#define TRACE_EVENT_DEFS_H_

#include "plugin.h"
#include <unordered_set>

struct trace_entry {
    unsigned short type;
    unsigned char flags;
    unsigned char preempt_count;
    int pid;
};

struct trace_field {
    std::string name;
    std::string type;
    int offset;
    int size;
    int is_signed;
    int filter_type;
    std::vector<char> val;
};

struct print_arg {
    std::string name;
    std::string prefixe;
    std::string format;
};

class TraceEvent{
public:
    TraceEvent();
    bool skiped = false;
    void set_print_format(std::string format);
    void parser_output_format(std::string format);
    std::string extractFormatString(std::string &input);
    bool contains_advanced_features(const std::string& spec);
    std::vector<std::string> extract_field_names(const std::string& input);
    std::string extract_field_name(const std::string& param);
    void parse_format_string(const std::string& fmt,std::vector<std::string>& prefixes,std::vector<std::string>& formats);
    std::string trim(const std::string& str);
    bool parse_format_spec();
    bool has_advanced_features();
    void print_trace_field(ulong addr, std::ostringstream& oss,std::string name);
    void print_softirq(ulong addr,std::ostringstream& oss);
    void print_dwc3_ep_status(ulong addr,std::ostringstream& oss);
    void print_dwc3_trb_event(ulong addr,std::ostringstream& oss);
    void print_ip(ulong addr,std::ostringstream& oss);
    bool isCharArray(const std::string &str);
    void dump();
    uint id;
    uint system_id;
    std::string name;
    std::string system;
    std::string org_print_fmt;
    std::vector<std::shared_ptr<print_arg>> arg_list;
    std::string print_fmt;
    std::string struct_type;
    std::unordered_map<std::string, std::shared_ptr<trace_field>> field_maps;
    size_t pos_ = 0;
    static size_t skip_cnt;
    virtual void handle(ulong addr,std::ostringstream& oss);
    ParserPlugin* plugin_ptr;
};

#endif // TRACE_EVENT_DEFS_H_
