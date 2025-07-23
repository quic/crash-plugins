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

#include "trace_event.h"

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wpointer-arith"

TraceEvent::TraceEvent(){

}

bool TraceEvent::isCharArray(const std::string& str) {
    int size;
    return std::sscanf(str.c_str(), "char[%d]", &size) == 1 && size >= 0;
}

void TraceEvent::print_dwc3_trb_event(ulong addr,std::ostringstream& oss){
    print_trace_field(addr, oss,"name");
    oss << std::left << ": trb ";
    print_trace_field(addr, oss,"trb");
    oss << std::left << "(E";
    print_trace_field(addr, oss,"enqueue");
    oss << std::left << ":D";
    print_trace_field(addr, oss,"dequeue");
    oss << std::left << ") buf ";
    print_trace_field(addr, oss,"bph");
    print_trace_field(addr, oss,"bpl");
    oss << std::left << "size ";
    print_trace_field(addr, oss,"size");
    oss << std::left << "ctrl ";
    print_trace_field(addr, oss,"ctrl");
}

void TraceEvent::print_post_rwmmio_event(ulong addr,std::ostringstream& oss){
    print_trace_field(addr, oss,"caller0");
    oss << std::left << " -> ";
    print_trace_field(addr, oss,"caller");
    oss << std::left << " width=";
    print_trace_field(addr, oss,"width");
    oss << std::left << " val=";
    print_trace_field(addr, oss,"val");
    oss << std::left << " addr=";
    print_trace_field(addr, oss,"addr");
}

void TraceEvent::print_rwmmio_event(ulong addr,std::ostringstream& oss){
    print_trace_field(addr, oss,"caller0");
    oss << std::left << " -> ";
    print_trace_field(addr, oss,"caller");
    oss << std::left << " width=";
    print_trace_field(addr, oss,"width");
    oss << std::left << " addr=";
    print_trace_field(addr, oss,"addr");
}

void TraceEvent::print_dwc3_ep_status(ulong addr,std::ostringstream& oss){
    print_trace_field(addr, oss,"name");
    oss << std::left << ": req ";
    print_trace_field(addr, oss,"req");
    oss << std::left << " length ";
    print_trace_field(addr, oss,"actual");
    oss << std::left << "/";
    print_trace_field(addr, oss,"length");
    oss << std::left << " ";
    std::shared_ptr<trace_field> filed_ptr = field_maps["zero"];
    int zero = plugin_ptr->read_int(addr + filed_ptr->offset,"zero");
    zero ? oss << std::left << "Z" : oss << std::left << "z";

    filed_ptr = field_maps["short_not_ok"];
    int short_not_ok = plugin_ptr->read_int(addr + filed_ptr->offset,"short_not_ok");
    short_not_ok ? oss << std::left << "S" : oss << std::left << "s";

    filed_ptr = field_maps["no_interrupt"];
    int no_interrupt = plugin_ptr->read_int(addr + filed_ptr->offset,"no_interrupt");
    no_interrupt ? oss << std::left << "i" : oss << std::left << "I";
    oss << std::left << " ==> ";
    print_trace_field(addr, oss,"status");
}

void TraceEvent::print_ip(ulong addr,std::ostringstream& oss){
    std::shared_ptr<trace_field> filed_ptr = field_maps["ip"];
    ulong ip = plugin_ptr->read_ulong(addr + filed_ptr->offset,"ip");
    if (is_kvaddr(ip)){
        ulong offset;
        struct syment *sp = value_search(ip, &offset);
        if (sp){
            oss << std::left << sp->name << ": ";
        }else{
            oss << std::left << std::hex << ip << ": ";
        }
    }else{
        oss << std::left << std::hex << ip << ": ";
    }
}

void TraceEvent::print_softirq(ulong addr,std::ostringstream& oss){
    oss << std::left << "vec=";
    std::shared_ptr<trace_field> filed_ptr = field_maps["vec"];
    if (filed_ptr == nullptr){
        return;
    }
    uint vec = plugin_ptr->read_uint(addr + filed_ptr->offset,"vec");
    oss << std::left << std::dec << vec;
    oss << std::left << " [action=";
    std::string state_str;
    switch (vec) {
        case 0:
            state_str = "HI";
            break;
        case 1:
            state_str = "TIMER";
            break;
        case 2:
            state_str = "NET_TX";
            break;
        case 3:
            state_str = "NET_RX";
            break;
        case 4:
            state_str = "BLOCK";
            break;
        case 5:
            state_str = "IRQ_POLL";
            break;
        case 6:
            state_str = "TASKLET";
            break;
        case 7:
            state_str = "SCHED";
            break;
        case 8:
            state_str = "HRTIMER";
            break;
        case 9:
            state_str = "RCU";
            break;
        default:
            state_str = "Unknown";
            break;
    }
    oss << std::left << state_str << "]";
}

void TraceEvent::print_trace_field(ulong addr, std::ostringstream& oss,std::string name) {
    std::shared_ptr<trace_field> field_ptr = field_maps[name];
    if (field_ptr == nullptr){
        return;
    }
    if (field_ptr->type.find("__data_loc") != std::string::npos && field_ptr->type.find("char[]") != std::string::npos){
        uint temp = plugin_ptr->read_uint(addr + field_ptr->offset,name);
        int len = (temp >> 16);
        if(len > 0){
            std::string tempval;
            if (len == 1){
                tempval = plugin_ptr->read_cstring(addr, field_ptr->offset * 4, name);
            }else{
                tempval = plugin_ptr->read_cstring(addr + (temp & 0xffff), len, name);
            }
            oss << std::left  << tempval;
        }
    }else if (field_ptr->type.find("char[]") != std::string::npos){
        std::string tempval = plugin_ptr->read_cstring(addr + field_ptr->offset,512, name);
        if (!tempval.empty()){
        }
        oss << std::left  << tempval;
    }else if (field_ptr->type.find("const char *") != std::string::npos){
        ulong str_addr = plugin_ptr->read_pointer(addr + field_ptr->offset,name);
        std::string tempval = plugin_ptr->read_cstring(str_addr,64, name);
        if (!tempval.empty()){
            oss << std::left  << tempval;
        }
    }else if (isCharArray(field_ptr->type)){
        std::string tempval = plugin_ptr->read_cstring(addr + field_ptr->offset, field_ptr->size, name);
        if (!tempval.empty()){
            oss << std::left  << tempval;
        }
    }else if (field_ptr->type == "int"
        || field_ptr->type == "pid_t") {
        oss << std::left  << std::dec << plugin_ptr->read_int(addr + field_ptr->offset, name);
    }else if (field_ptr->type == "long") {
        oss << std::left  << std::dec << plugin_ptr->read_long(addr + field_ptr->offset, name);
    }else if (field_ptr->type == "unsigned long"
        || field_ptr->type == "void *"
        || field_ptr->type == "size_t"
        || (field_ptr->type.find("struct") != std::string::npos && field_ptr->type.find("*") != std::string::npos)) {
        ulong tempval = plugin_ptr->read_ulong(addr + field_ptr->offset, name);
        if (name == "function" && field_ptr->type == "void *"){
            if (is_kvaddr(tempval)){
                ulong offset;
                struct syment *sp = value_search(tempval, &offset);
                if (sp){
                    oss << std::left << sp->name;
                }else{
                    oss << std::left << std::hex << tempval;
                }
            }
        }else{
            oss << std::left  << std::hex << tempval;
        }
    }else if (field_ptr->type == "__u32"
        || field_ptr->type == "u32"
        || field_ptr->type == "unsigned"
        || field_ptr->type == "uint32_t"
        || field_ptr->type == "unsigned int") {
        oss << std::left  << std::dec << plugin_ptr->read_uint(addr + field_ptr->offset, name);
    }else if (field_ptr->type == "__u64"
        || field_ptr->type == "u64"
        || field_ptr->type == "uint64_t"
        || field_ptr->type == "initcall_t"
        || field_ptr->type == "s64") {
        oss << std::left  << std::hex << plugin_ptr->read_ulonglong(addr + field_ptr->offset, name);
    }else if (field_ptr->type == "bool") {
        oss << std::left  << std::dec << plugin_ptr->read_bool(addr + field_ptr->offset, name);
    }else if (field_ptr->type == "u8") {
        oss << std::left  << std::dec << static_cast<int>(plugin_ptr->read_byte(addr + field_ptr->offset, name));
    }
}

void TraceEvent::handle(ulong addr,std::ostringstream& oss){
    if (skiped == true){
        oss << "skipped " << name << "\n\n";
        return;
    }
    for (const auto& arg_ptr : arg_list) {
        if (field_maps.find(arg_ptr->name) != field_maps.end()) { //exists
            oss << arg_ptr->prefixe;
            print_trace_field(addr,oss,arg_ptr->name);
            oss << " ";
        }
    }
}

void TraceEvent::set_print_format(std::string format) {
    org_print_fmt = format;
    if (!format.empty()){
        parser_output_format(format);
    }
}

size_t TraceEvent::skip_cnt = 0;
void TraceEvent::parser_output_format(std::string format) {
    if (has_advanced_features()){
        skip_cnt++;
        skiped = true;
    }else{
        print_fmt = extractFormatString(format);
        print_fmt.erase(std::remove_if(print_fmt.begin(), print_fmt.end(),
            [](char c) {
                return c == '\n' || c == '\r';
            }),
        print_fmt.end());
        // fprintf(fp, "%s \n\n",org_print_fmt.c_str());
        std::vector<std::string> name_list = extract_field_names(format);
        // for (const auto& var : arg_list) {
        //     fprintf(fp, "      %s \n",var.c_str());
        // }
        std::vector<std::string> prefixes;
        std::vector<std::string> formats;
        parse_format_string(print_fmt, prefixes, formats);
        for (size_t i = 0; i < prefixes.size(); ++i) {
            std::shared_ptr<print_arg> arg_ptr = std::make_shared<print_arg>();
            arg_ptr->name = name_list[i];
            arg_ptr->prefixe = prefixes[i];
            arg_ptr->format = formats[i];
            arg_list.push_back(arg_ptr);
            // fprintf(fp, "Prefix:%s Format:%s\n",prefixes[i].c_str(),formats[i].c_str());
        }
        // fprintf(fp, "%s \n\n",print_fmt.c_str());
    }
}

void TraceEvent::parse_format_string(const std::string& fmt,
                         std::vector<std::string>& prefixes,
                         std::vector<std::string>& formats) {
    size_t last_end = 0;
    size_t i = 0;
    std::string formt = fmt.substr(1, fmt.length() - 2);
    while (i < formt.size()) {
        if (formt[i] == '%') {
            size_t j = i + 1;
            while (j < formt.size() && formt[j] != ' ') {
                ++j;
            }
            if (j < formt.size()) ++j;
            std::string prefix = formt.substr(last_end, i - last_end);
            std::string format = formt.substr(i, j - i);
            prefixes.push_back(prefix);
            formats.push_back(format);
            i = j;
            last_end = j;
        } else {
            ++i;
        }
    }
}

std::string TraceEvent::trim(const std::string& str) {
    if (str.empty()) return str;
    auto start = std::find_if_not(str.begin(), str.end(), [](int c) {
        return std::isspace(static_cast<unsigned char>(c));
    });
    auto end = std::find_if_not(str.rbegin(), str.rend(), [](int c) {
        return std::isspace(static_cast<unsigned char>(c));
    }).base();
    return (start < end) ? std::string(start, end) : std::string();
}

std::string TraceEvent::extract_field_name(const std::string& param) {
    std::string cleaned = trim(param);
    const std::string get_str_prefix = "__get_str(";
    if (cleaned.size() > get_str_prefix.size() &&
        cleaned.substr(0, get_str_prefix.size()) == get_str_prefix &&
        cleaned.back() == ')') {
        return cleaned.substr(get_str_prefix.size(), cleaned.size() - get_str_prefix.size() - 1);
    }
    const std::string rec_prefix = "REC->";
    if (cleaned.size() > rec_prefix.size() &&
        cleaned.substr(0, rec_prefix.size()) == rec_prefix) {
        return cleaned.substr(rec_prefix.size());
    }
    const std::vector<std::string> prefixes = {
        "ctx->", "event->", "record->", "p->", "arg->"
    };
    for (const auto& prefix : prefixes) {
        if (cleaned.size() > prefix.size() &&
            cleaned.substr(0, prefix.size()) == prefix) {
            return cleaned.substr(prefix.size());
        }
    }
    return cleaned;
}

std::vector<std::string> TraceEvent::extract_field_names(const std::string& input) {
    std::vector<std::string> parameters;
    std::vector<std::string> field_names;
    size_t first_quote = input.find('\"');
    if (first_quote == std::string::npos) {
        throw std::invalid_argument("invaild char");
    }
    size_t second_quote = input.find('\"', first_quote + 1);
    if (second_quote == std::string::npos) {
        throw std::invalid_argument("invaild char");
    }
    size_t params_start = input.find_first_not_of(" \t,", second_quote + 1);
    if (params_start == std::string::npos) {
        return {};
    }
    std::string params_str = input.substr(params_start);
    size_t start_pos = 0;
    size_t comma_pos;
    while ((comma_pos = params_str.find(',', start_pos)) != std::string::npos) {
        std::string param = params_str.substr(start_pos, comma_pos - start_pos);
        if (!trim(param).empty()) {
            parameters.push_back(trim(param));
        }
        start_pos = comma_pos + 1;
        if (comma_pos == std::string::npos) break;
    }
    std::string last_param = params_str.substr(start_pos);
    if (!trim(last_param).empty()) {
        parameters.push_back(trim(last_param));
    }
    for (const auto& param : parameters) {
        field_names.push_back(extract_field_name(param));
    }
    return field_names;
}

bool TraceEvent::has_advanced_features() {
    if (org_print_fmt.find('?') != std::string::npos &&
    org_print_fmt.find(':') != std::string::npos) {
        return true;
    }
    if (org_print_fmt.find("__get_dynamic_array") != std::string::npos) {
        return true;
    }
    if (org_print_fmt.find("__builtin_constant_p") != std::string::npos) {
        return true;
    }
    if (org_print_fmt.find("__fswab16") != std::string::npos) {
        return true;
    }
    if (org_print_fmt.find("__fswab32") != std::string::npos) {
        return true;
    }
    return false;
}

bool TraceEvent::parse_format_spec() {
    if (pos_ < org_print_fmt.size() && org_print_fmt[pos_] == '%') {
        pos_++;
        return false;
    }
    std::string spec;
    while (pos_ < org_print_fmt.size()) {
        char c = org_print_fmt[pos_];
        if (isspace(c) || c == '%' || (!isalnum(c) && c != '.' && c != '-' &&
                                        c != '+' && c != '#' && c != '*' &&
                                        c != '?' && c != ':' && c != '(' &&
                                        c != ')' && c != '>' && c != '<' &&
                                        c != '[' && c != ']' && c != ',')) {
            break;
        }
        spec += c;
        pos_++;
    }
    return contains_advanced_features(spec);
}

bool TraceEvent::contains_advanced_features(const std::string& spec) {
    if (spec.find('(') != std::string::npos &&
        spec.find(')') != std::string::npos) {
        return true;
    }
    if (spec.find('?') != std::string::npos &&
        spec.find(':') != std::string::npos) {
        return true;
    }
    if (spec.find("->") != std::string::npos) {
        return true;
    }
    if (spec.find('*') != std::string::npos) {
        size_t pos = spec.find('*');
        if (pos > 0 && spec[pos-1] != '%' && !isalnum(spec[pos-1])) {
            return true;
        }
    }
    if (spec.find('[') != std::string::npos &&
        spec.find(']') != std::string::npos) {
        return true;
    }
    static const std::unordered_set<char> operators = {
        '&', '|', '^', '~', '+', '-', '*', '/', '%',
        '<', '>', '=', '!'
    };
    for (char c : spec) {
        if (operators.find(c) != operators.end()) {
            if (c == '+' || c == '-' || c == '#' || c == ' ') {
                continue;
            }
            return true;
        }
    }
    return false;
}

std::string TraceEvent::extractFormatString(std::string& input) {
    bool inQuote = false;
    std::string result;
    for (char ch : input) {
        if (ch == '"') {
            result += ch;
            if (inQuote) break;
            inQuote = true;
        } else if (inQuote) {
            result += ch;
        }
    }
    return inQuote ? result : "";
}

void TraceEvent::dump() {
    fprintf(fp, "[%d] %s: %s \n",id, name.c_str(), org_print_fmt.c_str());
    fprintf(fp, "   format: %s\n",print_fmt.c_str());
    fprintf(fp, "   args  :\n");
    for (const auto& arg_ptr : arg_list) {
        fprintf(fp, "       %s \n",arg_ptr->name.c_str());
    }
    fprintf(fp, "   %s {\n",struct_type.c_str());
    std::ostringstream oss;
    for (const auto& pair : field_maps) {
        std::shared_ptr<trace_field> field = pair.second;
        std::string var = field->type + " " + field->name + ",";
        oss << std::left << "         "  << std::setw(25) << var << "offset:" << field->offset << ", size:" << field->size;
        fprintf(fp, "%s\n",oss.str().c_str());
        oss.str("");
    }
    fprintf(fp, "   } \n");
    fprintf(fp, "\n\n");
}

#pragma GCC diagnostic pop
