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

#include "propinfo.h"

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wpointer-arith"

void PropInfo::cmd_main(void) {

}

std::string PropInfo::get_prop(std::string name){
    if (prop_map.size() == 0){
        parser_propertys();
        parser_prop_by_init();
    }
    if (prop_map.find(name) != prop_map.end()) {
        return prop_map[name];
    }
    return "";
}

PropInfo::~PropInfo(){
    swap_ptr = nullptr;
}

PropInfo::PropInfo(std::shared_ptr<Swapinfo> swap) : swap_ptr(swap){
    field_init(vm_area_struct, vm_file);
    field_init(vm_area_struct, vm_start);
    field_init(vm_area_struct, vm_end);
    field_init(file, f_path);
    field_init(path, dentry);
    field_init(path, mnt);

    for(ulong task_addr: for_each_process()){
        struct task_context *tc = task_to_context(task_addr);
        if (!tc){
            continue;
        }
        std::string task_name = tc->comm;
        if (task_name == "init" || tc->pid == 1){
            tc_init = tc;
            break;
        }
    }
    if (!tc_init){
        fprintf(fp, "Can't found init process !");
        return;
    }
    field_init(thread_info,flags);
    fill_thread_info(tc_init->thread_info);
    if (BITS64() && field_offset(thread_info, flags) != -1){
        ulong thread_info_flags = ULONG(tt->thread_info + field_offset(thread_info, flags));
        if(thread_info_flags & (1 << 22)){
            is_compat = true;
        }
    }
}

std::string PropInfo::get_symbol_file(std::string name){
    for (const auto& symbol : symbol_list) {
        if (symbol.name == name){
            return symbol.path;
        }
    }
    return "";
}

void PropInfo::print_propertys(){
    size_t max_len = 0;
    for (const auto& pair : prop_map) {
        max_len = std::max(max_len,pair.first.size());
    }
    size_t index = 1;
    for (const auto& pair : prop_map) {
        std::ostringstream oss;
        oss << "[" << std::setw(4) << std::setfill('0') << index << "]"
            << std::left << std::setw(max_len) << std::setfill(' ') << pair.first << " "
            << std::left << pair.second;
        fprintf(fp, "%s \n",oss.str().c_str());
        index++;
    }
}

void PropInfo::init_datatype_info(){
    field_init(SystemProperties, contexts_);
    field_init(ContextsSerialized, context_nodes_);
    field_init(ContextsSerialized, num_context_nodes_);
    field_init(ContextsSerialized, serial_prop_area_);
    field_init(ContextNode, pa_);
    field_init(ContextNode, filename_);
    field_init(ContextNode, context_);
    field_init(prop_bt, prop);
    field_init(prop_area, data_);
    field_init(prop_info, name);
    struct_init(ContextNode);
    if (field_offset(prop_area, data_) == -1){
        g_offset.SystemProperties_contexts_ = BITS64() ? (is_compat ? 32 : 64) : 32;
        g_offset.ContextsSerialized_context_nodes_ = BITS64() ? (is_compat ? 16 : 32) : 16;
        g_offset.ContextsSerialized_num_context_nodes_ = BITS64() ? (is_compat ? 20 : 40) : 20;
        g_offset.ContextsSerialized_serial_prop_area_ = BITS64() ? (is_compat ? 28 : 56) : 28;
        g_offset.ContextNode_pa_ = BITS64() ? (is_compat ? 12 : 16) : 12;
        g_offset.ContextNode_filename_ = BITS64() ? (is_compat ? 20 : 32) : 20;
        g_offset.ContextNode_context_ = BITS64() ? (is_compat ? 8 : 8) : 8;
        g_offset.prop_bt_prop = BITS64() ? (is_compat ? 4 : 4) : 4;
        g_offset.prop_area_data_ = BITS64() ? (is_compat ? 128 : 128) : 128;
        g_offset.prop_info_name = BITS64() ? (is_compat ? 96 : 96) : 96;
        g_size.ContextNode = BITS64() ? (is_compat ? 24 : 40) : 24;
    }else{
        g_offset.SystemProperties_contexts_ = field_offset(SystemProperties, contexts_);
        g_offset.ContextsSerialized_context_nodes_ = field_offset(ContextsSerialized, context_nodes_);
        g_offset.ContextsSerialized_num_context_nodes_ = field_offset(ContextsSerialized, num_context_nodes_);
        g_offset.ContextsSerialized_serial_prop_area_ = field_offset(ContextsSerialized, serial_prop_area_);
        g_offset.ContextNode_pa_ = field_offset(ContextNode, pa_);
        g_offset.ContextNode_filename_ = field_offset(ContextNode, filename_);
        g_offset.ContextNode_context_ = field_offset(ContextNode, context_);
        g_offset.prop_bt_prop = field_offset(prop_bt, prop);
        g_offset.prop_area_data_ = field_offset(prop_area, data_);
        g_offset.prop_info_name = field_offset(prop_info, name);
        g_size.ContextNode = struct_size(ContextNode);
    }
}

bool PropInfo::parser_propertys(){
    if (!tc_init){
        fprintf(fp, "Not found init process ! \n");
        return false;
    }
    std::string symbol_file = get_symbol_file("libc.so");
    if (symbol_file.empty() || symbol_file == ""){
        return false;
    }
    init_datatype_info();
    size_t pa_size_addr = swap_ptr->get_var_addr_by_bss("pa_size_", tc_init->task, symbol_file);
    if (!is_uvaddr(pa_size_addr,tc_init)){
        fprintf(fp, "pa_size: %#zx is not invaild !\n",pa_size_addr);
        return false;
    }
    if (is_compat){
        pa_size = swap_ptr->uread_uint(tc_init->task, pa_size_addr, "read pa_size");
    }else{
        pa_size = swap_ptr->uread_ulong(tc_init->task, pa_size_addr, "read pa_size");
    }
    if(debug)fprintf(fp, "pa_size:%#zx --> %zu \n",pa_size_addr, pa_size);

    size_t pa_data_size_addr = swap_ptr->get_var_addr_by_bss("pa_data_size_", tc_init->task, symbol_file);
    if (!is_uvaddr(pa_data_size_addr,tc_init)){
        fprintf(fp, "pa_data_size: %#zx is not invaild !\n",pa_data_size_addr);
        return false;
    }
    if (is_compat){
        pa_data_size = swap_ptr->uread_uint(tc_init->task, pa_data_size_addr, "read pa_data_size");
    }else{
        pa_data_size = swap_ptr->uread_ulong(tc_init->task, pa_data_size_addr, "read pa_data_size");
    }
    if(debug)fprintf(fp, "pa_data_size:%#zx --> %zu \n",pa_data_size_addr, pa_data_size);
    size_t system_prop_addr = swap_ptr->get_var_addr_by_bss("system_properties", tc_init->task, symbol_file);
    if (!is_uvaddr(system_prop_addr,tc_init)){
        fprintf(fp, "system_properties: %#zx is not invaild !\n",system_prop_addr);
        return false;
    }
    if(debug)fprintf(fp, "system_properties: %#zx \n",system_prop_addr);
    size_t contexts_addr = system_prop_addr + g_offset.SystemProperties_contexts_;
    if(debug)fprintf(fp, "contexts:%#zx offset: %d \n",contexts_addr, g_offset.SystemProperties_contexts_);
    if (is_compat){
        contexts_addr = swap_ptr->uread_uint(tc_init->task, contexts_addr, "read Contexts");
    }else{
        contexts_addr = swap_ptr->uread_ulong(tc_init->task, contexts_addr, "read Contexts");
    }
    if (!is_uvaddr(contexts_addr,tc_init)){
        fprintf(fp, "ContextsSerialized: %#zx is not invaild !\n",contexts_addr);
        return false;
    }
    if(debug)fprintf(fp, "ContextsSerialized: %#zx \n",contexts_addr);
    size_t num_context_nodes,context_nodes_addr,serial_prop_area_addr;
    if (is_compat){
        num_context_nodes = swap_ptr->uread_uint(tc_init->task, contexts_addr + g_offset.ContextsSerialized_num_context_nodes_, "read num_context_nodes_");
        context_nodes_addr = swap_ptr->uread_uint(tc_init->task, contexts_addr + g_offset.ContextsSerialized_context_nodes_, "read context_nodes_");
        serial_prop_area_addr = swap_ptr->uread_uint(tc_init->task, contexts_addr + g_offset.ContextsSerialized_serial_prop_area_, "read serial_prop_area_");
    }else{
        num_context_nodes = swap_ptr->uread_ulong(tc_init->task, contexts_addr + g_offset.ContextsSerialized_num_context_nodes_, "read num_context_nodes_");
        context_nodes_addr = swap_ptr->uread_ulong(tc_init->task, contexts_addr + g_offset.ContextsSerialized_context_nodes_, "read context_nodes_");
        serial_prop_area_addr = swap_ptr->uread_ulong(tc_init->task, contexts_addr + g_offset.ContextsSerialized_serial_prop_area_, "read serial_prop_area_");
    }
    if (!is_uvaddr(serial_prop_area_addr,tc_init)){
        fprintf(fp, "serial_prop_area: %#zx is not invaild !\n",serial_prop_area_addr);
        return false;
    }
    if(debug)fprintf(fp, "serial_prop_area: %#zx \n",serial_prop_area_addr);
    // parser_prop_area(serial_prop_area_addr);

    if (!is_uvaddr(context_nodes_addr,tc_init)){
        fprintf(fp, "context_nodes: %#zx is not invaild !\n",context_nodes_addr);
        return false;
    }
    if(debug)fprintf(fp, "context_nodes base: %#zx  cnt:%zu\n",context_nodes_addr,num_context_nodes);
    for (size_t i = 0; i < num_context_nodes; i++){
        size_t node_addr = context_nodes_addr + i * g_size.ContextNode;
        if (!is_uvaddr(node_addr,tc_init)){
            fprintf(fp, "ContextNode: %#zx is not invaild !\n",node_addr);
            continue;
        }
        size_t prop_area_addr,context_addr,filename_addr;
        if (is_compat){
            prop_area_addr = swap_ptr->uread_uint(tc_init->task, node_addr + g_offset.ContextNode_pa_, "read prop_area");
            context_addr = swap_ptr->uread_uint(tc_init->task, node_addr + g_offset.ContextNode_context_, "read context_");
            filename_addr = swap_ptr->uread_uint(tc_init->task, node_addr + g_offset.ContextNode_filename_, "read filename");
        }else{
            prop_area_addr = swap_ptr->uread_ulong(tc_init->task, node_addr + g_offset.ContextNode_pa_, "read prop_area");
            context_addr = swap_ptr->uread_ulong(tc_init->task, node_addr + g_offset.ContextNode_context_, "read context_");
            filename_addr = swap_ptr->uread_ulong(tc_init->task, node_addr + g_offset.ContextNode_filename_, "read filename");
        }
        std::string context = swap_ptr->uread_cstring(tc_init->task,context_addr,100, "prop context");
        std::string filename = swap_ptr->uread_cstring(tc_init->task,filename_addr,100, "prop filename");
        if(debug)fprintf(fp, "[%zu]ContextNode: %#zx prop_area:%#zx\n",i,node_addr,prop_area_addr);
        if (parser_prop_area(prop_area_addr) == false){
            continue;
        }
    }
    return true;
}

bool PropInfo::parser_prop_area(size_t area_vaddr){
    if (!is_uvaddr(area_vaddr,tc_init)){
        fprintf(fp, "prop_area: %#zx is not invaild !\n",area_vaddr);
        return false;
    }
    char prop_area_buf[sizeof(prop_area)];
    if(!swap_ptr->uread_buffer(tc_init->task,area_vaddr,prop_area_buf,sizeof(prop_area), "prop_area")){
        if(debug)fprintf(fp, "read prop_area fail at: %#zx !\n",area_vaddr);
        return false;
    }
    prop_area area = *reinterpret_cast<prop_area*>(prop_area_buf);
    if (area.magic_ != 0x504f5250){
        fprintf(fp, "prop_area magic not correct !\n");
        return false;
    }
    ulong data_addr = area_vaddr + g_offset.prop_area_data_;
    if(debug){
        std::ostringstream oss;
        oss << std::left << "prop_area:" << std::hex << area_vaddr << " "
            << "magic_:" << std::hex << area.magic_ << " "
            << "version_:" << std::hex << area.version_ << " "
            << "data_:" << std::hex << data_addr << " "
            << "bytes_used_:" << std::dec << std::setw(6) << area.bytes_used_ << " "
            << "serial_:" << std::dec << std::setw(6) << area.serial_;
        fprintf(fp, "%s \n",oss.str().c_str());
    }
    if (area.bytes_used_ > 0){
        parser_prop_bt(data_addr,data_addr);
    }
    return true;
}

void PropInfo::parser_prop_bt(size_t root, size_t prop_bt_addr){
    if (!is_uvaddr(prop_bt_addr,tc_init)){
        fprintf(fp, "   prop_bt: %#zx is not invaild !\n",prop_bt_addr);
        return;
    }
    char prop_bt_buf[sizeof(prop_bt)];
    if(!swap_ptr->uread_buffer(tc_init->task,prop_bt_addr,prop_bt_buf,sizeof(prop_bt), "prop_bt")){
        if(debug)fprintf(fp, "   read prop_bt fail at: %#zx !\n",prop_bt_addr);
        return;
    }
    prop_bt bt = *reinterpret_cast<prop_bt*>(prop_bt_buf);
    if(debug){
        std::ostringstream oss;
        oss << std::left << "   prop_bt:" << std::hex << prop_bt_addr << " "
            << "prop:" << std::dec << std::setw(5) << bt.prop << " "
            << "left:" << std::dec << std::setw(5) << bt.left << " "
            << "right:" << std::dec << std::setw(5) << bt.right << " "
            << "children:" << std::dec << bt.children;
        fprintf(fp, "%s \n",oss.str().c_str());
    }
    if (bt.prop > 0 && bt.prop < pa_data_size) {
        parser_prop_info(root + bt.prop);
    }
    if (bt.left > 0 && bt.left < pa_data_size) {
        parser_prop_bt(root, (root + bt.left));
    }
    if (bt.right > 0 && bt.right < pa_data_size) {
        parser_prop_bt(root, (root + bt.right));
    }
    if (bt.children > 0 && bt.children < pa_data_size) {
        parser_prop_bt(root, (root + bt.children));
    }
}

void PropInfo::parser_prop_info(size_t prop_info_addr){
    if (!is_uvaddr(prop_info_addr,tc_init)){
        fprintf(fp, "   prop_info: %#zx is not invaild !\n",prop_info_addr);
        return;
    }
    char prop_info_buf[sizeof(prop_info)];
    if(!swap_ptr->uread_buffer(tc_init->task,prop_info_addr,prop_info_buf,sizeof(prop_info), "prop_info")){
        if(debug)fprintf(fp, "   read prop_info fail at: %#zx !\n",prop_info_addr);
        return;
    }
    prop_info info = *reinterpret_cast<prop_info*>(prop_info_buf);
    ulong name_addr = prop_info_addr + g_offset.prop_info_name;
    std::string name = swap_ptr->uread_cstring(tc_init->task,name_addr,100, "prop name");
    if (!name.empty()){
        if(debug){
            std::ostringstream oss;
            oss << std::left << "   prop_info:" << std::hex << prop_info_addr << "--->"
                << "[" << name << "] : " << info.value;
            fprintf(fp, "%s \n",oss.str().c_str());
        }
        prop_map[name] = info.value;
    }
}

void PropInfo::parser_prop_by_init(){
    for(auto& task_addr : for_each_process()){
        struct task_context *tc = task_to_context(task_addr);
        if(tc && tc->pid == 1 /* init */){
            std::set<std::string> prop_files;
            // size_t index = 0;
            for(const auto& vma_addr : for_each_vma(task_addr)){
                void *vma_buf = read_struct(vma_addr, "vm_area_struct");
                if (!vma_buf) {
                    fprintf(fp, "Failed to read vm_area_struct at address %lx\n", vma_addr);
                    continue;
                }
                ulong vm_file = ULONG(vma_buf + field_offset(vm_area_struct, vm_file));
                ulong vm_start = ULONG(vma_buf + field_offset(vm_area_struct, vm_start));
                ulong vm_end = ULONG(vma_buf + field_offset(vm_area_struct, vm_end));
                size_t vma_len = vm_end - vm_start;
                FREEBUF(vma_buf);
                if (is_kvaddr(vm_file)){ //file vma
                    char buf[BUFSIZE];
                    char *file_buf = fill_file_cache(vm_file);
                    ulong dentry = ULONG(file_buf + field_offset(file, f_path) + field_offset(path, dentry));
                    if(is_kvaddr(dentry)){
                        if (field_offset(file, f_path) != -1 && field_offset(path, dentry) != -1 && field_offset(path, mnt) != -1) {
                            ulong vfsmnt = ULONG(file_buf + field_offset(file, f_path) + field_offset(path, mnt));
                            get_pathname(dentry, buf, BUFSIZE, 1, vfsmnt);
                        } else {
                            get_pathname(dentry, buf, BUFSIZE, 1, 0);
                        }
                        if (strstr(buf, "u:object_r:") != nullptr) {
                            if (prop_files.find(std::string(buf)) != prop_files.end()) {
                                continue;
                            }
                            prop_files.insert(std::string(buf));
                            char vma_data[vma_len];
                            if (!swap_ptr->uread_buffer(tc->task, vm_start, vma_data, vma_len, "read vma data for prop")) {
                                fprintf(fp, "uread_buffer fail in prop \n");
                            }
                            // if(index == 0){
                            //     prop_area pa = *reinterpret_cast<prop_area*>(vma_data);
                            //     fprintf(fp, "System Properties Magic:%#lx, Version:%#lx\n", pa.magic_, pa.version_);
                            // }
                            // index += 1;
                            prop_bt pb = *reinterpret_cast<prop_bt*>(vma_data + sizeof(prop_area));
                            if(pb.children != 0){
                                for_each_prop(pb.children, vma_len, vma_data);
                            }
                        }
                    }
                }
            }
        }
    }
}

/*
                                                  |<----------- prop3      ---------------------------------------------------------------------------------------------->|
                                                  |<----------- children2  ----------------------------------------------------->|                                        |
                                                  |<----------- children1  ---------------->|                                    |                                        |
+-----------+-------+------+--------+-------------+-------+-----+----+-----+---------+-----+-------+-----+----+-----+---------+--+-------+-----+----+-----+---------+-----+------+---------------+-------+
|bytes_used_|serial_|magic_|version_|reserved_[28]|namelen|prop1|left|right|children1|     |namelen|prop2|left|right|children2|  |namelen|prop3|left|right|children3|.....|serial|value/long_prop|name[0]|
+-----------+-------+------+--------+-------------+-------+-----+----+-----+---------+-----+-------+-----+----+-----+---------+--+-------+-----+----+-----+---------+-----+------+---------------+-------+
|<-----------        prop_area        ----------->|<----------- prop_bt   ---------->|     |<----------- prop_bt   ---------->|  |<----------- prop_bt   ---------->|     |<-------   prop_info   ------>|
|<-----------------------------------------------------------------------------          init vma         ---------------------------------------------------------------------------------------------->|
*/
bool PropInfo::for_each_prop(uint32_t prop_bt_off, size_t vma_len, char* vma_data){
    if(sizeof(prop_area) + prop_bt_off + sizeof(prop_bt) > vma_len)
        return false;
    prop_bt pb = *reinterpret_cast<prop_bt*>(vma_data + sizeof(prop_area) + prop_bt_off);
    uint32_t namelen = pb.namelen;
    uint prop = pb.prop;
    uint left = pb.left;
    uint right = pb.right;
    uint children = pb.children;
    if (left != 0){
        if(!for_each_prop(left, vma_len, vma_data)){
            return false;
        }
    }

    if(prop != 0){
        if((sizeof(prop_area) + prop + 92/*PROP_VALUE_MAX*/) < vma_len){
            std::string value = std::string(vma_data + sizeof(prop_area) + prop + 0x4/* serial*/, 92/*PROP_VALUE_MAX*/);
            /*
            see PROP_NAME_MAX in system_properties.h
            Deprecated: there's no limit on the length of a property name since
            API level 26, though the limit on property values (PROP_VALUE_MAX) remains.
            */
            std::string name = std::string(vma_data + sizeof(prop_area) + prop + sizeof(prop_info), 100);
            /*
            remove the case as below
            =
            ro.boot.memcg=
            */
            auto cleanedValue = cleanString(value);
            auto cleanedName = cleanString(name);

            if (cleanedValue && cleanedName) {
                // fprintf(fp, "%s=%s\n", cleanedName->c_str(), cleanedValue->c_str());
                prop_map[cleanedName.value()] = cleanedValue.value();
            }
        }
    }

    if (children != 0){
        if(!for_each_prop(children, vma_len, vma_data)){
            return false;
        }
    }

    if (right != 0){
        if(!for_each_prop(right, vma_len, vma_data)){
            return false;
        }
    }
    return true;
}

std::optional<std::string> PropInfo::cleanString(const std::string& str) {
    std::optional<std::string> cleanedStr;
    std::string tempStr = str;
    tempStr.erase(std::find(tempStr.begin(), tempStr.end(), '\0'), tempStr.end());

    tempStr.erase(0, tempStr.find_first_not_of(" \t\n\r\f\v"));
    tempStr.erase(tempStr.find_last_not_of(" \t\n\r\f\v") + 1);

    if (!tempStr.empty()) {
        bool hasValidChar = false;
        for (char c : tempStr) {
            if (c != '\0' && !std::isspace(c)) {
                hasValidChar = true;
                break;
            }
        }
        if (hasValidChar) {
            cleanedStr = tempStr;
        }
    }

    return cleanedStr;
}
#pragma GCC diagnostic pop
