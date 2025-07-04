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

#include "journal.h"

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wpointer-arith"

#ifndef BUILD_TARGET_TOGETHER
DEFINE_PLUGIN_COMMAND(Journal)
#endif

void Journal::cmd_main(void) {
    int c;
    std::string cppString;
    if (argcnt < 2) cmd_usage(pc->curcmd, SYNOPSIS);
    while ((c = getopt(argcnt, args, "li")) != EOF) {
        switch(c) {
            case 'l':
                parser_journal_log();
                break;
            case 'i':
                parser_journal_log_from_pagecache();
                break;
            default:
                argerrs++;
                break;
        }
    }
    if (argerrs)
        cmd_usage(pc->curcmd, SYNOPSIS);
}

Journal::Journal(std::shared_ptr<Swapinfo> swap) : swap_ptr(swap){
    init_command();
}

Journal::Journal(){
    init_command();
    swap_ptr = std::make_shared<Swapinfo>();
}

void Journal::init_command(){
    field_init(page,page_type);
    field_init(page,_mapcount);
    field_init(page,_count);
    field_init(page,_refcount);
    field_init(page,mapping);
    field_init(address_space,host);
    field_init(address_space,a_ops);
    field_init(address_space,nrpages);
    field_init(address_space,i_pages);
    field_init(address_space,page_tree);
    struct_init(address_space);
    field_init(inode,i_mapping);
    field_init(inode,i_dentry);
    field_init(inode,i_sb);
    field_init(dentry,d_u);
    /* max_pfn */
    if (csymbol_exists("max_pfn")){
        try_get_symbol_data(TO_CONST_STRING("max_pfn"), sizeof(ulong), &max_pfn);
    }
    /* min_low_pfn */
    if (csymbol_exists("min_low_pfn")){
        try_get_symbol_data(TO_CONST_STRING("min_low_pfn"), sizeof(ulong), &min_low_pfn);
    }
    cmd_name = "systemd";
    help_str_list={
        "systemd",                            /* command name */
        "dump journal log",                   /* short description */
        "-l \n"
            "  systemd -i \n"
            "  This command dumps the journal log.",
        "\n",
        "EXAMPLES",
        "  Dump journal log from systemd-journal process:",
        "    %s> systemd -l",
        "    Save system.journal to xxx/systemd/system.journal",
        "\n",
        "  Dump journal log from page cache:",
        "    %s> systemd -i",
        "    Save system.journal to xxx/systemd/system.journal",
        "\n",
    };
    initialize();
}

void Journal::parser_journal_log(){
    for(ulong task_addr: for_each_process()){
        struct task_context *tc = task_to_context(task_addr);
        if (!tc){
            continue;
        }
        std::string name = tc->comm;
        if (name == "systemd-journal"){
            tc_systemd_journal = tc;
            break;
        }
    }
    if(!tc_systemd_journal){
        fprintf(fp, "Do not find the systemd-journal \n");
        return;
    }
    task_ptr = std::make_shared<UTask>(swap_ptr, tc_systemd_journal->task);
    std::unordered_map<std::string, std::vector<std::shared_ptr<vma_struct>>> log_vma_list;
    for(const auto& vma_ptr : task_ptr->for_each_file_vma()){
        if (vma_ptr->name.find(".journal") == std::string::npos){
            continue;
        }
        std::string fileName;
        size_t pos = vma_ptr->name.find_last_of("/\\");
        if (pos == std::string::npos) {
            fileName = vma_ptr->name;
        }else{
            fileName = vma_ptr->name.substr(pos + 1);
        }
        // fprintf(fp, "[%#lx-%#lx]: %s\n", vma_ptr->vm_start, vma_ptr->vm_end, fileName.c_str());
        log_vma_list[fileName].push_back(vma_ptr);
    }
    for(const auto& pair : log_vma_list){
        std::stringstream log_path = get_curpath();
        log_path << "/systemd/";
        mkdir(log_path.str().c_str(), 0777);
        log_path << pair.first;
        FILE* logfile = fopen(log_path.str().c_str(), "wb");
        if (!logfile) {
            fprintf(fp, "Can't open %s\n", log_path.str().c_str());
            continue;
        }
        for(const auto& vma_ptr : pair.second){
            void* vma_data = task_ptr->read_vma_data(vma_ptr);
            if (vma_data){
                fwrite(vma_data, vma_ptr->vm_size, 1, logfile);
                std::free(vma_data);
            }
        }
        fclose(logfile);
        fprintf(fp, "Save %s to %s\n", pair.first.c_str(),log_path.str().c_str());
    }
}

bool Journal::page_buddy(ulong page_addr){
    if (THIS_KERNEL_VERSION >= LINUX(4, 19, 0)){
        uint page_type = read_uint(page_addr + field_offset(page,page_type),"page_type");
        return ((page_type & 0xf0000080) == 0xf0000000);
    }else{
        uint mapcount = read_int(page_addr + field_offset(page,_mapcount),"_mapcount");
        return (mapcount == 0xffffff80);
    }
}

int Journal::page_count(ulong page_addr){
    int count = 0;
    if (THIS_KERNEL_VERSION < LINUX(4, 6, 0)){
        count = read_int(page_addr + field_offset(page,_count),"_count");
    }else{
        count = read_int(page_addr + field_offset(page,_refcount),"_refcount");
    }
    return count;
}

void Journal::parser_journal_log_from_pagecache(){
    std::set<ulong> inode_list;
    for (size_t pfn = min_low_pfn; pfn < max_pfn; pfn++){
        ulong page = pfn_to_page(pfn);
        if (!is_kvaddr(page)){
            continue;
        }
        if(page_buddy(page) || page_count(page) == 0){
            continue;
        }
        ulong mapping = read_pointer(page + field_offset(page,mapping),"mapping");
        if (!is_kvaddr(mapping)){
            continue;
        }
        if((mapping & 0x1) == 1){ // skip anon page
            continue;
        }
        ulong inode = read_pointer(mapping + field_offset(address_space,host),"host");
        if (!is_kvaddr(inode)){
            continue;
        }
        ulong ops = read_pointer(mapping + field_offset(address_space,a_ops),"a_ops");
        if (!is_kvaddr(ops)){
            continue;
        }
        ulong i_mapping = read_pointer(inode + field_offset(inode,i_mapping),"i_mapping");
        if (!is_kvaddr(i_mapping) && mapping != i_mapping){
            continue;
        }
        inode_list.insert(inode);
    }
    char buf[BUFSIZE];
    std::unordered_map<std::string, ulong> log_list;
    for (const auto& addr : inode_list) {
        ulong hlist_head = addr + field_offset(inode,i_dentry);
        int offset = field_offset(dentry,d_u);
        std::string fileName;
        for (const auto& dentry : for_each_hlist(hlist_head,offset)) {
            get_pathname(dentry, buf, BUFSIZE, 1, 0);
            fileName = buf;
            if (!fileName.empty()){
                break;
            }
        }
        if (fileName.empty() || fileName.find(".journal") == std::string::npos){
            continue;
        }
        size_t pos = fileName.find_last_of("/\\");
        if (pos != std::string::npos) {
            fileName = fileName.substr(pos + 1);
        }
        // fprintf(fp, "%s\n", fileName.c_str());
        ulong i_mapping = read_pointer(addr + field_offset(inode,i_mapping),"i_mapping");
        if (!is_kvaddr(i_mapping)) {
            continue;
        }
        log_list[fileName] = i_mapping;
    }
    for(const auto& pair : log_list){
        std::stringstream log_path = get_curpath();
        log_path << "/systemd/";
        mkdir(log_path.str().c_str(), 0777);
        log_path << pair.first;
        FILE* logfile = fopen(log_path.str().c_str(), "wb");
        if (!logfile) {
            fprintf(fp, "Can't open %s\n", log_path.str().c_str());
            continue;
        }
        ulong i_mapping = pair.second;
        int i_pages_offset = field_offset(address_space,i_pages);
        if (i_pages_offset == -1){
            i_pages_offset = field_offset(address_space,page_tree);
        }
        char page_data[page_size];
        BZERO(&page_data, page_size);
        std::string i_pages_type = MEMBER_TYPE_NAME(TO_CONST_STRING("address_space"), TO_CONST_STRING("i_pages"));
        std::vector<ulong> pagelist = (i_pages_type == "xarray" ? for_each_xarray(i_mapping + i_pages_offset): for_each_radix(i_mapping + i_pages_offset));
        for(const auto& page_addr : pagelist){
            // fprintf(fp, "page: %#lx \n", page_addr);
            physaddr_t phyaddr = page_to_phy(page_addr);
            char* buf = (char*)read_memory(phyaddr, page_size, "file cache",false);
            if (buf != nullptr){
                fwrite(buf, page_size, 1, logfile);
                FREEBUF(buf);
            }else{
                fwrite(page_data, page_size, 1, logfile);
            }
        }
        fclose(logfile);
        fprintf(fp, "Save %s to %s\n", pair.first.c_str(),log_path.str().c_str());
    }
}

#pragma GCC diagnostic pop
