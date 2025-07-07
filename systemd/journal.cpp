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
    int flags = 0;
    int from = 0;
    std::string cppString;
    if (argcnt < 2) cmd_usage(pc->curcmd, SYNOPSIS);
    while ((c = getopt(argcnt, args, "dlsvcf:")) != EOF) {
        switch(c) {
            case 'd':
                flags |= DUMP_LOG;
                break;
            case 'l':
                flags |= LIST_LOG;
                break;
            case 's':
                flags |= SHOW_LOG;
                break;
            case 'v':
                from |= FROM_VMA;
                break;
            case 'c':
                from |= FROM_CACHE;
                break;
            case 'f':
                cppString.assign(optarg);
                break;
            default:
                argerrs++;
                break;
        }
    }
    if (argerrs){
        cmd_usage(pc->curcmd, SYNOPSIS);
        return;
    }
    if (flags & DUMP_LOG){
        if (from & FROM_VMA){
            dump_journal_log_from_vma();
        }else if(from & FROM_CACHE){
            dump_journal_log_from_pagecache();
        }
    }else if(flags & LIST_LOG){
        if (from & FROM_VMA){
            print_journal_log_from_vma();
        }else if(from & FROM_CACHE){
            print_journal_log_from_pagecache();
        }
    }else if(flags & SHOW_LOG){
        if (from & FROM_VMA){
            show_journal_log_from_vma(cppString);
        }else if(from & FROM_CACHE){
            show_journal_log_from_pagecache(cppString);
        }
    }
}

Journal::Journal(std::shared_ptr<Swapinfo> swap) : swap_ptr(swap){
    init_command();
}

Journal::Journal(){
    init_command();
    swap_ptr = std::make_shared<Swapinfo>();
}

void Journal::init_command(){
    field_init(inode,i_dentry);
    field_init(inode,i_sb);
    field_init(dentry,d_u);
    cmd_name = "systemd";
    help_str_list={
        "systemd",                            /* command name */
        "dump journal log",                   /* short description */
        "-lv \n"
            "  systemd -lc \n"
            "  systemd -dv \n"
            "  systemd -dc \n"
            "  systemd -svf <file name> \n"
            "  systemd -scf <file name> \n"
            "  This command dumps the journal log.",
        "\n",
        "EXAMPLES",
        "  List the journal log from process vma:",
        "    %s> systemd -lv",
        "     user-1000.journal",
        "     user-1001.journal",
        "     system.journal",
        "\n",
        "  List the journal log from pagecache:",
        "    %s> systemd -lc",
        "     user-1000@000006867b6bd57c-66947a3228a6eb72.journal~",
        "     system@11be06652b3743dd8c5e160346822b9b-0000000000000001-00061b1bd31c6794.journal",
        "\n",
        "  Dump the journal log from process vma:",
        "    %s> systemd -dv",
        "     Save user-1000.journal to xx/systemd/user-1000.journal",
        "\n",
        "  Dump the journal log from pagecache:",
        "    %s> systemd -dc",
        "     Save user-1000@000006867b6bd57c-66947a3228a6eb72.journal~ to xx/systemd/user-1000@000006867b6bd57c-66947a3228a6eb72.journal~",
        "\n",
        "  Show the journal log from process vma:",
        "    %s> systemd -svf system.journal",
        "     [2025-06-17 19:34:52] msm_voice_source_tracking_get: Error getting FNN ST Params, err=-22",
        "     [2025-06-17 19:34:52] msm_voice_source_tracking_get: Error getting Source Tracking Params, err=-22",
        "     [2025-06-17 19:34:52] lt9611_edid_work: Reading edid work from the init work.",
        "     [2025-06-17 19:34:52] msm_voice_source_tracking_get: Error getting FNN ST Params, err=-22",
        "     [2025-06-17 19:34:52] msm_voice_source_tracking_get: Error getting Source Tracking Params, err=-22",
        "\n",
        "  Dump the journal log from pagecache:",
        "    %s> systemd -scf system.journal",
        "     [2025-06-17 19:34:52] msm_voice_source_tracking_get: Error getting FNN ST Params, err=-22",
        "     [2025-06-17 19:34:52] msm_voice_source_tracking_get: Error getting Source Tracking Params, err=-22",
        "     [2025-06-17 19:34:52] lt9611_edid_work: Reading edid work from the init work.",
        "     [2025-06-17 19:34:52] msm_voice_source_tracking_get: Error getting FNN ST Params, err=-22",
        "     [2025-06-17 19:34:52] msm_voice_source_tracking_get: Error getting Source Tracking Params, err=-22",
        "\n",
    };
    initialize();
}

void Journal::get_journal_vma_list(){
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
}

bool Journal::write_vma_to_file(std::vector<std::shared_ptr<vma_struct>> vma_list, FILE* logfile){
    for(const auto& vma_ptr : vma_list){
        void* vma_data = task_ptr->read_vma_data(vma_ptr);
        if (vma_data){
            fwrite(vma_data, vma_ptr->vm_size, 1, logfile);
            std::free(vma_data);
        }
    }
    return true;
}

void Journal::dump_journal_log_from_vma(){
    tc_systemd_journal = find_proc("systemd-journal");
    if(!tc_systemd_journal){
        fprintf(fp, "Do not find the systemd-journal \n");
        return;
    }
    if(!task_ptr){
        task_ptr = std::make_shared<UTask>(swap_ptr, tc_systemd_journal->task);
    }
    if(log_vma_list.size() == 0){
        get_journal_vma_list();
    }
    for(const auto& pair : log_vma_list){
        std::stringstream log_path = get_curpath();
        log_path << "/systemd/";
        mkdir(log_path.str().c_str(), 0777);
        log_path << pair.first;
        FILE* logfile = fopen(log_path.str().c_str(), "wb");
        if (!logfile) {
            fprintf(fp, "Can't open %s\n", log_path.str().c_str());
            return;
        }
        write_vma_to_file(pair.second, logfile);
        fprintf(fp, "Save %s to %s\n", pair.first.c_str(),log_path.str().c_str());
    }
}


void Journal::print_journal_log_from_vma(){
    tc_systemd_journal = find_proc("systemd-journal");
    if(!tc_systemd_journal){
        fprintf(fp, "Do not find the systemd-journal \n");
        return;
    }
    if(!task_ptr){
        task_ptr = std::make_shared<UTask>(swap_ptr, tc_systemd_journal->task);
    }
    if(log_vma_list.size() == 0){
        get_journal_vma_list();
    }
    for(const auto& pair : log_vma_list){
        fprintf(fp, "%s \n", pair.first.c_str());
    }
}

void Journal::show_journal_log_from_pagecache(std::string name){
    if(log_inode_list.size() == 0){
        get_journal_inode_list();
    }
    for(const auto& pair : log_inode_list){
        if(pair.first == name){
            char tmp[] = "/tmp/journal.XXXXXX";
            int fd = mkstemp(tmp);
            if (fd < 0){
                return;
            }
            FILE *logfile = fdopen(fd,"w");
            if (!logfile){
                close(fd);
                return;
            }
            write_pagecache_to_file(pair.second, logfile);
            display_journal_log(tmp);
            fclose(logfile);
            close(fd);
        }
    }
}

void Journal::show_journal_log_from_vma(std::string name){
    tc_systemd_journal = find_proc("systemd-journal");
    if(!tc_systemd_journal){
        fprintf(fp, "Do not find the systemd-journal \n");
        return;
    }
    if(!task_ptr){
        task_ptr = std::make_shared<UTask>(swap_ptr, tc_systemd_journal->task);
    }
    if(log_vma_list.size() == 0){
        get_journal_vma_list();
    }
    for(const auto& pair : log_vma_list){
        if(pair.first == name){
            char tmp[] = "/tmp/journal.XXXXXX";
            int fd = mkstemp(tmp);
            if (fd < 0){
                return;
            }
            FILE *logfile = fdopen(fd,"w");
            if (!logfile){
                close(fd);
                return;
            }
            write_vma_to_file(pair.second, logfile);
            display_journal_log(tmp);
            fclose(logfile);
            close(fd);
        }
    }
}

void Journal::display_journal_log(char* filepath){
    sd_journal *journal = nullptr;
    const char *paths[] = {filepath, NULL};
    int ret = sd_journal_open_files(&journal, paths, 0);
    if (ret) {
        std::cerr << "Open file failed: " << strerror(-ret) << std::endl;
        return;
    }
    sd_journal_seek_head(journal);
    while (sd_journal_next(journal) > 0) {
        const void *data;
        size_t length;
        uint64_t timestamp;
        if (sd_journal_get_realtime_usec(journal, &timestamp) >= 0) {
            time_t sec = timestamp / 1000000;
            std::cout << "[" << std::put_time(std::localtime(&sec), "%F %T") << "] ";
        }
        if (sd_journal_get_data(journal, "_PID", &data, &length) >= 0) {
            std::cout << "PID=" << std::string((const char*)data + 5, length - 5) << " ";
        }
        if (sd_journal_get_data(journal, "MESSAGE", &data, &length) >= 0) {
            std::string message((const char*)data + 8, length - 8);
            std::cout << message;
        }
        std::cout << std::endl;
    }
    sd_journal_close(journal);
}

void Journal::get_journal_inode_list(){
    char buf[BUFSIZE];
    for (const auto& addr : for_each_inode()) {
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
        int i_pages_offset = field_offset(address_space,i_pages);
        if (i_pages_offset == -1){
            i_pages_offset = field_offset(address_space,page_tree);
        }
        std::string i_pages_type = MEMBER_TYPE_NAME(TO_CONST_STRING("address_space"), TO_CONST_STRING("i_pages"));
        std::vector<ulong> pagelist = (i_pages_type == "xarray" ? for_each_xarray(i_mapping + i_pages_offset): for_each_radix(i_mapping + i_pages_offset));
        if(pagelist.size() == 0){
            continue;
        }
        log_inode_list[fileName] = i_mapping;
    }
}

bool Journal::write_pagecache_to_file(ulong i_mapping, FILE* logfile){
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
    return true;
}

void Journal::dump_journal_log_from_pagecache(){
    if(log_inode_list.size() == 0){
        get_journal_inode_list();
    }
    for(const auto& pair : log_inode_list){
        std::stringstream log_path = get_curpath();
        log_path << "/systemd/";
        mkdir(log_path.str().c_str(), 0777);
        log_path << pair.first;
        FILE* logfile = fopen(log_path.str().c_str(), "wb");
        if (!logfile) {
            fprintf(fp, "Can't open %s\n", log_path.str().c_str());
            return;
        }
        write_pagecache_to_file(pair.second, logfile);
        fprintf(fp, "Save %s to %s\n", pair.first.c_str(),log_path.str().c_str());
    }
}

void Journal::print_journal_log_from_pagecache(){
    if(log_inode_list.size() == 0){
        get_journal_inode_list();
    }
    for(const auto& pair : log_inode_list){
        fprintf(fp, "%s \n", pair.first.c_str());
    }
}
#pragma GCC diagnostic pop
