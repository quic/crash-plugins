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
    while ((c = getopt(argcnt, args, "l")) != EOF) {
        switch(c) {
            case 'l':
                parser_journal_log();
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
    cmd_name = "systemd";
    help_str_list={
        "systemd",                            /* command name */
        "dump journal log",                   /* short description */
        "-l \n"
            "  This command dumps the journal info.",
        "\n",
        "EXAMPLES",
        "  Dump journal log info:",
        "    %s> systemd -l",
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

#pragma GCC diagnostic pop
