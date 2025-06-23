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

#include "procrank.h"

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wpointer-arith"

#ifndef BUILD_TARGET_TOGETHER
DEFINE_PLUGIN_COMMAND(Procrank)
#endif

void Procrank::cmd_main(void) {
    int c;
    std::string cppString;
    if (argcnt < 2) cmd_usage(pc->curcmd, SYNOPSIS);
    while ((c = getopt(argcnt, args, "ac")) != EOF) {
        switch(c) {
            case 'a':
                parser_process_memory();
                break;
            case 'c':
                parser_process_name();
                break;
            default:
                argerrs++;
                break;
        }
    }
    if (argerrs)
        cmd_usage(pc->curcmd, SYNOPSIS);
}

Procrank::Procrank(std::shared_ptr<Swapinfo> swap) : swap_ptr(swap){
    init_command();
}

Procrank::Procrank(){
    init_command();
    swap_ptr = std::make_unique<Swapinfo>();
    //print_table();
}

void Procrank::init_command(){
    cmd_name = "procrank";
    help_str_list={
        "procrank",                            /* command name */
        "dump process memory information",        /* short description */
        "-a \n"
            "  This command dumps the process info. sorted by rss",
        "-c \n"
            "  This command dumps the process cmdline.",
        "\n",
        "EXAMPLES",
        "  Display process memory info:",
        "    %s> procrank -a",
        "    PID        Vss        Rss        Pss        Uss        Swap        Comm",
        "    975      1.97Gb     51.09Mb    13.71Mb    3.54Mb     1.99Mb     Binder:975_3",
        "    465      1.69Gb     4.53Mb     286.01Kb   36.00Kb    26.01Mb    main",
        "\n",
        "EXAMPLES",
        "  Display process cmdline:",
        "    %s> procrank -c",
        "    PID      Comm                 Cmdline",
        "    1        init                 /system/bin/init",
        "\n",
    };
    initialize();
    //print_table();
}

void Procrank::parser_process_memory() {
    if (!swap_ptr->is_zram_enable()){
        return;
    }
    uint64_t total_vss = 0;
    uint64_t total_rss = 0;
    uint64_t total_pss = 0;
    uint64_t total_uss = 0;
    uint64_t total_swap = 0;
    if (procrank_list.size() == 0){
        for(ulong task_addr: for_each_process()){
            struct task_context *tc = task_to_context(task_addr);
            if(!tc){
                continue;
            }
            task_ptr = std::make_shared<UTask>(swap_ptr, task_addr);
            auto proc_mem_ptr = std::make_shared<procrank>();
            proc_mem_ptr->pid = tc->pid;
            // memcpy(procrank_result->comm, tc->comm, TASK_COMM_LEN + 1);
            proc_mem_ptr->cmdline = task_ptr->read_start_args();
            for (const auto& vma_ptr : task_ptr->for_each_vma_list()) {
                auto vma_mem_ptr = parser_vma(vma_ptr);
                proc_mem_ptr->vss += vma_mem_ptr->vss;
                proc_mem_ptr->rss += vma_mem_ptr->rss;
                proc_mem_ptr->pss += vma_mem_ptr->pss;
                proc_mem_ptr->uss += vma_mem_ptr->uss;
                proc_mem_ptr->swap += vma_mem_ptr->swap;
            }
            total_vss += proc_mem_ptr->vss;
            total_rss += proc_mem_ptr->rss;
            total_pss += proc_mem_ptr->pss;
            total_uss += proc_mem_ptr->uss;
            total_swap += proc_mem_ptr->swap;
            procrank_list.push_back(proc_mem_ptr);
            task_ptr.reset();
        }
        std::sort(procrank_list.begin(), procrank_list.end(),[&](const std::shared_ptr<procrank>& a, const std::shared_ptr<procrank>& b){
            return a->rss > b->rss;
        });
    }
    std::ostringstream oss_hd;
    oss_hd << std::left << std::setw(8) << "PID" << " "
        << std::left << std::setw(10) << "Vss" << " "
        << std::left << std::setw(10) << "Rss" << " "
        << std::left << std::setw(10) << "Pss" << " "
        << std::left << std::setw(10) << "Uss" << " "
        << std::left << std::setw(10) << "Swap" << " "
        << "Comm";
    fprintf(fp, "%s \n",oss_hd.str().c_str());
    for (const auto& p : procrank_list) {
        std::ostringstream oss;
        oss << std::left << std::setw(8) << p->pid << " "
            << std::left << std::setw(10) << csize(p->vss) << " "
            << std::left << std::setw(10) << csize(p->rss) << " "
            << std::left << std::setw(10) << csize(p->pss) << " "
            << std::left << std::setw(10) << csize(p->uss) << " "
            << std::left << std::setw(10) << csize(p->swap) << " "
            << p->cmdline;
        fprintf(fp, "%s \n",oss.str().c_str());
    }
    std::ostringstream oss_total;
    oss_total << std::left << std::setw(8) << "Total" << " "
        << std::left << std::setw(10) << csize(total_vss) << " "
        << std::left << std::setw(10) << csize(total_rss) << " "
        << std::left << std::setw(10) << csize(total_pss) << " "
        << std::left << std::setw(10) << csize(total_uss) << " "
        << std::left << std::setw(10) << csize(total_swap);
    fprintf(fp, "%s\n", oss_total.str().c_str());
}

std::shared_ptr<procrank> Procrank::parser_vma(std::shared_ptr<vma_struct> vma_ptr) {
    auto procrank_ptr = std::make_shared<procrank>();
    for(ulong vaddr = vma_ptr->vm_start; vaddr < vma_ptr->vm_end; vaddr+= page_size){
        ulong page_vaddr = vaddr & page_mask;
        physaddr_t paddr;
        if (!uvtop(task_ptr->get_task_context(), page_vaddr, &paddr, 0)) { //page not exists
            if(paddr == 0x0){ // pte == 0
                continue;
            }
            // bit0 is 0
            if((paddr & (1UL << 0)) == 0){
                procrank_ptr->swap += page_size;
            }
            continue;
        }
        ulong page_addr = phy_to_page(paddr);
        // typedef struct {
        //     int counter;
        // } atomic_t;
        // SIZE: 4
        ulong page_count = read_structure_field(page_addr,"page","_mapcount");
        // Page was unmapped between the presence check at the beginning of the loop and here.
        if(page_count == 0){
            continue;
        }
        procrank_ptr->rss += page_size;
        procrank_ptr->pss += page_size / page_count;
        procrank_ptr->uss += (page_count == 1) ? page_size : (0);
    }
    procrank_ptr->vss += vma_ptr->vm_end - vma_ptr->vm_start;
    return procrank_ptr;
}

void Procrank::parser_process_name() {
    std::ostringstream oss_hd;
    oss_hd << std::left << std::setw(8) << "PID" << " "
           << std::left << std::setw(20) << "Comm" << " "
           << std::left << std::setw(10) << "Cmdline" << "\n";
    for(ulong task_addr: for_each_process()){
        std::string cmdline;
        struct task_context *tc = task_to_context(task_addr);
        if (!tc){
            continue;
        }
        task_ptr = std::make_shared<UTask>(swap_ptr, task_addr);
        if (!swap_ptr->is_zram_enable()){
            cmdline = tc->comm;
        } else {
            cmdline = task_ptr->read_start_args();
        }
        oss_hd << std::left << std::setw(8) << tc->pid << " "
               << std::left << std::setw(20) << tc->comm << " "
               << std::left << std::setw(10) << cmdline << "\n";
        task_ptr.reset();
    }
    fprintf(fp, "%s \n", oss_hd.str().c_str());
}

#pragma GCC diagnostic pop
