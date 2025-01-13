// Copyright (c) 2024 Qualcomm Innovation Center, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause-Clear

#include "procrank.h"

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wpointer-arith"

#ifndef BUILD_TARGET_TOGETHER
DEFINE_PLUGIN_COMMAND(Procrank)
#endif

void Procrank::cmd_main(void) {
    int c;
    int flags;
    std::string cppString;
    if (argcnt < 2) cmd_usage(pc->curcmd, SYNOPSIS);
    while ((c = getopt(argcnt, args, "a")) != EOF) {
		switch(c) {
            case 'a':
                parser_process_memory();
                break;
            default:
                argerrs++;
                break;
		}
	}
    if (argerrs)
		cmd_usage(pc->curcmd, SYNOPSIS);
}

Procrank::Procrank(){
    cmd_name = "procrank";
    help_str_list={
    "procrank",/* command name */
    "dump process memory information",/* short description */
    };
    help_str_list={
	"procrank",							/* command name */
	"dump process memory information",		/* short description */
	"-a \n"
	"  This command dumps the process info. sorted by rss",
    "\n",
    "EXAMPLES",
	"  Display process memory info:",
	"    %s> procrank -a",
    "	PID        Vss        Rss        Pss        Uss        Swap        Comm",
    "	975      1.97Gb     51.09Mb    13.71Mb    3.54Mb     1.99Mb     Binder:975_3",
    "	465      1.69Gb     4.53Mb     286.01Kb   36.00Kb    26.01Mb    main",
    "\n",
    };
    initialize();
    //print_table();
}

void Procrank::parser_process_memory() {
    char buf_pid[BUFSIZE];
    char buf_vss[BUFSIZE];
    char buf_rss[BUFSIZE];
    char buf_pss[BUFSIZE];
    char buf_uss[BUFSIZE];
    char buf_swap[BUFSIZE];
    char buf_name[BUFSIZE];
    if (procrank_list.size() == 0){
        for(ulong task_addr: for_each_process()){
            auto procrank_result = std::make_shared<procrank>();
            for(ulong vma_addr: for_each_vma(task_addr)){
                auto procrank_ptr = parser_vma(vma_addr, task_addr);
                procrank_result->vss += procrank_ptr->vss;
                procrank_result->rss += procrank_ptr->rss;
                procrank_result->pss += procrank_ptr->pss;
                procrank_result->uss += procrank_ptr->uss;
                procrank_result->swap += procrank_ptr->swap;
            }
            struct task_context *tc = task_to_context(task_addr);
            procrank_result->pid = tc->pid;
            // memcpy(procrank_result->comm, tc->comm, TASK_COMM_LEN + 1);
            procrank_result->cmdline = read_start_args(task_addr);
            procrank_list.push_back(procrank_result);
        }
        std::sort(procrank_list.begin(), procrank_list.end(),[&](const std::shared_ptr<procrank>& a, const std::shared_ptr<procrank>& b){
            return a->rss > b->rss;
        });
    }
    fprintf(fp,"PID        Vss        Rss        Pss        Uss        Swap        Comm\n");
    for (const auto& p : procrank_list) {
        convert_size(p->vss,buf_vss);
        convert_size(p->rss,buf_rss);
        convert_size(p->pss,buf_pss);
        convert_size(p->uss,buf_uss);
        convert_size(p->swap,buf_swap);
        fprintf(fp, "%s %s %s %s %s %s %s\n",
            mkstring(buf_pid, 8, LJUST|INT_DEC, (char *)(unsigned long)p->pid),
            mkstring(buf_vss, 10, LJUST, buf_vss),
            mkstring(buf_rss, 10, LJUST, buf_rss),
            mkstring(buf_pss, 10, LJUST, buf_pss),
            mkstring(buf_uss, 10, LJUST, buf_uss),
            mkstring(buf_swap, 10, LJUST, buf_swap),
            mkstring(buf_name, p->cmdline.size() + 1, LJUST, p->cmdline.c_str()));
    }
}

std::shared_ptr<procrank> Procrank::parser_vma(ulong& vma_addr, ulong& task_addr) {
    auto procrank_ptr = std::make_shared<procrank>();
    physaddr_t physic_addr = (physaddr_t)0x0;
    // read struct vm_area_struct
    void *vma_struct = read_struct(vma_addr,"vm_area_struct");
    if(vma_struct == nullptr){
        return nullptr;
    }
    ulong vm_start = ULONG(vma_struct + field_offset(vm_area_struct, vm_start));
    ulong vm_end = ULONG(vma_struct + field_offset(vm_area_struct, vm_end));
    struct task_context *tc = task_to_context(task_addr);
    if(tc == nullptr){
        return nullptr;
    }
    for(ulong vaddr = vm_start; vaddr < vm_end; vaddr+= PAGESIZE()){
        ulong page_vaddr = vaddr & page_mask;
        ulong pte = get_pte(task_addr, page_vaddr);
        if(pte == 0x0)
            continue;
        // bit0 is 0
        if((pte & (1UL << 0)) == 0){
            procrank_ptr->swap += PAGESIZE();
            continue;
        }
        uvtop(tc, page_vaddr, &physic_addr, 0);
        ulong page_addr = 0;
        phys_to_page(physic_addr, &page_addr);
        void *page_struct = read_struct(page_addr,"page");
        // typedef struct {
        //     int counter;
        // } atomic_t;
        // SIZE: 4
        ulong page_count = 0;
        if (type_size("page", "_mapcount") == 4){
            page_count = UINT(page_struct + field_offset(page, _mapcount));
        } else if(type_size("page", "_mapcount") == 8) {
            page_count = ULONG(page_struct + field_offset(page, _mapcount));
        }

        // Page was unmapped between the presence check at the beginning of the loop and here.
        if(page_count == 0){
            FREEBUF(page_struct);
            continue;
        }
        procrank_ptr->rss += PAGESIZE();
        procrank_ptr->pss += PAGESIZE() / page_count;
        procrank_ptr->uss += (page_count == 1) ? PAGESIZE() : (0);
        FREEBUF(page_struct);
    }
    procrank_ptr->vss += vm_end - vm_start;
    FREEBUF(vma_struct);
    return procrank_ptr;
}

#pragma GCC diagnostic pop