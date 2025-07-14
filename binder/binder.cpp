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

#include "binder.h"

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wpointer-arith"

#ifndef BUILD_TARGET_TOGETHER
DEFINE_PLUGIN_COMMAND(Binder)
#endif

void Binder::cmd_main(void) {
    int c;
    if (argcnt < 2) cmd_usage(pc->curcmd, SYNOPSIS);
    struct binder_argument_t binder_arg;
    BZERO(&binder_arg, sizeof(binder_arg));
    while ((c = getopt(argcnt, args, "tnrbflap:")) != EOF) {
        switch(c) {
            case 'a':
                binder_arg.dump_all = 1;
                binder_arg.flags |= BINDER_THREAD;
                binder_arg.flags |= BINDER_NODE;
                binder_arg.flags |= BINDER_REF;
                binder_arg.flags |= BINDER_ALLOC;
                binder_proc_show(&binder_arg);
                break;
            case 'p':
                binder_arg.pid = atoi(optarg);
                binder_arg.flags |= BINDER_THREAD;
                binder_arg.flags |= BINDER_NODE;
                binder_arg.flags |= BINDER_REF;
                binder_arg.flags |= BINDER_ALLOC;
                binder_proc_show(&binder_arg);
                break;
            case 'f':
                print_binder_transaction_log_entry(true);
                break;
            case 'l':
                print_binder_transaction_log_entry(false);
                break;
            case 't':
                binder_arg.dump_all = 1;
                binder_arg.flags |= BINDER_THREAD;
                binder_proc_show(&binder_arg);
                break;
            case 'n':
                binder_arg.dump_all = 1;
                binder_arg.flags |= BINDER_NODE;
                binder_proc_show(&binder_arg);
                break;
            case 'r':
                binder_arg.dump_all = 1;
                binder_arg.flags |= BINDER_REF;
                binder_proc_show(&binder_arg);
                break;
            case 'b':
                binder_arg.dump_all = 1;
                binder_arg.flags |= BINDER_ALLOC;
                binder_proc_show(&binder_arg);
                break;
            default:
                argerrs++;
                break;
        }
    }
    if (argerrs)
        cmd_usage(pc->curcmd, SYNOPSIS);
}

void Binder::init_offset(void) {
    field_init(binder_proc,proc_node);
    field_init(binder_proc,context);
    field_init(binder_proc,max_threads);
    field_init(binder_proc,threads);
    field_init(binder_proc,nodes);
    field_init(binder_proc,refs_by_desc);
    field_init(binder_proc,alloc);
    field_init(binder_proc,todo);
    field_init(binder_proc,pid);
    field_init(binder_proc,tsk);
    field_init(binder_context, name);
    field_init(binder_thread, rb_node);
    field_init(binder_thread, tmp_ref);
    field_init(binder_thread, waiting_thread_node);
    field_init(binder_transaction, work);
    field_init(binder_node,debug_id);
    field_init(binder_node,work);
    field_init(binder_node,rb_node);
    field_init(binder_node,async_todo);
    field_init(binder_node,refs);
    field_init(binder_ref, rb_node_desc);
    field_init(binder_ref, node_entry);
    field_init(binder_buffer,rb_node);
    field_init(binder_work,entry);
    field_init(binder_alloc,vma);
    field_init(binder_alloc,free_buffers);
    field_init(task_struct,comm);
    field_init(binder_transaction,from);
    field_init(binder_transaction,from_parent);
    field_init(binder_transaction,to_parent);
    field_init(binder_transaction,to_thread);
    field_init(binder_transaction,to_proc);
    field_init(binder_transaction,buffer);
    field_init(binder_transaction,debug_id);
    field_init(binder_transaction,code);
    field_init(binder_transaction,flags);
    field_init(binder_transaction,need_reply);
    field_init(binder_transaction,priority);
    field_init(binder_priority,prio);
    field_init(binder_priority,sched_policy);

    struct_init(binder_proc);
    struct_init(binder_thread);
    struct_init(binder_transaction);
    struct_init(binder_buffer);
    struct_init(binder_node);
    struct_init(binder_alloc);
    struct_init(binder_lru_page);
    struct_init(binder_work);
}

void Binder::init_command(void) {
    cmd_name = "binder";
    help_str_list={
        "binder",                            /* command name */
        "dump binder log information",        /* short description */
        "-a \n"
            "  binder -p [pid]\n"
            "  binder -l\n"
            "  binder -f\n"
            "  binder -n\n"
            "  binder -b\n"
            "  binder -t\n"
            "  binder -r\n"                    /* argument synopsis, or " " if none */
        "  This command dumps the binder information.",
        "\n",
        "EXAMPLES",
        "  Display all binder proc states:",
        "    %s> binder -a",
        "       proc 7312",
        "       context hwbinder",
        "           thread 7335: l 00 need_return 0 tr 0",
        "\n",
        "  Display specific process binder states:",
        "    %s> binder -p 7312",
        "       proc 7312",
        "       context hwbinder",
        "           thread 7335: l 00 need_return 0 tr 0",
        "\n",
        "  Display binder transaction log:",
        "    %s> binder -l",
        "       409173: reply from 1239:5444 to 5301:5301 context binder node 0 handle -1 size 8:0 ret 0/0 l=0",
        "       409174: call  from 666:666 to 614:0 context hwbinder node 1171 handle 4 size 220:32 ret 0/0 l=0",
        "\n",
        "  Display binder fail log:",
        "    %s> binder -f",
        "       840   : call  from 616:616 to 0:0 context hwbinder node 738 handle 1 size 32:0 ret 29201/-1 l=2793",
        "       210296: reply from 1239:2118 to 0:0 context binder node 0 handle -1 size 8:0 ret 29189/0 l=2717" ,
        "\n",
        "  Display binder thread info:",
        "    %s> binder -t",
        "       binder_proc:0xea194000 viders.calendar [7340] binder dead:0 frozen:0 sr:0 ar:0 max:15 total:6 requested:0 started:4 ready:5",
        "         binder_thread:0xef071e00 pid:7358 loop:12 need_return:0",
        "         binder_thread:0xea194600 pid:7360 loop:11 need_return:0",
        "\n",
        "  Display binder node info:",
        "    %s> binder -n",
        "       binder_proc:0xea194000 viders.calendar [7340] binder dead:0 frozen:0 sr:0 ar:0 max:15 total:6 requested:0 started:4 ready:5",
        "         binder_node:0xebb46680 id:407676 ptr:0xa7fe1460 cookie:0xac7c9278 pri:0[139] hs:1 hw:1 ls:0 lw:0 is:1 iw:0 tr:0",
        "         binder_node:0xebeed500 id:407473 ptr:0xa7fe13e0 cookie:0xac7c91b0 pri:0[139] hs:1 hw:1 ls:0 lw:0 is:2 iw:0 tr:0",
        "\n",
        "  Display binder ref info:",
        "    %s> binder -r",
        "       binder_proc:0xea194000 viders.calendar [7340] binder dead:0 frozen:0 sr:0 ar:0 max:15 total:6 requested:0 started:4 ready:5",
        "         binder_ref:0xe8407e80 id:406535 desc:15 s:1 w:1 death:0x0 -> node_id:9291 binder_proc:0xebf3ba00 Binder:1239_3[1239]",
        "         binder_ref:0xdec2e640 id:406527 desc:7 s:1 w:1 death:0x0 -> node_id:9540 binder_proc:0xebf3ba00 Binder:1239_3[1239]",
        "\n",
        "  Display binder buffer info:",
        "    %s> binder -b",
        "       binder_proc:0xea194000 viders.calendar [7340] binder dead:0 frozen:0 sr:0 ar:0 max:15 total:6 requested:0 started:4 ready:5",
        "         binder_alloc:0xea194154 mm_struct:0xe681df80 vma:0xefa9d880 buffer:0x81a39000 size:1040384 free:520192",
        "           Page :0xf815f28c PA:0xa664b000",
        "           Page :0xf7d338f8 PA:0x88bce000",
        "           Free binder_buffer :0xdb035300 id:409018 data:0x81a390e0 PA:0xa664b0e0 size:296 offset:24 extra:0 pid:666 delivered",
        "           Alloc binder_buffer:0xdd8f62c0 id:408034 data:0x81a390d8 PA:0xa664b0d8 size:8 offset:0 extra:0 pid:1239 delivered",
        "\n",
    };
}

Binder::Binder(){}

void Binder::print_binder_transaction_log_entry(bool fail_log){
    ulong binder_transaction_log_addr;
    if(fail_log == true){
        if (!csymbol_exists("binder_transaction_log_failed")){
            fprintf(fp, "binder_transaction_log_failed doesn't exist in this kernel !\n");
        }
        binder_transaction_log_addr = csymbol_value("binder_transaction_log_failed");
        if (!is_kvaddr(binder_transaction_log_addr)) return;
    }else{
        if (!csymbol_exists("binder_transaction_log")){
            fprintf(fp, "binder_transaction_log doesn't exist in this kernel !\n");
        }
        binder_transaction_log_addr = csymbol_value("binder_transaction_log");
        if (!is_kvaddr(binder_transaction_log_addr)) return;
    }
    struct binder_transaction_log btl;
    if(!read_struct(binder_transaction_log_addr,&btl,sizeof(btl),"binder_transaction_log")){
        return;
    }
    int count = 0;
    if(btl.full == true){
        count = 32;
    }else{
        count = btl.cur;
    }
    for(int i=0;i<count;i++){
        struct binder_transaction_log_entry& log_entry = btl.entry[i];
        if(log_entry.debug_id <= 0) continue;
        fprintf(fp, "%-6d: %s from %d:%d to %d:%d context %s node %d handle %d size %d:%d ret %d/%d l=%d\n",
            log_entry.debug_id,
            (log_entry.call_type == 2) ? "reply" :
            ((log_entry.call_type == 1) ? "async" : "call "), log_entry.from_proc,
            log_entry.from_thread, log_entry.to_proc, log_entry.to_thread, log_entry.context_name,
            log_entry.to_node, log_entry.target_handle, log_entry.data_size, log_entry.offsets_size,
            log_entry.return_error, log_entry.return_error_param,
            log_entry.return_error_line);
    }
}

void Binder::binder_proc_show(struct binder_argument_t* binder_arg) {
    if (!csymbol_exists("binder_procs")){
        fprintf(fp, "binder_procs doesn't exist in this kernel!\n");
        return;
    }
    ulong binder_procs = csymbol_value("binder_procs");
    if (!is_kvaddr(binder_procs)) return;
    int offset = field_offset(binder_proc,proc_node);
    std::vector<ulong> proc_list = for_each_hlist(binder_procs,offset);
    for (const auto& proc_addr : proc_list) {
        ulong part1_addr = proc_addr + field_offset(binder_proc,proc_node);
        struct binder_proc_part1 proc_part1;
        if(!read_struct(part1_addr,&proc_part1,sizeof(proc_part1),"binder_proc_part1")){
            continue;
        }
        if (binder_arg->dump_all || binder_arg->pid == proc_part1.pid) {
            print_binder_proc(proc_addr,binder_arg->flags);
        }
    }
}

void Binder::print_binder_alloc(struct task_context *tc,ulong alloc_addr) {
    physaddr_t paddr;
    if(is_kvaddr(alloc_addr))return;
    struct binder_alloc alloc;
    BZERO(&alloc, sizeof(struct binder_alloc));
    if(!read_struct(alloc_addr,&alloc,sizeof(alloc),"binder_alloc")){
        return;
    }
    fprintf(fp, "  binder_alloc:%#lx mm_struct:%p vma:%p buffer:%p size:%d free:%d\n",alloc_addr,
            alloc.vma_vm_mm, alloc.vma, alloc.buffer, alloc.buffer_size, alloc.free_async_space);
    // read all the pages
    int nr_pages = alloc.buffer_size / PAGESIZE();
    for (int i = 0; i < nr_pages; ++i) {
        ulong lru_page_addr = (ulong)alloc.pages + i * struct_size(binder_lru_page);
        struct binder_lru_page lru_page;
        if(!read_struct(lru_page_addr,&lru_page,sizeof(lru_page),"binder_lru_page")){
            continue;
        }
        ulong page_addr = (ulong)lru_page.page_ptr;
        if(is_kvaddr(page_addr)){
            paddr = page_to_phy(page_addr);
            fprintf(fp, "    Page :%#lx PA:%#llx\n",page_addr,(ulonglong)paddr);
        }
    }
    // list all free buffers
    int offset = field_offset(binder_buffer,rb_node);
    std::vector<ulong> free_list = for_each_rbtree((ulong)alloc.free_buffers.rb_node,offset);
    struct binder_buffer buf;
    for (const auto& buffer_addr : free_list) {
        BZERO(&buf, sizeof(struct binder_buffer));
        if(!read_struct(buffer_addr,&buf,sizeof(buf),"binder_buffer")){
            continue;
        }
        paddr = 0;
        if(tc != nullptr){
            uvtop(tc, (ulong)buf.user_data, &paddr, 0);
        }
        fprintf(fp, "    Free binder_buffer :%#lx id:%d data:%#lx PA:%#llx size:%zd offset:%zd extra:%zd pid:%d %s\n",
           buffer_addr, buf.debug_id, (ulong)buf.user_data,(ulonglong)paddr,
           buf.data_size, buf.offsets_size,
           buf.extra_buffers_size,buf.pid,
           buf.transaction ? "active" : "delivered");
    }
    // list all allocated_buffers buffers
    std::vector<ulong> alloc_list = for_each_rbtree((ulong)alloc.allocated_buffers.rb_node,offset);
    for (const auto& buffer_addr : alloc_list) {
        BZERO(&buf, sizeof(struct binder_buffer));
        if(!read_struct(buffer_addr,&buf,sizeof(buf),"binder_buffer")){
            continue;
        }
        paddr = 0;
        if(tc != nullptr){
            uvtop(tc, (ulong)buf.user_data, &paddr, 0);
        }
        fprintf(fp, "    Alloc binder_buffer:%#lx id:%d data:%#lx PA:%#llx size:%zd offset:%zd extra:%zd pid:%d %s\n",
           buffer_addr, buf.debug_id, (ulong)buf.user_data,(ulonglong)paddr,
           buf.data_size, buf.offsets_size,
           buf.extra_buffers_size,buf.pid,
           buf.transaction ? "active" : "delivered");
    }
}

void Binder::print_binder_proc(ulong proc_addr,int flags) {
    ulong part1_addr = proc_addr + field_offset(binder_proc,proc_node);
    struct binder_proc_part1 proc_part1;
    if(!read_struct(part1_addr,&proc_part1,sizeof(proc_part1),"binder_proc_part1")){
        return;
    }
    ulong part2_addr = proc_addr + field_offset(binder_proc,max_threads);
    struct binder_proc_part2 proc_part2;
    if(!read_struct(part2_addr,&proc_part2,sizeof(proc_part2),"binder_proc_part2")){
        return;
    }
    struct task_context *tc = pid_to_context(proc_part1.pid);

    void *binder_proc_buf = read_struct(proc_addr,"binder_proc");
    if(binder_proc_buf == nullptr) return;
    // read context addr
    ulong context_addr = ULONG(binder_proc_buf + field_offset(binder_proc,context));
    // fprintf(fp, "context addr:%lx\n",context_addr);
    ulong name_addr = read_structure_field(context_addr,"binder_context","name");
    if (!is_kvaddr(name_addr)) return;
    // read context name
    std::string context_name = read_cstring(name_addr,16, "binder_context_name");
    // read proc name
    ulong tsk_addr = (ulong)proc_part1.tsk;
    std::string task_name = read_cstring(tsk_addr + field_offset(task_struct,comm),16, "task_struct_comm");
    // list all binder threads
    int offset = field_offset(binder_thread,rb_node);
    std::vector<ulong> thread_list = for_each_rbtree((ulong)proc_part1.threads.rb_node,offset);
    ulong list_head = (ulong)proc_part1.waiting_threads.next;
    offset = field_offset(binder_thread,waiting_thread_node);
    std::vector<ulong> wait_thread_list = for_each_list(list_head,offset);
    fprintf(fp, "binder_proc:%#lx %s [%d] %s dead:%d frozen:%d sr:%d ar:%d max:%d total:%zu requested:%d started:%d ready:%zu\n",
            proc_addr,task_name.c_str(),proc_part1.pid,context_name.c_str(),proc_part1.is_dead,proc_part1.is_frozen,proc_part1.sync_recv,proc_part1.async_recv,
            proc_part2.max_threads,thread_list.size(),proc_part2.requested_threads,proc_part2.requested_threads_started,wait_thread_list.size());
    // read all binder thread
    if (flags & BINDER_THREAD){
        for (const auto& thread_addr : thread_list) {
            print_binder_thread_ilocked(thread_addr);
        }
    }
    // read all binder node
    if (flags & BINDER_NODE){
        offset = field_offset(binder_node,rb_node);
        std::vector<ulong> node_list = for_each_rbtree((ulong)proc_part1.nodes.rb_node,offset);
        for (const auto& nodes_addr : node_list) {
            print_binder_node_nilocked(nodes_addr);
        }
    }
    // read all binder ref
    if (flags & BINDER_REF){
        offset = field_offset(binder_ref,rb_node_desc);
        std::vector<ulong> ref_list = for_each_rbtree((ulong)proc_part1.refs_by_desc.rb_node,offset);
        for (const auto& ref_addr : ref_list) {
            print_binder_ref_olocked(ref_addr);
        }
    }
    // read all binder alloc
    if (flags & BINDER_ALLOC){
        ulong alloc_addr = proc_addr + field_offset(binder_proc,alloc);
        if (!is_kvaddr(alloc_addr)){
            print_binder_alloc(tc,alloc_addr);
        }
    }
    // read all todo binder work of binder proc
    ulong list_head_todo = ULONG(binder_proc_buf + field_offset(binder_proc,todo));
    offset = field_offset(binder_work,entry);
    std::vector<ulong> work_list = for_each_list(list_head_todo,offset);
    for (const auto& work_addr : work_list) {
        print_binder_work_ilocked(proc_addr, "    ", "    pending transaction", work_addr);
    }
    FREEBUF(binder_proc_buf);
    fprintf(fp, "\n");
}

void Binder::print_binder_node_nilocked(ulong node_addr) {
    if (!is_kvaddr(node_addr))return;
    struct binder_node node;
    if(!read_struct((node_addr + field_offset(binder_node,work)),&node,sizeof(node),"binder_node")){
        return;
    }
    int debug_id = read_structure_field(node_addr,"binder_node","debug_id");
    // list all the binder_ref of node with hlist
    int offset = field_offset(binder_ref,node_entry);
    ulong refs_head = node_addr + field_offset(binder_node,refs);
    if (!is_kvaddr(refs_head))return;
    std::vector<ulong> ref_list = for_each_hlist(refs_head,offset);
    fprintf(fp, "  binder_node:%#lx id:%d ptr:%#lx cookie:%#lx pri:%s[%d] hs:%d hw:%d ls:%d lw:%d is:%d iw:%zu tr:%d\n",
           node_addr,debug_id, (ulong)node.ptr, (ulong)node.cookie,
           convert_sched(node.sched_policy), node.min_priority,
           node.has_strong_ref, node.has_weak_ref,
           node.local_strong_refs, node.local_weak_refs,
           node.internal_strong_refs, ref_list.size(), node.tmp_refs);
    for (const auto& ref_addr : ref_list) {
        struct binder_ref ref;
        if(!read_struct(ref_addr,&ref,sizeof(ref),"binder_ref")){
            continue;
        }
        ulong proc_addr = (ulong)ref.proc;
        if (!is_kvaddr(proc_addr)) continue;
        void *binder_proc_buf = read_struct(proc_addr,"binder_proc");
        if(binder_proc_buf == nullptr) return;
        // read proc name
        ulong tsk_addr = ULONG(binder_proc_buf + field_offset(binder_proc,tsk));
        int pid = UINT(binder_proc_buf + field_offset(binder_proc,pid));
        std::string task_name = read_cstring(tsk_addr + field_offset(task_struct,comm),16, "task_struct_comm");
        fprintf(fp, "     binder_ref:%#lx id:%d binder_proc:%#lx %s[%d]\n",ref_addr,ref.data.debug_id ,proc_addr,task_name.c_str(),pid);
        FREEBUF(binder_proc_buf);
    }
    if (is_kvaddr((ulong)node.proc)){
        // list all the binder_work of node with list
        ulong list_head = node_addr + field_offset(binder_node,async_todo);
        offset = field_offset(binder_work,entry);
        std::vector<ulong> work_list = for_each_list(list_head,offset);
        for (const auto& work_addr : work_list) {
            print_binder_work_ilocked((ulong)node.proc, "    ", "    pending async transaction", work_addr);
        }
    }
}

void Binder::print_binder_ref_olocked(ulong ref_addr) {
    if (!is_kvaddr(ref_addr))return;
    struct binder_ref ref;
    if(!read_struct(ref_addr,&ref,sizeof(ref),"binder_ref")){
        return;
    }
    ulong node_addr = (ulong)ref.node;
    if (!is_kvaddr(node_addr)) return;
    ulong death_addr = (ulong)ref.death;
    struct binder_node node;
    if(!read_struct((node_addr + field_offset(binder_node,work)),&node,sizeof(node),"binder_node")){
        return;
    }
    int debug_id = read_structure_field(node_addr,"binder_node","debug_id");
    if (is_kvaddr((ulong)node.proc)){
        void *binder_proc_buf = read_struct((ulong)node.proc,"binder_proc");
        if(binder_proc_buf == nullptr) return;
        ulong tsk_addr = ULONG(binder_proc_buf + field_offset(binder_proc,tsk));
        if (!is_kvaddr(tsk_addr)) {
            FREEBUF(binder_proc_buf);
            return;
        }
        int pid = UINT(binder_proc_buf + field_offset(binder_proc,pid));
        std::string task_name = read_cstring(tsk_addr + field_offset(task_struct,comm),16, "task_struct_comm");
        fprintf(fp, "  binder_ref:%#lx id:%d desc:%d s:%d w:%d death:%#lx -> node_id:%d binder_proc:%#lx %s[%d]\n",ref_addr,
           ref.data.debug_id, ref.data.desc,
           ref.data.strong,ref.data.weak, death_addr,debug_id,(ulong)node.proc,
           task_name.c_str(),pid);
        FREEBUF(binder_proc_buf);
    }else{
        fprintf(fp, "  binder_ref:%#lx id:%d desc:%d s:%d w:%d death:%#lx -> node_id:%d %s\n",ref_addr,
            ref.data.debug_id, ref.data.desc,ref.data.strong,
            ref.data.weak, death_addr,debug_id,"[dead]");
    }
}

void Binder::print_binder_thread_ilocked(ulong thread) {
    if (!is_kvaddr(thread))return;
    // fprintf(fp, "print_binder_thread_ilocked:%lx\n",thread);
    struct binder_thread binder_thread;
    if(!read_struct(thread,&binder_thread,sizeof(binder_thread),"binder_thread")){
        return;
    }
    if(binder_thread.pid <= 0)return;
    fprintf(fp, "  binder_thread:%#lx pid:%d loop:%d need_return:%d\n",thread, binder_thread.pid, binder_thread.looper,
         binder_thread.looper_need_return);
    ulong proc = (ulong)binder_thread.proc;
    ulong t = (ulong)binder_thread.transaction_stack;
    ulong t_from,t_from_parent,t_to_parent,t_to_thread;
    while (t) {
        void *binder_transaction_buf = read_struct(t,"binder_transaction");
        if(binder_transaction_buf == nullptr) return;
        t_from = ULONG(binder_transaction_buf + field_offset(binder_transaction,from));
        t_from_parent = ULONG(binder_transaction_buf + field_offset(binder_transaction,from_parent));
        t_to_parent = ULONG(binder_transaction_buf + field_offset(binder_transaction,to_parent));
        t_to_thread = ULONG(binder_transaction_buf + field_offset(binder_transaction,to_thread));
        FREEBUF(binder_transaction_buf);
        if (t_from == thread) {
            print_binder_transaction_ilocked(proc, "    outgoing transaction", t);
            t = t_from_parent;
        } else if (t_to_thread == thread) {
            print_binder_transaction_ilocked(proc, "    incoming transaction", t);
            t = t_to_parent;
        } else {
            print_binder_transaction_ilocked(proc, "    bad transaction", t);
            t = 0x0;
        }
    }
}

char* Binder::convert_sched(int i) {
    return sched_name[i];
}

void Binder::print_binder_transaction_ilocked(ulong proc_addr, const char* prefix, ulong transaction) {
    void *binder_transaction_buf = read_struct(transaction,"binder_transaction");
    if(binder_transaction_buf == nullptr) return;
    ulong t_from = ULONG(binder_transaction_buf + field_offset(binder_transaction,from));
    ulong t_to_thread = ULONG(binder_transaction_buf + field_offset(binder_transaction,to_thread));
    ulong t_to_proc = ULONG(binder_transaction_buf + field_offset(binder_transaction,to_proc));
    ulong t_buffer = ULONG(binder_transaction_buf + field_offset(binder_transaction,buffer));
    int t_debug_id = UINT(binder_transaction_buf + field_offset(binder_transaction,debug_id));
    unsigned int t_code = UINT(binder_transaction_buf + field_offset(binder_transaction,code));
    unsigned int t_flags = UINT(binder_transaction_buf + field_offset(binder_transaction,flags));
    unsigned int t_need_reply = UINT(binder_transaction_buf + field_offset(binder_transaction,need_reply));
    unsigned int t_sched_policy = UINT(binder_transaction_buf + field_offset(binder_transaction,priority) + field_offset(binder_priority,sched_policy));
    int t_prio = UINT(binder_transaction_buf + field_offset(binder_transaction,priority) + field_offset(binder_priority,prio));
    FREEBUF(binder_transaction_buf);

    struct binder_thread from_thread;
    struct binder_thread to_thread;
    struct binder_proc_part1 from_proc;
    struct binder_proc_part1 to_proc;
    if (is_kvaddr(t_from)) {
        if(!read_struct(t_from,&from_thread,sizeof(from_thread),"binder_thread")){
            return;
        }
        if(!read_struct((ulong)from_thread.proc,&from_proc,sizeof(from_proc),"binder_proc_part1")){
            return;
        }
    }
    if(!is_kvaddr(t_to_proc) || !read_struct(t_to_proc,&to_proc,sizeof(to_proc),"binder_proc_part1")){
        return;
    }
    if(!is_kvaddr(t_to_thread) || !read_struct(t_to_thread,&to_thread,sizeof(to_thread),"binder_thread")){
        return;
    }
    fprintf(fp, "%s:%#lx id:%d from %d:%d to %d:%d code:%d flags:%d pri:%s[%d] reply:%d",
            prefix, transaction,t_debug_id,
            t_from ? from_proc.pid : 0,
            t_from ? from_thread.pid : 0,
            t_to_proc ? to_proc.pid : 0,
            t_to_thread ? to_thread.pid : 0,
            t_code, t_flags, convert_sched(t_sched_policy),
            t_prio, t_need_reply);
    if (proc_addr != t_to_proc) {
        fprintf(fp, "\n");
        return;
    }
    if (!is_kvaddr(t_buffer)){
        fprintf(fp, " buffer free\n");
        return;
    }
    struct binder_buffer buf;
    if(!read_struct(t_buffer,&buf,sizeof(buf),"binder_buffer")){
        return;
    }
    ulong target_node = (ulong)buf.target_node;
    if (is_kvaddr(target_node)){
        int debug_id = read_structure_field((ulong)target_node,"binder_node","debug_id");
        fprintf(fp, " target_node:%#lx id:%d", target_node,debug_id);
    }
    fprintf(fp, " binder_buffer:%#lx size:%zd offset:%zd data:%p\n",t_buffer, buf.data_size, buf.offsets_size, buf.user_data);
}

void Binder::print_binder_work_ilocked(ulong proc_addr, const char* prefix, const char* transaction_prefix, ulong work) {
    ulong transaction;
    struct binder_work w;
    if(!read_struct(work,&w,sizeof(w),"binder_work")){
        return;
    }
    switch(w.type) {
        case BINDER_WORK_TRANSACTION:
            transaction = work - field_offset(binder_transaction,work);
            print_binder_transaction_ilocked(proc_addr, transaction_prefix, transaction);
            break;
        case BINDER_WORK_RETURN_ERROR: {
            ulong error_addr = work - offsetof(struct binder_error, work);
            struct binder_error e;
            if(!read_struct(error_addr,&e,sizeof(e),"binder_error")){
                break;
            }
            fprintf(fp, "%stransaction error: %u\n", prefix, e.cmd);
        } break;
        case BINDER_WORK_TRANSACTION_COMPLETE:
            fprintf(fp, "%stransaction complete\n", prefix);
            break;
        case BINDER_WORK_NODE: {
            ulong node_addr = work - field_offset(binder_node,work);
            struct binder_node node;
            if(!read_struct((node_addr + field_offset(binder_node,work)),&node,sizeof(node),"binder_node")){
                break;
            }
            int debug_id = read_structure_field(node_addr,"binder_node","debug_id");
            fprintf(fp, "%snode:%#lx work %d: u%lx c%lx\n", prefix, node_addr, debug_id, (ulong)node.ptr, (ulong)node.cookie);
        } break;
        case BINDER_WORK_DEAD_BINDER:
            fprintf(fp, "%shas dead binder\n", prefix);
            break;
        case BINDER_WORK_DEAD_BINDER_AND_CLEAR:
            fprintf(fp, "%shas cleared dead binder\n", prefix);
            break;
        case BINDER_WORK_CLEAR_DEATH_NOTIFICATION:
            fprintf(fp, "%shas cleared death notification\n", prefix);
            break;
        default:
            fprintf(fp, "%sunknown work: type %d\n", prefix, w.type);
            break;
    }
}
#pragma GCC diagnostic pop
