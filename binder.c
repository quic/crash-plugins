// Copyright (c) 2024 Qualcomm Innovation Center, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause-Clear

#include "binder.h"

static void binder_init(void);
static void binder_fini(void);
static void cmd_binder(void);

char *help_binder[] = {
	"binder",							/* command name */
	"dump binder log information",		/* short description */
	"-a \n"
    "  binder -p [pid]\n"
    "  binder -l\n"
    "  binder -f\n"
    "  binder -n\n"
    "  binder -b\n"
    "  binder -t\n"
    "  binder -r\n",				    /* argument synopsis, or " " if none */			       
	"  This command dumps the binder log information of a specified process.",
	"       -p  pid argument.",
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
    NULL
};

static struct command_table_entry command_table[] = {
    { "binder", cmd_binder, help_binder, 0 },
    { NULL }
};

struct binder_offset_table {
    DEFINE_MEMBER(binder_proc,proc_node)
    DEFINE_MEMBER(binder_proc,context)
    DEFINE_MEMBER(binder_proc,max_threads)
    DEFINE_MEMBER(binder_proc,threads)
    DEFINE_MEMBER(binder_proc,nodes)
    DEFINE_MEMBER(binder_proc,refs_by_desc)
    DEFINE_MEMBER(binder_proc,alloc)
    DEFINE_MEMBER(binder_proc,todo)
    DEFINE_MEMBER(binder_proc,pid)
    DEFINE_MEMBER(binder_proc,tsk)
    DEFINE_MEMBER(binder_context,name)
    DEFINE_MEMBER(binder_thread,tmp_ref)
    DEFINE_MEMBER(binder_thread,rb_node)
    DEFINE_MEMBER(binder_thread,waiting_thread_node)
    DEFINE_MEMBER(binder_transaction,work)
    DEFINE_MEMBER(binder_node,debug_id)
    DEFINE_MEMBER(binder_node,work)
    DEFINE_MEMBER(binder_node,rb_node)
    DEFINE_MEMBER(binder_node,async_todo)
    DEFINE_MEMBER(binder_node,refs)
    DEFINE_MEMBER(binder_ref,rb_node_desc)
    DEFINE_MEMBER(binder_ref,node_entry)
    DEFINE_MEMBER(binder_alloc,vma)
    DEFINE_MEMBER(binder_alloc,free_buffers)
    DEFINE_MEMBER(binder_buffer,rb_node)
    DEFINE_MEMBER(binder_work,entry)
    DEFINE_MEMBER(task_struct,comm)
    DEFINE_MEMBER(binder_transaction,from)
    DEFINE_MEMBER(binder_transaction,from_parent)
    DEFINE_MEMBER(binder_transaction,to_parent)
    DEFINE_MEMBER(binder_transaction,to_thread)
    DEFINE_MEMBER(binder_transaction,to_proc)
    DEFINE_MEMBER(binder_transaction,buffer)
    DEFINE_MEMBER(binder_transaction,debug_id)
    DEFINE_MEMBER(binder_transaction,code)
    DEFINE_MEMBER(binder_transaction,flags)
    DEFINE_MEMBER(binder_transaction,need_reply)
    DEFINE_MEMBER(binder_transaction,priority)
    DEFINE_MEMBER(binder_priority,prio)
    DEFINE_MEMBER(binder_priority,sched_policy)
} binder_offset_table;

static void offset_table_init(void) {
	BZERO(&binder_offset_table, sizeof(binder_offset_table));
    field_offset_init(binder_proc,proc_node);
    field_offset_init(binder_proc,context);
    field_offset_init(binder_proc,max_threads);
    field_offset_init(binder_proc,threads);
    field_offset_init(binder_proc,nodes);
    field_offset_init(binder_proc,refs_by_desc);
    field_offset_init(binder_proc,alloc);
    field_offset_init(binder_proc,todo);
    field_offset_init(binder_proc,pid);
    field_offset_init(binder_proc,tsk);
    field_offset_init(binder_context, name);
    field_offset_init(binder_thread, rb_node);
    field_offset_init(binder_thread, tmp_ref);
    field_offset_init(binder_thread, waiting_thread_node);
    field_offset_init(binder_transaction, work);
    field_offset_init(binder_node,debug_id);
    field_offset_init(binder_node,work);
    field_offset_init(binder_node,rb_node);
    field_offset_init(binder_node,async_todo);
    field_offset_init(binder_node,refs);
    field_offset_init(binder_ref, rb_node_desc);
    field_offset_init(binder_ref, node_entry);
    field_offset_init(binder_buffer,rb_node);
    field_offset_init(binder_work,entry);
    field_offset_init(binder_alloc,vma);
    field_offset_init(binder_alloc,free_buffers);
    field_offset_init(task_struct,comm);
    field_offset_init(binder_transaction,from);
    field_offset_init(binder_transaction,from_parent);
    field_offset_init(binder_transaction,to_parent);
    field_offset_init(binder_transaction,to_thread);
    field_offset_init(binder_transaction,to_proc);
    field_offset_init(binder_transaction,buffer);
    field_offset_init(binder_transaction,debug_id);
    field_offset_init(binder_transaction,code);
    field_offset_init(binder_transaction,flags);
    field_offset_init(binder_transaction,need_reply);
    field_offset_init(binder_transaction,priority);
    field_offset_init(binder_priority,prio);
    field_offset_init(binder_priority,sched_policy);
}

/**define all the struct which need calc struct size */
static struct binder_size_table {
    long binder_proc;
    long binder_thread;
    long binder_transaction;
    long binder_buffer;
    long binder_node;
    long binder_alloc;
    long binder_lru_page;
    long binder_work;
    DEFINE_MEMBER(binder_context,name)
} binder_size_table;

static void size_table_init(void) {
	BZERO(&binder_size_table, sizeof(binder_size_table));
    struct_size_init(binder_proc);
    struct_size_init(binder_thread);
    struct_size_init(binder_transaction);
    struct_size_init(binder_buffer);
    struct_size_init(binder_node);
    struct_size_init(binder_alloc);
    struct_size_init(binder_lru_page);
    struct_size_init(binder_work);
    field_size_init(binder_context, name); 
}

void __attribute__((constructor)) binder_init(void) {
    register_extension(command_table);
    offset_table_init();
    size_table_init();
}

void __attribute__((destructor)) binder_fini(void) {
    // fprintf(fp, "binder_fini\n");
}

void cmd_binder(void)
{
    int c;
    if (argcnt < 2) cmd_usage(pc->curcmd, SYNOPSIS);
	struct binder_argument_t binder_arg;
    BZERO(&binder_arg, sizeof(binder_arg));
    while ((c = getopt(argcnt, args, "tnrbflap:")) != EOF) {
		switch(c) {
            case 'a':
                binder_arg.dump_all = 1;
                binder_proc_show(&binder_arg);
                break;
            case 'p':
                binder_arg.pid = atoi(optarg);
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

void print_binder_transaction_log_entry(bool fail_log){
    ulong binder_transaction_log_addr;
    if(fail_log == true){
        if (!symbol_exists("binder_transaction_log_failed"))
            error(FATAL, "binder_transaction_log_failed doesn't exist in this kernel!\n");
        binder_transaction_log_addr = symbol_value("binder_transaction_log_failed");
        if (!binder_transaction_log_addr) return;
    }else{
        if (!symbol_exists("binder_transaction_log"))
            error(FATAL, "binder_transaction_log doesn't exist in this kernel!\n");
        binder_transaction_log_addr = symbol_value("binder_transaction_log");
        if (!binder_transaction_log_addr) return;
    }
    struct binder_transaction_log btl;
    readmem(binder_transaction_log_addr, KVADDR, &btl, sizeof(btl), "binder_transaction_log", FAULT_ON_ERROR);
    int count = 0;
    if(btl.full == true){
        count = 32;
    }else{
        count = btl.cur;
    }
    for(int i=0;i<count;i++){
        struct binder_transaction_log_entry log_entry = btl.entry[i];
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

void binder_proc_show(struct binder_argument_t* binder_arg) {
    if (!symbol_exists("binder_procs")){
        error(FATAL, "binder_procs doesn't exist in this kernel!\n");
        return;
    }
    ulong binder_procs = symbol_value("binder_procs");
    if (!binder_procs) return;
    ulong* proclist = NULL;
    int offset = field_offset(binder_proc,proc_node);
    int cnt = bd_for_each_hlist_entry(binder_procs,offset,&proclist);
    for (int i = 0; i < cnt; ++i) {
        if (!proclist[i]) continue;
        ulong part1_addr = proclist[i] + field_offset(binder_proc,proc_node);
        struct binder_proc_part1 proc_part1;
        readmem(part1_addr, KVADDR, &proc_part1, sizeof(struct binder_proc_part1), "binder_proc_part1", FAULT_ON_ERROR);
        if (binder_arg->dump_all || binder_arg->pid == proc_part1.pid) {
            print_binder_proc(proclist[i],binder_arg->flags);
        }
    }
    FREEBUF(proclist);
}

void print_binder_alloc(struct task_context *tc,ulong alloc_addr) {
    physaddr_t paddr;
    struct binder_alloc alloc;
    if(alloc_addr <= 0)return;
    readmem(alloc_addr + field_offset(binder_alloc,vma), KVADDR, &alloc, sizeof(struct binder_alloc), "binder_alloc", FAULT_ON_ERROR);
    fprintf(fp, "  binder_alloc:0x%lx mm_struct:%p vma:%p buffer:%p size:%d free:%d\n",alloc_addr,
            alloc.vma_vm_mm, alloc.vma, alloc.buffer, alloc.buffer_size, alloc.free_async_space);
    // read all the pages
    int nr_pages = alloc.buffer_size / PAGESIZE();
    for (int i = 0; i < nr_pages; ++i) {
        ulong lru_page_addr = (ulong)alloc.pages + i * struct_size(binder_lru_page);
        struct binder_lru_page lru_page;
        readmem(lru_page_addr, KVADDR, &lru_page, struct_size(binder_lru_page), "binder_lru_page", FAULT_ON_ERROR);
        ulong page_addr = (ulong)lru_page.page_ptr;
        if(page_addr > 0){
            is_page_ptr(page_addr, &paddr);
            fprintf(fp, "    Page :0x%lx PA:0x%llx\n",page_addr,(ulonglong)paddr);
        }
    }
    // list all free buffers
    ulong* buffer_data = NULL;
    int offset = field_offset(binder_buffer,rb_node);
    int cnt = bd_for_each_rbtree_entry((ulong)alloc.free_buffers.rb_node,offset,&buffer_data);
    paddr = 0;
    struct binder_buffer buf;
    for (int i = 0; i < cnt; ++i) {
        ulong buffer_addr = buffer_data[i];
        if (buffer_addr <= 0) continue;
        BZERO(&buf, sizeof(struct binder_buffer));
        readmem(buffer_addr, KVADDR, &buf, sizeof(struct binder_buffer), "binder_buffer", FAULT_ON_ERROR);
        paddr = 0;
        if(tc != NULL){
            uvtop(tc, (ulong)buf.user_data, &paddr, 0);
        }
        fprintf(fp, "    Free binder_buffer :0x%lx id:%d data:0x%lx PA:0x%llx size:%zd offset:%zd extra:%zd pid:%d %s\n",
		   buffer_addr, buf.debug_id, (ulong)buf.user_data,(ulonglong)paddr,
		   buf.data_size, buf.offsets_size,
		   buf.extra_buffers_size,buf.pid,
		   buf.transaction ? "active" : "delivered");
    }
    if(buffer_data != NULL)FREEBUF(buffer_data);

    // list all allocated_buffers buffers
    buffer_data = NULL;
    offset = field_offset(binder_buffer,rb_node);
    cnt = bd_for_each_rbtree_entry((ulong)alloc.allocated_buffers.rb_node,offset,&buffer_data);
    for (int i = 0; i < cnt; ++i) {
        ulong buffer_addr = buffer_data[i];
        if (buffer_addr <= 0) continue;
        BZERO(&buf, sizeof(struct binder_buffer));
        readmem(buffer_addr, KVADDR, &buf, sizeof(struct binder_buffer), "binder_buffer", FAULT_ON_ERROR);
        paddr = 0;
        if(tc != NULL){
            uvtop(tc, (ulong)buf.user_data, &paddr, 0);
        }
        fprintf(fp, "    Alloc binder_buffer:0x%lx id:%d data:0x%lx PA:0x%llx size:%zd offset:%zd extra:%zd pid:%d %s\n",
		   buffer_addr, buf.debug_id, (ulong)buf.user_data,(ulonglong)paddr,
		   buf.data_size, buf.offsets_size,
		   buf.extra_buffers_size,buf.pid,
		   buf.transaction ? "active" : "delivered");
    }
    if(buffer_data != NULL)FREEBUF(buffer_data);
}

void print_binder_proc(ulong proc_addr,int flags) {
    int cnt = 0;
    int offset = 0;

    ulong part1_addr = proc_addr + field_offset(binder_proc,proc_node);
    struct binder_proc_part1 proc_part1;
    readmem(part1_addr, KVADDR, &proc_part1, sizeof(struct binder_proc_part1), "binder_proc_part1", FAULT_ON_ERROR);

    ulong part2_addr = proc_addr + field_offset(binder_proc,max_threads);
    struct binder_proc_part2 proc_part2;
    readmem(part2_addr, KVADDR, &proc_part2, sizeof(struct binder_proc_part2), "binder_proc_part2", FAULT_ON_ERROR);

    struct task_context *tc = pid_to_context(proc_part1.pid);

    void *binder_proc_buf = bd_read_struct(proc_addr,struct_size(binder_proc),"binder_proc");
    if(binder_proc_buf == NULL) return;
    // read context addr
    ulong context_addr = ULONG(binder_proc_buf + field_offset(binder_proc,context));
    // fprintf(fp, "context addr:%lx\n",context_addr);
    void* buf = bd_read_structure_field(context_addr,field_offset(binder_context,name),field_size(binder_context,name),"binder_context_name");
    if(buf == NULL) return;
    // read context name
    char context_name[16];
    bd_read_cstring(ULONG(buf),context_name,16, "binder_context_name");
    FREEBUF(buf);
    // read proc name
    ulong tsk_addr = (ulong)proc_part1.tsk;
    char task_name[16];
    bd_read_cstring(tsk_addr + field_offset(task_struct,comm),task_name,16, "task_struct_comm");
    // list all binder threads
    ulong* thread_data = NULL;
    offset = field_offset(binder_thread,rb_node);
    int thread_cnt = bd_for_each_rbtree_entry((ulong)proc_part1.threads.rb_node,offset,&thread_data);
    // fprintf(fp, "thread_cnt:%d\n",thread_cnt);
    // list all waiting threads
    ulong* waiting_thread_data = NULL;
    ulong list_head = (ulong)proc_part1.waiting_threads.next;
    offset = field_offset(binder_thread,waiting_thread_node);
    int wait_thread_cnt = bd_for_each_list_entry(list_head,offset,&waiting_thread_data);
    if(waiting_thread_data != NULL)FREEBUF(waiting_thread_data);
    fprintf(fp, "binder_proc:0x%lx %s [%d] %s dead:%d frozen:%d sr:%d ar:%d max:%d total:%d requested:%d started:%d ready:%d\n", 
            proc_addr,task_name,proc_part1.pid,context_name,proc_part1.is_dead,proc_part1.is_frozen,proc_part1.sync_recv,proc_part1.async_recv,
            proc_part2.max_threads,thread_cnt,proc_part2.requested_threads,proc_part2.requested_threads_started,wait_thread_cnt);
    // read all binder thread
    if (flags & BINDER_THREAD){
        for (int i = 0; i < thread_cnt; ++i) {
            ulong threads_addr = thread_data[i];
            if (threads_addr <= 0) continue;
            print_binder_thread_ilocked(threads_addr);
        }
    }
    if(thread_data != NULL)FREEBUF(thread_data);
    // read all binder node
    if (flags & BINDER_NODE){
        ulong* node_data = NULL;
        offset = field_offset(binder_node,rb_node);
        cnt = bd_for_each_rbtree_entry((ulong)proc_part1.nodes.rb_node,offset,&node_data);
        for (int i = 0; i < cnt; ++i) {
            ulong nodes_addr = node_data[i];
            if (nodes_addr <= 0) continue;
            print_binder_node_nilocked(nodes_addr);
        }
        if(node_data != NULL)FREEBUF(node_data);
    }
    // read all binder ref
    if (flags & BINDER_REF){
        ulong* ref_data = NULL;
        offset = field_offset(binder_ref,rb_node_desc);
        cnt = bd_for_each_rbtree_entry((ulong)proc_part1.refs_by_desc.rb_node,offset,&ref_data);
        for (int i = 0; i < cnt; ++i) {
            ulong ref_addr = ref_data[i];
            if (ref_addr <= 0) continue;
            print_binder_ref_olocked(ref_addr);
        }
        if(ref_data != NULL)FREEBUF(ref_data);
    }
    // read all binder alloc
    if (flags & BINDER_ALLOC){
        ulong alloc_addr = proc_addr + field_offset(binder_proc,alloc);
        if (alloc_addr > 0){
            print_binder_alloc(tc,alloc_addr);
        }
    }
    // read all todo binder work of binder proc
    ulong* work_data = NULL;
    ulong list_head_todo = ULONG(binder_proc_buf + field_offset(binder_proc,todo));
    offset = field_offset(binder_work,entry);
    cnt = bd_for_each_list_entry(list_head_todo,offset,&work_data);
    for (int i = 0; i < cnt; ++i) {
        ulong work_addr = work_data[i];
        if (work_addr <= 0) continue;
        print_binder_work_ilocked(proc_addr, "    ", "    pending transaction", work_addr);
    }
    if(work_data != NULL)FREEBUF(work_data);

    FREEBUF(binder_proc_buf);
    fprintf(fp, "\n");
}

void print_binder_node_nilocked(ulong node_addr) {
    if(node_addr <= 0)return;
    struct binder_node node;
    readmem((node_addr + field_offset(binder_node,work)), KVADDR, &node, sizeof(struct binder_node), "binder_node", FAULT_ON_ERROR);
    void* buf = bd_read_structure_field(node_addr,field_offset(binder_node,debug_id),sizeof(int),"debug_id");
    int debug_id = UINT(buf);
    FREEBUF(buf);
    // list all the binder_ref of node with hlist
    ulong* reflist = NULL;
    int offset = field_offset(binder_ref,node_entry);
    ulong refs_head = node_addr + field_offset(binder_node,refs);
    int cnt = 0;
    if(!refs_head){
        cnt = bd_for_each_hlist_entry(refs_head,offset,&reflist);
    }
    fprintf(fp, "  binder_node:0x%lx id:%d ptr:0x%lx cookie:0x%lx pri:%s[%d] hs:%d hw:%d ls:%d lw:%d is:%d iw:%d tr:%d\n",
		   node_addr,debug_id, (ulong)node.ptr, (ulong)node.cookie,
		   convert_sched(node.sched_policy), node.min_priority,
		   node.has_strong_ref, node.has_weak_ref,
		   node.local_strong_refs, node.local_weak_refs,
		   node.internal_strong_refs, cnt, node.tmp_refs);
    if (cnt > 0){
        for (int i = 0; i < cnt; ++i) {
            ulong ref_addr = reflist[i];
            if (!ref_addr) continue;
            struct binder_ref ref;
            readmem(ref_addr, KVADDR, &ref, sizeof(struct binder_ref), "binder_ref", FAULT_ON_ERROR);
            ulong proc_addr = (ulong)ref.proc;
            if (!proc_addr) continue;
            void *binder_proc_buf = bd_read_struct(proc_addr,struct_size(binder_proc),"binder_proc");
            if(binder_proc_buf == NULL) return;
            // read proc name
            ulong tsk_addr = ULONG(binder_proc_buf + field_offset(binder_proc,tsk));
            int pid = UINT(binder_proc_buf + field_offset(binder_proc,pid));
            char task_name[16];
            bd_read_cstring(tsk_addr + field_offset(task_struct,comm),task_name,16, "task_struct_comm");
            fprintf(fp, "     binder_ref:0x%lx id:%d binder_proc:0x%lx %s[%d]\n",ref_addr,ref.data.debug_id ,proc_addr,task_name,pid);
            FREEBUF(binder_proc_buf);
        }
    }
    if(reflist != NULL)FREEBUF(reflist);
    if (node.proc){
        // list all the binder_work of node with list
        ulong* work_data = NULL;
        ulong list_head = node_addr + field_offset(binder_node,async_todo);
        offset = field_offset(binder_work,entry);
        cnt = bd_for_each_list_entry(list_head,offset,&work_data);
        for (int i = 0; i < cnt; ++i) {
            ulong work_addr = work_data[i];
            if (work_addr <= 0) continue;
            print_binder_work_ilocked((ulong)node.proc, "    ", "    pending async transaction", work_addr);
        }
        if(work_data != NULL)FREEBUF(work_data);
    }
}

void print_binder_ref_olocked(ulong ref_addr) {
    if(ref_addr <= 0)return;
    struct binder_ref ref;
    readmem(ref_addr, KVADDR, &ref, sizeof(struct binder_ref), "binder_ref", FAULT_ON_ERROR);
    ulong node_addr = (ulong)ref.node;
    if (node_addr <= 0) return;
    ulong death_addr = (ulong)ref.death;
    struct binder_node node;
    readmem((node_addr + field_offset(binder_node,work)), KVADDR, &node, sizeof(struct binder_node), "binder_node", FAULT_ON_ERROR);
    void* buf = bd_read_structure_field(node_addr,field_offset(binder_node,debug_id),sizeof(int),"debug_id");
    int debug_id = UINT(buf);
    FREEBUF(buf);
    if(node.proc){
        void *binder_proc_buf = bd_read_struct((ulong)node.proc,struct_size(binder_proc),"binder_proc");
        if(binder_proc_buf == NULL) return;
        ulong tsk_addr = ULONG(binder_proc_buf + field_offset(binder_proc,tsk));
        int pid = UINT(binder_proc_buf + field_offset(binder_proc,pid));
        char task_name[16];
        bd_read_cstring(tsk_addr + field_offset(task_struct,comm),task_name,16, "task_struct_comm");
        fprintf(fp, "  binder_ref:0x%lx id:%d desc:%d s:%d w:%d death:0x%lx -> node_id:%d binder_proc:0x%lx %s[%d]\n",ref_addr,
		   ref.data.debug_id, ref.data.desc,
		   ref.data.strong,ref.data.weak, death_addr,debug_id,(ulong)node.proc,
           task_name,pid);
        FREEBUF(binder_proc_buf);
    }else{
        fprintf(fp, "  binder_ref:0x%lx id:%d desc:%d s:%d w:%d death:0x%lx -> node_id:%d %s\n",ref_addr,
            ref.data.debug_id, ref.data.desc,ref.data.strong,
            ref.data.weak, death_addr,debug_id,"[dead]");
    }
}

void print_binder_thread_ilocked(ulong thread) {
    if(thread <= 0)return;
    // fprintf(fp, "print_binder_thread_ilocked:%lx\n",thread);
    struct binder_thread binder_thread;
    readmem(thread, KVADDR, &binder_thread, sizeof(struct binder_thread), "binder_thread", FAULT_ON_ERROR);
    if(binder_thread.pid <= 0)return;
    fprintf(fp, "  binder_thread:0x%lx pid:%d loop:%d need_return:%d\n",thread, binder_thread.pid, binder_thread.looper,
         binder_thread.looper_need_return);
    ulong proc = (ulong)binder_thread.proc;
    ulong t = (ulong)binder_thread.transaction_stack;
    ulong t_from,t_from_parent,t_to_parent,t_to_thread;
    while (t) {
        void *binder_transaction_buf = bd_read_struct(t,struct_size(binder_transaction),"binder_transaction");
        if(binder_transaction_buf == NULL) return;
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

char* sched_name[] = {
    "SCHED_NORMAL",
    "SCHED_FIFO",
    "SCHED_RR",
    "SCHED_BATCH",
    "SCHED_ISO",
    "SCHED_IDLE",
    "SCHED_DEADLINE",
};

char* convert_sched(int i) {
    return sched_name[i];
}

void print_binder_transaction_ilocked(ulong proc_addr, const char* prefix, ulong transaction) {
    void *binder_transaction_buf = bd_read_struct(transaction,struct_size(binder_transaction),"binder_transaction");
    if(binder_transaction_buf == NULL) return;
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
    if (t_from) {
        readmem(t_from, KVADDR, &from_thread, sizeof(struct binder_thread), "binder_thread", FAULT_ON_ERROR);
        readmem((ulong)from_thread.proc, KVADDR, &from_proc, sizeof(struct binder_proc_part1), "binder_proc_part1", FAULT_ON_ERROR);
    }
    if (t_to_proc) {
        readmem(t_to_proc, KVADDR, &to_proc, sizeof(struct binder_proc_part1), "binder_proc_part1", FAULT_ON_ERROR);
    }
    if (t_to_thread) {
        readmem(t_to_thread, KVADDR, &to_thread, sizeof(struct binder_thread), "binder_thread", FAULT_ON_ERROR);
    }
    fprintf(fp, "%s:0x%lx id:%d from %d:%d to %d:%d code:%d flags:%d pri:%s[%d] reply:%d",
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
    if (!t_buffer) {
        fprintf(fp, " buffer free\n");
        return;
    }
    struct binder_buffer buf;
    readmem(t_buffer, KVADDR, &buf, sizeof(struct binder_buffer), "binder_buffer", FAULT_ON_ERROR);
    ulong target_node = (ulong)buf.target_node;
    if (target_node) {
        void* buf = bd_read_structure_field((ulong)target_node,field_offset(binder_node,debug_id),sizeof(int),"debug_id");
        int debug_id = UINT(buf);
        FREEBUF(buf);
        fprintf(fp, " target_node:0x%lx id:%d", target_node,debug_id);
    }
    fprintf(fp, " binder_buffer:0x%lx size:%zd offset:%zd data:%p\n",t_buffer, buf.data_size, buf.offsets_size, buf.user_data);
}

void print_binder_work_ilocked(ulong proc_addr, const char* prefix, const char* transaction_prefix, ulong work) {
    ulong transaction;
    struct binder_work w;
    readmem(work, KVADDR, &w, struct_size(binder_work), "binder_work", FAULT_ON_ERROR);
    switch(w.type) {
        case BINDER_WORK_TRANSACTION:
            transaction = work - field_offset(binder_transaction,work);
            print_binder_transaction_ilocked(proc_addr, transaction_prefix, transaction);
            break;
        case BINDER_WORK_RETURN_ERROR: {
            ulong error = work - offsetof(struct binder_error, work);
            struct binder_error e;
            readmem(error, KVADDR, &e, sizeof(struct binder_error), "binder_error", FAULT_ON_ERROR);
            fprintf(fp, "%stransaction error: %u\n", prefix, e.cmd);
        } break;
        case BINDER_WORK_TRANSACTION_COMPLETE:
            fprintf(fp, "%stransaction complete\n", prefix);
            break;
        case BINDER_WORK_NODE: {
            ulong node_addr = work - field_offset(binder_node,work);
            struct binder_node node;
            readmem((node_addr + field_offset(binder_node,work)), KVADDR, &node, sizeof(struct binder_node), "binder_node", FAULT_ON_ERROR);
            void* buf = bd_read_structure_field(node_addr,field_offset(binder_node,debug_id),sizeof(int),"debug_id");
            int debug_id = UINT(buf);
            FREEBUF(buf);
            fprintf(fp, "%snode:0x%lx work %d: u%lx c%lx\n", prefix, node_addr, debug_id, (ulong)node.ptr, (ulong)node.cookie);
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

int bd_for_each_rbtree_entry(ulong rb_root,int offset,ulong **ptr){
    ulong *treeList;
    struct tree_data td;
    int cnt = 0;
    BZERO(&td, sizeof(struct tree_data));
    // td.flags |= VERBOSE | TREE_POSITION_DISPLAY | TREE_LINEAR_ORDER;
    td.flags |= TREE_NODE_POINTER;
    td.start = rb_root;
    td.node_member_offset = offset;
    hq_open();
    cnt = do_rbtree(&td);
    if(cnt==0)return 0;
    treeList = (ulong *)GETBUF(cnt * sizeof(void *));
    retrieve_list(treeList, cnt);
    for (int i = 0; i < cnt; ++i) {
        if (treeList[i] <= 0) continue;
        // fprintf(fp, "node addr:%lx\n",treeList[i]);
        treeList[i] -= td.node_member_offset;
        *ptr = treeList;
    }
    hq_close();
    return cnt;
}

int bd_for_each_list_entry(ulong list_head,int offset,ulong **ptr){
    struct list_data ld;
    BZERO(&ld, sizeof(struct list_data));
    ld.flags |= LIST_ALLOCATE;
    readmem(list_head, KVADDR, &ld.start,sizeof(ulong), "for_each_list_entry list_head", FAULT_ON_ERROR);
    ld.end = list_head;
    // ld.member_offset = offset;
    ld.list_head_offset = offset;
    if (empty_list(ld.start)) return 0;
    int cnt = do_list(&ld);
    if(cnt==0)return 0;
    *ptr = ld.list_ptr;
    return cnt;
}

int bd_for_each_hlist_entry(ulong hlist_head,int offset,ulong **ptr){
    ulong first = bd_read_pointer(hlist_head,"hlist_head");
    struct list_data ld;
    BZERO(&ld, sizeof(struct list_data));
    ld.flags |= LIST_ALLOCATE;
    ld.start = first;
    // ld.member_offset = offset;
    ld.list_head_offset = offset;
    if (empty_list(ld.start)) return 0;
    int cnt = do_list(&ld);
    if(cnt==0)return 0;
    *ptr = ld.list_ptr;
    return cnt;
}

void* bd_read_structure_field(ulong kvaddr,int offset, int size, char* name){
    ulong addr = kvaddr + offset;
    void *buf = (void *)GETBUF(size);
    if (!readmem(addr, KVADDR, buf, size, name, RETURN_ON_ERROR|QUIET)) {
        error(WARNING, "Can't read %s at %lx\n",name, addr);
        return NULL;
    }
    return buf;
}

void bd_read_cstring(ulong kvaddr,char* buf, int len, char* name){
    if (!readmem(kvaddr, KVADDR, buf, len, name, RETURN_ON_ERROR|QUIET)) {
        error(WARNING, "Can't read %s at %lx\n",name, kvaddr);
    }
}

void* bd_read_struct(ulong kvaddr,int size, char* name){
    void* buf = (void *)GETBUF(size);
    if (!readmem(kvaddr, KVADDR, buf, size, name, RETURN_ON_ERROR|QUIET)) {
        error(WARNING, "Can't read %s at %lx\n",name,kvaddr);
        return NULL;
    }
    return buf;
}

ulong bd_read_pointer(ulong kvaddr,char* name){
    ulong val;
    if (!readmem(kvaddr, KVADDR, &val, sizeof(void *), name, RETURN_ON_ERROR|QUIET)) {
        error(WARNING, "Can't read %s at %lx\n",name, kvaddr);
        return -1;
    }
    return val;
}