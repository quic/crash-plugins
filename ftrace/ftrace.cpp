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

#include "ftrace.h"

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wpointer-arith"

#ifndef BUILD_TARGET_TOGETHER
DEFINE_PLUGIN_COMMAND(Ftrace)
#endif

void Ftrace::cmd_main(void) {
    int c,cpu;
    std::string cppString;
    if (argcnt < 2) cmd_usage(pc->curcmd, SYNOPSIS);
    if (trace_list.size() == 0){
        parser_ftrace_trace_arrays();
    }
    if (event_maps.size() == 0){
        parser_ftrace_events_list();
    }
    if (common_field_maps.size() == 0){
        parser_common_trace_fields();
    }
    while ((c = getopt(argcnt, args, "als:fc:Sd")) != EOF) {
        switch(c) {
            case 'a':
                print_trace_log();
                break;
            case 'l':
                print_trace_array();
                break;
            case 'c':
                cppString.assign(optarg);
                try {
                    cpu = std::stoi(cppString);
                } catch (...) {
                    fprintf(fp, "invaild cpu arg %s\n",cppString.c_str());
                    break;
                }
                print_trace_log(cpu);
                break;
            case 's':
                cppString.assign(optarg);
                print_trace_log(cppString);
                break;
            case 'f':
                print_event_format();
                break;
            case 'd':
                ftrace_dump();
                break;
            case 'S':
                ftrace_show();
                break;
            default:
                argerrs++;
                break;
        }
    }
    if (argerrs)
        cmd_usage(pc->curcmd, SYNOPSIS);
}

void Ftrace::init_offset(){
    field_init(trace_array,current_trace);
    field_init(trace_array,array_buffer);
    field_init(trace_array,max_buffer);
    field_init(trace_array,buffer);
    field_init(trace_array, name);
    field_init(trace_array, list);
    field_init(array_buffer,buffer);
    field_init(array_buffer,time_start);
    field_init(array_buffer,cpu);
    field_init(tracer,name);

    field_init(ring_buffer, pages);
    field_init(ring_buffer, flags);
    field_init(ring_buffer, cpus);
    field_init(ring_buffer, buffers);
    field_init(trace_buffer, pages);
    field_init(trace_buffer, flags);
    field_init(trace_buffer, cpus);
    field_init(trace_buffer, buffers);

    field_init(trace_event_call, print_fmt);
    field_init(trace_event_call, flags);
    field_init(trace_event_call, name);
    field_init(trace_event_call, class);
    field_init(trace_event_call, event);
    field_init(trace_event_call, list);
    field_init(trace_event_call, tp);

    field_init(trace_event_class, system);
    field_init(trace_event_class, fields);

    field_init(trace_event, type);
    field_init(tracepoint, name);

    field_init(ring_buffer_per_cpu, nr_pages);
    field_init(ring_buffer_per_cpu, cpu);
    field_init(ring_buffer_per_cpu, pages);
    field_init(ring_buffer_per_cpu, head_page);
    field_init(ring_buffer_per_cpu, tail_page);
    field_init(ring_buffer_per_cpu, commit_page);
    field_init(ring_buffer_per_cpu, reader_page);
    field_init(ring_buffer_per_cpu, overrun);
    field_init(ring_buffer_per_cpu, entries);

    field_init(ring_buffer_event, array);
    struct_init(ring_buffer_event);
    struct_init(trace_entry);

    field_init(buffer_page, read);
    field_init(buffer_page, list);
    field_init(buffer_page, page);
    field_init(buffer_page, real_end);
    field_init(list_head, next);
    field_init(ftrace_event_field, link);
    field_init(ftrace_event_field, name);
    field_init(ftrace_event_field, type);
    field_init(ftrace_event_field, offset);
    field_init(ftrace_event_field, size);
    field_init(ftrace_event_field, is_signed);
    field_init(ftrace_event_field, filter_type);
    field_init(buffer_data_page, commit);
    field_init(buffer_data_page, time_stamp);
    field_init(buffer_data_page, data);

    field_init(saved_cmdlines_buffer, map_pid_to_cmdline);
    field_init(saved_cmdlines_buffer, map_cmdline_to_pid);
    field_init(saved_cmdlines_buffer, cmdline_num);
    field_init(saved_cmdlines_buffer, cmdline_idx);
    field_init(saved_cmdlines_buffer, saved_cmdlines);
}

void Ftrace::init_command(void) {
    cmd_name = "ftrace";
    help_str_list={
        "ftrace",                            /* command name */
        "dump ftrace information",        /* short description */
        "-a \n"
            "  ftrace -l\n"
            "  ftrace -c <cpu>\n"
            "  ftrace -s <name>\n"
            "  ftrace -f\n"
            "  ftrace -d\n"
            "  ftrace -S\n"
            "  This command dumps the ftrace info.",
        "\n",
        "EXAMPLES",
        "  List all trace array:",
        "    %s> ftrace -l",
        "       usb_xhci",
        "       usb",
        "       memory",
        "       clock_reg",
        "       binder",
        "       suspend",
        "       rproc_qcom",
        "       global",
        "  Display all ftrace log:",
        "\n",
        "    %s> ftrace -a",
        "       usb        UsbFfs-worker-1908   [0] d..2. 165.323101: dwc3_ep_queue ep4in: req ffffff8068d7f000 length 0/24 zsI ==> -115",
        "       usb        UsbFfs-worker-1908   [0] d..2. 165.323143: dwc3_prepare_trb ep4in: trb ffffffc00953d000(E1:D0) buf 02946619584size 24ctrl 2065",
        "       usb        UsbFfs-worker-1908   [0] d..2. 165.323165: dwc3_gadget_ep_cmd ep4in: cmd 589831params 000--> status: 0",
        "       usb        UsbFfs-worker-1908   [0] d..2. 165.323253: dwc3_ep_queue ep4in: req ffffff801563fe00 length 0/14 zsI ==> -115",
        "       usb        UsbFfs-worker-1908   [0] d..2. 165.323272: dwc3_prepare_trb ep4in: trb ffffffc00953d010(E2:D0) buf 02941848960size 14ctrl 2065",
        "       usb        UsbFfs-worker-1908   [0] d..2. 165.323293: dwc3_gadget_ep_cmd ep4in: cmd 589831params 000--> status: 0",
        "\n",
        "  Display ftrace log of specified trace array by name:",
        "    %s> ftrace -s binder",
        "       binder     binder:943_4-1443    [0] ..... 227.397723: binder_transaction transaction=89703 dest_node=0 dest_proc=1067 dest_thread=3576 reply=1 flags=0x0 code=0x0",
        "       binder     binder:943_4-1443    [0] ...1. 227.397729: binder_update_page_range proc=1067 allocate=1 offset=0 size=0",
        "       binder     binder:943_4-1443    [0] ..... 227.397735: binder_transaction_alloc_buf transaction=89703 data_size=0 offsets_size=0 extra_buffers_size=0",
        "       binder     binder:943_4-1443    [0] ..... 227.397810: binder_set_priority proc=943 thread=1443 old=98 => new=120 desired=120",
        "       binder     binder:943_2-1018    [0] ..... 227.397908: binder_transaction_received transaction=89702",
        "       binder     binder:943_2-1018    [0] ..... 227.397913: binder_return cmd=2151707138",
        "\n",
        "  Display all trace event info:",
        "    %s> ftrace -f",
        "       [25] ipi_raise: 'target_mask=%s (%s)', __get_bitmask(target_cpus), REC->reason",
        "           format: 'target_mask=%s (%s)'",
        "           args  :",
        "               __get_bitmask(target_cpus)",
        "               reason",
        "           trace_event_raw_ipi_raise {",
        "               __data_loc unsigned long[] target_cpus,offset:8, size:4",
        "               const char * reason,     offset:16, size:8",
        "           }",
        "\n",
        "  Display ftrace log of specified trace array by cpu:",
        "    %s> ftrace -c 1",
        "    global     sh-24270             [1] ..s1. 3471.158992: softirq_exit vec=9 [action=RCU]",
        "    global     sh-24270             [1] ..s1. 3471.158986: softirq_exit vec=9 [action=RCU]",
        "\n",
        "  Dump all trace to file:",
        "    %s> ftrace -d",
        "    Save to /path/ftrace.data",
        "\n",
        "  Display all trace via trace-cmd:",
        "    %s> ftrace -S",
        "    memory:            <...>-67    [001]    43.835156: tlbi_end:             group=5800000.qcom,ipa:ipa_smmu_ap",
        "    memory:            <...>-67    [001]    43.835160: tlbi_start:           group=5800000.qcom,ipa:ipa_smmu_ap",
        "\n",
    };
}

Ftrace::Ftrace(){
    pid_max = read_int(csymbol_value("pid_max"),"pid_max");
    if (!try_get_symbol_data(TO_CONST_STRING("nr_cpu_ids"), sizeof(int), &nr_cpu_ids)) {
        nr_cpu_ids = 1;
    }
}

void Ftrace::print_event_format(){
    for (const auto& pair : event_maps) {
        std::shared_ptr<TraceEvent> event_ptr = pair.second;
        event_ptr->dump();
    }
}

void Ftrace::print_trace_array(){
    std::ostringstream oss;
    for (const auto& ta : trace_list) {
        oss << std::left << std::setw(10)  << ta->name << "\n";
        for (const auto& cpu_rb_ptr : ta->cpu_ring_buffers) {
            oss << "    cpu[" << cpu_rb_ptr->cpu << "]"
                << " nr_pages:" << cpu_rb_ptr->buffer_pages.size()
                << " write_pages:" << cpu_rb_ptr->data_pages.size() << "\n";
        }
    }
    fprintf(fp, "%s", oss.str().c_str());
}

void Ftrace::print_trace_log(int cpu){
    if(debug)fprintf(fp, "skip event: %zu \n",TraceEvent::skip_cnt);
    if (trace_logs.size() == 0){
        for (const auto& ta : trace_list) {
            for (const auto& cpu_rb_ptr : ta->cpu_ring_buffers) {
                for (const auto& rb_addr : cpu_rb_ptr->data_pages) {
                    parse_buffer_page(ta, cpu_rb_ptr, rb_addr);
                }
            }
        }
        std::sort(trace_logs.begin(), trace_logs.end(),[&](std::shared_ptr<trace_log> a, std::shared_ptr<trace_log> b){
            return a->timestamp > b->timestamp;
        });
    }
    for (const auto& log_ptr : trace_logs) {
        if (log_ptr->cpu != cpu){
            continue;
        }
        fprintf(fp, "%s\n", log_ptr->log.c_str());
    }
}

void Ftrace::print_trace_log(){
    if(debug)fprintf(fp, "skip event: %zu \n",TraceEvent::skip_cnt);
    if (trace_logs.size() == 0){
        for (const auto& ta : trace_list) {
            for (const auto& cpu_rb_ptr : ta->cpu_ring_buffers) {
                for (const auto& rb_addr : cpu_rb_ptr->data_pages) {
                    parse_buffer_page(ta, cpu_rb_ptr, rb_addr);
                }
            }
        }
        std::sort(trace_logs.begin(), trace_logs.end(),[&](std::shared_ptr<trace_log> a, std::shared_ptr<trace_log> b){
            return a->timestamp > b->timestamp;
        });
    }
    for (const auto& log_ptr : trace_logs) {
        fprintf(fp, "%s\n", log_ptr->log.c_str());
    }
}

void Ftrace::print_trace_log(std::string name){
    if(debug)fprintf(fp, "skip event: %zu \n",TraceEvent::skip_cnt);
    if (trace_logs.size() == 0){
        for (const auto& ta : trace_list) {
            for (const auto& cpu_rb_ptr : ta->cpu_ring_buffers) {
                for (const auto& rb_addr : cpu_rb_ptr->data_pages) {
                    parse_buffer_page(ta, cpu_rb_ptr, rb_addr);
                }
            }
        }
        std::sort(trace_logs.begin(), trace_logs.end(),[&](std::shared_ptr<trace_log> a, std::shared_ptr<trace_log> b){
            return a->timestamp > b->timestamp;
        });
    }
    for (const auto& log_ptr : trace_logs) {
        if (log_ptr->array_name != name){
            continue;
        }
        fprintf(fp, "%s\n", log_ptr->log.c_str());
    }
}

void Ftrace::parser_savedcmd(){
    ulong savedcmd_addr = read_pointer(csymbol_value("savedcmd"),"savedcmd");
    if (is_kvaddr(savedcmd_addr)) {
        savedcmd_ptr = std::make_shared<saved_cmdlines_buffer>();
        savedcmd_ptr->map_pid_to_cmdline = savedcmd_addr + field_offset(saved_cmdlines_buffer,map_pid_to_cmdline);
        savedcmd_ptr->map_cmdline_to_pid = read_pointer(savedcmd_addr + field_offset(saved_cmdlines_buffer,map_cmdline_to_pid),"map_cmdline_to_pid");
        savedcmd_ptr->cmdline_num = read_uint(savedcmd_addr + field_offset(saved_cmdlines_buffer,cmdline_num),"cmdline_num");
        savedcmd_ptr->cmdline_idx = read_int(savedcmd_addr + field_offset(saved_cmdlines_buffer,cmdline_idx),"cmdline_idx");
        savedcmd_ptr->saved_cmdlines = read_pointer(savedcmd_addr + field_offset(saved_cmdlines_buffer,saved_cmdlines),"saved_cmdlines");
    }
}

void Ftrace::parser_ftrace_trace_arrays(){
    if (!csymbol_exists("ftrace_trace_arrays")){
        fprintf(fp, "ftrace_trace_arrays doesn't exist in this kernel!\n");
        return;
    }
    ulong trace_arrays_addr = csymbol_value("ftrace_trace_arrays");
    if (!is_kvaddr(trace_arrays_addr)) {
        fprintf(fp, "ftrace_trace_arrays address is invalid!\n");
        return;
    }
    ulong gtrace_addr = csymbol_value("global_trace");
    // fprintf(fp, "gtrace_addr:%#lx \n",gtrace_addr);
    int offset = field_offset(trace_array, list);
    for (const auto& addr : for_each_list(trace_arrays_addr,offset)) {
        std::shared_ptr<trace_array> ta_ptr = parser_trace_array(addr);
        if (addr == gtrace_addr){
            global_trace = ta_ptr;
            ta_ptr->name = "global";
        }
        trace_list.push_back(ta_ptr);
    }
    parser_savedcmd();
}

std::shared_ptr<trace_array> Ftrace::parser_trace_array(ulong addr){
    auto trace_ptr = std::make_shared<trace_array>();
    ulong name_addr = read_pointer(addr + field_offset(trace_array,name),"name addr");
    trace_ptr->addr = addr;
    if (is_kvaddr(name_addr)) {
        trace_ptr->name = read_cstring(name_addr,64, "name");
    }
    // fprintf(fp, "trace_array:%#lx name:%s size:%zu \n",addr, trace_ptr->name.c_str(), trace_ptr->name.size());
    ulong array_addr = addr + field_offset(trace_array,array_buffer);
    trace_ptr->time_start = read_ulong(array_addr + field_offset(array_buffer,time_start),"time_start");
    // trace_ptr->cpu = read_uint(array_addr + field_offset(array_buffer,cpu),"cpu");
    ulong buffer = read_pointer(array_addr + field_offset(array_buffer,buffer),"buffer addr");
    if (is_kvaddr(buffer)) {
        // fprintf(fp, "   trace_buffer:%#lx \n",buffer);
        parser_trace_buffer(trace_ptr,buffer);
    }
    // ulong data = read_pointer(array_addr + field_offset(array_buffer,data),"data addr");
    return trace_ptr;
}

void Ftrace::parser_trace_buffer(std::shared_ptr<trace_array> ta, ulong addr){
    ta->cpus = read_int(addr + field_offset(trace_buffer, cpus), "cpus");
    ulong buffers = read_pointer(addr + field_offset(trace_buffer, buffers), "buffers");
    if (!is_kvaddr(buffers))
        return;
    for (int i = 0; i < ta->cpus; i++){
        ulong rb_addr = read_pointer(buffers + i * sizeof(void *), "ring_buffer addr");
        if (!is_kvaddr(rb_addr))
            continue;
        parser_ring_buffer_per_cpu(ta, rb_addr);
    }
}

// crash> ring_buffer_per_cpu -ox
// struct ring_buffer_per_cpu {
//     [0x0] int cpu;
//     [0x4] atomic_t record_disabled;
//     [0x8] atomic_t resize_disabled;
//    [0x10] struct trace_buffer *buffer;
//    [0x18] raw_spinlock_t reader_lock;
//    [0x30] arch_spinlock_t lock;
//    [0x34] struct lock_class_key lock_key;
//    [0x38] struct buffer_data_page *free_page;
//    [0x40] unsigned long nr_pages;
//    [0x48] unsigned int current_context;
//    [0x50] struct list_head *pages;
//    [0x58] struct buffer_page *head_page;
//    [0x60] struct buffer_page *tail_page;
//    [0x68] struct buffer_page *commit_page;
//    [0x70] struct buffer_page *reader_page;
void Ftrace::parser_ring_buffer_per_cpu(std::shared_ptr<trace_array> ta, ulong addr){
    ulong nr_pages = read_ulong(addr + field_offset(ring_buffer_per_cpu,nr_pages),"nr_pages");
    if(nr_pages == 0) return;
    ta->nr_pages = nr_pages;
    auto ring_buf_ptr = std::make_shared<ring_buffer_per_cpu>();
    ring_buf_ptr->addr = addr;
    ring_buf_ptr->cpu = read_int(addr + field_offset(ring_buffer_per_cpu,cpu),"cpu");;
    // ulong tail_page = read_pointer(addr + field_offset(ring_buffer_per_cpu,tail_page),"tail_page");
    ulong commit_page = read_pointer(addr + field_offset(ring_buffer_per_cpu,commit_page),"commit_page");
    ulong reader_page = read_pointer(addr + field_offset(ring_buffer_per_cpu,reader_page),"reader_page");
    ulong head_page = read_pointer(addr + field_offset(ring_buffer_per_cpu,head_page),"head_page");
    ulong pages = read_pointer(addr + field_offset(ring_buffer_per_cpu,pages),"pages");
    // fprintf(fp, "   ring_buffer_per_cpu:%#lx cpu:%d nr_pages:%ld\n",addr, ring_buf_ptr->cpu,nr_pages);
    ring_buf_ptr->buffer_pages.resize(nr_pages);
    size_t page_index = 0;
    ulong real_head_page = head_page;
    ulong bp_addr = pages;
    while (is_kvaddr(bp_addr) && page_index < nr_pages){
        ring_buf_ptr->buffer_pages[page_index] = bp_addr;
        bp_addr = read_pointer(bp_addr + field_offset(buffer_page,list) + field_offset(list_head,next),"buffer_page");
        if (bp_addr & 3) {
            bp_addr &= ~3;
            real_head_page = bp_addr;
        }
        page_index ++;
    }
    ulong head_page_index;
    for (ulong i = 0; i < ring_buf_ptr->buffer_pages.size(); i++){
        if (real_head_page == ring_buf_ptr->buffer_pages[i]){
            head_page_index = i;
            break;
        }
    }
    if (buffer_page_has_data(reader_page)){
        ring_buf_ptr->data_pages.push_back(reader_page);
    }
    ulong index = head_page_index;
    if (reader_page != commit_page){
        while (true){
            ring_buf_ptr->data_pages.push_back(ring_buf_ptr->buffer_pages[index]);
            if (ring_buf_ptr->buffer_pages[index] == commit_page){
                break;
            }
            index ++;
            if (index == nr_pages){
                index = 0;
            }
            if (index == head_page_index) {
                break;
            }
        }
    }
    ta->cpu_ring_buffers.push_back(ring_buf_ptr);
}

ulong Ftrace::buffer_page_has_data(ulong addr){
    return read_ulong(addr + field_offset(buffer_page,real_end),"real_end");
}

// crash> struct buffer_page -ox
// struct buffer_page {
//    [0x0] struct list_head list;
//   [0x10] local_t write;
//   [0x18] unsigned int read;
//   [0x20] local_t entries;
//   [0x28] unsigned long real_end;
//   [0x30] struct buffer_data_page *page;
// }
// SIZE: 0x38
// crash> struct buffer_data_page
// struct buffer_data_page {
//     u64 time_stamp;
//     local_t commit;
//     unsigned char data[];
// }
// SIZE: 16
void Ftrace::parse_buffer_page(std::shared_ptr<trace_array> ta_ptr, std::shared_ptr<ring_buffer_per_cpu> rb_ptr, ulong addr){
    ulong bdp_addr = read_pointer(addr + field_offset(buffer_page,page),"page");
    if (!is_kvaddr(bdp_addr)) {
        return;
    }
    ulong commit = read_ulong(bdp_addr + field_offset(buffer_data_page,commit),"commit");
    if (commit <= 0) {
        return;
    }
    // fprintf(fp, "      buffer_page:%#lx buffer_data_page:%#lx commit:%ld\n",addr,bdp_addr,commit);
    uint64_t time_stamp = read_ulonglong(bdp_addr + field_offset(buffer_data_page,time_stamp),"time_stamp");
    ulong event_timestamp = 0;
    ulong event_end = bdp_addr + commit;
    ulong event_addr = bdp_addr + field_offset(buffer_data_page,data);
    ulong total_read = 0;
    while (total_read < commit){
        // crash> struct ring_buffer_event
        // struct ring_buffer_event {
        //     u32 type_len : 5;
        //     u32 time_delta : 27;
        //     u32 array[];
        // }
        // SIZE: 4
        struct ring_buffer_event rb_event;
        if(!read_struct(event_addr,&rb_event,sizeof(rb_event),"ring_buffer_event")){
            break;
        }
        int trace_len = 0;
        event_timestamp += rb_event.time_delta;
        // so type_len is set to 0 and 32 bit array filed holds length
        // while payload starts afterwards at array[1]
        //                               event_addr                           array[]  trace_entry_addr
        //                                   |                                   |           |
        //                                   v                                   v           v
        //   ---------------------------------------------------------------------------------------------------------------------------
        //   |    struct buffer_data_page    |      struct ring_buffer_event     |    u32    | struct trace_entry  |  struct trace_xxx  |
        //   ----------------------------------------------------------------------------------------------------------------------------
        if (rb_event.type_len == 0){
            ulong trace_entry_addr = event_addr + field_offset(ring_buffer_event,array) + sizeof(uint32_t);
            if (is_kvaddr(trace_entry_addr)) {
                parse_trace_entry(ta_ptr, rb_ptr, trace_entry_addr, time_stamp + event_timestamp);
            }
            trace_len = struct_size(ring_buffer_event) + rb_event.array[0];
        // Data Events
        //                               event_addr                      trace_entry_addr
        //                                   |                                   |
        //                                   v                                   v
        //   -----------------------------------------------------------------------------------------------
        //   |    struct buffer_data_page    |      struct ring_buffer_event     |   struct trace_entry    |
        //   -----------------------------------------------------------------------------------------------
        }else if (rb_event.type_len <= RINGBUF_TYPE_DATA_TYPE_LEN_MAX){
            ulong trace_entry_addr = event_addr + field_offset(ring_buffer_event,array);
            if (is_kvaddr(trace_entry_addr)) {
                parse_trace_entry(ta_ptr, rb_ptr, trace_entry_addr, time_stamp + event_timestamp);
            }
            trace_len = struct_size(ring_buffer_event) + (rb_event.type_len << 2);
        // Padding event or discarded event
        }else if (rb_event.type_len == RINGBUF_TYPE_PADDING){
            if (event_addr > event_end){
                break;
            }
            if (rb_event.time_delta == 1){
                trace_len = struct_size(ring_buffer_event) + rb_event.array[0];
            }else{
                trace_len = struct_size(ring_buffer_event) + (event_end - event_addr);
            }
        // This is a time extend event
        //                               event_addr                           array[]
        //                                   |                                   |
        //                                   v                                   v
        //   ---------------------------------------------------------------------------------
        //   |    struct buffer_data_page    |      struct ring_buffer_event     |    u32    |
        //   ---------------------------------------------------------------------------------
        }else if (rb_event.type_len == RINGBUF_TYPE_TIME_EXTEND){
            event_timestamp += (read_uint(event_addr + field_offset(ring_buffer_event,array),"array") << 27);
            trace_len = struct_size(ring_buffer_event) + sizeof(uint32_t);
        // Accounts for an absolute timestamp
        }else if (rb_event.type_len == RINGBUF_TYPE_TIME_STAMP){
            event_timestamp = 0;
            trace_len = struct_size(ring_buffer_event) + sizeof(uint32_t);
        }
        event_addr += trace_len;
        total_read += trace_len;
    }
}

// crash> struct trace_entry -ox
// struct trace_entry {
//   [0x0] unsigned short type;
//   [0x2] unsigned char flags;
//   [0x3] unsigned char preempt_count;
//   [0x4] int pid;
// }
// SIZE: 0x8
void Ftrace::parse_trace_entry(std::shared_ptr<trace_array> ta_ptr, std::shared_ptr<ring_buffer_per_cpu> rb_ptr, ulong addr, ulong timestamp){
    struct trace_entry entry;
    if(!read_struct(addr, &entry,sizeof(entry),"trace_entry")){
        return;
    }
    if (event_maps.find(entry.type) == event_maps.end()) { //not exists
        return;
    }
    if (entry.pid > pid_max){
        return;
    }
    std::shared_ptr<TraceEvent> event_ptr = event_maps[entry.type];
    if (event_ptr->name.empty()){
        return;
    }
    std::string comm;
    if (comm_pid_dict.find(entry.pid) != comm_pid_dict.end()) { //exists
        comm = comm_pid_dict[entry.pid];
    }else{
        comm = find_cmdline(entry.pid);
    }
    std::string lat_fmt = get_lat_fmt(entry.flags,entry.preempt_count);
    std::ostringstream oss;
    oss << std::left << std::setw(10)  << ta_ptr->name << " "
        << std::left << std::setw(20)  << comm << " "
        << std::left << "[" << rb_ptr->cpu << "] "
        << std::left << lat_fmt << " "
        << std::left << std::fixed << std::setprecision(6) << (double)timestamp/1000000000 << ": "
        << std::left << event_ptr->name << " ";
    // fprintf(fp, "%s ",oss.str().c_str());
    event_ptr->handle(addr,oss);
    std::shared_ptr<trace_log> log_ptr = std::make_shared<trace_log>();
    log_ptr->array_name = ta_ptr->name;
    log_ptr->cpu = rb_ptr->cpu;
    log_ptr->timestamp = timestamp;
    log_ptr->log = oss.str();
    trace_logs.push_back(log_ptr);
    // fprintf(fp, "%s \n",oss.str().c_str());
}

std::string Ftrace::find_cmdline(int pid){
    std::string comm = "<TBD>";
    if (pid == 0){
        comm = "<idle>";
    }else if (savedcmd_ptr != nullptr){
        int tpid = pid & (pid_max - 1);
        int index = read_int(savedcmd_ptr->map_pid_to_cmdline + tpid * sizeof(unsigned int),"map_pid_to_cmdline");
        ulong pid_addr = savedcmd_ptr->map_cmdline_to_pid + index * sizeof(unsigned int);
        if (index >= 0 && is_kvaddr(pid_addr)){
            int cmdline_tpid = read_int(pid_addr,"map_cmdline_to_pid");
            ulong comm_addr = savedcmd_ptr->saved_cmdlines + index * 16;
            if (cmdline_tpid == pid && is_kvaddr(comm_addr)){
                comm = read_cstring(comm_addr, 16, "comm");
            }else{
                struct task_context * tc = pid_to_context(pid);
                if (tc){
                    comm = tc->comm;
                }
            }
        }
    }
    std::string name = comm + "-" + std::to_string(pid);
    comm_pid_dict[pid] = name;
    return name;
}

void Ftrace::parser_ftrace_events_list(){
    if (!csymbol_exists("ftrace_events")){
        fprintf(fp, "ftrace_events doesn't exist in this kernel!\n");
        return;
    }
    ulong ftrace_events = csymbol_value("ftrace_events");
    if (!is_kvaddr(ftrace_events)) {
        fprintf(fp, "ftrace_events address is invalid!\n");
        return;
    }
    for (const auto& addr : for_each_list(ftrace_events,field_offset(trace_event_call, list))) {
        std::shared_ptr<TraceEvent> event_ptr = parser_trace_event_call(addr);
        if (event_ptr != nullptr){
            event_maps[event_ptr->id] = event_ptr;
        }
    }
}

#define CREATE_EVENT_IF_MATCH(event_name)               \
else if (name == #event_name){                          \
    event_ptr = std::make_shared<event_name##_event>(); \
    event_ptr->name = name;                             \
    event_ptr->struct_type = "trace_event_raw_" + name; \
}

// crash> struct trace_event_call -ox
// struct trace_event_call {
//    [0x0] struct list_head list;
//   [0x10] struct trace_event_class *class;
//          union {
//   [0x18]     char *name;
//   [0x18]     struct tracepoint *tp;
//          };
//   [0x20] struct trace_event event;
//   [0x50] char *print_fmt;
//   [0x58] struct event_filter *filter;
//          union {
//   [0x60]     void *module;
//   [0x60]     atomic_t refcnt;
//          };
//   [0x68] void *data;
//   [0x70] int flags;
std::shared_ptr<TraceEvent> Ftrace::parser_trace_event_call(ulong addr){
    uint id = get_event_type_id(addr);
    if (event_maps.find(id) != event_maps.end()) { //exists
        return nullptr;
    }
    std::string name = get_event_type_name(addr);
    std::shared_ptr<TraceEvent> event_ptr;
    if (id == 6) { // TRACE_BPRINT
        event_ptr = std::make_shared<bprint_event>();
        event_ptr->name = "bprint";
        event_ptr->struct_type = "bputs_entry";
    }else if (id == 5){
        event_ptr = std::make_shared<print_event>();
        event_ptr->name = "print";
        event_ptr->struct_type = "print_entry";
    }else if (id == 4){
        event_ptr = std::make_shared<kernel_stack_event>();
        event_ptr->name = "kernel_stack";
        event_ptr->struct_type = "stack_entry";
    }else if (id == 12){
        event_ptr = std::make_shared<user_stack_event>();
        event_ptr->name = "user_stack";
        event_ptr->struct_type = "userstack_entry";
    }else if (id == 14){
        event_ptr = std::make_shared<bputs_event>();
        event_ptr->name = "bputs";
        event_ptr->struct_type = "bputs_entry";
    }
    CREATE_EVENT_IF_MATCH(sched_switch)
    CREATE_EVENT_IF_MATCH(softirq_raise)
    CREATE_EVENT_IF_MATCH(softirq_entry)
    CREATE_EVENT_IF_MATCH(softirq_exit)
    CREATE_EVENT_IF_MATCH(irq_handler_exit)
    CREATE_EVENT_IF_MATCH(binder_return)
    CREATE_EVENT_IF_MATCH(binder_command)
    CREATE_EVENT_IF_MATCH(dwc3_ep_queue)
    CREATE_EVENT_IF_MATCH(dwc3_ep_dequeue)
    CREATE_EVENT_IF_MATCH(dwc3_prepare_trb)
    CREATE_EVENT_IF_MATCH(dwc3_gadget_giveback)
    CREATE_EVENT_IF_MATCH(dwc3_gadget_ep_cmd)
    CREATE_EVENT_IF_MATCH(dwc3_event)
    CREATE_EVENT_IF_MATCH(dwc3_complete_trb)
    CREATE_EVENT_IF_MATCH(rwmmio_read)
    CREATE_EVENT_IF_MATCH(rwmmio_write)
    CREATE_EVENT_IF_MATCH(rwmmio_post_read)
    CREATE_EVENT_IF_MATCH(rwmmio_post_write)
    CREATE_EVENT_IF_MATCH(gpio_value)
    CREATE_EVENT_IF_MATCH(gpio_direction)
    CREATE_EVENT_IF_MATCH(gpio_direction)
    CREATE_EVENT_IF_MATCH(dma_map_page)
    CREATE_EVENT_IF_MATCH(dma_unmap_page)
    CREATE_EVENT_IF_MATCH(dma_map_resource)
    CREATE_EVENT_IF_MATCH(dma_unmap_resource)
    CREATE_EVENT_IF_MATCH(dma_alloc)
    CREATE_EVENT_IF_MATCH(dma_free)
    CREATE_EVENT_IF_MATCH(dma_map_sg)
    CREATE_EVENT_IF_MATCH(dma_unmap_sg)
    CREATE_EVENT_IF_MATCH(dma_sync_single_for_cpu)
    CREATE_EVENT_IF_MATCH(dma_sync_single_for_device)
    CREATE_EVENT_IF_MATCH(dma_sync_sg_for_cpu)
    CREATE_EVENT_IF_MATCH(dma_sync_sg_for_device)
    CREATE_EVENT_IF_MATCH(swiotlb_bounced)
    else{
        event_ptr = std::make_shared<TraceEvent>();
        event_ptr->name = name;
        event_ptr->struct_type = "trace_event_raw_" + name;
    }
    event_ptr->set_print_format(get_event_type_print_fmt(addr));
    event_ptr->system = get_event_type_system(addr);
    event_ptr->id = id;
    event_ptr->plugin_ptr = this;
    if (event_ptr->name.empty() || event_ptr->system.empty()){
        return nullptr;
    }
    // fprintf(fp, "id:%d %s \n", event_ptr->id, event_ptr->name.c_str());
    ulong event_class = read_pointer(addr + field_offset(trace_event_call,class),"event_class");
    if (is_kvaddr(event_class)) {
        for (const auto& field_addr : for_each_list(event_class + field_offset(trace_event_class, fields),field_offset(ftrace_event_field, link))) {
            auto field_ptr = parser_event_field(field_addr);
            event_ptr->field_maps[field_ptr->name] = field_ptr;
        }
    }
    return event_ptr;
}

void Ftrace::parser_common_trace_fields(){
     if (!csymbol_exists("ftrace_common_fields")){
         return;
     }
     ulong ftrace_common_addr = csymbol_value("ftrace_common_fields");
     for (const auto& field_addr : for_each_list(ftrace_common_addr,field_offset(ftrace_event_field, link))) {
        auto field_ptr = parser_event_field(field_addr);
        common_field_maps[field_ptr->name] = field_ptr;
     }
}

uint Ftrace::get_event_type_id(ulong addr){
    return read_uint(addr + field_offset(trace_event_call,event) + field_offset(trace_event,type),"type");
}

std::string Ftrace::get_event_type_name(ulong addr){
    int flags = read_int(addr + field_offset(trace_event_call,flags),"flags");
    int TRACE_EVENT_FL_TRACEPOINT = 0;
    if (THIS_KERNEL_VERSION >= LINUX(4, 14, 0)){
        TRACE_EVENT_FL_TRACEPOINT = 0x10;
    }else if (THIS_KERNEL_VERSION >= LINUX(4, 9, 0)){
        TRACE_EVENT_FL_TRACEPOINT = 0x20;
    }else{
        TRACE_EVENT_FL_TRACEPOINT = 0x40;
    }
    std::string name="";
    if (THIS_KERNEL_VERSION >= LINUX(3, 18, 0) && (flags & TRACE_EVENT_FL_TRACEPOINT)){
        ulong tracepoint_addr = read_pointer(addr + field_offset(trace_event_call,tp),"tracepoint addr");
        ulong name_addr = read_pointer(tracepoint_addr + field_offset(tracepoint,name),"name addr");
        if (is_kvaddr(name_addr)) {
            name = read_cstring(name_addr,64, "name");
        }
    }else{
        ulong name_addr = read_pointer(addr + field_offset(trace_event_call,name),"name addr");
        if (is_kvaddr(name_addr)) {
            name = read_cstring(name_addr,64, "name");
        }
    }
    return name;
}

std::string Ftrace::get_event_type_system(ulong addr){
    std::string name;
    ulong class_addr = read_pointer(addr + field_offset(trace_event_call,class),"class addr");
    if (is_kvaddr(class_addr)) {
        ulong name_addr = read_pointer(class_addr + field_offset(trace_event_class,system),"system addr");
        if (is_kvaddr(name_addr)) {
            name = read_cstring(name_addr,64, "name");
        }
    }
    return name;
}

std::string Ftrace::get_event_type_print_fmt(ulong addr){
    std::string print_fmt;
    ulong fmt_addr = read_pointer(addr + field_offset(trace_event_call,print_fmt),"print_fmt addr");
    if (is_kvaddr(fmt_addr)) {
        print_fmt = read_long_string(fmt_addr,"print_fmt");
    }
    return print_fmt;
}

std::shared_ptr<trace_field> Ftrace:: parser_event_field(ulong addr){
    std::shared_ptr<trace_field> field_ptr = std::make_shared<trace_field>();
    field_ptr->offset = read_int(addr + field_offset(ftrace_event_field,offset),"offset");
    field_ptr->size = read_int(addr + field_offset(ftrace_event_field,size),"size");
    field_ptr->is_signed = read_int(addr + field_offset(ftrace_event_field,is_signed),"is_signed");
    field_ptr->filter_type = read_int(addr + field_offset(ftrace_event_field,filter_type),"filter_type");
    ulong name_addr = read_pointer(addr + field_offset(ftrace_event_field,name),"name addr");
    if (is_kvaddr(name_addr)) {
        field_ptr->name = read_cstring(name_addr,512, "name");
    }else{
        field_ptr->name = "";
    }
    ulong type_addr = read_pointer(addr + field_offset(ftrace_event_field,type),"type addr");
    if (is_kvaddr(type_addr)) {
        field_ptr->type = read_cstring(type_addr,512, "type");
    }else{
        field_ptr->type = "";
    }
    // std::ostringstream oss;
    // oss << std::left << field_ptr->type << " "
    //     << std::left << field_ptr->name << "\n";
    // fprintf(fp, "   %s", oss.str().c_str());
    return field_ptr;
}

std::string Ftrace::get_lat_fmt(unsigned char flags, unsigned char preempt_count) {
    std::string lat_fmt;
    bool nmi = flags & TRACE_FLAG_NMI;
    bool hardirq = flags & TRACE_FLAG_HARDIRQ;
    bool softirq = flags & TRACE_FLAG_SOFTIRQ;
    bool bh_off = flags & TRACE_FLAG_BH_OFF;
    char irqs_off;
    if ((flags & TRACE_FLAG_IRQS_OFF) && bh_off) {
        irqs_off = 'D';
    } else if (flags & TRACE_FLAG_IRQS_OFF) {
        irqs_off = 'd';
    } else if (bh_off) {
        irqs_off = 'b';
    } else if (flags & TRACE_FLAG_IRQS_NOSUPPORT) {
        irqs_off = 'X';
    } else {
        irqs_off = '.';
    }
    unsigned char resched = flags & (TRACE_FLAG_NEED_RESCHED | TRACE_FLAG_PREEMPT_RESCHED);
    char need_resched;
    if (resched == (TRACE_FLAG_NEED_RESCHED | TRACE_FLAG_PREEMPT_RESCHED)) {
        need_resched = 'N';
    } else if (resched == TRACE_FLAG_NEED_RESCHED) {
        need_resched = 'n';
    } else if (resched == TRACE_FLAG_PREEMPT_RESCHED) {
        need_resched = 'p';
    } else {
        need_resched = '.';
    }
    char hardsoft_irq;
    if (nmi && hardirq) {
        hardsoft_irq = 'Z';
    } else if (nmi) {
        hardsoft_irq = 'z';
    } else if (hardirq && softirq) {
        hardsoft_irq = 'H';
    } else if (hardirq) {
        hardsoft_irq = 'h';
    } else if (softirq) {
        hardsoft_irq = 's';
    } else {
        hardsoft_irq = '.';
    }
    lat_fmt += irqs_off;
    lat_fmt += need_resched;
    lat_fmt += hardsoft_irq;
    if (preempt_count & 0xf) {
        lat_fmt += std::to_string(preempt_count & 0xf)[0];
    } else {
        lat_fmt += '.';
    }
    if (preempt_count & 0xf0) {
        lat_fmt += std::to_string((preempt_count >> 4))[0];
    } else {
        lat_fmt += '.';
    }
    return lat_fmt;
}

#define TRACE_CMD_FILE_VERSION_STRING "6"

bool Ftrace::write_trace_data(){
    write_init_data();
    write_header_data();
    write_events_data();
    write_kallsyms_data();
    write_printk_data();
    write_cmdlines();
    ulonglong res_data_offset = ftell(trace_file);
    write_res_data();
    write_buffer_data();
    fseek(trace_file, res_data_offset, SEEK_SET);
    /* Fix up the global trace's options header with the instance offsets */
    write_res_data();
    fflush(trace_file);
    return true;
}

void Ftrace::write_buffer_data(){
    for (const auto& ta_ptr : trace_list) {
        if (ta_ptr->name != "global") continue;
        ta_ptr->offset = ftell(trace_file);
        write_trace_array_buffers(ta_ptr);
    }

    for (const auto& ta_ptr : trace_list) {
        if (ta_ptr->name == "global") continue;
        ta_ptr->offset = ftell(trace_file);
        fwrite("flyrecord", 10, 1, trace_file);
        write_trace_array_buffers(ta_ptr);
    }
}

// +--------------------------------+
// | CPU Buffer Headers             |
// |--------------------------------|<---- offset
// | [CPU 0] Offset (8 bytes)       |
// | [CPU 0] Size   (8 bytes)       |
// |--------------------------------|
// | [CPU 1] Offset (8 bytes)       |
// | [CPU 1] Size   (8 bytes)       |
// |--------------------------------|
// | ...                            |
// |--------------------------------|
// | Padding to page_size           |
// +------------------------------- +<---- buffer_offset
// | CPU 0 data                     |
// +--------------------------------+
// | CPU 1 data                     |
// +--------------------------------+
// | ...                            |
// +--------------------------------+
void Ftrace::write_trace_array_buffers(std::shared_ptr<trace_array> ta_ptr) {
    size_t header_start_offset = ftell(trace_file);
    size_t header_total_size = ta_ptr->cpus * 16;
    size_t data_start_offset = roundup(header_start_offset + header_total_size, page_size);
    size_t buffer_offset = data_start_offset;
    for (int cpu = 0; cpu < ta_ptr->cpus; cpu++) {
        auto& ring_buffer = ta_ptr->cpu_ring_buffers[cpu];
        size_t buffer_size = page_size * ring_buffer->data_pages.size();
        fwrite(&buffer_offset, 8, 1, trace_file);
        fwrite(&buffer_size, 8, 1, trace_file);
        buffer_offset += buffer_size;
    }
    fseek(trace_file, data_start_offset, SEEK_SET);
    for (int cpu = 0; cpu < ta_ptr->cpus; cpu++) {
        auto& ring_buffer = ta_ptr->cpu_ring_buffers[cpu];
        for (const auto& buffer_page : ring_buffer->data_pages) {
            ulong page = read_pointer(buffer_page + field_offset(buffer_page, page), "buffer_page page");
            // fprintf(fp, "page: %#lx \n", page);
            char* buf = (char*)read_memory(page, page_size, "get page context");
            fwrite(buf, page_size, 1, trace_file);
            FREEBUF(buf);
        }
    }
}

// +------------------------------+
// | nr_cpu_buffers (4 bytes)     |
// +------------------------------+
// | "options  " (10 bytes)       |
// +------------------------------+
// | option (2 bytes)             |
// +------------------------------+
// | option_size (4 bytes)        |
// +------------------------------+
// | offset (8 bytes)             |
// +------------------------------+
// | name (N+1 bytes)             |
// +------------------------------+
// | ...                          |
// +------------------------------+
// | TRACECMD_OPTION_DONE (2B)    |
// +------------------------------+
// | "flyrecord" (10 bytes)       |
// +------------------------------+
void Ftrace::write_res_data(){
    fwrite(&nr_cpu_ids, 4, 1, trace_file);

    // write_options
    fwrite("options  ", 10, 1, trace_file);
    unsigned short option = TRACECMD_OPTION_BUFFER;
    for (const auto& ta_ptr : trace_list) {
        if(ta_ptr->name == "global"){
            continue;
        }
        fwrite(&option, 2, 1, trace_file);

        ulonglong option_size = ta_ptr->name.size() + 1 + 8;
        fwrite(&option_size, 4, 1, trace_file);

        fwrite(&ta_ptr->offset, 8, 1, trace_file);
        if(debug)fprintf(fp, "%s offset[%zu] \n", ta_ptr->name.c_str(), ta_ptr->offset);

        fwrite(ta_ptr->name.c_str(), ta_ptr->name.size() + 1, 1, trace_file);
    }
    option = TRACECMD_OPTION_DONE;
    fwrite(&option, 2, 1, trace_file);

    fwrite("flyrecord", 10, 1, trace_file);
}

void Ftrace::write_cmdlines(){
    std::vector<char> data_buf;
    size_t pos = 0;
    struct task_context *tc = FIRST_CONTEXT();
    for (ulong i = 0; i < RUNNING_TASKS(); i++){
        write_to_buf(data_buf, pos, "%d %s\n",  (int)tc[i].pid, tc[i].comm);
    }
    fwrite(&pos, 8, 1, trace_file);
    fwrite(data_buf.data(), data_buf.size() - 1, 1, trace_file);
}

void Ftrace::write_printk_data(){
    if (!csymbol_exists("__start___trace_bprintk_fmt") || !csymbol_exists("__stop___trace_bprintk_fmt")){
        return;
    }
    std::vector<char> data_buf;
    size_t pos = 0;
    ulong bprintk_fmt_s = csymbol_value("__start___trace_bprintk_fmt");
    ulong bprintk_fmt_e = csymbol_value("__stop___trace_bprintk_fmt");
    size_t count = (bprintk_fmt_e - bprintk_fmt_s) / sizeof(long);
    if (count != 0) {
        ulong bprintks[count];
        if(read_struct(bprintk_fmt_s,bprintks, count * sizeof(ulong), "__trace_bprintk_fmt")){
            for (size_t i = 0; i < count; i++) {
                if (!is_kvaddr(bprintks[i])) {
                    continue;
                }
                char tmpbuf[4096];
                size_t len = read_string(bprintks[i], tmpbuf, sizeof(tmpbuf));
                if (!len){
                    continue;
                }
                write_to_buf(data_buf, pos, "0x%lx : \"",  bprintks[i]);
                for (size_t i = 0; tmpbuf[i]; i++) {
                    switch (tmpbuf[i]) {
                        case '\n':
                            write_to_buf(data_buf, pos, "\\n");
                            break;
                        case '\t':
                            write_to_buf(data_buf, pos, "\\t");
                            break;
                        case '\\':
                            write_to_buf(data_buf, pos, "\\\\");
                            break;
                        case '"':
                            write_to_buf(data_buf, pos, "\\\"");
                            break;
                        default:
                            write_to_buf(data_buf, pos, "%c", tmpbuf[i]);
                            break;
                    }
                }
                write_to_buf(data_buf, pos, "\"\n");
            }
        }
    }
    /* Add modules */
    if (csymbol_exists("trace_bprintk_fmt_list")){
        int addr_is_array = 0;
        switch (MEMBER_TYPE(TO_CONST_STRING("trace_bprintk_fmt"), TO_CONST_STRING("fmt"))) {
            case TYPE_CODE_ARRAY:
                addr_is_array = 1;
                break;
            case TYPE_CODE_PTR:
            default:
                break;
        }
        ulong fmt_list = csymbol_value("trace_bprintk_fmt_list");
        struct kernel_list_head mod_fmt;
        if(read_struct(fmt_list, &mod_fmt, sizeof(mod_fmt), "list_head")){
            while ((ulong)mod_fmt.next != fmt_list){
                ulong node_addr = (ulong)mod_fmt.next + sizeof(mod_fmt);
                if (!addr_is_array) {
                    node_addr = read_ulong(node_addr,"node_addr");
                }
                if(!read_struct((ulong)mod_fmt.next, &mod_fmt, sizeof(mod_fmt), "list_head")){
                    break;
                }
                char tmpbuf[4096];
                size_t len = read_string(node_addr, tmpbuf, sizeof(tmpbuf));
                if (!len){
                    continue;
                }
                write_to_buf(data_buf, pos, "0x%lx : \"",  node_addr);
                for (size_t i = 0; tmpbuf[i]; i++) {
                    switch (tmpbuf[i]) {
                    case '\n':
                        write_to_buf(data_buf, pos, "\\n");
                        break;
                    case '\t':
                        write_to_buf(data_buf, pos, "\\t");
                        break;
                    case '\\':
                        write_to_buf(data_buf, pos, "\\\\");
                        break;
                    case '"':
                        write_to_buf(data_buf, pos, "\\\"");
                        break;
                    default:
                        write_to_buf(data_buf, pos, "%c", tmpbuf[i]);
                        break;
                    }
                }
                write_to_buf(data_buf, pos, "\"\n");
                count++;
            }
        }
    }
    if (count == 0){
        unsigned int size = 0;
        fwrite(&size, 4, 1, trace_file);
    }
    if (data_buf.size() != 0){
        fwrite(&pos, 4, 1, trace_file);
        fwrite(data_buf.data(), data_buf.size() - 1, 1, trace_file);
    }
}

void Ftrace::write_kallsyms_data(){
    struct syment *sp;
    std::vector<char> sym_buf;
    size_t pos = 0;
    for (sp = st->symtable; sp < st->symend; sp++){
        if (!sp)continue;
        write_to_buf(sym_buf, pos, "%lx %c %s\n",  sp->value, sp->type, sp->name);
    }
    if (MODULE_MEMORY()){
        save_proc_kallsyms_mod_v6_4(sym_buf, pos);
    }else{
        save_proc_kallsyms_mod_legacy(sym_buf, pos);
    }
    fwrite(&pos, 4, 1, trace_file);
    fwrite(sym_buf.data(), sym_buf.size() - 1, 1, trace_file);
}

void Ftrace::save_proc_kallsyms_mod_v6_4(std::vector<char>& buf, size_t& pos){
    int i = 0, t = 0;
    struct syment *sp;
    for (i = 0; i < st->mods_installed; i++) {
        struct load_module *lm = &st->load_modules[i];
        for_each_mod_mem_type(t) {
            if (!lm->symtable[t]){
                continue;
            }
            for (sp = lm->symtable[t]; sp <= lm->symend[t]; sp++) {
                if (!strncmp(sp->name, "_MODULE_", strlen("_MODULE_"))){
                    continue;
                }
                /* Currently sp->type for modules is not trusted */
                write_to_buf(buf, pos, "%lx %c %s\t[%s]\n",  sp->value, 'm', sp->name, lm->mod_name);
            }
        }
    }
}

void Ftrace::save_proc_kallsyms_mod_legacy(std::vector<char>& buf, size_t& pos){
    int i = 0;
    struct syment *sp;
    for (i = 0; i < st->mods_installed; i++) {
        struct load_module *lm = &st->load_modules[i];
        for (sp = lm->mod_symtable; sp <= lm->mod_symend; sp++) {
            if (!strncmp(sp->name, "_MODULE_", strlen("_MODULE_")))
                continue;
            /* Currently sp->type for modules is not trusted */
            write_to_buf(buf, pos, "%lx %c %s\t[%s]\n",  sp->value, 'm', sp->name, lm->mod_name);
        }
    }
}

// ftrace events and other systems events
void Ftrace::write_events_data(){
    uint system_id = 1;
    uint index = 0;
    std::unordered_map<std::string, uint> system_id_map;
    system_id_map["ftrace"] = system_id++;
    for (auto &pair : event_maps) {
        std::shared_ptr<TraceEvent> event_ptr = pair.second;
        const std::string &sys = event_ptr->system;
        if (system_id_map.find(sys) == system_id_map.end()) {
            system_id_map[sys] = system_id++;
        }
        event_ptr->system_id = system_id_map[sys];
        index++;
    }
    /* ftrace events */
    write_events(1);
    /* other systems events */
    uint nr_systems = system_id - 2;
    fwrite(&nr_systems, 4, 1, trace_file);
    for (uint id = 2; id < nr_systems + 2; id++){
        std::shared_ptr<TraceEvent> event_ptr;
        for (auto &pair : event_maps) {
            event_ptr = pair.second;
            if (event_ptr->system_id == id){
                break;
            }
        }
        fwrite(event_ptr->system.data(), event_ptr->system.size() + 1, 1, trace_file);
        write_events(event_ptr->system_id);
    }
}

void Ftrace::write_events(uint system_id){
    int total = 0;
    for (auto &pair : event_maps) {
        std::shared_ptr<TraceEvent> event_ptr = pair.second;
        if (event_ptr->system_id == system_id){
            total++;
        }
    }
    if (debug){
        fprintf(fp, "system_id:%d total:%d \n", system_id, total);
        for (auto &pair : event_maps) {
            std::shared_ptr<TraceEvent> event_ptr = pair.second;
            if (event_ptr->system_id != system_id){
                continue;
            }
            fprintf(fp, "   %s\n", event_ptr->name.c_str());
        }
    }
    fwrite(&total, 4, 1, trace_file);
    for (auto &pair : event_maps) {
        std::shared_ptr<TraceEvent> event_ptr = pair.second;
        if (event_ptr->system_id != system_id){
            continue;
        }
        write_event(event_ptr);
    }
}

void Ftrace::write_event(std::shared_ptr<TraceEvent> event_ptr){
    std::vector<char> event_buf;
    size_t pos = 0;
    write_to_buf(event_buf, pos, "name: %s\n", event_ptr->name.c_str());
    write_to_buf(event_buf, pos, "ID: %d\n", event_ptr->id);
    write_to_buf(event_buf, pos, "format:\n");
    for (auto &pair : common_field_maps) {
        std::shared_ptr<trace_field> field_ptr = pair.second;
        // can't find [
        size_t position = field_ptr->type.find("[");
        if (position == std::string::npos || field_ptr->type == "__data_loc"){
            write_to_buf(event_buf, pos, "\tfield:%s %s;\toffset:%u;\tsize:%u;\tsigned:%d;\n", field_ptr->type.c_str(), field_ptr->name.c_str(), field_ptr->offset,field_ptr->size, !!field_ptr->is_signed);
        }else{
            write_to_buf(event_buf, pos, "\tfield:%.*s %s%s;\toffset:%u;\tsize:%u;\tsigned:%d;\n", (int)(position),
                    field_ptr->type.c_str(), field_ptr->name.c_str(), field_ptr->type.c_str() + position, field_ptr->offset, field_ptr->size, !!field_ptr->is_signed);
        }
    }

    write_to_buf(event_buf, pos, "\n");
    for (auto &pair : event_ptr->field_maps) {
        std::shared_ptr<trace_field> field_ptr = pair.second;
        // can't find [
        size_t position = field_ptr->type.find("[");
        if (position == std::string::npos || field_ptr->type == "__data_loc"){
            write_to_buf(event_buf, pos, "\tfield:%s %s;\toffset:%u;\tsize:%u;\tsigned:%d;\n", field_ptr->type.c_str(), field_ptr->name.c_str(), field_ptr->offset,field_ptr->size, !!field_ptr->is_signed);
        }else{
            write_to_buf(event_buf, pos, "\tfield:%.*s %s%s;\toffset:%u;\tsize:%u;\tsigned:%d;\n", (int)(position),
                    field_ptr->type.c_str(), field_ptr->name.c_str(), field_ptr->type.c_str() + position, field_ptr->offset, field_ptr->size, !!field_ptr->is_signed);
        }
    }
    write_to_buf(event_buf, pos, "\nprint fmt: %s\n", event_ptr->org_print_fmt.c_str());
    fwrite(&pos, 8, 1, trace_file);
    // if (debug){
    //     fprintf(fp, "%s:\n", event_ptr->name.c_str());
    //     fprintf(fp, "%s \n\n", hexdump(0x1000,(char*)event_buf.data(), event_buf.size() - 1).c_str());
    // }
    fwrite(event_buf.data(), event_buf.size() - 1, 1, trace_file);
}

void Ftrace::write_header_data(){
    /* save header_page */
    fwrite("header_page", 12, 1, trace_file);
    std::vector<char> head_buf;
    size_t pos = 0;
    write_to_buf(head_buf, pos, "\tfield: u64 timestamp;\toffset:0;\tsize:8;\tsigned:0;\n");
    write_to_buf(head_buf, pos, "\tfield: local_t commit;\toffset:8;\tsize:%zu;\tsigned:1;\n", sizeof(long));
    write_to_buf(head_buf, pos, "\tfield: int overwrite;\toffset:8;\tsize:%zu;\tsigned:1;\n", sizeof(long));
    write_to_buf(head_buf, pos, "\tfield: char data;\toffset:%zu;\tsize:%zu;\tsigned:1;\n", 8 + sizeof(long), PAGESIZE() - 8 - sizeof(long));

    fwrite(&pos, 8, 1, trace_file);
    fwrite(head_buf.data(), head_buf.size()-1, 1, trace_file);

    /* save header_event */
    fwrite("header_event", 13, 1, trace_file);
    std::vector<char> event_buf;
    pos = 0;
    write_to_buf(event_buf, pos, "# compressed entry header\n"
            "\ttype_len    :    5 bits\n"
            "\ttime_delta  :   27 bits\n"
            "\tarray       :   32 bits\n"
            "\n"
            "\tpadding     : type == 29\n"
            "\ttime_extend : type == 30\n"
            "\tdata max type_len  == 28\n");
    fwrite(&pos, 8, 1, trace_file);
    fwrite(event_buf.data(), event_buf.size()-1, 1, trace_file);
}

void Ftrace::write_init_data(){
    fwrite("\027\010\104tracing", 10, 1, trace_file);
    fwrite(TRACE_CMD_FILE_VERSION_STRING, strlen(TRACE_CMD_FILE_VERSION_STRING) + 1, 1, trace_file);
    /* Crash ensure core file endian and the host endian are the same */
    int value = 1;
    if (is_bigendian()){
        value = 1;
    }else{
        value = 0;
    }
    fwrite(&value, 1, 1, trace_file);

    /* save size of long (this may not be what the kernel is) */
    value = sizeof(long);
    fwrite(&value, 1, 1, trace_file);
    value = page_size;
    fwrite(&value, 4, 1, trace_file);
}

void Ftrace::dump_file(){
    FILE* tmp_file = fopen(trace_path.c_str(), "rb");
    if (!tmp_file) {
        fprintf(fp, "Can't open %s\n", trace_path.c_str());
        return;
    }
    fseek(tmp_file, 0, SEEK_END);
    size_t fileSize = ftell(tmp_file);
    rewind(tmp_file);
    char* buffer = static_cast<char*>(malloc(fileSize));
    if (buffer == nullptr) {
        fprintf(fp, "Memory allocation failed \n");
        return;
    }
    size_t bytesRead = fread(buffer, 1, fileSize, tmp_file);
    if (bytesRead != fileSize) {
        fprintf(fp, "Error reading file fileSize:%zu, bytesRead:%zu \n",fileSize,bytesRead);
        free(buffer);
        return;
    }
    fprintf(fp, "%s \n\n", hexdump(0x1000,(char*)buffer,fileSize).c_str());
    free(buffer);
}

void Ftrace::write_to_buf(std::vector<char>& buffer, size_t& pos, const char* fmt, ...) {
    if (fmt == nullptr) return;
    va_list args;
    va_start(args, fmt);
    // Try to print into the current buffer
    int n = vsnprintf(buffer.data() + pos, buffer.size() - pos, fmt, args);
    va_end(args);
    if (n > -1 && static_cast<size_t>(n) < buffer.size() - pos) {
        // If it fits, update the position
        pos += n;
    } else {
        // Otherwise, resize the buffer and try again
        if (n > -1) {
            // We need exactly 'n' more bytes
            size_t newSize = pos + n + 1;
            buffer.resize(newSize);
        } else {
            // Handle the case where vsnprintf returns -1 (e.g., due to invalid format string)
            std::cerr << "Error in vsnprintf" << std::endl;
            return;
        }
        // Retry printing into the resized buffer
        va_start(args, fmt);
        n = vsnprintf(buffer.data() + pos, buffer.size() - pos, fmt, args);
        va_end(args);
        if (n > -1) {
            pos += n;
        } else {
            std::cerr << "Error in vsnprintf after resizing" << std::endl;
        }
    }
}

void Ftrace::ftrace_show() {
    char buf[4096] = {0};
    std::string traceCmd = "trace-cmd";
    const char* envTraceCmd = std::getenv("TRACE_CMD");
    if (envTraceCmd) {
        traceCmd = envTraceCmd;
    }
    FILE* file = popen(traceCmd.c_str(), "r");
    if (!file) {
        fprintf(fp, "Failed to run trace-cmd.\n");
        return;
    }
    size_t ret = fread(buf, 1, sizeof(buf) - 1, file);
    buf[ret] = '\0';
    pclose(file);
    if (!strstr(buf, "trace-cmd version")) {
        if (envTraceCmd) {
            fprintf(fp, "Invalid environment TRACE_CMD: %s\n", envTraceCmd);
        } else {
            fprintf(fp, "\"Ftrace -S\" requires trace-cmd.\n Please set the environment TRACE_CMD if you installed it in a special path.\n");
        }
        return;
    }
    char cwd[PATH_MAX];
    if (!getcwd(cwd, sizeof(cwd))) {
        return;
    }
    std::string tracePath = std::string(cwd) + "/ftrace.data";
    if (access(tracePath.c_str(), F_OK) != 0) {
        ftrace_dump();
    }
    // run trace-cmd report
    std::ostringstream cmd;
    cmd << traceCmd << " report " << tracePath;
    file = popen(cmd.str().c_str(), "r");
    if (!file) {
        fprintf(fp, "Failed to run trace-cmd report.\n");
        return;
    }
    while ((ret = fread(buf, 1, sizeof(buf) - 1, file)) > 0) {
        buf[ret] = '\0';
        fprintf(fp, "%s", buf);
    }
    pclose(file);
}

void Ftrace::ftrace_dump() {
    char cwd[PATH_MAX];
    if (!getcwd(cwd, sizeof(cwd))) {
        return;
    }
    trace_path = std::string(cwd) + "/ftrace.data";
    if (access(trace_path.c_str(), F_OK) == 0) {
        if (unlink(trace_path.c_str()) != 0) {
            return;
        }
    }
    trace_file = fopen(trace_path.c_str(), "wb");
    if (!trace_file) {
        fprintf(fp, "Can't open %s\n", trace_path.c_str());
        return;
    }
    write_trace_data();
    fclose(trace_file);
    fprintf(fp, "Saved to %s\n", trace_path.c_str());
}

#pragma GCC diagnostic pop
