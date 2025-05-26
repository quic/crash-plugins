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

#include "rtb.h"

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wpointer-arith"

#ifndef BUILD_TARGET_TOGETHER
DEFINE_PLUGIN_COMMAND(Rtb)
#endif

void Rtb::cmd_main(void) {
    int c;
    std::string cppString;
    if (argcnt < 2) cmd_usage(pc->curcmd, SYNOPSIS);
    if (!is_enable_rtb()){
        return;
    }
    if(rtb_state_ptr.get() == nullptr){
        parser_rtb_log();
    }
    while ((c = getopt(argcnt, args, "ac:i")) != EOF) {
        switch(c) {
            case 'a':
                print_rtb_log();
                break;
            case 'c':
                cppString.assign(optarg);
                try {
                    int cpu = std::stoi(cppString);
                    if(cpu >= rtb_state_ptr->step_size){
                        fprintf(fp, "invaild arg %s\n",cppString.c_str());
                        return;
                    }
                    print_percpu_rtb_log(cpu);
                } catch (...) {
                    fprintf(fp, "invaild arg %s\n",cppString.c_str());
                }
                break;
            case 'i':
                print_rtb_log_memory();
                break;
            default:
                argerrs++;
                break;
        }
    }
    if (argerrs)
        cmd_usage(pc->curcmd, SYNOPSIS);
}

void Rtb::init_offset(){
    field_init(msm_rtb_state,msm_rtb_idx);
    field_init(msm_rtb_state,rtb);
    field_init(msm_rtb_state,phys);
    field_init(msm_rtb_state,nentries);
    field_init(msm_rtb_state,size);
    field_init(msm_rtb_state,enabled);
    field_init(msm_rtb_state,initialized);
    field_init(msm_rtb_state,step_size);
    struct_init(msm_rtb_state);
    struct_init(msm_rtb_layout);
    struct_init(rtb_idx);
}

Rtb::Rtb(){
    init_offset();
    cmd_name = "rtb";
    help_str_list={
        "rtb",            /* command name */
        "dump rtb log",        /* short description */
        "-a \n"
            "  rtb -c <cpu>\n"
            "  rtb -i\n"
            "  This command dumps the rtb log.",
        "\n",
        "EXAMPLES",
        "  Display all rtb log:",
        "    %s> rtb -a",
        "       [234.501829] [12532249254] <0>: LOGK_CTXID ctxid:1621 called from addr ffffffd4d628a684 __schedule Line 220 of include/trace/events/sched.h",
        "       [234.501836] [12532249398] <0>: LOGK_IRQ interrupt:1 handled from addr ffffffd4d627c7b4 ipi_handler.04f2cb5359f849bb5e8105832b6bf932.cfi_jt Line 888 of arch/arm64/kernel/entry.S",
        "       [234.501949] [12532251573] <0>: LOGK_CTXID ctxid:4284 called from addr ffffffd4d628a684 __schedule Line 220 of include/trace/events/sched.h",
        "       [234.502641] [12532264845] <0>: LOGK_CTXID ctxid:4285 called from addr ffffffd4d628a684 __schedule Line 220 of include/trace/events/sched.h",
        "\n",
        "  Display rtb log with specified cpu:",
        "    %s> rtb -c 0",
        "       [234.501829] [12532249254] <0>: LOGK_CTXID ctxid:1621 called from addr ffffffd4d628a684 __schedule Line 220 of include/trace/events/sched.h",
        "       [234.501836] [12532249398] <0>: LOGK_IRQ interrupt:1 handled from addr ffffffd4d627c7b4 ipi_handler.04f2cb5359f849bb5e8105832b6bf932.cfi_jt Line 888 of arch/arm64/kernel/entry.S",
        "       [234.501949] [12532251573] <0>: LOGK_CTXID ctxid:4284 called from addr ffffffd4d628a684 __schedule Line 220 of include/trace/events/sched.h",
        "       [234.502641] [12532264845] <0>: LOGK_CTXID ctxid:4285 called from addr ffffffd4d628a684 __schedule Line 220 of include/trace/events/sched.h",
        "\n",
        "  Display rtb log memory info:",
        "    %s> rtb -i",
        "       RTB log size:1.00Mb",
        "",
        "       bc500000-->-----------------",
        "                  |    rtb_state  |",
        "       bc500828-->-----------------",
        "                  |    rtb_layout |",
        "                  |---------------|",
        "                  |    rtb_layout |",
        "                  |---------------|",
        "                  |    .....      |",
        "       bc600000-->-----------------",
        "\n",
    };
    initialize();
}

bool Rtb::is_enable_rtb(){
    init_offset();
    if(field_size(msm_rtb_state,rtb) == -1){
        fprintf(fp, "Please run mod -s msm_rtb.ko.\n");
        return false;
    }
    return true;
}

double Rtb::get_timestamp(struct rtb_layout& layout){
    if (layout.timestamp == 0) {
        return 0.0;
    }
    double ts_float = static_cast<double>(layout.timestamp) / 1e9;
    return std::round(ts_float * 1e6) / 1e6;
}

std::string Rtb::get_fun_name(struct rtb_layout& layout){
    struct syment *sp;
    ulong offset;
    std::string res = "Unknown function";
    if (is_kvaddr(layout.caller)){
        sp = value_search(layout.caller, &offset);
        if (sp) {
            res = sp->name;
        }
    }
    return res;
}

std::string Rtb::get_caller(struct rtb_layout& layout){
    char cmd_buf[BUFSIZE];
    std::string result = "";
    if (is_kvaddr(layout.caller)){
        open_tmpfile();
        sprintf(cmd_buf, "info line *0x%llx",(ulonglong)layout.caller);
        if (!gdb_pass_through(cmd_buf, fp, GNU_RETURN_ON_ERROR)){
            close_tmpfile();
        }
        rewind(pc->tmpfile);
        while (fgets(cmd_buf, BUFSIZE, pc->tmpfile)){
            std::string content = cmd_buf;
            size_t pos = content.find("No line number information available");
            if (pos != std::string::npos) {
                break;
            }
            pos = content.find("starts at");
            if (pos != std::string::npos) {
                result = content.substr(0, pos);
                break;
            }
        }
        close_tmpfile();
    }
    return result;
}

void Rtb::print_none(int cpu, struct rtb_layout& layout) {
    fprintf(fp, "<%d> No data\n",cpu);
}

static std::vector<std::string> type_str = {
    "LOGK_NONE",
    "LOGK_READL",
    "LOGK_WRITEL",
    "LOGK_LOGBUF",
    "LOGK_HOTPLUG",
    "LOGK_CTXID",
    "LOGK_TIMESTAMP",
    "LOGK_L2CPREAD",
    "LOGK_L2CPWRITE",
    "LOGK_IRQ",
};

void Rtb::print_read_write(int cpu, struct rtb_layout& layout) {
    std::string name = get_fun_name(layout);
    std::string line = get_caller(layout);
    fprintf(fp, "[%f] [%lld] <%d>: %s from address:%llx(%llx) called from addr %llx %s %s\n",
        get_timestamp(layout),
        ((ulonglong)layout.cycle_count),
        cpu,
        type_str[layout.log_type].c_str(),
        ((ulonglong)layout.data),
        ((ulonglong)virt_to_phy(layout.data)),
        ((ulonglong)layout.caller),
        name.c_str(),
        line.c_str()
    );
}

void Rtb::print_logbuf(int cpu, struct rtb_layout& layout) {
    std::string name = get_fun_name(layout);
    std::string line = get_caller(layout);
    fprintf(fp, "[%f] [%lld] <%d>: %s log end:%llx called from addr %llx %s %s\n",
        get_timestamp(layout),
        ((ulonglong)layout.cycle_count),
        cpu,
        type_str[layout.log_type].c_str(),
        ((ulonglong)layout.data),
        ((ulonglong)layout.caller),
        name.c_str(),
        line.c_str()
    );
}

void Rtb::print_hotplug(int cpu, struct rtb_layout& layout) {
    std::string name = get_fun_name(layout);
    std::string line = get_caller(layout);
    fprintf(fp, "[%f] [%lld] <%d>: %s cpu data:%llx called from addr %llx %s %s\n",
        get_timestamp(layout),
        ((ulonglong)layout.cycle_count),
        cpu,
        type_str[layout.log_type].c_str(),
        ((ulonglong)layout.data),
        ((ulonglong)layout.caller),
        name.c_str(),
        line.c_str()
    );
}

void Rtb::print_ctxid(int cpu, struct rtb_layout& layout) {
    std::string name = get_fun_name(layout);
    std::string line = get_caller(layout);
    fprintf(fp, "[%f] [%lld] <%d>: %s ctxid:%lld called from addr %llx %s %s\n",
        get_timestamp(layout),
        ((ulonglong)layout.cycle_count),
        cpu,
        type_str[layout.log_type].c_str(),
        ((ulonglong)layout.data),
        ((ulonglong)layout.caller),
        name.c_str(),
        line.c_str()
    );
}

void Rtb::print_timestamp(int cpu, struct rtb_layout& layout) {
    std::string name = get_fun_name(layout);
    std::string line = get_caller(layout);
    fprintf(fp, "[%f] [%lld] <%d>: %s timestamp:%llx called from addr %llx %s %s\n",
        get_timestamp(layout),
        ((ulonglong)layout.cycle_count),
        cpu,
        type_str[layout.log_type].c_str(),
        ((ulonglong)layout.data),
        ((ulonglong)layout.caller),
        name.c_str(),
        line.c_str()
    );
}

void Rtb::print_l2cpread_write(int cpu, struct rtb_layout& layout) {
    std::string name = get_fun_name(layout);
    std::string line = get_caller(layout);
    fprintf(fp, "[%f] [%lld] <%d>: %s from offset:%llx called from addr %llx %s %s\n",
        get_timestamp(layout),
        ((ulonglong)layout.cycle_count),
        cpu,
        type_str[layout.log_type].c_str(),
        ((ulonglong)layout.data),
        ((ulonglong)layout.caller),
        name.c_str(),
        line.c_str()
    );
}

void Rtb::print_irq(int cpu, struct rtb_layout& layout) {
    std::string name = get_fun_name(layout);
    std::string line = get_caller(layout);
    fprintf(fp, "[%f] [%lld] <%d>: %s interrupt:%lld handled from addr %llx %s %s\n",
        get_timestamp(layout),
        ((ulonglong)layout.cycle_count),
        cpu,
        type_str[layout.log_type].c_str(),
        ((ulonglong)layout.data),
        ((ulonglong)layout.caller),
        name.c_str(),
        line.c_str()
    );
}

int Rtb::print_rtb_layout(int cpu,int index){
    ulong addr = rtb_state_ptr->rtb_layout + index * struct_size(msm_rtb_layout);
    struct rtb_layout layout;
    if(!read_struct(addr,&layout,sizeof(layout),"msm_rtb_layout")){
        return 0;
    }
    if (layout.sentinel[0] != 0xFF || layout.sentinel[1] != 0xAA || layout.sentinel[2] != 0xFF){
        return 0;
    }
    // fprintf(fp, "msm_rtb_layout:%lx \n",addr);
    if (layout.idx == 0 || layout.log_type == 0){
        return 0;
    }
    int type = layout.log_type & 0x7F;
    switch (type)
    {
    case LOGK_NONE:
        print_none(cpu, layout);
        break;
    case LOGK_READL:
    case LOGK_WRITEL:
        print_read_write(cpu, layout);
        break;
    case LOGK_LOGBUF:
        print_logbuf(cpu, layout);
        break;
    case LOGK_HOTPLUG:
        print_hotplug(cpu, layout);
        break;
    case LOGK_CTXID:
        print_ctxid(cpu, layout);
        break;
    case LOGK_TIMESTAMP:
        print_timestamp(cpu, layout);
        break;
    case LOGK_L2CPREAD:
    case LOGK_L2CPWRITE:
        print_l2cpread_write(cpu, layout);
        break;
    case LOGK_IRQ:
        print_irq(cpu, layout);
        break;
    default:
        print_none(cpu, layout);
        break;
    }
    return layout.idx;
}

int Rtb::next_rtb_entry(int index){
    int step_size = rtb_state_ptr->step_size;
    int mask = rtb_state_ptr->nentries - 1;
    int unused_size = (mask + 1) % step_size;
    if (((index + step_size + unused_size) & mask) < (index & mask)){
        return (index + step_size + unused_size) & mask;
    }
    return (index + step_size) & mask;
}

void Rtb::print_percpu_rtb_log(int cpu){
    if (rtb_state_ptr->initialized != 1){
        fprintf(fp, "RTB was not initialized in this build.\n");
        return;
    }
    int index = 0;
    int last_idx = 0;
    int next = 0;
    int next_idx = 0;
    if (THIS_KERNEL_VERSION >= LINUX(5,10,0)){
        if(get_config_val("CONFIG_QCOM_RTB_SEPARATE_CPUS") == "y"){
            index = rtb_state_ptr->rtb_idx[cpu];
        }else{
            index = rtb_state_ptr->rtb_idx[0];
        }
    }else{
        if(get_config_val("CONFIG_QCOM_RTB_SEPARATE_CPUS") == "y"){
            index = read_int(csymbol_value("msm_rtb_idx_cpu") + kt->__per_cpu_offset[cpu],"msm_rtb_idx_cpu");
        }else{
            index = read_int(csymbol_value("msm_rtb_idx"),"msm_rtb_idx");
        }
    }
    index = index & (rtb_state_ptr->nentries - 1);
    // fprintf(fp, "rtb_layout index for cpu[%d] is %d \n",cpu, index);
    struct rtb_layout layout;
    while (1){
        last_idx = print_rtb_layout(cpu,index);
        // fprintf(fp, "last_index:%d, last_idx:%d\n",index, last_idx);
        next = next_rtb_entry(index);
        ulong addr = rtb_state_ptr->rtb_layout + next * struct_size(msm_rtb_layout);
        BZERO(&layout, sizeof(layout));
        if(!read_struct(addr,&layout,sizeof(layout),"msm_rtb_layout")){
            break;
        }
        next_idx = layout.idx;
        // fprintf(fp, "next:%d, next_idx:%d\n",next, next_idx);
        if (last_idx < next_idx){
            index = next;
        }
        if (next != index){
            break;
        }
    }
}

void Rtb::print_rtb_log_memory(){
    physaddr_t start = rtb_state_ptr->phys - struct_size(msm_rtb_state);
    size_t size = rtb_state_ptr->size;
    fprintf(fp, "RTB log size:%s\n\n",csize(size).c_str());
    fprintf(fp, "%llx-->-----------------\n",(ulonglong)start);
    fprintf(fp, "           |    rtb_state  |\n");
    fprintf(fp, "%llx-->-----------------\n",(ulonglong)rtb_state_ptr->phys);
    fprintf(fp, "           |    rtb_layout |\n");
    fprintf(fp, "           |---------------|\n");
    fprintf(fp, "           |    rtb_layout |\n");
    fprintf(fp, "           |---------------|\n");
    fprintf(fp, "           |    .....      |\n");
    fprintf(fp, "%llx-->-----------------\n",(ulonglong)(start + size));
    fprintf(fp, "\n");
}

void Rtb::print_rtb_log(){
    if (rtb_state_ptr->initialized != 1){
        fprintf(fp, "RTB was not initialized in this build.\n");
        return;
    }
    for (int cpu = 0; cpu < rtb_state_ptr->step_size; cpu++){
        print_percpu_rtb_log(cpu);
    }
}

void Rtb::parser_rtb_log(){
    ulong msm_rtb_addr = 0;
    if (THIS_KERNEL_VERSION >= LINUX(5,10,0)){
        msm_rtb_addr = csymbol_value("msm_rtb_ptr");
    }else{
        msm_rtb_addr = csymbol_value("msm_rtb");
    }
    if(!msm_rtb_addr){
        fprintf(fp, "RTB is disabled\n");
        return;
    }
    msm_rtb_addr = read_pointer(msm_rtb_addr,"msm_rtb");
    void *rtb_state_buf = read_struct(msm_rtb_addr,"msm_rtb_state");
    if(rtb_state_buf == nullptr) return;
    rtb_state_ptr = std::make_shared<rtb_state>();
    size_t cnt = field_size(msm_rtb_state,msm_rtb_idx)/struct_size(rtb_idx);
    for (size_t i = 0; i < cnt; i++){
        ulong rtb_idx_addr = msm_rtb_addr + i * struct_size(rtb_idx);
        int idx = read_int(rtb_idx_addr,"rtb_idx");
        // fprintf(fp, "rtb_idx[%zu]:%lx --> %d \n",i,rtb_idx_addr,idx);
        rtb_state_ptr->rtb_idx.push_back(idx);
    }
    rtb_state_ptr->rtb_layout = ULONG(rtb_state_buf + field_offset(msm_rtb_state,rtb));
    rtb_state_ptr->phys = ULONG(rtb_state_buf + field_offset(msm_rtb_state,phys));
    rtb_state_ptr->nentries = INT(rtb_state_buf + field_offset(msm_rtb_state,nentries));
    rtb_state_ptr->size = INT(rtb_state_buf + field_offset(msm_rtb_state,size));
    rtb_state_ptr->enabled = INT(rtb_state_buf + field_offset(msm_rtb_state,enabled));
    rtb_state_ptr->initialized = INT(rtb_state_buf + field_offset(msm_rtb_state,initialized));
    rtb_state_ptr->step_size = INT(rtb_state_buf + field_offset(msm_rtb_state,step_size));
    // fprintf(fp, "enabled:%d initialized:%d \n",rtb_state_ptr->enabled,rtb_state_ptr->initialized);
    FREEBUF(rtb_state_buf);
}
#pragma GCC diagnostic pop
