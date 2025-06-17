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

#include "debugimage.h"

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wpointer-arith"

#ifndef BUILD_TARGET_TOGETHER
DEFINE_PLUGIN_COMMAND(DebugImage)
#endif

void DebugImage::cmd_main(void) {
    int c;
    int pid = -1;
    int cpu = 0;
    std::string cppString;
    if (argcnt < 2) cmd_usage(pc->curcmd, SYNOPSIS);
    if (image_list.size() == 0){
        parser_memdump();
    }
    while ((c = getopt(argcnt, args, "acsp:C:")) != EOF) {
        switch(c) {
            case 'a':
                print_memdump();
                break;
            case 'c':
                parse_cpu_ctx();
                break;
            case 's':
                print_cpu_stack();
                break;
            case 'p':
                cppString.assign(optarg);
                try {
                    pid = std::stoi(cppString);
                } catch (...) {
                    fprintf(fp, "invaild pid arg %s\n",cppString.c_str());
                    break;
                }
                print_task_stack(pid);
                break;
            case 'C':
                cppString.assign(optarg);
                try {
                    cpu = std::stoi(cppString);
                } catch (...) {
                    fprintf(fp, "invaild cpu arg %s\n",cppString.c_str());
                    break;
                }
                print_irq_stack(cpu);
                break;
            default:
                argerrs++;
                break;
        }
    }
    if (argerrs)
        cmd_usage(pc->curcmd, SYNOPSIS);
}

DebugImage::DebugImage(){
    cmd_name = "dbi";
    help_str_list={
        "dbi",                            /* command name */
        "dump debug image region information",        /* short description */
        "-a \n"
            "  dbi -c\n"
            "  dbi -s\n"
            "  dbi -p <pid>\n"
            "  dbi -C <cpu> \n"
            "  This command dump debug image info.",
        "\n",
        "EXAMPLES",
        "  Display all debug image info:",
        "    %s> dbi -a",
        "     DumpTable base:bc700000",
        "     Id   Dump_entry       version magic            DataAddr         DataLen    Name",
        "     0    bc707e10         20      42445953         bc707e50         2048       c0_context",
        "     1    bc708650         20      42445953         bc708690         2048       c1_context",
        "     2    bc708e90         20      42445953         bc708ed0         2048       c2_context",
        "     3    bc7096d0         20      42445953         bc709710         2048       c3_context",
        "\n",
        "  Generate the cmm file:",
        "    %s> dbi -c",
        "    c0_context  core:0  version:1.4",
        "    save to xx/core0_regs.cmm",
        "    c1_context  core:1  version:1.4",
        "    save to xx/core1_regs.cmm",
        "    c2_context  core:2  version:1.4",
        "    save to xx/core2_regs.cmm",
        "    c3_context  core:3  version:1.4",
        "    save to xx/core3_regs.cmm",
        "\n",
        "  Parser cpu stack which capture by sdi:",
        "    %s> dbi -s",
        "     c0_context  core:0  version:1.4",
        "     Core0 PC: <ffffffd20a0b601c>: ipi_handler.04f2cb5359f849bb5e8105832b6bf932+c8",
        "     Core0 LR: <ffffffd20a0b6014>: ipi_handler.04f2cb5359f849bb5e8105832b6bf932+c0",
        "     PID: 0        TASK: ffffffd20c4a7e80  CPU: 0    COMMAND: swapper/0",
        "      #0 [ffffffc008003f50] handle_percpu_devid_irq at ffffffd20a1d8884",
        "      #1 [ffffffc008003fa0] handle_domain_irq at ffffffd20a1cffac",
        "      #2 [ffffffc008003fe0] gic_handle_irq.0baca5b50aed29204608b368989cedda at ffffffd20a0101f8",
        "      --- <IRQ stack> ---",
        "      #3 [ffffffd20c483b70] call_on_irq_stack at ffffffd20a01495c",
        "      #4 [ffffffd20c483b90] do_interrupt_handler at ffffffd20a0a15f0",
        "      #5 [ffffffd20c483ba0] el1_interrupt at ffffffd20b0731a0",
        "      #6 [ffffffd20c483bc0] el1h_64_irq_handler at ffffffd20b073164",
        "      #7 [ffffffd20c483d00] el1h_64_irq at ffffffd20a011370",
        "      #8 [ffffffd20c483d30] cpuidle_enter_state at ffffffd20abfbaac",
        "      #9 [ffffffd20c483d80] cpuidle_enter at ffffffd20abfc034",
        "     #10 [ffffffd20c483dc0] do_idle at ffffffd20a18c584",
        "     #11 [ffffffd20c483e20] cpu_startup_entry at ffffffd20a18c694",
        "     #12 [ffffffd20c483e40] rest_init at ffffffd20b075370",
        "     #13 [ffffffd20c483e60] arch_call_rest_init at ffffffd20bff9718",
        "     #14 [ffffffd20c483e90] start_kernel at ffffffd20bff9af4",
        "\n",
        "  Display the stack for specified task pid (only support ARM64):",
        "    %s> dbi -p 663",
        "    cpu_context:",
        "       X19: 0xffffff80031e6180",
        "       X20: 0xffffff8027e02700",
        "       X21: 0xffffff8027e02700",
        "       X22: 0xffffffd20c4a5000",
        "       X23: 0xffffff80031e6180",
        "       X24: 0xffffff8027e02710",
        "       X25: 0xffffffd20c493a38",
        "       X26: 0xffffff8027e02700",
        "       X27: 0xffffff80199f4970",
        "       X28: 0xffffffc00c423bf0",
        "       fp:  0xffffffc00c423a70",
        "       sp:  0xffffffc00c423a70",
        "       pc:  0xffffffd20b09f5e4",
        "",
        "   Stack:0xffffffc00c420000~0xffffffc00c424000",
        "   [0]Potential backtrace -> FP:0xffffffc00c423a50, LR:0xffffffc00c423a58",
        "       #0 [ffffffc00c423a70] __switch_to at ffffffd20b09f598",
        "       #1 [ffffffc00c423ac0] __schedule at ffffffd20b09fd78",
        "       #2 [ffffffc00c423b20] schedule at ffffffd20b0a032c",
        "       #3 [ffffffc00c423d60] qseecom_ioctl at ffffffd20e7ab400 [qseecom_dlkm]",
        "       #4 [ffffffc00c423dc0] __arm64_sys_ioctl at ffffffd20a43bd4c",
        "       #5 [ffffffc00c423e10] invoke_syscall at ffffffd20a0b6f98",
        "       #6 [ffffffc00c423e30] el0_svc_common at ffffffd20a0b6ecc",
        "       #7 [ffffffc00c423e70] do_el0_svc at ffffffd20a0b6da8",
        "       #8 [ffffffc00c423e80] el0_svc at ffffffd20b0734e4",
        "       #9 [ffffffc00c423ea0] el0t_64_sync_handler at ffffffd20b073468",
        "       #10 [ffffffc00c423fe0] el0t_64_sync at ffffffd20a011620",
        "           PC: 0000007e9c1b150c   LR: 0000007e9c157394   SP: 0000007c07b3ea00",
        "           X29: 0000007c07b3eae0  X28: 0000007c08ccce94  X27: 0000007c08ccd84a",
        "           X26: 0000007c08cccecb  X25: 0000007c08ccd774  X24: 0000007c07b3ec80",
        "           X23: 000000000000025c  X22: b400007e294c4110  X21: 0000007c07b46000",
        "           X20: 0000007c08cccf27  X19: 0000007c07b3f000  X18: 0000007c06d00000",
        "           X17: 0000007e9c1572f4  X16: 0000007e9d39f2a8  X15: 00000009023a4dd6",
        "           X14: 0000000000002a3c  X13: 0000007c07b3e6d8  X12: ffffffffffffffff",
        "           X11: 0000007c07b3e570  X10: ffffff80ffffffd0   X9: 0000007c07b3eab0",
        "           X8: 000000000000001d   X7: 7f7f7f7f7f7f7f7f   X6: 6467731f63606471",
        "           X5: 0000000000002a3c   X4: 0000007c07b3e450   X3: 0000007c07b3e400",
        "           X2: 0000000000081000   X1: 0000000000009705   X0: 0000000000000009",
        "           ORIG_X0: 0000000000000009  SYSCALLNO: 1d  PSTATE: 80000000",
        "\n",
        "  Display the current stack for specified cpu(only support ARM64):",
        "    %s> dbi -C 0",
        "    CPU[0] irq stack:0xffffffc008000000~0xffffffc008004000",
        "    [0]Potential backtrace -> FP:0xffffffc008003ee0, LR:0xffffffc008003ee8",
        "    PID: 0        TASK: ffffffd20c4a7e80  CPU: 0    COMMAND: swapper/0",
        "       #0 [ffffffc008003f20] ipi_handler.04f2cb5359f849bb5e8105832b6bf932 at ffffffd20a0b6010",
        "       #1 [ffffffc008003f50] handle_percpu_devid_irq at ffffffd20a1d8884",
        "       #2 [ffffffc008003fa0] handle_domain_irq at ffffffd20a1cffac",
        "       #3 [ffffffc008003fe0] gic_handle_irq.0baca5b50aed29204608b368989cedda at ffffffd20a0101f8",
        "       --- <IRQ stack> ---",
        "       #4 [ffffffd20c483b70] call_on_irq_stack at ffffffd20a01495c",
        "       #5 [ffffffd20c483b90] do_interrupt_handler at ffffffd20a0a15f0",
        "       #6 [ffffffd20c483ba0] el1_interrupt at ffffffd20b0731a0",
        "       #7 [ffffffd20c483bc0] el1h_64_irq_handler at ffffffd20b073164",
        "       #8 [ffffffd20c483d00] el1h_64_irq at ffffffd20a011370",
        "       #9 [ffffffd20c483d30] cpuidle_enter_state at ffffffd20abfbaac",
        "       #10 [ffffffd20c483d80] cpuidle_enter at ffffffd20abfc034",
        "       #11 [ffffffd20c483dc0] do_idle at ffffffd20a18c584",
        "       #12 [ffffffd20c483e20] cpu_startup_entry at ffffffd20a18c694",
        "       #13 [ffffffd20c483e40] rest_init at ffffffd20b075370",
        "       #14 [ffffffd20c483e60] arch_call_rest_init at ffffffd20bff9718",
        "       #15 [ffffffd20c483e90] start_kernel at ffffffd20bff9af4",
        "\n",
    };

    field_init(msm_dump_cpu_ctx, affinity);
    cpu_index_offset = field_offset(msm_dump_cpu_ctx, affinity);
    if (cpu_index_offset == -1){
        cpu_index_offset = 0x10;
    }
    initialize();
}

void DebugImage::print_memdump(){
    std::ostringstream oss_hd;
    oss_hd  << std::left << std::setw(4)            << "Id" << " "
            << std::left << std::setw(16)           << "Dump_entry" << " "
            << std::left << std::setw(8)            << "version" << " "
            << std::left << std::setw(VADDR_PRLEN)  << "magic" << " "
            << std::left << std::setw(VADDR_PRLEN)  << "DataAddr" << " "
            << std::left << std::setw(10)           << "DataLen" << " "
            << std::left << "Name";
    fprintf(fp, "%s \n",oss_hd.str().c_str());
    // parse_dump_v2
    for (const auto& entry_ptr : image_list) {
        std::ostringstream oss;
        oss << std::left << std::setw(4)            << std::dec << entry_ptr->id << " "
            << std::left << std::setw(16)           << std::hex << entry_ptr->addr << " "
            << std::left << std::setw(8)            << std::dec << entry_ptr->version << " "
            << std::left << std::setw(VADDR_PRLEN)  << std::hex << entry_ptr->magic << " "
            << std::left << std::setw(VADDR_PRLEN)  << std::hex << entry_ptr->data_addr << " "
            << std::left << std::setw(10)           << std::dec << entry_ptr->data_len << " "
            << std::left  << entry_ptr->data_name;
        fprintf(fp, "%s \n",oss.str().c_str());
    }
}

void DebugImage::parser_memdump(){
    struct_init(msm_memory_dump);
    if (struct_size(msm_memory_dump) == -1){
        fprintf(fp, "memdump doesn't exist in this kernel! load memory_dump_v2.ko\n");
        return;
    }
    if (!csymbol_exists("memdump")){
        return;
    }
    ulong dump_addr = csymbol_value("memdump");
    if (!is_kvaddr(dump_addr)) {
        fprintf(fp, "memdump address is invalid!\n");
        return;
    }
    field_init(msm_memory_dump,table_phys);
    field_init(msm_dump_table,version);
    field_init(msm_dump_table,num_entries);
    field_init(msm_dump_table,entries);
    field_init(msm_dump_entry,id);
    field_init(msm_dump_entry,name);
    field_init(msm_dump_entry,type);
    field_init(msm_dump_entry,addr);
    field_init(msm_dump_data,version);
    field_init(msm_dump_data,magic);
    field_init(msm_dump_data,name);
    field_init(msm_dump_data,addr);
    field_init(msm_dump_data,len);
    field_init(msm_dump_data,reserved);
    struct_init(msm_dump_table);
    struct_init(msm_dump_entry);
    struct_init(msm_dump_data);
    uint64_t table_phys = read_ulonglong(dump_addr + field_offset(msm_memory_dump,table_phys),"table_phys");
    // fprintf(fp, "DumpTable base:%" PRIx64 "\n", table_phys);
    parser_dump_table(table_phys);
}

void DebugImage::print_cpu_stack(){
    for (const auto& entry_ptr : image_list) {
        if (entry_ptr->id >= DATA_CPU_CTX && entry_ptr->id < DATA_L1_INST_TLB){
            parse_cpu_stack(entry_ptr);
        }
    }
}

void DebugImage::parse_cpu_ctx(){
    for (const auto& entry_ptr : image_list) {
        if (entry_ptr->id >= DATA_CPU_CTX && entry_ptr->id < DATA_L1_INST_TLB){
            parse_cpu_ctx(entry_ptr);
        }
    }
}

void DebugImage::parse_cpu_stack(std::shared_ptr<Dump_entry> entry_ptr){
    int core = entry_ptr->id - DATA_CPU_CTX;
    int major = entry_ptr->version >> 4;
    int minor = entry_ptr->version & 0xF;
    if (major == 2 && minor == 0){ //v2.0
        uint32_t affinity = read_uint(entry_ptr->data_addr + cpu_index_offset, "affinity", false);
        parser_ptr = std::make_shared<Cpu64_Context_V20>();
        core = parser_ptr->get_vcpu_index(affinity);
        fprintf(fp, "%s  core:%d  version:%d.%d\n", entry_ptr->data_name.c_str(), core, major, minor);
    }else{
        fprintf(fp, "%s  core:%d  version:%d.%d\n", entry_ptr->data_name.c_str(), core, major, minor);
        if (BITS64()){
            if (major == 1 && minor == 3){ //v1.3
                parser_ptr = std::make_shared<Cpu64_Context_V13>();
            }else if (major == 1 && minor == 4){ //v1.4
                parser_ptr = std::make_shared<Cpu64_Context_V14>();
            }
        }else{
            parser_ptr = std::make_shared<Cpu32_Context>();
        }
    }
    parser_ptr->print_stack(entry_ptr);
}

void DebugImage::parse_cpu_ctx(std::shared_ptr<Dump_entry> entry_ptr){
    int core = entry_ptr->id - DATA_CPU_CTX;
    // init_regs_v2
    int major = entry_ptr->version >> 4;
    int minor = entry_ptr->version & 0xF;
    if (major == 2 && minor == 0){ //v2.0
        uint32_t affinity = read_uint(entry_ptr->data_addr + cpu_index_offset, "affinity", false);
        parser_ptr = std::make_shared<Cpu64_Context_V20>();
        core = parser_ptr->get_vcpu_index(affinity);
        fprintf(fp, "%s  core:%d  version:%d.%d\n", entry_ptr->data_name.c_str(), core, major, minor);
    }else{
        fprintf(fp, "%s  core:%d  version:%d.%d\n", entry_ptr->data_name.c_str(), core, major,minor);
        if (BITS64()){
            if (major == 1 && minor == 3){ //v1.3
                parser_ptr = std::make_shared<Cpu64_Context_V13>();
            }else if (major == 1 && minor == 4){ //v1.4
                parser_ptr = std::make_shared<Cpu64_Context_V14>();
            }
        }else{
            parser_ptr = std::make_shared<Cpu32_Context>();
        }
    }
    parser_ptr->generate_cmm(entry_ptr);
}

void DebugImage::parser_dump_data(std::shared_ptr<Dump_entry> entry_ptr){
    entry_ptr->version = read_uint(entry_ptr->addr + field_offset(msm_dump_data,version),"version",false);
    entry_ptr->magic = read_uint(entry_ptr->addr + field_offset(msm_dump_data,magic),"magic",false);
    if ((entry_ptr->magic != MAGIC_NUMBER) && (entry_ptr->magic != HYP_MAGIC_NUMBER)){
        return;
    }
    if (entry_ptr->id > DATA_MAX){
        return;
    }
    entry_ptr->data_name= read_cstring(entry_ptr->addr + field_offset(msm_dump_data,name),32, "name",false);
    entry_ptr->data_addr = read_ulonglong(entry_ptr->addr + field_offset(msm_dump_data,addr),"addr",false);
    entry_ptr->data_len = read_ulonglong(entry_ptr->addr + field_offset(msm_dump_data,len),"len",false);
    image_list.push_back(entry_ptr);
}

void DebugImage::parser_dump_table(uint64_t paddr){
    uint32_t num_entries = read_uint(paddr + field_offset(msm_dump_table,num_entries),"num_entries",false);
    if (num_entries == 0 || num_entries > 100){
        return;
    }
    uint64_t entries = paddr + field_offset(msm_dump_table,entries);
    for (size_t i = 0; i < num_entries; i++){
        uint64_t entry_addr = entries + struct_size(msm_dump_entry) * i;
        std::shared_ptr<Dump_entry> entry_ptr = std::make_shared<Dump_entry>();
        entry_ptr->id = read_uint(entry_addr + field_offset(msm_dump_entry,id),"id",false);
        int type = read_uint(entry_addr + field_offset(msm_dump_entry,type),"type",false);
        entry_ptr->addr = read_ulonglong(entry_addr + field_offset(msm_dump_entry,addr),"addr",false);
        // entry_ptr->name = read_cstring(entry_addr + field_offset(msm_dump_entry,name),32, "name",false);
        if (type == Entry_type::ENTRY_TYPE_DATA){
            parser_dump_data(entry_ptr);
        }else if (type == Entry_type::ENTRY_TYPE_TABLE){
            parser_dump_table(entry_ptr->addr);
        }
    }
}

void DebugImage::print_task_stack(int pid){
#if defined(ARM64)
    struct task_context *tc = pid_to_context(pid);
    if(!tc){
        fprintf(fp, "No such task_context \n");
        return;
    }
    field_init(task_struct, thread);
    field_init(thread_struct, cpu_context);

    struct cpu_context cc;
    BZERO(&cc, sizeof(struct cpu_context));
    if(!read_struct(tc->task + field_offset(task_struct, thread) + field_offset(thread_struct, cpu_context), &cc , sizeof(struct cpu_context) ,"cpu_context in dbi")){
        return;
    }

    fprintf(fp, "cpu_context:\n");
    fprintf(fp, "   X19: %#lx\n", cc.x19);
    fprintf(fp, "   X20: %#lx\n", cc.x20);
    fprintf(fp, "   X21: %#lx\n", cc.x21);
    fprintf(fp, "   X22: %#lx\n", cc.x22);
    fprintf(fp, "   X23: %#lx\n", cc.x23);
    fprintf(fp, "   X24: %#lx\n", cc.x24);
    fprintf(fp, "   X25: %#lx\n", cc.x25);
    fprintf(fp, "   X26: %#lx\n", cc.x26);
    fprintf(fp, "   X27: %#lx\n", cc.x27);
    fprintf(fp, "   X28: %#lx\n", cc.x28);
    fprintf(fp, "   fp:  %#lx\n", cc.fp);
    fprintf(fp, "   sp:  %#lx\n", cc.sp);
    fprintf(fp, "   pc:  %#lx\n\n", cc.pc);

    std::map<ulong, ulong> mem_maps;
    ulong stackbase = GET_STACKBASE(tc->task);
    ulong stacktop = GET_STACKTOP(tc->task);
    fprintf(fp, "Stack:%#lx~%#lx \n",stackbase, stacktop);
    for(ulong addr = stackbase; addr < stacktop; addr += 0x10){
        ulong fp = read_pointer(addr, "frame pointer x29");
        mem_maps[addr] = fp;
    }
    int cnt = 0;
    for(ulong x29: find_x29(mem_maps)){
        ulong x30 = x29 + 8;
        if(x30 < stackbase && x30 > stacktop){ // out of range
            continue;
        }
        fprintf(fp, "[%d]Potential backtrace -> FP:%#lx, LR:%#lx\n",cnt, x29, x30);
        uwind_task_back_trace(pid, x30);
        cnt++;
    }
#endif
}

void DebugImage::print_irq_stack(int cpu){
#if defined(ARM64)
    if (cpu > kt->cpus){
        fprintf(fp, "invaild cpu ! \n");
        return;
    }
    // for (int i = 0; i < kt->cpus; i++){
        std::map<ulong, ulong> mem_maps;
        ulong irq_stack = machdep->machspec->irq_stacks[cpu];
        fprintf(fp, "CPU[%d] irq stack:%#lx~%#lx \n",cpu, irq_stack, irq_stack + machdep->machspec->irq_stack_size);
        for(ulong addr = irq_stack; addr < irq_stack + machdep->machspec->irq_stack_size; addr += 0x10){
            ulong fp = read_pointer(addr, "frame pointer x29");
            mem_maps[addr] = fp;
        }
        int cnt = 0;
        for(ulong x29: find_x29(mem_maps)){
            ulong x30 = x29 + 8;
            if(x30 < irq_stack && x30 > irq_stack+ machdep->machspec->irq_stack_size){ // out of range
                continue;
            }
            fprintf(fp, "[%d]Potential backtrace -> FP:%#lx, LR:%#lx\n",cnt, x29, x30);
            uwind_irq_back_trace(cpu,x30);
            cnt++;
        }
        fprintf(fp, "\n");
    // }
#endif
}

std::set<ulong> DebugImage::find_x29(const std::map<ulong /* addr */, ulong /* x29 */>& addr_x29) {
    // Step 1: Build a set of x29 for fast lookup
    std::set<ulong> x29_sets;
    for (const auto& kv : addr_x29) {
        x29_sets.insert(kv.second);
    }
    // Step 2: Find the first key (starting from the largest) that exists in the value set
    ulong start_addr = 0;
    bool found_start = false;
    // Reverse iterate through the map (from largest key to smallest)
    for (auto it = addr_x29.rbegin(); it != addr_x29.rend(); ++it) {
        bool exists_in_x29 = (x29_sets.find(it->first) != x29_sets.end());
        if(debug){
            fprintf(fp, "Checking: %#lx - exists in x29? %s\n", it->first, (exists_in_x29 ? "YES" : "NO"));
        }
        if (exists_in_x29) {
            start_addr = it->first;
            found_start = true;
            if(debug){
                fprintf(fp, "!!! FOUND START ADDRESS: %#lx\n", start_addr);
            }
            break;
        }
    }
    if (!found_start) {
        if(debug){
            fprintf(fp, "No valid addr in x29\n");
        }
        return {};
    }
    // Step 3: save all addrs that x29 == start_addr
    std::set<ulong> current_addrs;
    for (const auto& kv : addr_x29) {
        if (kv.second == start_addr) {
            current_addrs.insert(kv.first);
            if(debug){
                fprintf(fp, "  Found mapping addr -> x29: %#lx -> %#lx\n", kv.first, kv.second);
            }
        }
    }
    if(debug){
        fprintf(fp, "  Total mappings found: %zu\n\n", current_addrs.size());
    }
    // Step 4: Iteratively find final addrs, strictly following decreasing order
    std::set<ulong> result_addrs;
    int iteration = 0;
    while (!current_addrs.empty()) {
        iteration++;
        if(debug){
            fprintf(fp, "     loop: %d, processing %zu addrs\n", iteration, current_addrs.size());
        }
        std::set<ulong> next_addrs;
        for (ulong addr : current_addrs) {
            if(debug){
                fprintf(fp, "  Processing address: %#lx\n", addr);
            }
            bool found = false;
            // Look for addrs whose value equals the current addr and are smaller than the current addr
            for (const auto& kv : addr_x29) {
                if (kv.second == addr && kv.first < addr) {
                    if(debug){
                        fprintf(fp, "    Found valid child addr -> x29: %#lx -> %#lx\n", kv.first, kv.second);
                    }
                    next_addrs.insert(kv.first);
                    found = true;
                }
            }
            // If not found, current addr is a final addr
            if (!found) {
                if(debug){
                    fprintf(fp, "    No valid child found - marking as final address\n");
                }
                result_addrs.insert(addr);
            }
        }
        if(debug){
            fprintf(fp, "  Found %zu addresses for next loop\n\n", next_addrs.size());
        }
        current_addrs = next_addrs;
    }
    if(debug){
        fprintf(fp, "Final addresses found: %zu\n\n", result_addrs.size());
    }
    return result_addrs;
}

#pragma GCC diagnostic pop
