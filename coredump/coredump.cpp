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

#include "coredump.h"

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wpointer-arith"

#ifndef BUILD_TARGET_TOGETHER
DEFINE_PLUGIN_COMMAND(Coredump)
#endif

void Coredump::cmd_main(void) {
    int c;
    int pid;
    std::string cppString, file_path;
    if (argcnt < 2) cmd_usage(pc->curcmd, SYNOPSIS);
    while ((c = getopt(argcnt, args, "p:m:")) != EOF) {
        switch(c) {
            case 'p':
                cppString.assign(optarg);
                try {
                    pid = std::stoi(cppString);
                    generate_coredump(pid);
                } catch (...) {
                    fprintf(fp, "invaild pid arg %s\n",cppString.c_str());
                }
                break;
            case 'm':
                cppString.assign(optarg);
                try {
                    pid = std::stoi(cppString);
                    print_proc_mapping(pid);
                } catch (...) {
                    fprintf(fp, "invaild pid arg %s\n",cppString.c_str());
                }
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
}

void Coredump::print_proc_mapping(int pid){
    struct task_context *tc = pid_to_context(pid);
    if (!tc) {
        fprintf(fp, "No such pid: %d\n", pid);
        return;
    }
    set_context(tc->task, NO_PID, TRUE);
    ulong task_flags = read_structure_field(tc->task,"task_struct","flags");
    if (task_flags & PF_KTHREAD) {
        fprintf(fp, "pid %d is kernel thread,no vm.\n", pid);
        return;
    }
    if (!tc->mm_struct) {
        fprintf(fp, "pid %d have no virtual memory space.\n", pid);
        return;
    }
    std::shared_ptr<Core> core_parser = core_ptr;
    if (BITS64()){
        fill_thread_info(tc->thread_info);
        if (field_offset(thread_info, flags) != -1){
            ulong thread_flags = read_ulong(tc->task + field_offset(task_struct, thread_info) + field_offset(thread_info, flags), "coredump task_struct thread_info flags");
            if(thread_flags & (1 << 22)){
                is_compat = true;
                core_parser = compat_core_ptr;
                if(debug){
                    fprintf(fp, "is_compat: %d\n", is_compat);
                }
            }
        }
    }
    core_parser->set_core_pid(pid);
    core_parser->print_proc_mapping();
}

void Coredump::generate_coredump(int pid){
    struct task_context *tc = pid_to_context(pid);
    if (!tc) {
        fprintf(fp, "No such pid: %d\n", pid);
        return;
    }
    set_context(tc->task, NO_PID, TRUE);
    ulong task_flags = read_structure_field(tc->task,"task_struct","flags");
    if (task_flags & PF_KTHREAD) {
        fprintf(fp, "pid %d is kernel thread,not support coredump.\n", pid);
        return;
    }
    if (!tc->mm_struct) {
        fprintf(fp, "pid %d have no virtual memory space.\n", pid);
        return;
    }
    std::shared_ptr<Core> core_parser = core_ptr;
    if (BITS64()){
        fill_thread_info(tc->thread_info);
        if (field_offset(thread_info, flags) != -1){
            ulong thread_flags = read_ulong(tc->task + field_offset(task_struct, thread_info) + field_offset(thread_info, flags), "coredump task_struct thread_info flags");
            if(thread_flags & (1 << 22)){
                is_compat = true;
                core_parser = compat_core_ptr;
                if(debug){
                    fprintf(fp, "is_compat: %d\n", is_compat);
                }
            }
        }
    }
    core_parser->set_core_pid(pid);
    core_parser->parser_core_dump();
    fprintf(fp, "Coredump is Done \n");
}

Coredump::Coredump(std::shared_ptr<Swapinfo> swap) : swap_ptr(swap){
    init_command();
}

Coredump::Coredump(){
    swap_ptr = std::make_shared<Swapinfo>();
    init_command();
    //print_table();
}

void Coredump::init_command(){
    field_init(task_struct, flags);
    field_init(task_struct, thread_info);
    field_init(thread_info, flags);
    PaserPlugin::cmd_name = "coredump";
    help_str_list={
        "coredump",                            /* command name */
        "generate process coredump",        /* short description */
        "-p <pid>\n"
            "  coredump -m <pid>\n"
            "  This command generate process coredump.",
        "\n",
        "EXAMPLES",
        "  Generate process coredump:",
        "    %s> coredump -p 323",
        "\n",
        "  Show process maps:",
        "    %s> coredump -m 323",
        "      VMA:f0ff4198 [fb0e000-fb13000] r--p 00000000 /system/bin/logd",
        "      VMA:f0ff4ee0 [fb13000-fb2c000] r-xp 00000004 /system/bin/logd",
        "      VMA:f0ff4bb0 [fb2c000-fb2d000] r--p 0000001c /system/bin/logd",
        "      VMA:f0ff4880 [fb2d000-fb2e000] rw-p 0000001c /system/bin/logd",
        "      VMA:e8514ee0 [a6d28000-a70fb000] rw-p 000a6d28 libc_malloc",
        "      VMA:f0ff9cc0 [a70fb000-a70fc000] ---p 000a70fb",
        "      VMA:f0cf6770 [a70fc000-a71fb000] rw-p 000a70fc stack_and_tls:356",
        "\n",
    };
    initialize();

#if defined(ARM64)
    if (machine_type(TO_CONST_STRING("ARM64"))){
        compat_core_ptr = std::make_shared<Compat>(swap_ptr);
        core_ptr = std::make_shared<Arm64>(swap_ptr);
    } else {
        fprintf(fp, "Not support this platform \n");
    }
#endif
#if defined(ARM)
    if (machine_type(TO_CONST_STRING("ARM"))){
        core_ptr = std::make_shared<Arm>(swap_ptr);
    } else {
        fprintf(fp, "Not support this platform \n");
    }
#endif
}

#pragma GCC diagnostic pop
