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

#include "wdt.h"

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wpointer-arith"

#ifndef BUILD_TARGET_TOGETHER
DEFINE_PLUGIN_COMMAND(Watchdog)
#endif

void Watchdog::cmd_main(void) {
    int c;
    std::string cppString;
    if (argcnt < 2) cmd_usage(pc->curcmd, SYNOPSIS);
    while ((c = getopt(argcnt, args, "a")) != EOF) {
        switch(c) {
            case 'a':
                print_watchdog_info();
                break;
            default:
                argerrs++;
                break;
        }
    }
    if (argerrs)
        cmd_usage(pc->curcmd, SYNOPSIS);
}

Watchdog::Watchdog(){
    field_init(msm_watchdog_data,base);
    field_init(msm_watchdog_data,pet_time);
    field_init(msm_watchdog_data,bark_time);
    field_init(msm_watchdog_data,bark_irq);
    field_init(msm_watchdog_data,do_ipi_ping);
    field_init(msm_watchdog_data,in_panic);
    field_init(msm_watchdog_data,wakeup_irq_enable);
    field_init(msm_watchdog_data,irq_ppi);
    field_init(msm_watchdog_data,last_pet);
    field_init(msm_watchdog_data,alive_mask);
    field_init(msm_watchdog_data,wdog_cpu_dd);
    field_init(msm_watchdog_data,enabled);
    field_init(msm_watchdog_data,user_pet_enabled);
    field_init(msm_watchdog_data,watchdog_task);
    field_init(msm_watchdog_data,pet_timer);
    field_init(msm_watchdog_data,timer_expired);
    field_init(msm_watchdog_data,user_pet_complete);
    field_init(msm_watchdog_data,timer_fired);
    field_init(msm_watchdog_data,thread_start);
    field_init(msm_watchdog_data,ping_start);
    field_init(msm_watchdog_data,ping_end);
    field_init(msm_watchdog_data,cpu_idle_pc_state);
    field_init(msm_watchdog_data,freeze_in_progress);
    field_init(msm_watchdog_data,irq_counts);
    field_init(msm_watchdog_data,ipi_counts);
    field_init(msm_watchdog_data,irq_counts_running);
    field_init(msm_watchdog_data,user_pet_timer);
    field_init(msm_watchdog_data,watchdog_task);
    field_init(timer_list,expires);
    struct_init(msm_watchdog_data);
    cmd_name = "wdt";
    help_str_list={
        "wdt",                            /* command name */
        "dump watchdog information",        /* short description */
        "-a \n"
            "  This command dumps the watchdog info.",
        "\n",
        "EXAMPLES",
        "  Display watchdog info:",
        "    %s> wdt -a",
        "     enabled               : True",
        "     base                  : c5a66000",
        "     user_pet_enabled      : False",
        "     pet_time              : 9.36s",
        "     bark_time             : 15s",
        "     bite_time             : 18s",
        "     bark_irq              : 25",
        "     user_pet_complete     : True",
        "     wakeup_irq_enable     : True",
        "     in_panic              : True",
        "     irq_ppi               : False",
        "     freeze_in_progress    : False",
        "",
        "     pet_timer:",
        "        jiffies             : 4299314482",
        "        expires             : 4348153",
        "        timer_expired       : False",
        "        timer_fired         : 14784480161054",
        "        last_jiffies_update : 14790618520938",
        "        tick_next_period    : 14790621854271",
        "        tick_do_timer_cpu   : 3",
        "",
        "     watchdog_thread:",
        "        watchdog_task       : eb1d5c80",
        "        pid                 : 40",
        "        cpu                 : 0",
        "        task_state          : IN",
        "        last_run            : 14784480389231",
        "        thread_start        : 14784480630012",
        "        last_pet            : 14784480640950",
        "        do_ipi_ping         : True",
        "        ping cpu[0]         : 1203198795~1203203274(4479ns)",
        "        ping cpu[1]         : 0~0(0ns)",
        "        ping cpu[2]         : 0~0(0ns)",
        "        ping cpu[3]         : 0~0(0ns)",
        "\n",
    };
    initialize();
}

void Watchdog::print_watchdog_info(){
    if (!csymbol_exists("wdog_data")){
        fprintf(fp, "wdog_data doesn't exist in this kernel!\n");
        return;
    }
    ulong wdt_addr = read_pointer(csymbol_value("wdog_data"),"wdog_data");
    if (!is_kvaddr(wdt_addr)) {
        fprintf(fp, "wdog_data address is invalid!\n");
        return;
    }
    void *wdt_buf = read_struct(wdt_addr,"msm_watchdog_data");
    if (!wdt_buf) {
        return;
    }
    ulong base = UINT(wdt_buf + field_offset(msm_watchdog_data,base));
    uint pet_time = UINT(wdt_buf + field_offset(msm_watchdog_data,pet_time));
    uint bark_time = UINT(wdt_buf + field_offset(msm_watchdog_data,bark_time));
    uint bark_irq = UINT(wdt_buf + field_offset(msm_watchdog_data,bark_irq));
    bool enabled = BOOL(wdt_buf + field_offset(msm_watchdog_data,enabled));
    bool user_pet_enabled = BOOL(wdt_buf + field_offset(msm_watchdog_data,user_pet_enabled));
    bool do_ipi_ping = BOOL(wdt_buf + field_offset(msm_watchdog_data,do_ipi_ping));
    bool in_panic = BOOL(wdt_buf + field_offset(msm_watchdog_data,in_panic));
    bool wakeup_irq_enable = BOOL(wdt_buf + field_offset(msm_watchdog_data,wakeup_irq_enable));
    bool irq_ppi = BOOL(wdt_buf + field_offset(msm_watchdog_data,irq_ppi));
    bool timer_expired = BOOL(wdt_buf + field_offset(msm_watchdog_data,timer_expired));
    bool user_pet_complete = BOOL(wdt_buf + field_offset(msm_watchdog_data,user_pet_complete));
    bool freeze_in_progress = BOOL(wdt_buf + field_offset(msm_watchdog_data,freeze_in_progress));
    uint64_t last_pet = ULONGLONG(wdt_buf + field_offset(msm_watchdog_data,last_pet));
    uint64_t timer_fired = ULONGLONG(wdt_buf + field_offset(msm_watchdog_data,timer_fired));
    uint64_t thread_start = ULONGLONG(wdt_buf + field_offset(msm_watchdog_data,thread_start));
    ulong watchdog_task = ULONG(wdt_buf + field_offset(msm_watchdog_data,watchdog_task));
    FREEBUF(wdt_buf);
    struct task_context* tc = task_to_context(watchdog_task);
    uint64_t jiffies = 0;
    if (csymbol_exists("jiffies")){
        jiffies = read_ulonglong(csymbol_value("jiffies"),"jiffies");
    }else if (csymbol_exists("jiffies_64")){
        jiffies = read_ulonglong(csymbol_value("jiffies_64"),"jiffies");
    }
    uint64_t last_jiffies_update = read_ulonglong(csymbol_value("last_jiffies_update"),"last_jiffies_update");
    uint64_t tick_next_period = read_ulonglong(csymbol_value("tick_next_period"),"tick_next_period");
    int tick_do_timer_cpu = read_int(csymbol_value("tick_do_timer_cpu"),"tick_do_timer_cpu");
    ulong expires = read_ulong(wdt_addr + field_offset(msm_watchdog_data,pet_timer) + field_offset(timer_list,expires),"expires");
    char buf[BUFSIZE];
    std::ostringstream oss;
    oss << std::left << std::setw(20) << "enabled               : " << (enabled ? "True":"False") << "\n"
        << std::left << std::setw(20) << "wdt_base              : " << std::hex << base << "\n"
        << std::left << std::setw(20) << "user_pet_enabled      : " << (user_pet_enabled ? "True":"False") << "\n"
        << std::left << std::setw(20) << "pet_time              : " << std::dec << ((double)pet_time / 1000) << "s\n"
        << std::left << std::setw(20) << "bark_time             : " << std::dec << ((double)bark_time / 1000) << "s\n"
        << std::left << std::setw(20) << "bite_time             : " << std::dec << ((double)bark_time + 3 * 1000)/1000 << "s\n"
        << std::left << std::setw(20) << "bark_irq              : " << std::dec << bark_irq << "\n"
        << std::left << std::setw(20) << "user_pet_complete     : " << (user_pet_complete ? "True":"False") << "\n"
        << std::left << std::setw(20) << "wakeup_irq_enable     : " << (wakeup_irq_enable ? "True":"False") << "\n"
        << std::left << std::setw(20) << "in_panic              : " << (in_panic ? "True":"False") << "\n"
        << std::left << std::setw(20) << "irq_ppi               : " << (irq_ppi ? "True":"False") << "\n"
        << std::left << std::setw(20) << "freeze_in_progress    : " << (freeze_in_progress ? "True":"False") << "\n\n"
        << std::left << "pet_timer: " << "\n"
        << std::left << std::setw(20) << "  jiffies             : " << std::dec << jiffies  << "\n"
        << std::left << std::setw(20) << "  expires             : " << std::dec << expires << "\n"
        << std::left << std::setw(20) << "  timer_expired       : " << (timer_expired ? "True":"False") << "\n"
        << std::left << std::setw(20) << "  timer_fired         : " << std::dec << timer_fired << "\n"
        << std::left << std::setw(20) << "  last_jiffies_update : " << std::dec << last_jiffies_update << "\n"
        << std::left << std::setw(20) << "  tick_next_period    : " << std::dec << tick_next_period << "\n"
        << std::left << std::setw(20) << "  tick_do_timer_cpu   : " << std::dec << tick_do_timer_cpu << "\n\n"
        << std::left << "watchdog_thread: " << "\n"
        << std::left << std::setw(20) << "  watchdog_task       : " << std::hex << watchdog_task << "\n"
        << std::left << std::setw(20) << "  pid                 : " << std::dec << tc->pid << "\n"
        << std::left << std::setw(20) << "  cpu                 : " << std::dec << tc->processor << "\n"
        << std::left << std::setw(20) << "  task_state          : " << task_state_string(watchdog_task, buf, 0) << "\n"
        << std::left << std::setw(20) << "  last_run            : " << task_last_run(watchdog_task) << "\n"
        << std::left << std::setw(20) << "  thread_start        : " << std::dec << thread_start << "\n"
        << std::left << std::setw(20) << "  last_pet            : " << std::dec << last_pet << "\n"
        << std::left << std::setw(20) << "  do_ipi_ping         : " << (do_ipi_ping ? "True":"False") << "\n";
    ulong ping_start_addr = wdt_addr + field_offset(msm_watchdog_data,ping_start);
    ulong ping_end_addr = wdt_addr + field_offset(msm_watchdog_data,ping_end);
    for (size_t i = 0; i < NR_CPUS; i++) {
        if (!kt->__per_cpu_offset[i])
            continue;
        ulong ping_start = read_ulonglong(ping_start_addr + i * sizeof(unsigned long long),"ping_start");
        ulong ping_end =  read_ulonglong(ping_end_addr + i * sizeof(unsigned long long),"ping_end");
        std::string pcpu = "ping cpu[" + std::to_string(i) + "]";
        oss << std::left << "  " << std::setw(20) << pcpu << ": " << ping_start << "~" << ping_end << "(" << (ping_end - ping_start)<< "ns)" << "\n";
    }
    oss << std::left << "-----------------------------------------------" << "\n";
    if (timer_expired == false){
        oss << std::left << "pet_timer is not trigger !" << "\n";
    }
    fprintf(fp, "%s \n",oss.str().c_str());
}


#pragma GCC diagnostic pop
