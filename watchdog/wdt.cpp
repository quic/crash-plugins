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
    while ((c = getopt(argcnt, args, "au")) != EOF) {
        switch(c) {
            case 'a':
                parser_msm_wdt();
                break;
            case 'u':
                parser_upstream_wdt();
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
    field_init(cdev,dev);
    struct_init(msm_watchdog_data);
    cmd_name = "wdt";
    help_str_list={
        "wdt",                            /* command name */
        "dump watchdog information",        /* short description */
        "-a \n"
            "  wdt -u \n"
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

void Watchdog::parser_msm_wdt(){
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

void Watchdog::parser_upstream_wdt(){
    ulong wdt_addr = get_wdt_by_cdev();
    if (!is_kvaddr(wdt_addr)) {
        fprintf(fp, "the upstream wdt do not exist \n");
        return;
    }
    void *wdt_buf = read_struct(wdt_addr, "watchdog_core_data");
    if (!wdt_buf) {
        return;
    }
    ulong status = ULONG(wdt_buf + field_offset(watchdog_core_data, status));
    // ulonglong last_keepalive = ULONGLONG(wdt_buf + field_offset(watchdog_core_data, last_keepalive));
    // ulonglong open_deadline = ULONGLONG(wdt_buf + field_offset(watchdog_core_data, open_deadline));
    ulonglong last_hw_keepalive = ULONGLONG(wdt_buf + field_offset(watchdog_core_data, last_hw_keepalive));
    ulong watchdog_device = ULONG(wdt_buf + field_offset(watchdog_core_data, wdd));
    FREEBUF(wdt_buf);
    uint64_t jiffies = 0;
    if (csymbol_exists("jiffies")){
        jiffies = read_ulonglong(csymbol_value("jiffies"), "jiffies");
    }else if (csymbol_exists("jiffies_64")){
        jiffies = read_ulonglong(csymbol_value("jiffies_64"), "jiffies");
    }
    uint64_t last_jiffies_update = read_ulonglong(csymbol_value("last_jiffies_update"), "last_jiffies_update from wdt");
    // uint64_t tick_next_period = read_ulonglong(csymbol_value("tick_next_period"), "tick_next_period from wdt");
    int tick_do_timer_cpu = read_int(csymbol_value("tick_do_timer_cpu"), "tick_do_timer_cpu from wdt");
    uint64_t pet_timer_expires = read_ulonglong(wdt_addr + field_offset(watchdog_core_data, timer)
    + field_offset(hrtimer, node) + field_offset(timerqueue_node, expires), "expires from wdt");
    ulong watchdog_kworker_addr = read_pointer(csymbol_value("watchdog_kworker"), "watchdog_kworker from wdt");
    ulong wdt_task_addr = read_pointer(watchdog_kworker_addr + field_offset(kthread_worker, task), "kthread_worker from wdt");
    uint wdog_task_state = 0;
    if(field_offset(task_struct, __state) != -1){
        wdog_task_state = read_int(wdt_task_addr + field_offset(task_struct, __state), "__state from wdt");
    } else {
        wdog_task_state = read_int(wdt_task_addr + field_offset(task_struct, state), "state from wdt");
    }
    ulonglong wdog_task_arrived = read_ulonglong(wdt_task_addr + field_offset(task_struct, sched_info) + field_offset(sched_info, last_arrival), "last_arrival from wdt");
    ulonglong wdog_task_queued = read_ulonglong(wdt_task_addr + field_offset(task_struct, sched_info) + field_offset(sched_info, last_queued), "last_queued from wdt");
    int wdog_task_oncpu = read_int(wdt_task_addr + field_offset(task_struct, on_cpu), "on_cpu from wdt");
    int wdog_task_cpu = get_task_cpu(wdt_task_addr, get_thread_info_addr(wdt_task_addr));
    unsigned char pet_timer_state = read_byte(wdt_addr  + field_offset(watchdog_core_data, timer) + field_offset(hrtimer, state), "watchdog_kworker from wdt");
    int bite_time = read_int(watchdog_device + field_offset(watchdog_device, timeout), "timeout from wdt");
    int pretimeout = read_int(watchdog_device + field_offset(watchdog_device, pretimeout), "pretimeout from wdt");
    int bark_time = bite_time - pretimeout;
    std::ostringstream oss;
    oss << std::left << std::setw(20) << "Bark time             : " << bark_time << "s" << "\n"
        << std::left << std::setw(20) << "Watchdog last pet     : " << nstoSec(last_hw_keepalive) << "s\n"
        << std::left << std::setw(20) << "Watchdog next pet     : " << nstoSec(last_hw_keepalive+ bark_time) << "s\n";
    bool pet_timer_expired = false;
    if(wdog_task_state == 0 && wdog_task_oncpu == 1){
        pet_timer_expired = true;
        oss << std::left << std::setw(20) << "Watchdog task running on core " << wdog_task_cpu <<  " from " << nstoSec(wdog_task_arrived) << "s\n";
    }else if(wdog_task_state == 0){
        oss << std::left << std::setw(20) << "Watchdog task is waiting on core " << wdog_task_cpu <<  " from " << nstoSec(wdog_task_queued) << "s\n";
    }else if(wdog_task_state == 1 && pet_timer_expired){
        oss << std::left << std::setw(20) << "Pet timer expired but Watchdog task is not queued \n";
    }else if(pet_timer_expired){
        oss << std::left << std::setw(20) << "Pet timer expired \n";
    }else{
        oss << std::left << std::setw(20) << "Watchdog pet timer not expired \n";
        if(jiffies > pet_timer_expires){
            oss << std::left << std::setw(20) << "Current jiffies crossed pet_timer expires jiffies \n";
        }
    }
    oss << std::left << std::setw(20) << "Watchdog status:  " << status << "\n";
    oss << std::left << std::setw(20) << "pet_timer_state: " << static_cast<int>(pet_timer_state) << "\n";
    oss << std::left << std::setw(20) << "pet_timer_expires: " << nstoSec(pet_timer_expires) << "s\n";
    oss << std::left << std::setw(20) << "Current jiffies: " << jiffies << "\n";
    oss << std::left << std::setw(20) << "Timestamp of last timer interrupt(last_jiffies_update): " << nstoSec(last_jiffies_update) << "s\n";
    oss << std::left << std::setw(20) << "tick_do_timer_cpu: " << tick_do_timer_cpu << "\n";
    for (size_t i = 0; i < NR_CPUS; i++) {
        if (!kt->__per_cpu_offset[i])
            continue;
        ulong tick_cpu_device_addr = csymbol_value("tick_cpu_device") + kt->__per_cpu_offset[i];
        if (!is_kvaddr(tick_cpu_device_addr)) continue;
        ulong evt_dev_addr = read_structure_field(tick_cpu_device_addr, "tick_device", "evtdev");
        if(is_kvaddr(evt_dev_addr)){
            ulong next_event = read_structure_field(evt_dev_addr, "clock_event_device", "next_event");
            oss << std::left << "CPU:" << i << " tick_device next_event:" << nstoSec(next_event) << "s\n";
        }
    }
    fprintf(fp, "%s \n", oss.str().c_str());
}

std::string Watchdog::nstoSec(ulonglong ns) {
    double seconds = ns / 1e9;
    std::ostringstream oss;
    oss << std::fixed << std::setprecision(8) << seconds;
    return oss.str();
}

ulong Watchdog::get_wdt_by_cdev(){
    uint watchdog_devt = read_uint(csymbol_value("watchdog_devt"),"dev_t");
    for (const auto& cdev_addr : for_each_cdev()) {
        uint dev = read_uint(cdev_addr + field_offset(cdev, dev),"dev_t");
        if (dev == watchdog_devt){
            return cdev_addr;
        }
    }
    return 0;
}

int Watchdog::get_task_cpu(ulong task_addr, ulong thread_info_addr){
    if((get_config_val("CONFIG_THREAD_INFO_IN_TASK") == "y") && THIS_KERNEL_VERSION < LINUX(5, 19, 0)){
        return read_int(task_addr + field_offset(task_struct, cpu), "cpu from wdt");
    } else {
        return read_int(thread_info_addr + field_offset(thread_info, cpu), "cpu from wdt");
    }
}

ulong Watchdog::get_thread_info_addr(ulong task_addr){
    if(get_config_val("CONFIG_THREAD_INFO_IN_TASK") == "y"){
        return task_addr + field_offset(task_struct, thread_info);
    } else {
        return read_pointer(task_addr + field_offset(task_struct, stack), "stack from wdt");
    }
}


#pragma GCC diagnostic pop
