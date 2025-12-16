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
                parser_wdt_core();
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
    do_init_offset = false;
}

void Watchdog::init_command(void) {
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
}

void Watchdog::init_offset(void) {
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

    // upstream wdt
    field_init(watchdog_core_data, cdev);
    field_init(watchdog_core_data, wdd);
    field_init(watchdog_core_data, last_keepalive);
    field_init(watchdog_core_data, open_deadline);
    field_init(watchdog_core_data, status);
    field_init(watchdog_core_data, timer);
    // CONFIG_WATCHDOG_HRTIMER_PRETIMEOUT
    field_init(watchdog_core_data, pretimeout_timer);
    field_init(watchdog_core_data, last_hw_keepalive);
    field_init(watchdog_core_data, last_hw_keepalive);
    field_init(watchdog_device, pretimeout);
    field_init(watchdog_device, timeout);
    field_init(kthread_worker, task);
    field_init(clock_event_device, next_event);
    field_init(clock_event_device, cpumask);
    field_init(tick_device, evtdev);
    field_init(hrtimer, node);
    field_init(hrtimer, _softexpires);
    field_init(hrtimer, state);
    field_init(probe, dev);
    field_init(probe, data);
    field_init(timerqueue_node, expires);
    field_init(task_struct, __state);
    field_init(task_struct, state);
    field_init(task_struct, thread_info);
    field_init(task_struct, stack);
    field_init(task_struct, on_cpu);
    field_init(task_struct, cpu);
    field_init(task_struct, sched_info);
    field_init(sched_info, last_arrival);
    field_init(sched_info, last_queued);
    field_init(thread_info, cpu);
    struct_init(watchdog_core_data);
    field_offset(clock_event_device, next_event);
    field_offset(tick_device, evtdev);
    field_init(cdev,dev);

    // platform_driver and device_driver
    field_init(platform_driver, driver);
    field_init(device_driver, name);
    struct_init(platform_driver);
    struct_init(device_driver);

    // qcom_wdt structure
    field_init(qcom_wdt, wdd);
    field_init(qcom_wdt, rate);
    field_init(qcom_wdt, base);
    field_init(qcom_wdt, layout);
    struct_init(qcom_wdt);

    // watchdog_device structure
    field_init(watchdog_device, min_timeout);
    field_init(watchdog_device, max_timeout);
    field_init(watchdog_device, min_hw_heartbeat_ms);
    field_init(watchdog_device, max_hw_heartbeat_ms);
    field_init(watchdog_device, wd_data);
    field_init(watchdog_device, status);
    struct_init(watchdog_device);

    // watchdog_core_data structure (additional fields)
    field_init(watchdog_core_data, work);
    struct_init(kthread_work);
}

ulong Watchdog::find_qcom_wdt(){
    // Get the address of qcom_watchdog_driver symbol (platform_driver structure)
    ulong wdt_driver_addr = csymbol_value("qcom_watchdog_driver");
    if (!is_kvaddr(wdt_driver_addr)) {
        LOGE("qcom_watchdog_driver address is invalid! %#lx\n", wdt_driver_addr);
        return 0;
    }

    // Calculate the address of device_driver within platform_driver
    // device_driver is embedded after 6 function pointers
    ulong device_driver_addr = wdt_driver_addr + field_offset(platform_driver, driver);

    // Read the name pointer from device_driver structure (first field)
    ulong name_ptr = read_pointer(device_driver_addr + field_offset(device_driver, name),
                                   "device_driver.name");
    if (!is_kvaddr(name_ptr)) {
        LOGE("device_driver.name pointer is invalid! %#lx\n", name_ptr);
        return 0;
    }

    // Read the driver name string
    std::string driver_name = read_cstring(name_ptr, 64, "driver name");
    // Search for the driver in all bus types
    ulong driv_addr = 0;
    for (const auto& bus_ptr : for_each_bus_type()) {
        for (const auto& driver_addr : for_each_driver(bus_ptr->name)) {
            std::shared_ptr<driver> driv_ptr = parser_driver(driver_addr);
            if (driv_ptr && driv_ptr->name == driver_name) {
                driv_addr = driv_ptr->addr;
                break;
            }
        }
        if (driv_addr != 0) {
            break;
        }
    }

    // Validate driver address
    if (!is_kvaddr(driv_addr)) {
        LOGE("Driver address not found for: %s\n", driver_name.c_str());
        return 0;
    }

    // Get all devices bound to this driver
    std::vector<std::shared_ptr<device>> device_list = for_each_device_for_driver(driv_addr);

    // Return the device address if exactly one device is found
    if (device_list.size() > 0) {
        return device_list[0]->driver_data;
    } else {
        LOGW("No device found for driver: %s\n", driver_name.c_str());
    }

    return 0;
}

/**
 * Parse watchdog core data structures
 *
 * This function determines the watchdog type (MSM or QCOM) and parses
 * the appropriate watchdog structure with detailed information.
 */
void Watchdog::parser_wdt_core(){
    init_offset();

    // Check if MSM watchdog exists
    ulong wdt_addr = read_pointer(csymbol_value("wdog_data"),"wdog_data");
    if (!is_kvaddr(wdt_addr)) {
        // MSM watchdog not found, try QCOM watchdog
        ulong qcom_wdt_addr = find_qcom_wdt();
        if (!is_kvaddr(qcom_wdt_addr)) {
            LOGE("No watchdog found\n");
            return;
        }

        PRINT("qcom_wdt:%#lx\n", qcom_wdt_addr);

        // Read qcom_wdt structure
        void *qcom_wdt_buf = read_struct(qcom_wdt_addr, "qcom_wdt");
        if (!qcom_wdt_buf) {
            LOGE("Failed to read qcom_wdt structure at address %#lx\n", qcom_wdt_addr);
            return;
        }

        // Parse qcom_wdt fields
        ulong rate = ULONG(qcom_wdt_buf + field_offset(qcom_wdt, rate));
        ulong base = ULONG(qcom_wdt_buf + field_offset(qcom_wdt, base));

        // Get watchdog_device address (embedded structure)
        ulong wdd_addr = qcom_wdt_addr + field_offset(qcom_wdt, wdd);

        FREEBUF(qcom_wdt_buf);

        // Read watchdog_device structure
        void *wdd_buf = read_struct(wdd_addr, "watchdog_device");
        if (!wdd_buf) {
            LOGE("Failed to read watchdog_device structure at address %#lx\n", wdd_addr);
            return;
        }

        // Parse watchdog_device fields
        uint timeout = UINT(wdd_buf + field_offset(watchdog_device, timeout));
        uint pretimeout = UINT(wdd_buf + field_offset(watchdog_device, pretimeout));
        uint min_timeout = UINT(wdd_buf + field_offset(watchdog_device, min_timeout));
        uint max_timeout = UINT(wdd_buf + field_offset(watchdog_device, max_timeout));
        uint min_hw_heartbeat_ms = UINT(wdd_buf + field_offset(watchdog_device, min_hw_heartbeat_ms));
        uint max_hw_heartbeat_ms = UINT(wdd_buf + field_offset(watchdog_device, max_hw_heartbeat_ms));
        ulong wd_data_addr = ULONG(wdd_buf + field_offset(watchdog_device, wd_data));
        ulong wdd_status = ULONG(wdd_buf + field_offset(watchdog_device, status));

        FREEBUF(wdd_buf);

        // Output qcom_wdt information
        std::ostringstream oss;
        oss << "=== QCOM Watchdog Information ===\n";
        oss << std::left << std::setw(25) << "  rate" << ": " << std::dec << rate << " Hz\n";
        oss << std::left << std::setw(25) << "  base" << ": " << std::hex << std::showbase << base << "\n";
        oss << std::left << std::setw(25) << "  timeout" << ": " << std::dec << timeout << "s\n";
        oss << std::left << std::setw(25) << "  pretimeout" << ": " << std::dec << pretimeout << "s\n";
        oss << std::left << std::setw(25) << "  bark_time" << ": " << std::dec << (timeout - pretimeout) << "s\n";
        oss << std::left << std::setw(25) << "  min_timeout" << ": " << std::dec << min_timeout << "s\n";
        oss << std::left << std::setw(25) << "  max_timeout" << ": " << std::dec << max_timeout << "s\n";
        oss << std::left << std::setw(25) << "  min_hw_heartbeat_ms" << ": " << std::dec << min_hw_heartbeat_ms << "ms\n";
        oss << std::left << std::setw(25) << "  max_hw_heartbeat_ms" << ": " << std::dec << max_hw_heartbeat_ms << "ms\n";
        oss << std::left << std::setw(25) << "  watchdog_core_data" << ": " << std::hex << std::showbase << wd_data_addr << "\n";
        oss << std::left << std::setw(25) << "  status" << ": " << parse_wdd_status(wdd_status) << "\n";

        // Parse watchdog_core_data if available
        if (is_kvaddr(wd_data_addr)) {
            void *wd_data_buf = read_struct(wd_data_addr, "watchdog_core_data");
            if (wd_data_buf) {
                ulonglong last_keepalive = ULONGLONG(wd_data_buf + field_offset(watchdog_core_data, last_keepalive));
                ulonglong last_hw_keepalive = ULONGLONG(wd_data_buf + field_offset(watchdog_core_data, last_hw_keepalive));
                ulonglong open_deadline = ULONGLONG(wd_data_buf + field_offset(watchdog_core_data, open_deadline));
                ulong core_status = ULONG(wd_data_buf + field_offset(watchdog_core_data, status));

                // Get hrtimer information
                // hrtimer structure: node, _softexpires, function, base, state, ...
                ulong timer_addr = wd_data_addr + field_offset(watchdog_core_data, timer);
                ulonglong timer_node_expires = read_ulonglong(timer_addr + field_offset(hrtimer, node)
                    + field_offset(timerqueue_node, expires), "timer node expires");
                ulonglong timer_softexpires = read_ulonglong(timer_addr + field_offset(hrtimer, _softexpires),
                    "timer _softexpires");
                unsigned char timer_state = read_byte(timer_addr + field_offset(hrtimer, state), "timer state");

                FREEBUF(wd_data_buf);
                oss << std::left << std::setw(25) << "  last_keepalive" << ": " << nstoSec(last_keepalive) << "s\n";
                oss << std::left << std::setw(25) << "  last_hw_keepalive" << ": " << nstoSec(last_hw_keepalive) << "s\n";
                oss << std::left << std::setw(25) << "  open_deadline" << ": " << nstoSec(open_deadline) << "s\n";
                oss << std::left << std::setw(25) << "  timer.node.expires" << ": " << nstoSec(timer_node_expires) << "s\n";
                oss << std::left << std::setw(25) << "  timer._softexpires" << ": " << nstoSec(timer_softexpires) << "s\n";
                oss << std::left << std::setw(25) << "  timer.state" << ": " << std::dec << static_cast<int>(timer_state) << "\n";
                oss << std::left << std::setw(25) << "  core_status" << ": " << parse_core_status(core_status) << "\n";
            }
        }

        oss << "=================================\n";
        PRINT("%s", oss.str().c_str());
    } else {
        // MSM watchdog found
        parser_msm_wdt();
    }
}

void Watchdog::parser_msm_wdt(){
    init_offset();
    ulong wdt_addr = read_pointer(csymbol_value("wdog_data"),"wdog_data");
    if (!is_kvaddr(wdt_addr)) {
        LOGE("wdog_data address is invalid! %#lx\n", wdt_addr);
        return;
    }
    void *wdt_buf = read_struct(wdt_addr,"msm_watchdog_data");
    if (!wdt_buf) {
        LOGE("Failed to read msm_watchdog_data structure at address %#lx\n", wdt_addr);
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
    ulong pid = 0;
    int processor = -1;
    if(!tc){
        LOGE("No such watchdog task \n");
    } else {
        pid = tc->pid;
        processor = tc->processor;
    }
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
    oss << "\n=== MSM Watchdog Information ===\n";
    oss << std::left << std::setw(25) << "  enabled" << ": " << (enabled ? "True":"False") << "\n";
    oss << std::left << std::setw(25) << "  base" << ": " << std::hex << std::showbase << base << "\n";
    oss << std::left << std::setw(25) << "  user_pet_enabled" << ": " << (user_pet_enabled ? "True":"False") << "\n";
    oss << std::left << std::setw(25) << "  pet_time" << ": " << std::dec << ((double)pet_time / 1000) << "s\n";
    oss << std::left << std::setw(25) << "  bark_time" << ": " << std::dec << ((double)bark_time / 1000) << "s\n";
    oss << std::left << std::setw(25) << "  bite_time" << ": " << std::dec << ((double)bark_time + 3 * 1000)/1000 << "s\n";
    oss << std::left << std::setw(25) << "  bark_irq" << ": " << std::dec << bark_irq << "\n";
    oss << std::left << std::setw(25) << "  user_pet_complete" << ": " << (user_pet_complete ? "True":"False") << "\n";
    oss << std::left << std::setw(25) << "  wakeup_irq_enable" << ": " << (wakeup_irq_enable ? "True":"False") << "\n";
    oss << std::left << std::setw(25) << "  in_panic" << ": " << (in_panic ? "True":"False") << "\n";
    oss << std::left << std::setw(25) << "  irq_ppi" << ": " << (irq_ppi ? "True":"False") << "\n";
    oss << std::left << std::setw(25) << "  freeze_in_progress" << ": " << (freeze_in_progress ? "True":"False") << "\n\n";
    oss << std::left << std::setw(25) << "pet_timer:"  << "\n";
    oss << std::left << std::setw(25) << "  jiffies" << ": " << std::dec << jiffies  << "\n";
    oss << std::left << std::setw(25) << "  pet_timer.expires" << ": " << std::dec << expires << "\n";
    oss << std::left << std::setw(25) << "  timer_expired" << ": " << (timer_expired ? "True":"False") << "\n";
    oss << std::left << std::setw(25) << "  timer_fired" << ": " << nstoSec(timer_fired) << "s\n";
    oss << std::left << std::setw(25) << "  last_jiffies_update" << ": " << nstoSec(last_jiffies_update) << "s\n";
    oss << std::left << std::setw(25) << "  tick_next_period" << ": " << nstoSec(tick_next_period) << "s\n";
    oss << std::left << std::setw(25) << "  tick_do_timer_cpu" << ": " << std::dec << tick_do_timer_cpu << "\n\n";
    oss << std::left << std::setw(25) << "watchdog_thread:"  << "\n";
    oss << std::left << std::setw(25) << "  watchdog_task" << ": " << std::hex << std::showbase << watchdog_task << "\n";
    oss << std::left << std::setw(25) << "  pid" << ": " << std::dec << pid << "\n";
    oss << std::left << std::setw(25) << "  cpu" << ": " << std::dec << processor << "\n";
    oss << std::left << std::setw(25) << "  task_state" << ": " << task_state_string(watchdog_task, buf, 0) << "\n";
    oss << std::left << std::setw(25) << "  last_run" << ": " << nstoSec(task_last_run(watchdog_task)) << "s\n";
    oss << std::left << std::setw(25) << "  thread_start" << ": " << nstoSec(thread_start) << "s\n";
    oss << std::left << std::setw(25) << "  last_pet" << ": " << nstoSec(last_pet) << "s\n";
    oss << std::left << std::setw(25) << "  do_ipi_ping" << ": " << (do_ipi_ping ? "True":"False") << "\n";
    ulong ping_start_addr = wdt_addr + field_offset(msm_watchdog_data,ping_start);
    ulong ping_end_addr = wdt_addr + field_offset(msm_watchdog_data,ping_end);
    for (size_t i = 0; i < NR_CPUS; i++) {
        if (!kt->__per_cpu_offset[i])
            continue;
        ulong ping_start = read_ulonglong(ping_start_addr + i * sizeof(unsigned long long),"ping_start");
        ulong ping_end =  read_ulonglong(ping_end_addr + i * sizeof(unsigned long long),"ping_end");
        oss << std::left << std::setw(25) << ("  ping_cpu[" + std::to_string(i) + "]")
            << ": " << nstoSec(ping_start) << "s ~ " << nstoSec(ping_end) << "s (" << (ping_end - ping_start) << "ns)\n";
    }

    if (timer_expired == false){
        oss << "\n[Note] Pet timer has not triggered!\n";
    }
    oss << "=================================\n";
    PRINT("%s",oss.str().c_str());
}

void Watchdog::parser_upstream_wdt(){
    init_offset();
    ulong wdt_addr = get_wdt_by_cdev();
    if (!is_kvaddr(wdt_addr)) {
        LOGE("the upstream wdt do not exist \n");
        return;
    }
    void *wdt_buf = read_struct(wdt_addr, "watchdog_core_data");
    if (!wdt_buf) {
        LOGE("Failed to read watchdog_core_data structure at address %#lx\n", wdt_addr);
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
    int wdog_task_cpu = get_task_cpu(wdt_task_addr, task_to_thread_info(wdt_task_addr));
    unsigned char pet_timer_state = read_byte(wdt_addr  + field_offset(watchdog_core_data, timer) + field_offset(hrtimer, state), "watchdog_kworker from wdt");
    int bite_time = read_int(watchdog_device + field_offset(watchdog_device, timeout), "timeout from wdt");
    int pretimeout = read_int(watchdog_device + field_offset(watchdog_device, pretimeout), "pretimeout from wdt");
    int bark_time = bite_time - pretimeout;

    std::ostringstream oss;
    oss << "\n=== Upstream Watchdog Information ===\n";
    oss << std::left << std::setw(25) << "  bark_time" << ": " << std::dec << bark_time << "s\n";
    oss << std::left << std::setw(25) << "  bite_time" << ": " << std::dec << bite_time << "s\n";
    oss << std::left << std::setw(25) << "  last_hw_keepalive" << ": " << nstoSec(last_hw_keepalive) << "s\n";
    oss << std::left << std::setw(25) << "  next_keepalive" << ": " << nstoSec(last_hw_keepalive + (ulonglong)bark_time * 1000000000ULL) << "s\n";
    oss << std::left << std::setw(25) << "  status" << ": " << parse_core_status(status) << "\n";
    oss << std::left << std::setw(25) << "  pet_timer.expires" << ": " << nstoSec(pet_timer_expires) << "s\n";
    oss << std::left << std::setw(25) << "  pet_timer.state" << ": " << std::dec << static_cast<int>(pet_timer_state) << "\n";
    oss << std::left << std::setw(25) << "  jiffies" << ": " << std::dec << jiffies << "\n";
    oss << std::left << std::setw(25) << "  last_jiffies_update" << ": " << nstoSec(last_jiffies_update) << "s\n";
    oss << std::left << std::setw(25) << "  tick_do_timer_cpu" << ": " << std::dec << tick_do_timer_cpu << "\n";
    oss << std::left << std::setw(25) << "  watchdog_task" << ": " << std::hex << std::showbase << wdt_task_addr << "\n";
    oss << std::left << std::setw(25) << "  task_state" << ": " << std::dec << wdog_task_state << "\n";
    oss << std::left << std::setw(25) << "  task_cpu" << ": " << std::dec << wdog_task_cpu << "\n";
    oss << std::left << std::setw(25) << "  task_on_cpu" << ": " << (wdog_task_oncpu ? "True" : "False") << "\n";
    oss << std::left << std::setw(25) << "  task_last_arrival" << ": " << nstoSec(wdog_task_arrived) << "s\n";
    oss << std::left << std::setw(25) << "  task_last_queued" << ": " << nstoSec(wdog_task_queued) << "s\n";

    // Per-CPU tick device information
    for (size_t i = 0; i < NR_CPUS; i++) {
        if (!kt->__per_cpu_offset[i])
            continue;
        ulong tick_cpu_device_addr = csymbol_value("tick_cpu_device") + kt->__per_cpu_offset[i];
        if (!is_kvaddr(tick_cpu_device_addr)) continue;
        ulong evt_dev_addr = read_structure_field(tick_cpu_device_addr, "tick_device", "evtdev");
        if(is_kvaddr(evt_dev_addr)){
            ulong next_event = read_structure_field(evt_dev_addr, "clock_event_device", "next_event");
            oss << std::left << std::setw(25) << ("  tick_cpu[" + std::to_string(i) + "].next_event")
                << ": " << nstoSec(next_event) << "s\n";
        }
    }

    // Analysis and warnings
    bool pet_timer_expired = (pet_timer_state != 0);
    if(wdog_task_state == 0 && wdog_task_oncpu == 1){
        oss << "\n[Note] Watchdog task is running on CPU " << wdog_task_cpu << "\n";
    }else if(wdog_task_state == 0){
        oss << "\n[Note] Watchdog task is waiting on CPU " << wdog_task_cpu << "\n";
    }else if(wdog_task_state == 1 && pet_timer_expired){
        oss << "\n[Warning] Pet timer expired but watchdog task is not queued!\n";
    }else if(pet_timer_expired){
        oss << "\n[Warning] Pet timer has expired!\n";
    }else{
        if(jiffies > pet_timer_expires){
            oss << "\n[Warning] Current jiffies crossed pet_timer expires!\n";
        }
    }

    oss << "=================================\n";
    PRINT("%s", oss.str().c_str());
}

std::string Watchdog::nstoSec(ulonglong ns) {
    double seconds = ns / 1e9;
    std::ostringstream oss;
    oss << std::fixed << std::setprecision(8) << seconds;
    return oss.str();
}

/**
 * Parse watchdog device status bits to human-readable string
 *
 * @param status The status value from watchdog_device.status
 * @return String representation of active status bits
 */
std::string Watchdog::parse_wdd_status(ulong status) {
    std::vector<std::string> flags;

    // Watchdog status bit definitions
    if (status & (1UL << 0)) flags.push_back("WDOG_ACTIVE");
    if (status & (1UL << 1)) flags.push_back("WDOG_NO_WAY_OUT");
    if (status & (1UL << 2)) flags.push_back("WDOG_STOP_ON_REBOOT");
    if (status & (1UL << 3)) flags.push_back("WDOG_HW_RUNNING");
    if (status & (1UL << 4)) flags.push_back("WDOG_STOP_ON_UNREGISTER");
    if (status & (1UL << 5)) flags.push_back("WDOG_NO_PING_ON_SUSPEND");

    if (flags.empty()) {
        return "0x0 (none)";
    }

    std::ostringstream oss;
    oss << std::hex << std::showbase << status << " (";
    for (size_t i = 0; i < flags.size(); i++) {
        if (i > 0) oss << " | ";
        oss << flags[i];
    }
    oss << ")";

    return oss.str();
}

/**
 * Parse watchdog core data status bits to human-readable string
 *
 * @param status The status value from watchdog_core_data.status
 * @return String representation of active status bits
 */
std::string Watchdog::parse_core_status(ulong status) {
    std::vector<std::string> flags;

    // Watchdog core data status bit definitions
    if (status & (1UL << 0)) flags.push_back("WDOG_DEV_OPEN");
    if (status & (1UL << 1)) flags.push_back("WDOG_ALLOW_RELEASE");
    if (status & (1UL << 2)) flags.push_back("WDOG_KEEPALIVE");

    if (flags.empty()) {
        return "0x0 (none)";
    }

    std::ostringstream oss;
    oss << std::hex << std::showbase << status << " (";
    for (size_t i = 0; i < flags.size(); i++) {
        if (i > 0) oss << " | ";
        oss << flags[i];
    }
    oss << ")";

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


#pragma GCC diagnostic pop
