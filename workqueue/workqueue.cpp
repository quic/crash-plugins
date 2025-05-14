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

#include "workqueue.h"

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wpointer-arith"

#ifndef BUILD_TARGET_TOGETHER
DEFINE_PLUGIN_COMMAND(Workqueue)
#endif

void Workqueue::cmd_main(void) {
    int c;
    std::string cppString;
    if (argcnt < 2) cmd_usage(pc->curcmd, SYNOPSIS);
    if (workqueue_list.size() == 0){
        parse_workqueue();
    }
    while ((c = getopt(argcnt, args, "wpP:")) != EOF) {
        switch(c) {
            case 'w':
                print_worker();
                break;
            case 'p':
                print_pool();
                break;
            case 'P':
                cppString.assign(optarg);
                print_pool_by_addr(cppString);
                break;
            default:
                argerrs++;
                break;
        }
    }
    if (argerrs)
        cmd_usage(pc->curcmd, SYNOPSIS);
}

Workqueue::Workqueue(){
    field_init(workqueue_struct, list);
    field_init(workqueue_struct, name);
    field_init(workqueue_struct, flags);
    field_init(workqueue_struct, pwqs);

    field_init(pool_workqueue, pwqs_node);
    field_init(pool_workqueue, inactive_works);
    field_init(pool_workqueue, pool);
    field_init(pool_workqueue, refcnt);
    field_init(pool_workqueue, nr_active);
    field_init(pool_workqueue, max_active);

    field_init(worker_pool, cpu);
    field_init(worker_pool, node);
    field_init(worker_pool, id);
    field_init(worker_pool, flags);
    field_init(worker_pool, watchdog_ts);
    field_init(worker_pool, nr_running);
    field_init(worker_pool, worklist);
    field_init(worker_pool, nr_workers);
    field_init(worker_pool, nr_idle);
    field_init(worker_pool, idle_list);
    field_init(worker_pool, workers);
    field_init(worker_pool, busy_hash);

    field_init(worker, node);
    field_init(worker, entry);
    field_init(worker, current_work);
    field_init(worker, current_func);
    field_init(worker, task);
    field_init(worker, last_active);
    field_init(worker, id);
    field_init(worker, sleeping);
    field_init(worker, desc);
    field_init(worker, last_func);
    field_init(worker, flags);

    field_init(work_struct, entry);
    field_init(work_struct, data);
    field_init(work_struct, func);

    struct_init(workqueue_struct);
    struct_init(pool_workqueue);
    struct_init(worker_pool);
    struct_init(worker);
    struct_init(work_struct);
    // print_table();
    cmd_name = "wq";
    help_str_list={
        "wq",                            /* command name */
        "dump workqueue information",        /* short description */
        "-w\n"
            "  wq -p\n"
            "  wq -P <worker_pool addr>\n"
            "  This command dumps the workqueue info.",
        "\n",
        "EXAMPLES",
        "  Display worker:",
        "    %s> wq -w",
        "    worker           name             pid    flags                                  workqueue      sleeping last_active IDLE last_func current_func",
        "    ffffff8017a46840 kworker/1:1H     111    WORKER_PREP|WORKER_IDLE                kverityd       0        4294894838  Yes  func_name func_name",
        "\n",
        "  Display worker_pool:",
        "    %s> wq -p",
        "    worker_pool       cpu     workers idle running works flags",
        "    ffffff800a019c00  Unbound 1       1    0       0     POOL_DISASSOCIATED",
        "\n",
        "  Display worker by given the worker_pool address",
        "    %s> wq -P ffffff800303e400",
        "     worker:",
        "        kworker/u8:0 [Idle] pid:8",
        "        kworker/u8:1 [Idle] pid:10",
        "        kworker/u8:2 [Busy] pid:67",
        "        kworker/u8:3 [Idle] pid:87",
        "     Delayed Work:",
        "     Pending Work:",
        "        func_name",
        "\n",
    };
    initialize();
}

void Workqueue::print_worker(){
    //sort
    std::vector<std::pair<ulong, std::shared_ptr<worker>>> worker_list(worker_list_map.begin(), worker_list_map.end());
    std::sort(worker_list.begin(), worker_list.end(),[&](const std::pair<ulong, std::shared_ptr<worker>>& a, const std::pair<ulong, std::shared_ptr<worker>>& b){
        return a.second->last_active > b.second->last_active;
    });
    size_t name_max_len = 0;
    size_t last_func_max_len = 0;
    for (const auto& pair_ptr : worker_list) {
        std::shared_ptr<worker> worker_ptr = pair_ptr.second;
        if(worker_ptr == nullptr) continue;
        name_max_len = std::max(name_max_len,worker_ptr->comm.size());
        last_func_max_len = std::max(last_func_max_len,print_func_name(worker_ptr->last_func).size());
    }
    std::ostringstream oss_hd;
    oss_hd << std::left << std::setw(VADDR_PRLEN) << "worker" << " "
        << std::left << std::setw(name_max_len) << "name" << " "
        << std::left << std::setw(6) << "pid" << " "
        << std::left << std::setw(worker_flags_len) << "flags" << " "
        << std::left << std::setw(workqueue_name_len) << "workqueue" << " "
        << std::left << std::setw(8) << "sleeping" << " "
        << std::left << std::setw(11) << "last_active" << " "
        << std::left << std::setw(4) << "IDLE" << " "
        << std::left << std::setw(last_func_max_len) << "last_func" << " "
        << "current_func";
    fprintf(fp, "%s \n",oss_hd.str().c_str());
    for(const auto& pair_ptr : worker_list){
        std::shared_ptr<worker> worker_ptr = pair_ptr.second;
        if(worker_ptr == nullptr) continue;
        std::string idle = "No";
        if (std::find(idle_worker_list.begin(), idle_worker_list.end(), worker_ptr) != idle_worker_list.end()) {
            idle = "Yes";
        } else {
            idle = "No";
        }
        std::ostringstream oss;
        oss << std::left << std::setw(VADDR_PRLEN) << std::hex << worker_ptr->addr << " "
            << std::left << std::setw(name_max_len) << worker_ptr->comm << " "
            << std::left << std::setw(6) << std::dec << worker_ptr->pid << " "
            << std::left << std::setw(worker_flags_len) << worker_ptr->flags << " "
            << std::left << std::setw(workqueue_name_len) << worker_ptr->desc << " "
            << std::left << std::setw(8) << worker_ptr->sleeping << " "
            << std::left << std::setw(11) << worker_ptr->last_active << " "
            << std::left << std::setw(4) << idle << " "
            << std::left << std::setw(last_func_max_len) << print_func_name(worker_ptr->last_func) << " "
            << print_func_name(worker_ptr->current_func);
        fprintf(fp, "%s \n",oss.str().c_str());
    }
}

void Workqueue::print_pool_by_addr(std::string addr){
    ulong address = 0;
    try {
        address = std::stoul(addr, nullptr, 16);
    } catch (const std::exception& e) {
        fprintf(fp, "Exception caught: %s \n", e.what());
    }
    if (is_kvaddr(address)) {
        if(worker_pool_map.find(address) == worker_pool_map.end())
            fprintf(fp, "No such worker pool \n");
        for(const auto& worker_pool : worker_pool_map){
            if(worker_pool.first == address){
                fprintf(fp, "worker:\n");
                for(const auto& worker_ptr : worker_pool.second->workers){
                    std::string idle = "Idle";
                    if (std::find(idle_worker_list.begin(), idle_worker_list.end(), worker_ptr) != idle_worker_list.end()) {
                        idle = "Idle";
                    } else {
                        idle = "Busy";
                    }
                    std::ostringstream oss;
                    oss << std::left << "   " << worker_ptr->comm << " "
                        << std::left << "[" << idle << "] "
                        << std::left << "pid:" << worker_ptr->pid;
                    fprintf(fp, "%s \n",oss.str().c_str());
                }
                fprintf(fp, "\nDelayed Work:\n");
                for(const auto& pool_workqueue_ptr : worker_pool.second->pwq_list){
                    for(const auto& work_struct_ptr : pool_workqueue_ptr->delay_works_list){
                        fprintf(fp, "   %s\n",print_func_name(work_struct_ptr->func).c_str());
                    }
                }
                fprintf(fp, "\nPending Work:\n");
                for(const auto& work_struct_ptr : worker_pool.second->worklist){
                    fprintf(fp, "   %s\n",print_func_name(work_struct_ptr->func).c_str());
                }
            } /*else {
                fprintf(fp, "No such worker pool \n");
            } */
        }
    } else {
        fprintf(fp, "Invalid virtual address: %lx \n", address);
    }
}

void Workqueue::print_pool(){
    std::ostringstream oss_hd;
    oss_hd << std::left << std::setw(VADDR_PRLEN + 5) << "worker_pool" << " "
        << std::left << std::setw(10) << "cpu" << " "
        << std::left << std::setw(10) << "workers" << " "
        << std::left << std::setw(10) << "idle" << " "
        << std::left << std::setw(10) << "running" << " "
        << std::left << std::setw(10) << "works" << " "
        << std::left << "flags";
    fprintf(fp, "%s \n",oss_hd.str().c_str());
    for(const auto& pair_ptr : worker_pool_map){
        std::shared_ptr<worker_pool> wp_ptr = pair_ptr.second;
        std::string cpu = "";
        if(wp_ptr->cpu < 0){
            cpu = "Unbound";
        } else {
            cpu = std::to_string(wp_ptr->cpu);
        }
        std::ostringstream oss;
        oss << std::left << std::setw(VADDR_PRLEN + 5) << std::hex << wp_ptr->addr << " "
            << std::left << std::setw(10) << std::dec << cpu << " "
            << std::left << std::setw(10) << std::dec << wp_ptr->nr_workers << " "
            << std::left << std::setw(10) << std::dec << wp_ptr->nr_idle << " "
            << std::left << std::setw(10) << std::dec << wp_ptr->nr_running << " "
            << std::left << std::setw(10) << std::dec << wp_ptr->worklist.size() << " "
            << std::left << wp_ptr->flags;
        fprintf(fp, "%s \n",oss.str().c_str());
    }
}

std::string Workqueue::print_func_name(ulong func_addr){
    struct syment *sp;
    ulong offset;
    std::ostringstream oss;
    if (is_kvaddr(func_addr)){
        sp = value_search(func_addr, &offset);
        if (sp){
            oss << sp->name << "+0x" << std::hex << offset;
            // sprintf(buf_last_func, "[<%lx>] %s+0x%lx ", worker_member->last_func, sp->name, offset);
        }else{
            oss << "[<" << std::hex << func_addr << ">] " << sp;
        }
    }else{
        oss << "None";
    }
    return oss.str();
}

template <typename T>
std::string Workqueue::parser_flags(uint flags, const std::unordered_map<T, std::string>& flags_array){
    std::string result;
    bool first = true;
    for (const auto& map : flags_array) {
        if (flags & map.first) {
            if (!first) {
                result += "|";
            }
            result += map.second;
            first = false;
        }
    }
    if (result.empty()) {
        result = "None";
    }
    return result;
}

std::shared_ptr<worker> Workqueue::parser_worker(ulong addr,std::shared_ptr<worker_pool> wp_ptr){
    auto worker_ptr = std::make_shared<worker>();
    worker_ptr->addr = addr;
    worker_ptr->wp_ptr = wp_ptr;
    std::unordered_map<worker_flags, std::string> str_flag_array = {
        {WORKER_DIE, "WORKER_DIE"},
        {WORKER_IDLE, "WORKER_IDLE"},
        {WORKER_PREP, "WORKER_PREP"},
        {WORKER_CPU_INTENSIVE, "WORKER_CPU_INTENSIVE"},
        {WORKER_UNBOUND, "WORKER_UNBOUND"},
        {WORKER_REBOUND, "WORKER_REBOUND"},
    };
    void *worker_buf = read_struct(addr, "worker");
    unsigned int flags = UINT(worker_buf + field_offset(worker, flags));
    worker_ptr->flags = parser_flags(flags, str_flag_array);
    worker_flags_len = std::max(worker_flags_len, worker_ptr->flags.size());
    worker_ptr->current_func = ULONG(worker_buf + field_offset(worker, current_func));
    worker_ptr->task_addr = ULONG(worker_buf + field_offset(worker, task));
    worker_ptr->last_active = ULONG(worker_buf + field_offset(worker, last_active));
    worker_ptr->id = INT(worker_buf + field_offset(worker, id));
    worker_ptr->sleeping = INT(worker_buf + field_offset(worker, sleeping));
    worker_ptr->desc = read_cstring(addr + field_offset(worker, desc), 24, "worker_desc");
    if (worker_ptr->desc.size() == 0)
    worker_ptr->desc = "None";
    struct task_context *tc = task_to_context(worker_ptr->task_addr);
    if (tc){
        worker_ptr->comm = tc->comm;
        worker_ptr->pid = tc->pid;
    }else{
        worker_ptr->comm = "";
        worker_ptr->pid = -1;
    }
    workqueue_name_len = std::max(workqueue_name_len, worker_ptr->desc.size());
    worker_ptr->last_func = ULONG(worker_buf + field_offset(worker, last_func));
    FREEBUF(worker_buf);
    return worker_ptr;
}

std::vector<std::shared_ptr<worker>> Workqueue::parser_worker_list(ulong list_head_addr,int offset,std::shared_ptr<worker_pool> wp_ptr){
    std::vector<std::shared_ptr<worker>> worker_list;
    std::vector<ulong> list = for_each_list(list_head_addr, offset);
    std::shared_ptr<worker> worker_ptr;
    for(const auto& worker_addr : list){
        if (worker_list_map.find(worker_addr) == worker_list_map.end()) {
            worker_ptr = parser_worker(worker_addr,wp_ptr);
            worker_list_map[worker_addr] = worker_ptr;
        } else {
            worker_ptr = worker_list_map[worker_addr];
        }
        worker_list.push_back(worker_ptr);
    }
    return worker_list;
}

std::vector<std::shared_ptr<work_struct>> Workqueue::parser_work_list(ulong list_head_addr){
    std::vector<std::shared_ptr<work_struct>> work_list;
    int offset = field_offset(work_struct, entry);
    std::vector<ulong> list = for_each_list(list_head_addr, offset);
    for(const auto& work_addr : list){
        auto work_ptr = std::make_shared<work_struct>();
        work_ptr->addr = work_addr;
        work_ptr->data = read_ulong(work_addr + field_offset(work_struct, data), "work_struct_data");
        work_ptr->func = read_pointer(work_addr + field_offset(work_struct, func), "work_struct_func");
        work_list.push_back(work_ptr);
    }
    return work_list;
}

std::shared_ptr<worker_pool> Workqueue::parser_worker_pool(ulong addr,std::shared_ptr<pool_workqueue> pwq_ptr){
    auto wp_ptr = std::make_shared<worker_pool>();
    wp_ptr->addr = addr;
    void *wp_buf = read_struct(addr, "worker_pool");
    wp_ptr->cpu = INT(wp_buf + field_offset(worker_pool, cpu));
    wp_ptr->node = INT(wp_buf + field_offset(worker_pool, node));
    wp_ptr->id = INT(wp_buf + field_offset(worker_pool, id));
    std::unordered_map<worker_pool_flags, std::string> str_flag_array = {
        {POOL_MANAGER_ACTIVE, "POOL_MANAGER_ACTIVE"},
        {POOL_DISASSOCIATED, "POOL_DISASSOCIATED"}
    };
    wp_ptr->pwq_list.insert(pwq_ptr);
    unsigned int flags = UINT(wp_buf + field_offset(worker_pool, flags));
    wp_ptr->flags = parser_flags(flags, str_flag_array);
    worker_pool_flags_len = std::max(worker_pool_flags_len, wp_ptr->flags.size());
    wp_ptr->nr_workers = INT(wp_buf + field_offset(worker_pool, nr_workers));
    wp_ptr->nr_idle = INT(wp_buf + field_offset(worker_pool, nr_idle));
    wp_ptr->watchdog_ts = ULONG(wp_buf + field_offset(worker_pool, watchdog_ts));
    wp_ptr->nr_running = ULONG(wp_buf + field_offset(worker_pool, nr_running));
    wp_ptr->worklist = parser_work_list(addr + field_offset(worker_pool, worklist));
    int offset = field_offset(worker, node);
    wp_ptr->workers = parser_worker_list(addr + field_offset(worker_pool, workers),offset,wp_ptr);
    offset = field_offset(worker, entry);
    wp_ptr->idle_list = parser_worker_list(addr + field_offset(worker_pool, idle_list), offset,wp_ptr);
    idle_worker_list.insert(idle_worker_list.end(), wp_ptr->idle_list.begin(), wp_ptr->idle_list.end());
    FREEBUF(wp_buf);
    return wp_ptr;
}

std::shared_ptr<pool_workqueue> Workqueue::parser_pool_workqueue(ulong addr,std::shared_ptr<workqueue_struct> wq_ptr){
    auto pwq_ptr = std::make_shared<pool_workqueue>();
    pwq_ptr->addr = addr;
    pwq_ptr->wq_ptr = wq_ptr;
    void *pwq_buf = read_struct(addr, "pool_workqueue");
    pwq_ptr->refcnt = INT(pwq_buf + field_offset(pool_workqueue, refcnt));
    pwq_ptr->nr_active = INT(pwq_buf + field_offset(pool_workqueue, nr_active));
    pwq_ptr->max_active = INT(pwq_buf + field_offset(pool_workqueue, max_active));
    ulong pool_addr = ULONG(pwq_buf + field_offset(pool_workqueue, pool));
    FREEBUF(pwq_buf);
    if (is_kvaddr(pool_addr)){
        std::shared_ptr<worker_pool> wp_ptr;
        if (worker_pool_map.find(pool_addr) == worker_pool_map.end()){ // Do not find the pool_addr
            wp_ptr = parser_worker_pool(pool_addr,pwq_ptr);
            worker_pool_map[pool_addr] = wp_ptr;
        }else{
            wp_ptr = worker_pool_map[pool_addr];
        }
        pwq_ptr->wp_ptr = wp_ptr;
    }
    if(field_offset(pool_workqueue, inactive_works) >= 0){
        pwq_ptr->delay_works_list = parser_work_list(addr + field_offset(pool_workqueue, inactive_works));
    } else {
        field_init(pool_workqueue, delayed_works);
        pwq_ptr->delay_works_list = parser_work_list(addr + field_offset(pool_workqueue, delayed_works));
    }
    return pwq_ptr;
}

std::shared_ptr<workqueue_struct> Workqueue::parser_workqueue_struct(ulong addr){
    auto wq_ptr = std::make_shared<workqueue_struct>();
    wq_ptr->addr = addr;
    wq_ptr->name = read_cstring(addr + field_offset(workqueue_struct, name), 24, "workqueue_struct_name");
    unsigned int flags = read_uint(addr + field_offset(workqueue_struct, flags), "workqueue_struct_flags");
    std::unordered_map<workqueue_struct_flags, std::string> str_flag_array = {
        {WQ_UNBOUND, "WQ_UNBOUND"},
        {WQ_FREEZABLE, "WQ_FREEZABLE"},
        {WQ_MEM_RECLAIM, "WQ_MEM_RECLAIM"},
        {WQ_HIGHPRI, "WQ_HIGHPRI"},
        {WQ_CPU_INTENSIVE, "WQ_CPU_INTENSIVE"},
        {WQ_SYSFS, "WQ_SYSFS"}
    };
    wq_ptr->flags = parser_flags(flags, str_flag_array);
    ulong pwqs_head_addr = addr + field_offset(workqueue_struct, pwqs);
    int offset = field_offset(pool_workqueue, pwqs_node);
    std::vector<ulong> pwq_list = for_each_list(pwqs_head_addr, offset);
    for (const auto& pwq_addr : pwq_list){
        wq_ptr->pwqs.push_back(parser_pool_workqueue(pwq_addr,wq_ptr));
    }
    return wq_ptr;
}

void Workqueue::parse_workqueue(){
    if (!csymbol_exists("workqueues")){
        fprintf(fp, "workqueues doesn't exist in this kernel! \n");
        return;
    }
    ulong workqueues_addr = csymbol_value("workqueues");
    if (!is_kvaddr(workqueues_addr)) return;
    if (workqueue_list.size() > 0) return;
    int offset = field_offset(workqueue_struct, list);
    std::vector<ulong> list = for_each_list(workqueues_addr, offset);
    for(const auto& addr : list){
        // fprintf(fp, "workqueue_addr %lx \n", addr);
        auto workqueue_struct = parser_workqueue_struct(addr);
        workqueue_list.push_back(workqueue_struct);
    }
}

#pragma GCC diagnostic pop
