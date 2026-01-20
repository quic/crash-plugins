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

#include "workqueue.h"

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wpointer-arith"

#ifndef BUILD_TARGET_TOGETHER
DEFINE_PLUGIN_COMMAND(Workqueue)
#endif

void Workqueue::cmd_main(void) {
    if (argcnt < 2) {
        cmd_usage(pc->curcmd, SYNOPSIS);
        return;
    }

    if (workqueue_list.empty()) {
        LOGI("Workqueue list is empty, parsing workqueues");
        parse_workqueue();
    } else {
        LOGD("Using cached workqueue list (size=%zu)", workqueue_list.size());
    }

    int c;
    std::string arg_str;

    while ((c = getopt(argcnt, args, "sdc:")) != EOF) {
        switch(c) {
            case 's':
                LOGI("Executing print_summary command");
                print_summary();
                break;
            case 'd':
                LOGI("Executing print_detailed command");
                print_detailed();
                break;
            case 'c':
                arg_str.assign(optarg);
                LOGI("Executing print_check with argument: %s", arg_str.c_str());
                print_check(arg_str);
                break;
            default:
                LOGW("Unknown option: %c", c);
                argerrs++;
                break;
        }
    }

    if (argerrs) {
        cmd_usage(pc->curcmd, SYNOPSIS);
    }

    LOGD("Command execution completed");
}

void Workqueue::init_offset(void) {
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
    field_init(worker_pool, attrs);

    struct_init(workqueue_attrs);
    field_init(workqueue_attrs, nice);

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
    field_init(worker, hentry);

    field_init(work_struct, entry);
    field_init(work_struct, data);
    field_init(work_struct, func);

    struct_init(workqueue_struct);
    struct_init(pool_workqueue);
    struct_init(worker_pool);
    struct_init(worker);
    struct_init(work_struct);

    struct_init(hlist_head);
    field_init(worker_pool,hash_node);
    field_init(hlist_head,first);
    field_init(hlist_node,next);
}

void Workqueue::init_command(void) {
    cmd_name = "wq";
    help_str_list={
        "wq",
        "dump workqueue information",
        "-s | -d | -c <cpu|addr>\n"
            "  This command dumps workqueue information with different levels of detail.",
        "\n",
        "OPTIONS",
        "  -s              Display summary statistics (system status, quick stats, warnings)",
        "  -d              Display detailed information (per-CPU pools, unbound pools)",
        "  -c <cpu|addr>   Check specific CPU or worker pool address",
        "\n",
        "EXAMPLES",
        "  Display summary:",
        "    %s> wq -s",
        "    ========== Workqueue Summary ==========",
        "    System Status: OK",
        "    Quick Stats:",
        "      Pools: 16 (16 per-CPU + 0 unbound)",
        "      Workers: 32 (4 busy, 28 idle)",
        "      Pending Works: 2",
        "\n",
        "  Display detailed information:",
        "    %s> wq -d",
        "    ========== Detailed Workqueue Information ==========",
        "    Per-CPU Pools:",
        "    CPU 0:",
        "      [Normal] 0xffffff800303e400 | 4 workers (3 idle, 1 busy) | 1 pending",
        "      [High] 0xffffff800303e800 | 2 workers (2 idle, 0 busy) | 0 pending",
        "\n",
        "  Check specific CPU:",
        "    %s> wq -c 0",
        "    ========== CPU 0 Details ==========",
        "    [Normal Priority] 0xffffff800303e400",
        "      Workers: 4 (3 idle, 1 busy)",
        "      Pending: 1 works",
        "\n",
        "  Check specific pool address:",
        "    %s> wq -c 0xffffff800303e400",
        "    worker:",
        "       kworker/0:0 [Idle] pid:8",
        "       kworker/0:1 [Busy] pid:10",
        "    Pending Work:",
        "       func_name+0x10",
        "\n",
    };
}

Workqueue::Workqueue(){}

void Workqueue::print_pool_by_addr(std::string addr) {
    LOGD("Starting with address string: %s", addr.c_str());
    ulong address = 0;
    try {
        address = std::stoul(addr, nullptr, 16);
    } catch (const std::exception& e) {
        LOGE("Exception parsing address: %s", e.what());
        return;
    }
    if (!is_kvaddr(address)) {
        LOGE("Invalid kernel virtual address: 0x%lx", address);
        return;
    }
    auto it = worker_pool_map.find(address);
    if (it == worker_pool_map.end()) {
        PRINT("No such worker pool\n");
        return;
    }
    const auto& worker_pool = it->second;
    LOGI("Found worker pool at 0x%lx (cpu=%d, workers=%d)",
         address, worker_pool->cpu, worker_pool->nr_workers);

    // Print pool info with nr_running
    const char* pool_type = (worker_pool->nice == 0) ? "Normal Pool" : "High Pool";
    PRINT("\n[%s] 0x%lx (cpu=%d, nr_running=%lu)\n",
          pool_type, address, worker_pool->cpu, worker_pool->nr_running);

    // Collect pool_workqueue information
    std::string pwq_info = "";
    if (!worker_pool->pwq_list.empty()) {
        for (const auto& pwq : worker_pool->pwq_list) {
            if (!pwq_info.empty()) pwq_info += ", ";
            std::ostringstream pwq_addr;
            pwq_addr << std::hex << pwq->addr;
            pwq_info += "pwq[0x" + pwq_addr.str() + "]";

            // Add workqueue information if available
            if (pwq->wq_ptr) {
                std::ostringstream wq_addr;
                wq_addr << std::hex << pwq->wq_ptr->addr;
                pwq_info += " -> workqueue_struct[0x" + wq_addr.str() + "]";

                if (!pwq->wq_ptr->name.empty()) {
                    pwq_info += " " + pwq->wq_ptr->name;
                }
            }
        }
        PRINT("  %s\n", pwq_info.c_str());
    }

    // Print workers
    PRINT("Workers:\n");
    LOGD("Printing %zu workers", worker_pool->workers.size());
    for (const auto& worker_ptr : worker_pool->workers) {
        bool is_idle = std::find(idle_worker_list.begin(),
                                 idle_worker_list.end(),
                                 worker_ptr) != idle_worker_list.end();

        // Get current work information
        std::string current_work = "None";
        if (worker_ptr->current_func != 0) {
            current_work = print_func_name(worker_ptr->current_func);
        }

        PRINT("   %s [%s] pid:%d | current_func=%s | flags=%s\n",
                worker_ptr->comm.c_str(),
                is_idle ? "Idle" : "Busy",
                worker_ptr->pid,
                current_work.c_str(),
                worker_ptr->flags.c_str());
    }
    // Print delayed work
    PRINT("\nDelayed Work:\n");
    for (const auto& pool_workqueue_ptr : worker_pool->pwq_list) {
        for (const auto& work_struct_ptr : pool_workqueue_ptr->delay_works_list) {
            PRINT("   %s\n", print_func_name(work_struct_ptr->func).c_str());
        }
    }
    // Print pending work
    PRINT("\nPending Work:\n");
    for (const auto& work_struct_ptr : worker_pool->worklist) {
        PRINT("   %s\n", print_func_name(work_struct_ptr->func).c_str());
    }
}

std::string Workqueue::print_func_name(ulong func_addr) {
    LOGD("Looking up function at address: 0x%lx", func_addr);
    if (!is_kvaddr(func_addr)) {
        return "None";
    }
    ulong offset;
    struct syment *sp = value_search(func_addr, &offset);
    if (sp) {
        std::ostringstream oss;
        oss << sp->name << "+0x" << std::hex << offset;
        return oss.str();
    }
    std::ostringstream oss;
    oss << "[<" << std::hex << func_addr << ">]";
    return oss.str();
}

template <typename T>
std::string Workqueue::parser_flags(uint flags,
                                    const std::unordered_map<T, std::string>& flags_array) {
    if (flags == 0) {
        return "None";
    }
    std::vector<std::string> flag_names;
    for (const auto& pair : flags_array) {
        if (flags & pair.first) {
            flag_names.push_back(pair.second);
        }
    }
    if (flag_names.empty()) {
        return "None";
    }
    std::ostringstream oss;
    for (size_t i = 0; i < flag_names.size(); ++i) {
        if (i > 0) oss << "|";
        oss << flag_names[i];
    }
    return oss.str();
}


std::shared_ptr<worker> Workqueue::parser_worker(ulong addr,
                                                  std::shared_ptr<worker_pool> wp_ptr) {
    LOGD("          Parsing worker at address: 0x%lx", addr);
    auto worker_ptr = std::make_shared<worker>();
    worker_ptr->addr = addr;
    worker_ptr->wp_ptr = wp_ptr;
    static const std::unordered_map<worker_flags, std::string> flag_names = {
        {WORKER_DIE, "WORKER_DIE"},
        {WORKER_IDLE, "WORKER_IDLE"},
        {WORKER_PREP, "WORKER_PREP"},
        {WORKER_CPU_INTENSIVE, "WORKER_CPU_INTENSIVE"},
        {WORKER_UNBOUND, "WORKER_UNBOUND"},
        {WORKER_REBOUND, "WORKER_REBOUND"},
    };
    void *worker_buf = read_struct(addr, "worker");
    unsigned int flags = UINT(worker_buf + field_offset(worker, flags));
    worker_ptr->flags = parser_flags(flags, flag_names);
    worker_flags_len = std::max(worker_flags_len, worker_ptr->flags.size());
    worker_ptr->current_func = ULONG(worker_buf + field_offset(worker, current_func));
    worker_ptr->task_addr = ULONG(worker_buf + field_offset(worker, task));
    worker_ptr->last_active = ULONG(worker_buf + field_offset(worker, last_active));
    worker_ptr->id = INT(worker_buf + field_offset(worker, id));
    worker_ptr->sleeping = INT(worker_buf + field_offset(worker, sleeping));
    worker_ptr->last_func = ULONG(worker_buf + field_offset(worker, last_func));
    worker_ptr->desc = read_cstring(addr + field_offset(worker, desc), 24, "worker_desc");
    if (worker_ptr->desc.empty()) {
        worker_ptr->desc = "None";
    }
    workqueue_name_len = std::max(workqueue_name_len, worker_ptr->desc.size());
    struct task_context *tc = task_to_context(worker_ptr->task_addr);
    if (tc) {
        worker_ptr->comm = tc->comm;
        worker_ptr->pid = tc->pid;
        LOGD("          Worker task: %s (pid=%d)", tc->comm, tc->pid);
    } else {
        LOGW("          Failed to get task context for task_addr: 0x%lx", worker_ptr->task_addr);
        worker_ptr->comm = "";
        worker_ptr->pid = -1;
    }
    FREEBUF(worker_buf);
    LOGI("          Successfully parsed worker at 0x%lx (id=%d, flags=%s)",
         addr, worker_ptr->id, worker_ptr->flags.c_str());
    return worker_ptr;
}


std::vector<std::shared_ptr<worker>> Workqueue::parser_worker_list(ulong list_head_addr,int offset,std::shared_ptr<worker_pool> wp_ptr){
    LOGD("        Parsing worker list at 0x%lx (offset=%d)", list_head_addr, offset);
    std::vector<std::shared_ptr<worker>> worker_list;
    std::vector<ulong> list = for_each_list(list_head_addr, offset);
    LOGD("        Found %zu workers in list", list.size());
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
    LOGI("        Parsed %zu workers", worker_list.size());
    return worker_list;
}

std::vector<std::shared_ptr<work_struct>> Workqueue::parser_work_list(ulong list_head_addr){
    LOGD("        Parsing work list at 0x%lx", list_head_addr);
    std::vector<std::shared_ptr<work_struct>> work_list;
    int offset = field_offset(work_struct, entry);
    std::vector<ulong> list = for_each_list(list_head_addr, offset);
    LOGD("        Found %zu work items in list", list.size());
    for(const auto& work_addr : list){
        auto work_ptr = std::make_shared<work_struct>();
        work_ptr->addr = work_addr;
        work_ptr->data = read_ulong(work_addr + field_offset(work_struct, data), "work_struct_data");
        work_ptr->func = read_pointer(work_addr + field_offset(work_struct, func), "work_struct_func");
        work_list.push_back(work_ptr);
    }
    LOGD("        Parsed %zu work items", work_list.size());
    return work_list;
}

std::shared_ptr<worker_pool> Workqueue::parser_worker_pool(ulong addr,std::shared_ptr<pool_workqueue> pwq_ptr){
    LOGD("      Parsing worker pool at address: 0x%lx", addr);
    auto wp_ptr = std::make_shared<worker_pool>();
    wp_ptr->addr = addr;
    void *wp_buf = read_struct(addr, "worker_pool");
    wp_ptr->cpu = INT(wp_buf + field_offset(worker_pool, cpu));
    wp_ptr->node = INT(wp_buf + field_offset(worker_pool, node));
    wp_ptr->id = INT(wp_buf + field_offset(worker_pool, id));

    wp_ptr->nice = 0;
    ulong attrs_addr = ULONG(wp_buf + field_offset(worker_pool, attrs));
    if (is_kvaddr(attrs_addr)) {
        void *attrs_buf = read_struct(attrs_addr, "workqueue_attrs");
        if (attrs_buf) {
            wp_ptr->nice = INT(attrs_buf + field_offset(workqueue_attrs, nice));
            LOGD("      Worker pool 0x%lx has nice=%d", addr, wp_ptr->nice);
            FREEBUF(attrs_buf);
        }
    }

    static const std::unordered_map<worker_pool_flags, std::string> str_flag_array = {
        {POOL_MANAGER_ACTIVE, "POOL_MANAGER_ACTIVE"},
        {POOL_DISASSOCIATED, "POOL_DISASSOCIATED"}
    };
    if (pwq_ptr) {
        wp_ptr->pwq_list.insert(pwq_ptr);
    }
    unsigned int flags = UINT(wp_buf + field_offset(worker_pool, flags));
    wp_ptr->flags = parser_flags(flags, str_flag_array);
    worker_pool_flags_len = std::max(worker_pool_flags_len, wp_ptr->flags.size());
    wp_ptr->nr_workers = INT(wp_buf + field_offset(worker_pool, nr_workers));
    wp_ptr->nr_idle = INT(wp_buf + field_offset(worker_pool, nr_idle));
    wp_ptr->watchdog_ts = ULONG(wp_buf + field_offset(worker_pool, watchdog_ts));
    wp_ptr->nr_running = INT(wp_buf + field_offset(worker_pool, nr_running));
    wp_ptr->worklist = parser_work_list(addr + field_offset(worker_pool, worklist));
    int offset = field_offset(worker, node);
    wp_ptr->workers = parser_worker_list(addr + field_offset(worker_pool, workers),offset,wp_ptr);
    offset = field_offset(worker, entry);
    wp_ptr->idle_list = parser_worker_list(addr + field_offset(worker_pool, idle_list), offset,wp_ptr);
    idle_worker_list.insert(idle_worker_list.end(), wp_ptr->idle_list.begin(), wp_ptr->idle_list.end());
    FREEBUF(wp_buf);
    LOGI("      Successfully parsed worker pool at 0x%lx (cpu=%d, workers=%d, idle=%d, works=%zu)",
         addr, wp_ptr->cpu, wp_ptr->nr_workers, wp_ptr->nr_idle, wp_ptr->worklist.size());
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
        LOGD("    Valid pool address: 0x%lx", pool_addr);
        std::shared_ptr<worker_pool> wp_ptr;
        if (worker_pool_map.find(pool_addr) == worker_pool_map.end()){ // Do not find the pool_addr
            LOGD("    Creating new worker pool for address: 0x%lx", pool_addr);
            wp_ptr = parser_worker_pool(pool_addr,pwq_ptr);
            worker_pool_map[pool_addr] = wp_ptr;
        }else{
            LOGD("    Using cached worker pool for address: 0x%lx", pool_addr);
            wp_ptr = worker_pool_map[pool_addr];
        }
        pwq_ptr->wp_ptr = wp_ptr;
    } else {
        LOGW("    Invalid pool address: 0x%lx", pool_addr);
    }
    if(field_offset(pool_workqueue, inactive_works) >= 0){
        LOGD("    Parsing inactive_works");
        pwq_ptr->delay_works_list = parser_work_list(addr + field_offset(pool_workqueue, inactive_works));
    } else {
        LOGD("    Parsing delayed_works (inactive_works not available)");
        field_init(pool_workqueue, delayed_works);
        pwq_ptr->delay_works_list = parser_work_list(addr + field_offset(pool_workqueue, delayed_works));
    }
    LOGI("    Successfully parsed pool_workqueue at 0x%lx (refcnt=%d, nr_active=%d, max_active=%d)",
         addr, pwq_ptr->refcnt, pwq_ptr->nr_active, pwq_ptr->max_active);
    return pwq_ptr;
}

std::shared_ptr<workqueue_struct> Workqueue::parser_workqueue_struct(ulong addr){
    LOGD("  Parsing workqueue_struct at address: 0x%lx", addr);
    auto wq_ptr = std::make_shared<workqueue_struct>();
    wq_ptr->addr = addr;
    wq_ptr->name = read_cstring(addr + field_offset(workqueue_struct, name), 24, "workqueue_struct_name");
    LOGD("  Workqueue name: %s", wq_ptr->name.c_str());
    unsigned int flags = read_uint(addr + field_offset(workqueue_struct, flags), "workqueue_struct_flags");
    static const std::unordered_map<workqueue_struct_flags, std::string> str_flag_array = {
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
    LOGD("  Found %zu pool_workqueues", pwq_list.size());
    size_t pwq_index = 0;
    for (const auto& pwq_addr : pwq_list){
        pwq_index++;
        LOGD("    [%zu/%zu] Parsing pool_workqueue at address: 0x%lx", pwq_index, pwq_list.size(), pwq_addr);
        wq_ptr->pwqs.push_back(parser_pool_workqueue(pwq_addr,wq_ptr));
    }
    LOGI("  Successfully parsed workqueue '%s' at 0x%lx (flags=%s, pwqs=%zu)",
         wq_ptr->name.c_str(), addr, wq_ptr->flags.c_str(), wq_ptr->pwqs.size());
    LOGI("  ========================================  ");
    return wq_ptr;
}

void Workqueue::parse_cpu_worker_pools() {
    LOGI("========== parse_cpu_worker_pools START ==========");
    if (!csymbol_exists("cpu_worker_pools")) {
        LOGW("cpu_worker_pools symbol not found");
        return;
    }
    ulong cpu_worker_pools_addr = csymbol_value("cpu_worker_pools");
    ulong n_pools = read_enum_val("NR_STD_WORKER_POOLS");
    int worker_pool_size = struct_size(worker_pool);
    for (size_t i = 0; i < NR_CPUS; i++) {
        if (!kt->__per_cpu_offset[i])
            continue;
        ulong worker_pool_addr = cpu_worker_pools_addr + kt->__per_cpu_offset[i];
        if (!is_kvaddr(worker_pool_addr)) {
            continue;
        }
        // Parse normal pool + high pool
        for (size_t j = 0; j < n_pools; j++) {
            ulong worker_pool_j = worker_pool_addr + j * worker_pool_size;

            // Check if already parsed
            if (worker_pool_map.find(worker_pool_j) != worker_pool_map.end()) {
                LOGD("CPU %zu pool %zu already parsed, skipping", i, j);
                continue;
            }

            // Use existing parser_worker_pool to parse and fill data
            LOGD("Parsing CPU %zu pool %zu at 0x%lx", i, j, worker_pool_j);
            auto wp_ptr = parser_worker_pool(worker_pool_j, nullptr);
            worker_pool_map[worker_pool_j] = wp_ptr;
        }
    }

    LOGI("========== parse_cpu_worker_pools END (parsed %zu pools) ==========",
         worker_pool_map.size());
}

void Workqueue::parse_unbound_pool_hash() {
    LOGI("========== parse_unbound_pool_hash START ==========");

    if (!csymbol_exists("unbound_pool_hash")) {
        LOGW("unbound_pool_hash symbol not found");
        return;
    }

    ulong unbound_pool_hash = csymbol_value("unbound_pool_hash");
    ulong unbound_pool_hash_base = unbound_pool_hash;

    size_t hash_size = 64;
    int hash_entry_size = struct_size(hlist_head);
    int hash_node_offset = field_offset(worker_pool, hash_node);
    int first_offset = field_offset(hlist_head, first);
    int next_offset = field_offset(hlist_node, next);

    size_t total_unbound_pools = 0;

    for (size_t hash_index = 0; hash_index < hash_size; hash_index++){
        ulong bucket_addr = unbound_pool_hash_base + hash_index * hash_entry_size;

        // Read hlist_head.first pointer
        ulong first_worker_pool = read_pointer(bucket_addr + first_offset, "first");
        if (!is_kvaddr(first_worker_pool)) {
            continue;
        }

        LOGD("Processing bucket %zu", hash_index);
        ulong next_worker_pool = first_worker_pool;

        while(is_kvaddr(next_worker_pool)){
            // Calculate worker_pool address from hash_node
            ulong worker_pool_addr = next_worker_pool - hash_node_offset;

            // Check if already parsed
            if (worker_pool_map.find(worker_pool_addr) != worker_pool_map.end()) {
                LOGD("  Unbound pool 0x%lx already parsed, skipping", worker_pool_addr);
                next_worker_pool = read_pointer(next_worker_pool + next_offset, "next");
                continue;
            }

            total_unbound_pools++;

            // Use existing parser_worker_pool to parse and fill data
            LOGD("  Parsing unbound pool at 0x%lx", worker_pool_addr);
            auto wp_ptr = parser_worker_pool(worker_pool_addr, nullptr);
            worker_pool_map[worker_pool_addr] = wp_ptr;

            // Get next worker_pool in the hlist chain
            next_worker_pool = read_pointer(next_worker_pool + next_offset, "next");
        }
    }

    LOGI("========== parse_unbound_pool_hash END (parsed %zu unbound pools) ==========",
         total_unbound_pools);
}

void Workqueue::print_summary() {
    LOGD("Starting print_summary");

    // Calculate statistics
    size_t total_workers = worker_list_map.size();
    size_t total_idle = idle_worker_list.size();
    size_t total_busy = total_workers - total_idle;

    size_t total_pending = 0;
    size_t cpu_pools = 0;
    size_t unbound_pools = 0;

    std::map<int, size_t> cpu_pending_map;

    for (const auto& pair : worker_pool_map) {
        const auto& pool = pair.second;
        total_pending += pool->worklist.size();

        if (pool->cpu >= 0) {
            cpu_pools++;
            cpu_pending_map[pool->cpu] += pool->worklist.size();
        } else {
            unbound_pools++;
        }
    }

    // Find busiest CPU
    int busiest_cpu = -1;
    size_t max_pending = 0;
    for (const auto& pair : cpu_pending_map) {
        if (pair.second > max_pending) {
            max_pending = pair.second;
            busiest_cpu = pair.first;
        }
    }

    // Print summary
    PRINT("\n========== Workqueue Summary ==========\n");

    // System status
    if (max_pending > 5 || total_busy > total_workers * 0.5) {
        PRINT("System Status: WARNING (high load detected)\n");
    } else {
        PRINT("System Status: OK\n");
    }

    PRINT("\nQuick Stats:\n");
    PRINT("  Pools: %zu (%zu per-CPU + %zu unbound)\n",
          worker_pool_map.size(), cpu_pools, unbound_pools);
    PRINT("  Workers: %zu (%zu busy, %zu idle)\n",
          total_workers, total_busy, total_idle);
    PRINT("  Pending Works: %zu\n", total_pending);

    // Per-CPU summary
    if (!cpu_pending_map.empty()) {
        PRINT("\nPer-CPU Summary:\n");
        for (const auto& pair : cpu_pending_map) {
            const char* warning = (pair.second > 5) ? "  [HIGH]" : "";
            PRINT("  CPU %-2d: %-4zu pending%s\n", pair.first, pair.second, warning);
        }
    }

    // Warnings
    bool has_warnings = false;
    if (max_pending > 5) {
        if (!has_warnings) {
            PRINT("\nWarnings:\n");
            has_warnings = true;
        }
        PRINT("  - CPU %d has %zu pending works\n",
              busiest_cpu, max_pending);
    }

    if (!has_warnings) {
        PRINT("\nNo issues detected.\n");
    }

    PRINT("\nTip: Use 'wq -d' for details, 'wq -c %d' for CPU %d details\n",
          busiest_cpu >= 0 ? busiest_cpu : 0,
          busiest_cpu >= 0 ? busiest_cpu : 0);
    PRINT("=======================================\n\n");
}

void Workqueue::print_detailed() {
    LOGD("Starting print_detailed");

    PRINT("\n========== Detailed Workqueue Information ==========\n");

    // Print explanation
    PRINT("\nNote:\n");
    PRINT("  - Idle: Worker is in idle_list (not currently executing work)\n");
    PRINT("  - Pending: Work items in worklist waiting to be executed\n");
    PRINT("  - nr_running: Number of workers currently executing work\n");
    PRINT("  - [DETACHED]: Pool is DISASSOCIATED (detached from CPU, legacy pool)\n");
    PRINT("  - When nr_running > 0, idle workers won't be woken up even if there are pending works\n");

    // Group pools by CPU
    std::map<int, std::vector<std::shared_ptr<worker_pool>>> cpu_pools_map;
    std::vector<std::shared_ptr<worker_pool>> unbound_pools_list;

    for (const auto& pair : worker_pool_map) {
        if (pair.second->cpu >= 0) {
            cpu_pools_map[pair.second->cpu].push_back(pair.second);
        } else {
            unbound_pools_list.push_back(pair.second);
        }
    }

    // Print per-CPU pools
    PRINT("\nPer-CPU Pools:\n");
    for (const auto& cpu_pair : cpu_pools_map) {
        int cpu = cpu_pair.first;
        const auto& pools = cpu_pair.second;

        PRINT("\nCPU %d:\n", cpu);
        for (const auto& pool : pools) {
            int busy_count = pool->nr_workers - pool->nr_idle;

            // void __init workqueue_init_early(void)
            const char* pool_type = (pool->nice == 0) ? "Normal Pool" : "High Pool";
            const char* warning = (pool->worklist.size() > 5) ? " [HIGH]" : "";

            LOGD("CPU %d: pool 0x%lx has id=%d, nice=%d, flags=%s",
                 cpu, pool->addr, pool->id, pool->nice, pool->flags.c_str());

            // Collect pool_workqueue information
            std::string pwq_info = "";
            if (!pool->pwq_list.empty()) {
                for (const auto& pwq : pool->pwq_list) {
                    if (!pwq_info.empty()) pwq_info += ", ";
                    std::ostringstream pwq_addr;
                    pwq_addr << std::hex << pwq->addr;
                    pwq_info += "pool_workqueue:0x" + pwq_addr.str();

                    // Add workqueue information if available
                    if (pwq->wq_ptr) {
                        std::ostringstream wq_addr;
                        wq_addr << std::hex << pwq->wq_ptr->addr;
                        pwq_info += " -> workqueue_struct[0x" + wq_addr.str() + "]";

                        if (!pwq->wq_ptr->name.empty()) {
                            pwq_info += " " + pwq->wq_ptr->name;
                        }
                    }
                }
            }

            // Show flags if not "None"
            if (pool->flags != "None") {
                // Check if DISASSOCIATED and add [DETACHED] marker
                std::string detached_marker = "";
                if (pool->flags.find("DISASSOCIATED") != std::string::npos) {
                    detached_marker = " [DETACHED]";
                }
                PRINT("  [%-11s] 0x%-16lx | %d workers (%d idle, %d busy) | %zu pending | nr_running=%lu%s | %s%s\n",
                      pool_type, pool->addr, pool->nr_workers, pool->nr_idle,
                      busy_count, pool->worklist.size(), pool->nr_running, warning,
                      pool->flags.c_str(), detached_marker.c_str());
                if (!pwq_info.empty()) {
                    PRINT("    %s\n", pwq_info.c_str());
                }
            } else {
                PRINT("  [%-11s] 0x%-16lx | %d workers (%d idle, %d busy) | %zu pending | nr_running=%lu%s\n",
                      pool_type, pool->addr, pool->nr_workers, pool->nr_idle,
                      busy_count, pool->worklist.size(), pool->nr_running, warning);
                if (!pwq_info.empty()) {
                    PRINT("    %s\n", pwq_info.c_str());
                }
            }

            // Show busy workers (not in idle_list)
            if (busy_count > 0) {
                PRINT("    Busy:");
                for (const auto& worker : pool->workers) {
                    bool is_idle = std::find(pool->idle_list.begin(),
                                           pool->idle_list.end(),
                                           worker) != pool->idle_list.end();
                    if (!is_idle) {
                        PRINT(" %s pid: %d", worker->comm.c_str(), worker->pid);
                    }
                }
                PRINT("\n");
            }

            // Show pending works (first 3)
            if (!pool->worklist.empty()) {
                PRINT("    Pending:");
                size_t count = 0;
                for (const auto& work : pool->worklist) {
                    if (count++ >= 3) {
                        PRINT(" ...");
                        break;
                    }
                    PRINT(" %s", print_func_name(work->func).c_str());
                }
                PRINT("\n");
            }
        }
    }

    // Print unbound pools
    if (!unbound_pools_list.empty()) {
        PRINT("\nUnbound Pools:\n");
        for (const auto& pool : unbound_pools_list) {
            int busy_count = pool->nr_workers - pool->nr_idle;
            PRINT("  0x%lx | %d workers (%d idle, %d busy) | %zu pending\n",
                  pool->addr, pool->nr_workers, pool->nr_idle,
                  busy_count, pool->worklist.size());
        }
    }

    PRINT("\nSummary: %zu pools, %zu workers, %zu total pending works\n",
          worker_pool_map.size(), worker_list_map.size(),
          [this]() {
              size_t total = 0;
              for (const auto& p : worker_pool_map) total += p.second->worklist.size();
              return total;
          }());
    PRINT("====================================================\n\n");
}

void Workqueue::print_check(std::string arg) {
    LOGD("Starting print_check with arg: %s", arg.c_str());

    // Check if the argument starts with "0x" to identify it as a hex address
    bool is_address = (arg.length() > 2 && arg.substr(0, 2) == "0x");

    // If not clearly an address, try to parse as CPU number
    bool is_cpu = !is_address;
    int cpu_num = -1;

    if (is_cpu) {
        try {
            cpu_num = std::stoi(arg);
            // Valid CPU number
            is_cpu = (cpu_num >= 0);
        } catch (...) {
            // Not a valid CPU number
            is_cpu = false;
            // Check if it might be an address without 0x prefix
            try {
                std::stoul(arg, nullptr, 16);
                is_address = true;
            } catch (...) {
                // Not a valid address either
                LOGE("Not a valid address either");
            }
        }
    }

    if (is_cpu) {
        // Print CPU details
        PRINT("\n========== CPU %d Details ==========\n", cpu_num);

        std::vector<std::shared_ptr<worker_pool>> cpu_pools;
        for (const auto& pair : worker_pool_map) {
            if (pair.second->cpu == cpu_num) {
                cpu_pools.push_back(pair.second);
            }
        }

        if (cpu_pools.empty()) {
            PRINT("No pools found for CPU %d\n", cpu_num);
            return;
        }

        size_t total_workers = 0;
        size_t total_idle = 0;
        size_t total_pending = 0;

        for (const auto& pool : cpu_pools) {
            const char* pool_type = (pool->nice == 0) ? "Normal" : "High";
            int busy_count = pool->nr_workers - pool->nr_idle;
            // queue_work() / __queue_work()
            //     → kick_pool()
            //         → wake_up_process(idle_worker)
            PRINT("\n[%s Priority] 0x%lx (nr_running=%lu)\n", pool_type, pool->addr, pool->nr_running);
            PRINT("  Workers: %d (%d idle, %d busy)\n",
                  pool->nr_workers, pool->nr_idle, busy_count);
            PRINT("  Pending: %zu works\n", pool->worklist.size());

    // Collect pool_workqueue information
    std::string pwq_info = "";
    if (!pool->pwq_list.empty()) {
        for (const auto& pwq : pool->pwq_list) {
            if (!pwq_info.empty()) pwq_info += ", ";
            std::ostringstream pwq_addr;
            pwq_addr << std::hex << pwq->addr;
            pwq_info += "pool_workqueue[0x" + pwq_addr.str() + "]";

            // Add workqueue information if available
            if (pwq->wq_ptr) {
                std::ostringstream wq_addr;
                wq_addr << std::hex << pwq->wq_ptr->addr;
                pwq_info += " -> workqueue_struct[0x" + wq_addr.str() + "]";

                if (!pwq->wq_ptr->name.empty()) {
                    pwq_info += " " + pwq->wq_ptr->name;
                }
            }
        }
        PRINT("  %s\n", pwq_info.c_str());
    }

            // Show workers
            if (!pool->workers.empty()) {
                PRINT("  Workers:\n");
                for (const auto& worker : pool->workers) {
                    bool is_idle = std::find(pool->idle_list.begin(),
                                           pool->idle_list.end(),
                                           worker) != pool->idle_list.end();

                    // Get current work information
                    std::string current_work = "None";
                    if (worker->current_func != 0) {
                        current_work = print_func_name(worker->current_func);
                    }

                    PRINT("    - %s [pid:%d] %s | current_func=%s | flags=%s\n",
                          worker->comm.c_str(),
                          worker->pid,
                          is_idle ? "idle" : "busy",
                          current_work.c_str(),
                          worker->flags.c_str());
                }
            }

            // Show pending works
            if (!pool->worklist.empty()) {
                PRINT("  Pending Works:\n");
                for (const auto& work : pool->worklist) {
                    PRINT("    - %s\n", print_func_name(work->func).c_str());
                }
            }

            total_workers += pool->nr_workers;
            total_idle += pool->nr_idle;
            total_pending += pool->worklist.size();
        }

        PRINT("\nCPU %d Summary:\n", cpu_num);
        PRINT("  Total Workers: %zu (%zu busy, %zu idle)\n",
              total_workers, total_workers - total_idle, total_idle);
        PRINT("  Total Pending: %zu works\n", total_pending);
        PRINT("=====================================\n\n");

    } else if (is_address) {
        // Handle as address
        LOGI("Handling %s as an address", arg.c_str());
        print_pool_by_addr(arg);
    } else {
        PRINT("Invalid argument: %s (not a CPU number or valid address)\n", arg.c_str());
    }
}

void Workqueue::parse_workqueue() {
    LOGD("Starting workqueue parsing");

    if (!workqueue_list.empty()) {
        LOGD("Workqueue list already populated (size=%zu)", workqueue_list.size());
        return;
    }

    // 1. Parse workqueues list
    if (csymbol_exists("workqueues")) {
        ulong workqueues_addr = csymbol_value("workqueues");
        LOGD("workqueues symbol address: 0x%lx", workqueues_addr);
        if (is_kvaddr(workqueues_addr)) {
            int offset = field_offset(workqueue_struct, list);
            std::vector<ulong> list = for_each_list(workqueues_addr, offset);
            LOGI("Found %zu workqueues to parse", list.size());
            for (const auto& addr : list) {
                auto workqueue_struct = parser_workqueue_struct(addr);
                workqueue_list.push_back(workqueue_struct);
            }
        }
    }

    // 2. Parse per-CPU worker pools
    parse_cpu_worker_pools();

    // 3. Parse unbound worker pools
    parse_unbound_pool_hash();

    LOGI("Successfully parsed all workqueues (total=%zu, worker_pools=%zu, workers=%zu)",
         workqueue_list.size(), worker_pool_map.size(), worker_list_map.size());
}

#pragma GCC diagnostic pop
