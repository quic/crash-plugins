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

#ifndef WORKQUEUE_DEFS_H_
#define WORKQUEUE_DEFS_H_

#include "plugin.h"
#include <map>

enum worker_flags {
  WORKER_DIE = 1 << 1,
  WORKER_IDLE = 1 << 2,
  WORKER_PREP = 1 << 3,
  WORKER_CPU_INTENSIVE = 1 << 6,
  WORKER_UNBOUND = 1 << 7,
  WORKER_REBOUND = 1 << 8,
};

enum worker_pool_flags {
  POOL_MANAGER_ACTIVE = 1 << 0,
  POOL_DISASSOCIATED = 1 << 2,
};

enum workqueue_struct_flags {
  WQ_UNBOUND = 1 << 1,
  WQ_FREEZABLE = 1 << 2,
  WQ_MEM_RECLAIM = 1 << 3,
  WQ_HIGHPRI = 1 << 4,
  WQ_CPU_INTENSIVE = 1 << 5,
  WQ_SYSFS = 1 << 6,
};

struct worker;
struct worker_pool;
struct pool_workqueue;
struct workqueue_struct;

// task
struct work_struct{
  ulong addr;
  ulong data;
  ulong func;
};

// staff
struct worker{
  ulong addr;
  std::string comm;
  int pid;
  // std::shared_ptr<work_struct> current_work;
  ulong current_func;
  ulong task_addr;
  ulong last_active;
  std::string flags;
  int id;
  int sleeping;
  std::string desc;
  ulong last_func;
  std::shared_ptr<worker_pool> wp_ptr;
};

// department
struct worker_pool{
  ulong addr;
  int cpu;
  int node;
  int id;
  int nice;
  std::string flags;
  ulong watchdog_ts;
  int nr_running;
  std::vector<std::shared_ptr<work_struct>> worklist; // save pending work_struct
  int nr_workers;
  int nr_idle;
  std::set<std::shared_ptr<pool_workqueue>> pwq_list; // save all pool_workqueue
  std::vector<std::shared_ptr<worker>> idle_list; // save idle worker
  std::vector<std::shared_ptr<worker>> workers; // save all worker
  std::vector<ulong> busy_hash;
};

// department leader
struct pool_workqueue{
  ulong addr;
  std::shared_ptr<workqueue_struct> wq_ptr;
  std::shared_ptr<worker_pool> wp_ptr;
  int refcnt;
  int nr_active;
  int max_active;
  std::vector<std::shared_ptr<work_struct>> delay_works_list; // save delay work_struct
};

// project
struct workqueue_struct{
  ulong addr;
  std::string name;
  std::string flags;
  int nr_drainers;
  std::vector<std::shared_ptr<pool_workqueue>> pwqs;
  std::shared_ptr<worker> rescuer;
};

class Workqueue : public ParserPlugin {
private:
    std::vector<std::shared_ptr<workqueue_struct>> workqueue_list;
    std::unordered_map<ulong/* worker ddr address */, std::shared_ptr<worker>> worker_list_map;
    std::unordered_map<ulong/* worker_pool addr address */, std::shared_ptr<worker_pool>> worker_pool_map;
    std::vector<std::shared_ptr<worker>> idle_worker_list; // save all idle worker, same as idle_list
    // only format for print
    size_t workqueue_name_len = 0;
    size_t worker_flags_len = 0;
    size_t worker_pool_flags_len = 0;

    void print_summary();
    void print_detailed();
    void print_check(std::string arg);
    void print_pool_by_addr(std::string addr);
    std::vector<std::shared_ptr<work_struct>> parser_work_list(ulong list_head);
    std::shared_ptr<worker> parser_worker(ulong addr,std::shared_ptr<worker_pool> wp_ptr);
    std::vector<std::shared_ptr<worker>> parser_worker_list(ulong list_head_addr,int offset,std::shared_ptr<worker_pool> wp_ptr);
    std::shared_ptr<worker_pool> parser_worker_pool(ulong addr,std::shared_ptr<pool_workqueue> pwq_ptr);
    std::shared_ptr<pool_workqueue> parser_pool_workqueue(ulong addr,std::shared_ptr<workqueue_struct> wq_ptr);
    std::shared_ptr<workqueue_struct> parser_workqueue_struct(ulong addr);
    void parse_cpu_worker_pools();
    void parse_unbound_pool_hash();
    void parse_workqueue();
    template <typename T>
    std::string parser_flags(uint flags, const std::unordered_map<T, std::string>& flags_array);

public:
    Workqueue();
    void cmd_main(void) override;
    void init_offset(void) override;
    void init_command(void) override;
    DEFINE_PLUGIN_INSTANCE(Workqueue)
};

#endif // WORKQUEUE_DEFS_H_
