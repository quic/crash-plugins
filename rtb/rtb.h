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

#ifndef RTB_DEFS_H_
#define RTB_DEFS_H_

#include "plugin.h"
#include <cmath>
enum logk_event_type {
    LOGK_NONE = 0,
    LOGK_READL = 1,
    LOGK_WRITEL = 2,
    LOGK_LOGBUF = 3,
    LOGK_HOTPLUG = 4,
    LOGK_CTXID = 5,
    LOGK_TIMESTAMP = 6,
    LOGK_L2CPREAD = 7,
    LOGK_L2CPWRITE = 8,
    LOGK_IRQ = 9,
};

struct rtb_layout {
    unsigned char sentinel[3];
    unsigned char log_type;
    uint32_t idx;
    uint64_t caller;
    uint64_t data;
    uint64_t timestamp;
    uint64_t cycle_count;
} __attribute__ ((__packed__));

struct rtb_state {
    std::vector<ulong> rtb_idx;
    ulong rtb_layout;
    physaddr_t phys;
    int nentries;
    int size;
    int enabled;
    int initialized;
    uint32_t filter;
    int step_size;
};

class Rtb : public ParserPlugin {
private:
    std::shared_ptr<rtb_state> rtb_state_ptr;
public:
    Rtb();
    void cmd_main(void) override;
    void init_offset();
    void parser_rtb_log();
    bool is_enable_rtb();
    void print_rtb_log();
    void print_percpu_rtb_log(int cpu);
    void print_rtb_log_memory();
    int print_rtb_layout(int cpu,int index);
    int next_rtb_entry(int index);
    void print_none(int cpu, struct rtb_layout& layout);
    void print_read_write(int cpu, struct rtb_layout& layout);
    void print_logbuf(int cpu, struct rtb_layout& layout);
    void print_hotplug(int cpu, struct rtb_layout& layout);
    void print_ctxid(int cpu, struct rtb_layout& layout);
    void print_timestamp(int cpu, struct rtb_layout& layout);
    void print_l2cpread_write(int cpu, struct rtb_layout& layout);
    void print_irq(int cpu, struct rtb_layout& layout);
    std::string get_caller(struct rtb_layout& layout);
    std::string get_fun_name(struct rtb_layout& layout);
    double get_timestamp(struct rtb_layout& layout);
    DEFINE_PLUGIN_INSTANCE(Rtb)
};

#endif // RTB_DEFS_H_
