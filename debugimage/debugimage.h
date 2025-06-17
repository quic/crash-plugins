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

#ifndef DEBUG_IMAGE_DEFS_H_
#define DEBUG_IMAGE_DEFS_H_

#include "plugin.h"
#include "cpu32_ctx.h"
#include "cpu64_ctx_v13.h"
#include "cpu64_ctx_v14.h"
#include "cpu64_ctx_v20.h"

struct Dump_entry {
    ulong addr;
    uint32_t id;
    uint32_t version;
    uint32_t magic;
    std::string data_name;
    uint64_t data_addr;
    uint64_t data_len;
};

enum Entry_type{
    ENTRY_TYPE_DATA,
    ENTRY_TYPE_TABLE
};

enum Dump_data_ids {
    DATA_CPU_CTX = 0x00,
    DATA_L1_INST_TLB = 0x20,
    DATA_L1_DATA_TLB = 0x40,
    DATA_L1_INST_CACHE = 0x60,
    DATA_L1_DATA_CACHE = 0x80,
    DATA_ETM_REG = 0xA0,
    DATA_L2_CACHE = 0xC0,
    DATA_L3_CACHE = 0xD0,
    DATA_OCMEM = 0xE0,
    DATA_DBGUI_REG = 0xE5,
    DATA_MISC = 0xE8,
    DATA_VSENSE = 0xE9,
    DATA_TMC_ETF = 0xF0,
    DATA_TMC_ETF_SWAO = 0xF1,
    DATA_TMC_REG = 0x100,
    DATA_TMC_ETR_REG = 0x100,
    DATA_TMC_ETF_REG = 0x101,
    DATA_TMC_ETR1_REG = 0x105,
    DATA_TMC_ETF_SWAO_REG = 0x102,
    DATA_LOG_BUF = 0x110,
    DATA_LOG_BUF_FIRST_IDX = 0x111,
    DATA_L2_TLB = 0x120,
    DATA_DCC_REG = 0xE6,
    DATA_DCC_SRAM = 0xE7,
    DATA_SCANDUMP = 0xEB,
    DATA_RPMH = 0xEC,
    DATA_FCMDUMP = 0xEE,
    DATA_CPUSS = 0xEF,
    DATA_SCANDUMP_PER_CPU = 0x130,
    DATA_LLC_CACHE = 0x140,
    DATA_MHM = 0x161,
    DATA_MAX = 0x164,
};

struct cpu_context {
    unsigned long x19;
    unsigned long x20;
    unsigned long x21;
    unsigned long x22;
    unsigned long x23;
    unsigned long x24;
    unsigned long x25;
    unsigned long x26;
    unsigned long x27;
    unsigned long x28;
    unsigned long fp;
    unsigned long sp;
    unsigned long pc;
};

class ImageParser;

class DebugImage : public ParserPlugin {
private:
    const uint MAGIC_NUMBER = 0x42445953;
    const uint HYP_MAGIC_NUMBER = 0x42444832;
    std::vector<std::shared_ptr<Dump_entry>> image_list;
    std::shared_ptr<ImageParser> parser_ptr;
    bool debug = false;
    int32_t cpu_index_offset = 0;

public:
    DebugImage();
    void print_memdump();
    void cmd_main(void) override;
    DEFINE_PLUGIN_INSTANCE(DebugImage)
    void parser_memdump();
    void parser_debugimage(ulong addr);
    void print_cpu_stack();
    void parse_cpu_ctx();
    void parse_cpu_stack(std::shared_ptr<Dump_entry> entry_ptr);
    void parse_cpu_ctx(std::shared_ptr<Dump_entry> entry_ptr);
    void parser_dump_data(std::shared_ptr<Dump_entry> entry_ptr);
    void parser_dump_table(uint64_t paddr);
    std::set<ulong> find_x29(const std::map<ulong, ulong>& addr_x29);
    void print_task_stack(int pid);
    void print_irq_stack(int cpu);
};

#endif // DEBUG_IMAGE_DEFS_H_
