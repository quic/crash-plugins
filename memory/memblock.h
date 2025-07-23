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

#ifndef MEMBLOCK_DEFS_H_
#define MEMBLOCK_DEFS_H_

#include "plugin.h"
#include "devicetree/devicetree.h"

enum memblock_flags {
  MEMBLOCK_NONE = 0,
  MEMBLOCK_HOTPLUG = 1,
  MEMBLOCK_MIRROR = 2,
  MEMBLOCK_NOMAP = 4,
};

struct memblock_region {
    ulong addr;
    physaddr_t base;
    physaddr_t size;
    enum memblock_flags flags;
};

struct memblock_type {
    ulong addr;
    unsigned long cnt;
    unsigned long max;
    uint64_t total_size;
    std::vector<std::shared_ptr<memblock_region>> regions;
    std::string name;
};

struct memblock {
    ulong addr;
    bool bottom_up;
    unsigned long current_limit;
    struct memblock_type memory;
    struct memblock_type reserved;
};

class Memblock : public ParserPlugin {
private:
    std::shared_ptr<memblock> block;

    void parser_memblock();
    void parser_memblock_type(ulong addr,memblock_type* type);
    std::vector<std::shared_ptr<memblock_region>> parser_memblock_region(ulong addr,int cnt);
    void print_memblock();
    void print_memblock_type(memblock_type* type);

public:
    Memblock();
    void cmd_main(void) override;
    void init_offset(void) override;
    void init_command(void) override;
    DEFINE_PLUGIN_INSTANCE(Memblock)
};


#endif // MEMBLOCK_DEFS_H_
